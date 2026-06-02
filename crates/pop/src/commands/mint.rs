//! `pop mint` — the core funder flow.
//!
//! Derives a fresh funder key, creates a PoP quote, INDEPENDENTLY re-verifies
//! the returned funding address (recompute cm→P_internal→Q and assert it
//! matches the mint's address + returned internal_key/leaf_script), persists
//! the deposit and writes the recovery file BEFORE showing the address, polls
//! for funding, records the funding outpoint, mints the ecash, and PRINTS the
//! cashuB token (optionally also to a file). The ecash is not stored.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Network;
use cdk_common::nuts::CurrencyUnit;
use clap::Parser;

use pops_core_funder::{reconstruct, Construction, ConstructionParams};

use crate::chain::Esplora;
use crate::config::Config;
use crate::db::{Deposit, DepositState};
use crate::derive::funder_path_string;
use crate::error::PopError;
use crate::mint_client::{self, now_unix, PopQuoteResponse};
use crate::recovery::{utc_iso8601, RecoveryFile};
use crate::signer::HotKeySigner;
use crate::wallet::{recovery_dir, Wallet};
use crate::SCHEMA_VERSION;

/// Default seconds in a "30d" style duration.
const SECS_PER_DAY: u64 = 86_400;

/// Arguments for `pop mint`.
#[derive(Debug, Parser)]
pub struct MintArgs {
    /// Mint base URL (e.g. `https://mint.example`).
    #[arg(long, value_name = "URL")]
    pub mint_url: String,

    /// Amount to lock + mint, in sats.
    #[arg(long, value_name = "SATS")]
    pub amount: u64,

    /// Credential lifetime as a duration (e.g. `30d`, `12h`). `ts = now + dur`.
    /// Mutually exclusive with `--unit`.
    #[arg(long, value_name = "DUR", conflicts_with = "unit")]
    pub duration: Option<String>,

    /// Explicit unit `pop_<ts_expiry>`. Mutually exclusive with `--duration`.
    #[arg(long, value_name = "pop_<ts>")]
    pub unit: Option<String>,

    /// The mint's 33-byte compressed identity pubkey (hex). REQUIRED on first
    /// use of a mint (TOFU-pinned into config.toml); it is the value committed
    /// into `cm` and is needed to independently verify the funding address.
    /// On later mints to the same mint it must match the pin or it's a hard
    /// error.
    #[arg(long, value_name = "HEX33")]
    pub mint_pubkey: Option<String>,

    /// Optional human label for the deposit.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,

    /// Poll interval while waiting for funding, seconds.
    #[arg(long, value_name = "SECS", default_value_t = 5)]
    pub poll_interval: u64,

    /// Overall timeout for the funding poll, seconds.
    #[arg(long, value_name = "SECS", default_value_t = 1800)]
    pub poll_timeout: u64,

    /// Also write the issued cashuB token to this file.
    #[arg(long, value_name = "PATH")]
    pub token_out: Option<std::path::PathBuf>,

    /// Resume an existing open deposit by id (skip quote-create; reattach).
    #[arg(long, value_name = "DEPOSIT_ID")]
    pub resume: Option<String>,
}

/// The product of the shared pre-poll half of the flow: the quote has been
/// created, the funding address INDEPENDENTLY verified, the deposit persisted
/// (Unpaid), and the recovery file written. Both `quote::run` (which stops
/// here) and `mint::run` (which goes on to poll + mint) consume this.
pub struct QuoteOutcome {
    /// Wallet-local deposit id (uuid).
    pub deposit_id: String,
    /// Resolved unit string `pop_<ts_expiry>`.
    pub unit_str: String,
    /// CLTV expiry / unit ts.
    pub ts_expiry: u64,
    /// Amount locked + to be minted, sats.
    pub amount: u64,
    /// The full reconstructed taproot construction (carries the funding
    /// address).
    pub construction: Construction,
    /// Frozen funder derivation path string.
    pub derivation_path: String,
    /// The mint's quote id.
    pub quote_id: String,
    /// The written recovery file (with the funding outpoint still `None`).
    pub recovery: RecoveryFile,
}

impl QuoteOutcome {
    /// BIP-21 payment URI for the funding address + exact amount.
    pub fn bip21_uri(&self) -> String {
        format!(
            "bitcoin:{}?amount={}",
            self.construction.address,
            format_btc(self.amount)
        )
    }
}

/// The shared PRE-POLL half of the funder flow, used by BOTH `pop mint` and
/// `pop quote`: resolve the unit, derive a fresh funder key, create the quote,
/// INDEPENDENTLY verify the returned funding address, persist the deposit
/// (Unpaid), and write the recovery file. Stops before any funding poll.
///
/// Prints NOTHING to stdout (the caller emits the single JSON object, or the
/// human result); all diagnostics/progress go to STDERR.
///
/// # Errors
///
/// Propagates every step's errors; aborts with [`PopError::AddressMismatch`] on
/// an address-verification mismatch.
pub async fn create_and_persist_quote(
    wallet: &mut Wallet,
    http: &reqwest::Client,
    base: &str,
    seed: &[u8],
    args: &MintArgs,
    wallet_dir: &Path,
) -> Result<QuoteOutcome, Box<dyn std::error::Error>> {
    let network = wallet.network();

    // ---- Resolve the unit. ----
    let unit_str = resolve_unit(args)?;
    let ts_expiry = parse_unit_ts(&unit_str)?;
    // Progress/diagnostics always go to STDERR (stdout stays pure-json in the
    // default mode; in --human mode the final result is what lands on stdout).
    eprintln!(
        "Unit:    {unit_str}  (recover-after {})",
        utc_iso8601(ts_expiry)
    );

    // ---- Derive a fresh funder key at the next index. ----
    let index = wallet.db.next_derivation_index()?;
    let funder = wallet.funder_key(seed, index)?;
    let funder_secret_hex = hex::encode(funder.secret_key.secret_bytes());
    let funder_cdk = mint_client::parse_cdk_secret(&funder_secret_hex)?;

    // ---- Create the quote. ----
    eprintln!("Creating quote at {base} for {} sats ...", args.amount);
    let quote = mint_client::create_quote(http, base, args.amount, &unit_str, &funder_cdk).await?;

    // ---- Pin the mint identity key (TOFU) + INDEPENDENTLY verify the address.
    let nonce = require_nonce(&quote)?;
    let mint_pubkey =
        pin_and_resolve_mint_pubkey(&mut wallet.config, base, args.mint_pubkey.as_deref())?;
    wallet.config.write(wallet_dir)?;

    let params = ConstructionParams {
        mint_pubkey,
        ts_expiry,
        nonce,
        funder_pubkey: funder.xonly,
        network,
    };
    verify_quote_address(&quote, &params, &funder.xonly, ts_expiry)?;
    let construction = reconstruct(&params);
    eprintln!("Address independently verified against the mint's quote. OK.");

    // ---- Persist the deposit (Unpaid) + write the recovery file FIRST. ----
    let deposit_id = uuid::Uuid::new_v4().to_string();
    let derivation_path = funder_path_string(network, index);
    let deposit = Deposit {
        id: deposit_id.clone(),
        label: args.label.clone(),
        mint_url: base.to_string(),
        unit: unit_str.clone(),
        ts_expiry,
        amount: args.amount,
        funder_index: index,
        funder_pubkey: hex::encode(funder.xonly.serialize()),
        quote_lock_pubkey: funder_cdk.public_key().to_hex(),
        p_internal: hex::encode(construction.internal_key.serialize()),
        leaf_script: hex::encode(construction.leaf_script.as_bytes()),
        nonce: hex::encode(nonce),
        mint_pubkey: hex::encode(mint_pubkey),
        funding_address: construction.address.clone(),
        quote_id: quote.quote.clone(),
        state: DepositState::Unpaid,
        funding_txid: None,
        funding_vout: None,
        recovery_txid: None,
        created_at: now_unix(),
    };
    wallet.db.insert_deposit(&deposit)?;

    let recovery = RecoveryFile::build(
        &deposit_id,
        args.label.as_deref(),
        base,
        args.amount,
        &unit_str,
        &params,
        &derivation_path,
        None,
    );
    let recovery_path = recovery.write(&recovery_dir(wallet_dir))?;
    eprintln!("Recovery file written: {}", recovery_path.display());

    Ok(QuoteOutcome {
        deposit_id,
        unit_str,
        ts_expiry,
        amount: args.amount,
        construction,
        derivation_path,
        quote_id: quote.quote,
        recovery,
    })
}

/// Runs `pop mint`.
///
/// # Errors
///
/// Propagates every step's errors; aborts on an address-verification mismatch.
pub async fn run(
    args: &MintArgs,
    wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = Wallet::open(wallet_dir)?;
    let base = args.mint_url.trim_end_matches('/').to_string();
    let http = reqwest::Client::new();

    // Load the seed up front (mint always needs the funder key).
    let seed = wallet.load_seed()?;

    if let Some(deposit_id) = &args.resume {
        return resume(&mut wallet, &http, &base, deposit_id, &seed, args, json).await;
    }

    // ---- Shared pre-poll half: quote -> verify -> persist -> recovery file. ----
    let outcome =
        create_and_persist_quote(&mut wallet, &http, &base, &seed, args, wallet_dir).await?;

    // ---- Show the funding instruction (human result only). ----
    if !json {
        print_funding_instruction(
            &outcome.construction.address,
            outcome.amount,
            outcome.ts_expiry,
            &outcome.derivation_path,
        );
    }

    // ---- Poll until PAID. ---- (progress always to stderr)
    eprintln!(
        "\nWaiting for funding (poll every {}s, timeout {}s) ...",
        args.poll_interval, args.poll_timeout
    );
    let paid = mint_client::poll_until_paid(
        &http,
        &base,
        &outcome.quote_id,
        &outcome.construction.address,
        Duration::from_secs(args.poll_interval),
        Duration::from_secs(args.poll_timeout),
    )
    .await?;
    eprintln!("Funding credited (amount_paid={}).", paid.amount_paid);

    // ---- Record the funding outpoint + patch the recovery file. ----
    record_funding_outpoint(
        &wallet,
        wallet_dir,
        &outcome.deposit_id,
        &outcome.construction.address,
        &outcome.recovery,
    )
    .await?;
    wallet.db.set_state(&outcome.deposit_id, DepositState::Paid)?;

    // ---- Mint the ecash + print the token. ----
    finish_mint(
        &wallet,
        &http,
        &base,
        &outcome.deposit_id,
        &outcome.unit_str,
        &seed,
        args,
        json,
    )
    .await
}

/// `--resume` path: reattach to an open deposit and re-run from the funding
/// poll (or directly mint if already PAID).
async fn resume(
    wallet: &mut Wallet,
    http: &reqwest::Client,
    base: &str,
    deposit_id: &str,
    seed: &[u8],
    args: &MintArgs,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let dep = wallet
        .db
        .get_deposit(deposit_id)?
        .ok_or_else(|| PopError::DepositNotFound {
            deposit_id: deposit_id.to_string(),
        })?;
    if dep.state == DepositState::Minted {
        return Err(PopError::invalid_input(format!(
            "deposit {deposit_id} is already Minted"
        ))
        .into());
    }
    if dep.state == DepositState::Recovered {
        return Err(PopError::invalid_input(format!(
            "deposit {deposit_id} was already Recovered"
        ))
        .into());
    }
    // Sanity: the resumed deposit's funder key must still derive to the stored
    // pubkey (guards against a wrong wallet/seed).
    let funder = wallet.funder_key(seed, dep.funder_index)?;
    if hex::encode(funder.xonly.serialize()) != dep.funder_pubkey {
        return Err(PopError::invalid_input(
            "resumed deposit's derived funder key does not match the stored \
             funder pubkey (wrong seed?)",
        )
        .into());
    }

    eprintln!("Resuming deposit {deposit_id} (state {:?}).", dep.state);
    if dep.state == DepositState::Unpaid {
        let paid = mint_client::poll_until_paid(
            http,
            base,
            &dep.quote_id,
            &dep.funding_address,
            Duration::from_secs(args.poll_interval),
            Duration::from_secs(args.poll_timeout),
        )
        .await?;
        eprintln!("Funding credited (amount_paid={}).", paid.amount_paid);
        // Patch outpoint into the recovery file.
        let dir = wallet.dir.clone();
        let recovery_path = RecoveryFile::path_in(&recovery_dir(&dir), deposit_id);
        if let Ok(rf) = RecoveryFile::load(&recovery_path) {
            record_funding_outpoint(wallet, &dir, deposit_id, &dep.funding_address, &rf).await?;
        }
        wallet.db.set_state(deposit_id, DepositState::Paid)?;
    }

    finish_mint(wallet, http, base, deposit_id, &dep.unit, seed, args, json).await
}

/// Mints the ecash for a PAID deposit and prints the cashuB token. The
/// unlocked `seed` (already held by the caller) re-derives the NUT-20 signing
/// key from the deposit's stored index.
#[allow(clippy::too_many_arguments)]
async fn finish_mint(
    wallet: &Wallet,
    http: &reqwest::Client,
    base: &str,
    deposit_id: &str,
    unit_str: &str,
    seed: &[u8],
    args: &MintArgs,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let dep = wallet
        .db
        .get_deposit(deposit_id)?
        .ok_or_else(|| PopError::internal("deposit vanished mid-mint"))?;
    let unit = CurrencyUnit::from_str(unit_str)
        .map_err(|e| PopError::internal(format!("unit `{unit_str}` is not a valid CurrencyUnit: {e}")))?;

    // NUT-20 signing for the issuance request goes through the funder signer
    // seam, bound to this deposit's index (re-derives from the seed internally).
    let signer = HotKeySigner::new(seed, wallet.network(), dep.funder_index);

    eprintln!("Issuing {} sats of {unit_str} ...", dep.amount);
    let token = mint_client::mint_token(
        http,
        base,
        &dep.quote_id,
        &unit,
        dep.amount,
        &signer,
        dep.funder_index,
    )
    .await?;
    let token_str = token.to_string();

    wallet.db.set_state(deposit_id, DepositState::Minted)?;

    if let Some(path) = &args.token_out {
        std::fs::write(path, &token_str)
            .map_err(|e| PopError::invalid_input(format!("failed to write token to {}: {e}", path.display())))?;
        eprintln!("Token written to {}", path.display());
    }

    if json {
        let out = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "deposit_id": deposit_id,
            "mint_url": base,
            "unit": unit_str,
            "amount_sats": dep.amount,
            "state": "minted",
            "token": token_str,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("\n==================== ISSUED ====================");
        println!("mint:        {base}");
        println!("unit:        {unit_str}");
        println!("amount:      {} sats", dep.amount);
        println!("deposit id:  {deposit_id}");
        println!("\nYour cashuB credential token (NOT stored by this wallet — save it):\n");
        println!("{token_str}");
    }
    Ok(())
}

/// Discovers + records the funding outpoint from the address history, and
/// patches it into the recovery file.
async fn record_funding_outpoint(
    wallet: &Wallet,
    wallet_dir: &Path,
    deposit_id: &str,
    funding_address: &str,
    recovery: &RecoveryFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let esplora = Esplora::new(&wallet.config.esplora_url);
    let utxos = esplora.address_utxos(funding_address).await?;
    // Pick the first confirmed UTXO (the credited deposit). If none confirmed
    // yet, fall back to the first seen.
    let chosen = utxos
        .iter()
        .find(|u| u.status.confirmed)
        .or_else(|| utxos.first());
    match chosen {
        Some(u) => {
            wallet
                .db
                .set_funding_outpoint(deposit_id, &u.txid, u.vout)?;
            let mut patched = recovery.clone();
            patched.funding_outpoint = Some(format!("{}:{}", u.txid, u.vout));
            patched.write(&recovery_dir(wallet_dir))?;
            eprintln!("Funding outpoint recorded: {}:{}", u.txid, u.vout);
        }
        None => {
            eprintln!(
                "Note: funding credited by the mint but no UTXO visible at the address \
                 via esplora yet; outpoint will be filled on next `status`/`recover`."
            );
        }
    }
    Ok(())
}

/// Resolves the unit string from `--unit` or `--duration` (`now + dur`).
fn resolve_unit(args: &MintArgs) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(u) = &args.unit {
        if !u.starts_with("pop_") {
            return Err(
                PopError::invalid_input(format!("--unit must be of the form pop_<ts> (got {u})")).into(),
            );
        }
        return Ok(u.clone());
    }
    let dur = args.duration.as_deref().unwrap_or("30d");
    let secs = parse_duration_secs(dur)?;
    let ts = now_unix() + secs;
    Ok(format!("pop_{ts}"))
}

/// Parses a `pop_<ts>` unit's expiry timestamp.
fn parse_unit_ts(unit: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let ts_str = unit
        .strip_prefix("pop_")
        .ok_or_else(|| PopError::invalid_input(format!("unit `{unit}` is not pop_<ts>")))?;
    ts_str
        .parse::<u64>()
        .map_err(|e| PopError::invalid_input(format!("unit `{unit}` has a non-numeric ts: {e}")).into())
}

/// Parses a duration like `30d`, `12h`, `45m`, `3600s` into seconds.
fn parse_duration_secs(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(s.len()),
    );
    let n: u64 = num.parse().map_err(|_| {
        PopError::invalid_input(format!("invalid duration `{s}` (expected e.g. 30d, 12h, 45m)"))
    })?;
    let mult = match unit {
        "d" | "" => SECS_PER_DAY,
        "h" => 3_600,
        "m" => 60,
        "s" => 1,
        other => {
            return Err(PopError::invalid_input(format!(
                "unknown duration unit `{other}` (use d|h|m|s)"
            ))
            .into())
        }
    };
    Ok(n * mult)
}

/// Extracts the required 32-byte nonce from the quote response.
fn require_nonce(quote: &PopQuoteResponse) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let nonce_hex = quote.nonce.as_ref().ok_or_else(|| {
        PopError::MintError {
            status: None,
            mint_message: "quote response is missing `nonce` (cannot build the recovery commitment)"
                .to_string(),
        }
    })?;
    let bytes = hex::decode(nonce_hex)
        .map_err(|e| PopError::internal(format!("quote nonce hex decode failed: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| PopError::internal("quote nonce must be 32 bytes").into())
}

/// Resolves the mint's 33-byte identity pubkey, TOFU-pinning it on first use.
///
/// cdk-pop's quote response does NOT echo the mint pubkey (it is a mint-side
/// config value fed into `cm`), so the funder MUST supply it out-of-band the
/// first time. Resolution order:
/// - if `--mint-pubkey` is given, TOFU-pin it (a mismatch with an existing pin
///   is a hard error via `Config::pin_mint_pubkey`);
/// - else use a previously pinned key;
/// - else error (without it the address cannot be independently verified — the
///   funder's sole defense).
fn pin_and_resolve_mint_pubkey(
    config: &mut Config,
    base: &str,
    supplied: Option<&str>,
) -> Result<[u8; 33], Box<dyn std::error::Error>> {
    if let Some(hex_str) = supplied {
        let hex_str = hex_str.trim().to_lowercase();
        // Validate shape before pinning (user input → invalid_input).
        let bytes = hex::decode(&hex_str)
            .map_err(|e| PopError::invalid_input(format!("--mint-pubkey hex decode failed: {e}")))?;
        let arr: [u8; 33] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PopError::invalid_input("--mint-pubkey must be 33 bytes (compressed)"))?;
        // TOFU-pin (a changed key for a known mint is a hard error — surfaced as
        // invalid_input so the caller can re-confirm the mint identity).
        config
            .pin_mint_pubkey(base, &hex_str)
            .map_err(|e| PopError::invalid_input(e.to_string()))?;
        return Ok(arr);
    }
    if let Some(hex_str) = config.mint_pubkeys.get(base) {
        let bytes = hex::decode(hex_str)
            .map_err(|e| PopError::internal(format!("pinned mint_pubkey hex decode failed: {e}")))?;
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| PopError::internal("pinned mint_pubkey must be 33 bytes").into());
    }
    Err(PopError::invalid_input(format!(
        "no mint identity key for {base}. The funder MUST know the mint's identity \
         pubkey to independently verify the funding address (the sole defense against a \
         malicious address). Pass --mint-pubkey <33-byte-compressed-hex> on first use; \
         it will be TOFU-pinned in config.toml."
    ))
    .into())
}

/// INDEPENDENT address verification: recompute the construction from public
/// params and assert it matches the mint's returned address + internal_key +
/// leaf_script. Aborts on any mismatch.
fn verify_quote_address(
    quote: &PopQuoteResponse,
    params: &ConstructionParams,
    funder_xonly: &XOnlyPublicKey,
    ts_expiry: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let c = reconstruct(params);

    // Each of these is the SAME security stop: the mint's construction differs
    // from our independent reconstruction → `address_mismatch` (do NOT fund).
    // `expected` = our recomputed value, `got` = what the mint returned.
    if quote.request != c.address {
        return Err(PopError::AddressMismatch {
            expected: c.address.clone(),
            got: quote.request.clone(),
        }
        .into());
    }

    if let Some(ik) = &quote.internal_key {
        let ours = hex::encode(c.internal_key.serialize());
        if !ik.eq_ignore_ascii_case(&ours) {
            return Err(PopError::AddressMismatch {
                expected: ours,
                got: ik.clone(),
            }
            .into());
        }
    }

    if let Some(ls) = &quote.leaf_script {
        let ours = hex::encode(c.leaf_script.as_bytes());
        if !ls.eq_ignore_ascii_case(&ours) {
            return Err(PopError::AddressMismatch {
                expected: ours,
                got: ls.clone(),
            }
            .into());
        }
    }

    // Cross-check the echoed funder pubkey, if present.
    if let Some(fp) = &quote.funder_pubkey {
        let ours = hex::encode(funder_xonly.serialize());
        if !fp.eq_ignore_ascii_case(&ours) {
            return Err(PopError::AddressMismatch {
                expected: ours,
                got: fp.clone(),
            }
            .into());
        }
    }

    // The leaf must bind exactly our ts_expiry (defensive; reconstruct already
    // used it).
    debug_assert_eq!(params.ts_expiry, ts_expiry);
    Ok(())
}

/// Prints the funding instruction: address, exact amount, BIP-21 URI, recovery
/// date, and which derivation key recovers it.
pub fn print_funding_instruction(address: &str, amount: u64, ts_expiry: u64, derivation_path: &str) {
    let btc = format_btc(amount);
    println!("\n==================== FUND THIS ADDRESS ====================");
    println!("Send EXACTLY {amount} sats ({btc} BTC) to:");
    println!("\n    {address}\n");
    println!("BIP-21 URI (scan with a phone wallet):");
    println!("    bitcoin:{address}?amount={btc}");
    println!("\nOver- or under-funding will NOT credit. Funding is on-chain (~1 conf),");
    println!("not instant — this wallet waits for the mint to confirm before issuing.");
    println!(
        "\nRecoverable by YOU after {} via derivation {}.",
        utc_iso8601(ts_expiry),
        derivation_path
    );
    println!("===========================================================");
}

/// Formats sats as a fixed-8-decimal BTC string for BIP-21.
fn format_btc(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    format!("{whole}.{frac:08}")
}

/// Unused network arg kept for signature symmetry in tests.
#[allow(dead_code)]
fn _net(_n: Network) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_secs("30d").unwrap(), 30 * SECS_PER_DAY);
        assert_eq!(parse_duration_secs("12h").unwrap(), 12 * 3600);
        assert_eq!(parse_duration_secs("45m").unwrap(), 45 * 60);
        assert_eq!(parse_duration_secs("3600s").unwrap(), 3600);
        assert_eq!(parse_duration_secs("7").unwrap(), 7 * SECS_PER_DAY);
        assert!(parse_duration_secs("5y").is_err());
    }

    #[test]
    fn unit_ts_parsing() {
        assert_eq!(parse_unit_ts("pop_1782259200").unwrap(), 1_782_259_200);
        assert!(parse_unit_ts("pop_notanumber").is_err());
        assert!(parse_unit_ts("sat").is_err());
    }

    #[test]
    fn btc_formatting() {
        assert_eq!(format_btc(100_000_000), "1.00000000");
        assert_eq!(format_btc(10_000), "0.00010000");
        assert_eq!(format_btc(1), "0.00000001");
    }

    /// Builds a `QuoteOutcome` over cdk-pop's pinned regtest construction
    /// vector and asserts the BIP-21 URI it emits (the one new pure datum the
    /// `quote` JSON adds) is exactly `bitcoin:<addr>?amount=<btc>`.
    #[test]
    fn quote_outcome_bip21_uri_is_exact() {
        use crate::recovery::RecoveryFile;
        use pops_core_funder::{reconstruct, ConstructionParams};
        use bitcoin::secp256k1::XOnlyPublicKey;
        use bitcoin::Network;

        // Same fixed inputs as recovery::tests -> pinned regtest address.
        let mint_pubkey: [u8; 33] = [
            0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        const G_X: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let funder = XOnlyPublicKey::from_slice(&G_X).unwrap();
        let params = ConstructionParams {
            mint_pubkey,
            ts_expiry: 1_782_259_200,
            nonce: [0x42; 32],
            funder_pubkey: funder,
            network: Network::Regtest,
        };
        let construction = reconstruct(&params);
        let recovery = RecoveryFile::build(
            "dep-bip21",
            None,
            "https://mint.example",
            10_000,
            "pop_1782259200",
            &params,
            "m/5271376'/1'/0'/0/0",
            None,
        );
        let outcome = QuoteOutcome {
            deposit_id: "dep-bip21".to_string(),
            unit_str: "pop_1782259200".to_string(),
            ts_expiry: 1_782_259_200,
            amount: 10_000,
            construction,
            derivation_path: "m/5271376'/1'/0'/0/0".to_string(),
            quote_id: "q1".to_string(),
            recovery,
        };
        assert_eq!(
            outcome.bip21_uri(),
            "bitcoin:bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd?amount=0.00010000"
        );
    }
}
