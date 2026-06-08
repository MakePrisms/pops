//! `pop mint` — the core funder flow: derive a fresh funder key, create a PoP
//! quote, INDEPENDENTLY re-verify the returned funding address (recompute
//! cm→P_internal→Q and assert it matches the mint's), persist the deposit and
//! write the recovery file BEFORE showing the address, poll for funding, record
//! the outpoint, mint the ecash, and PRINT the cashuB token. The ecash is not
//! stored.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Network;
use cdk_common::nuts::{CurrencyUnit, Proofs};
use clap::Parser;

use pops_core_funder::{reconstruct, Construction, ConstructionParams};
use pops_core_verify::unit::{format_pop_unit, parse_pop_unit};

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

/// Arguments for `pop mint`. `--mint-url`, `--amount`, and one of
/// `{--duration, --unit}` are required for a fresh mint, but ALL are optional
/// with `--resume <id>` (reloaded from the persisted deposit).
#[derive(Debug, Parser)]
#[command(group(
    // The group is NOT required at the clap level because ArgGroup can't express
    // "required UNLESS --resume"; the conditional check lives in
    // `missing_required_unit_group` (raised from `main` as a usage error),
    // avoiding the cryptic mint-side "Unit unsupported" (11013).
    clap::ArgGroup::new("unit_or_duration")
        .args(["duration", "unit"])
        .required(false)
        .multiple(false)
))]
pub struct MintArgs {
    /// Mint base URL (e.g. `https://mint.example`). Required for a fresh mint;
    /// loaded from the deposit with `--resume`.
    #[arg(long, value_name = "URL", required_unless_present = "resume")]
    pub mint_url: Option<String>,

    /// Amount to lock + mint, in sats. Required for a fresh mint; loaded from the
    /// deposit with `--resume`.
    #[arg(long, value_name = "SATS", required_unless_present = "resume")]
    pub amount: Option<u64>,

    /// Credential lifetime as a duration (e.g. `30d`, `12h`). `ts = now + dur`.
    /// Mutually exclusive with `--unit`; one of the two is required for a fresh
    /// mint (loaded from the deposit with `--resume`).
    #[arg(long, value_name = "DUR", conflicts_with = "unit")]
    pub duration: Option<String>,

    /// Explicit unit `pop_<ts_expiry>`. Mutually exclusive with `--duration`; one
    /// of the two is required for a fresh mint (loaded from the deposit with
    /// `--resume`).
    #[arg(long, value_name = "pop_<ts>")]
    pub unit: Option<String>,

    /// The mint's 33-byte compressed identity pubkey (66 hex chars), available
    /// from the mint's `GET /v1/info` endpoint. REQUIRED on first use of a mint
    /// (TOFU-pinned into config.toml); it is the value committed into `cm` and is
    /// needed to independently verify the funding address. On later mints to the
    /// same mint it must match the pin or it's a hard error.
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

    /// Resume an existing open deposit by id (skip quote-create; reattach). When
    /// set, `--mint-url`/`--amount`/`--duration`/`--unit` are all optional and
    /// reloaded from the persisted deposit.
    #[arg(long, value_name = "DEPOSIT_ID")]
    pub resume: Option<String>,
}

impl MintArgs {
    /// The amount for a FRESH mint (clap-required unless `--resume`, so always
    /// `Some` on this path; `None` is an internal invariant break).
    fn required_amount(&self) -> Result<u64, Box<dyn std::error::Error>> {
        self.amount.ok_or_else(|| {
            PopError::internal("--amount missing on a fresh mint (clap should have required it)").into()
        })
    }

    /// True iff a FRESH mint supplied NEITHER `--duration` nor `--unit` — the
    /// case that would otherwise fail mint-side with "Unit unsupported" (11013).
    pub fn missing_required_unit_group(&self) -> bool {
        self.resume.is_none() && self.duration.is_none() && self.unit.is_none()
    }
}

/// The product of the shared pre-poll half: quote created, funding address
/// independently verified, deposit persisted (Unpaid), recovery file written.
/// Consumed by both `quote::run` (stops here) and `mint::run` (polls + mints).
pub struct QuoteOutcome {
    /// Wallet-local deposit id (uuid).
    pub deposit_id: String,
    /// Resolved unit string `pop_<ts_expiry>`.
    pub unit_str: String,
    /// CLTV expiry / unit ts.
    pub ts_expiry: u64,
    /// Amount locked + to be minted, sats.
    pub amount: u64,
    /// The reconstructed taproot construction (carries the funding address).
    pub construction: Construction,
    /// Frozen funder derivation path string.
    pub derivation_path: String,
    /// The mint's quote id.
    pub quote_id: String,
    /// The written recovery file (funding outpoint still `None`).
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

/// The shared pre-poll half (both `pop mint` and `pop quote`): resolve unit,
/// derive funder key, create quote, independently verify the funding address,
/// persist the deposit (Unpaid), write the recovery file. Stops before polling.
/// Prints nothing to stdout (diagnostics go to stderr).
///
/// # Errors
///
/// Propagates every step; aborts with [`PopError::AddressMismatch`] on an
/// address-verification mismatch.
pub async fn create_and_persist_quote(
    wallet: &mut Wallet,
    http: &reqwest::Client,
    base: &str,
    seed: &[u8],
    args: &MintArgs,
    wallet_dir: &Path,
) -> Result<QuoteOutcome, Box<dyn std::error::Error>> {
    let network = wallet.network();

    let amount = args.required_amount()?;
    let unit_str = resolve_unit(args)?;
    let ts_expiry = parse_unit_ts(&unit_str)?;
    // All progress goes to STDERR so stdout stays pure-json in the default mode.
    eprintln!(
        "Unit:    {unit_str}  (recover-after {})",
        utc_iso8601(ts_expiry)
    );

    let index = wallet.db.next_derivation_index()?;
    let funder = wallet.funder_key(seed, index)?;
    let funder_secret_hex = hex::encode(funder.secret_key.secret_bytes());
    let funder_cdk = mint_client::parse_cdk_secret(&funder_secret_hex)?;

    eprintln!("Creating quote at {base} for {amount} sats ...");
    let quote = mint_client::create_quote(http, base, amount, &unit_str, &funder_cdk).await?;

    // Pin the mint identity key (TOFU) + INDEPENDENTLY verify the address.
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

    // Persist + write the recovery file BEFORE showing the address (so funds can
    // always be recovered).
    let deposit_id = uuid::Uuid::new_v4().to_string();
    let derivation_path = funder_path_string(network, index);
    let deposit = Deposit {
        id: deposit_id.clone(),
        label: args.label.clone(),
        mint_url: base.to_string(),
        unit: unit_str.clone(),
        ts_expiry,
        amount,
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
        amount,
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
        amount,
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
    let http = reqwest::Client::new();

    // Mint always needs the funder key.
    let seed = wallet.load_seed()?;

    if let Some(deposit_id) = &args.resume {
        return resume(&mut wallet, &http, deposit_id, &seed, args, json).await;
    }

    // Fresh mint: --mint-url is clap-required here (required_unless_present resume).
    let base = args
        .mint_url
        .as_deref()
        .ok_or_else(|| {
            PopError::internal("--mint-url missing on a fresh mint (clap should have required it)")
        })?
        .trim_end_matches('/')
        .to_string();

    let outcome =
        create_and_persist_quote(&mut wallet, &http, &base, &seed, args, wallet_dir).await?;

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
    let network = wallet.network();
    let paid = mint_client::poll_until_paid(
        &http,
        &base,
        &outcome.quote_id,
        &outcome.construction.address,
        network,
        Duration::from_secs(args.poll_interval),
        Duration::from_secs(args.poll_timeout),
    )
    .await?;
    eprintln!("Funding credited (amount_paid={}).", paid.amount_paid);

    // Exact-amount guard: an under-/over-funded deposit must NOT mint the wrong
    // value (the BTC stays CLTV-recoverable, so abort before issuing).
    verify_funded_amount(outcome.amount, paid.amount_paid)?;

    record_funding_outpoint(
        &wallet,
        wallet_dir,
        &outcome.deposit_id,
        &outcome.construction.address,
        &outcome.recovery,
    )
    .await?;
    wallet.db.set_state(&outcome.deposit_id, DepositState::Paid)?;

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

/// `--resume` path: reattach to an open deposit and re-run from the funding poll
/// (or mint directly if already PAID). Mint URL/amount/unit come from the
/// PERSISTED deposit; a redundantly-supplied flag that MISMATCHES is rejected
/// (`invalid_input`) so a copy-paste error can't target a different mint/amount.
async fn resume(
    wallet: &mut Wallet,
    http: &reqwest::Client,
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

    // Persisted wins; validate any redundant flag matches rather than silently
    // ignoring a wrong one.
    let base = dep.mint_url.trim_end_matches('/').to_string();
    if let Some(supplied) = args.mint_url.as_deref() {
        if supplied.trim_end_matches('/') != base {
            return Err(PopError::invalid_input(format!(
                "--mint-url ({supplied}) does not match deposit {deposit_id}'s mint ({}); \
                 --resume uses the persisted mint — omit --mint-url",
                dep.mint_url
            ))
            .into());
        }
    }
    if let Some(supplied) = args.amount {
        if supplied != dep.amount {
            return Err(PopError::invalid_input(format!(
                "--amount ({supplied}) does not match deposit {deposit_id}'s amount ({}); \
                 --resume uses the persisted amount — omit --amount",
                dep.amount
            ))
            .into());
        }
    }
    let base = base.as_str();

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
    // The resumed funder key must still derive to the stored pubkey (guards a
    // wrong wallet/seed).
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
        let network = wallet.network();
        let paid = mint_client::poll_until_paid(
            http,
            base,
            &dep.quote_id,
            &dep.funding_address,
            network,
            Duration::from_secs(args.poll_interval),
            Duration::from_secs(args.poll_timeout),
        )
        .await?;
        eprintln!("Funding credited (amount_paid={}).", paid.amount_paid);
        // Exact-amount guard (see `verify_funded_amount`); the BTC stays
        // CLTV-recoverable, so abort before issuing.
        verify_funded_amount(dep.amount, paid.amount_paid)?;
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
    // `mint_token` also returns the raw proofs: once it returns, the mint has
    // ALREADY issued the bearer ecash, so the proofs are available for
    // value-recovery if the stringify below fails.
    let (token, proofs) = mint_client::mint_token(
        http,
        base,
        &dep.quote_id,
        &unit,
        dep.amount,
        &signer,
        dep.funder_index,
    )
    .await?;

    // VALUE-RECOVERY GATE: `Token::to_string` panics on a CBOR `fmt::Error`,
    // which here would vaporize already-issued bearer ecash. Use the fallible
    // `token_to_string`; on Err, surface `token_encode_failed` carrying the raw
    // proofs so the ecash is recoverable. Must never fire (proof CBOR does not
    // fail).
    let token_str = mint_client::token_to_string(&token)
        .map_err(|reason| token_encode_failure(&reason, &proofs))?;

    // Record Minted only NOW (with the string in hand). A stringify failure
    // above returned WITHOUT advancing state, so a `--resume` can re-issue
    // against the quote — the value is never stranded behind a `Minted` flag.
    wallet.db.set_state(deposit_id, DepositState::Minted)?;

    // Emit the token to stdout BEFORE the optional `--token-out` write, so the
    // issued ecash is ALWAYS surfaced even if that file write fails.
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

    // The token is already on stdout, so a `--token-out` write failure is a
    // convenience miss, NOT value loss — warn rather than error (which would
    // hide the only copy).
    if let Some(path) = &args.token_out {
        match std::fs::write(path, &token_str) {
            Ok(()) => eprintln!("Token written to {}", path.display()),
            Err(e) => eprintln!(
                "warning: failed to write token to {} ({e}); the token was printed to stdout above — save it from there",
                path.display()
            ),
        }
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
    // First confirmed UTXO (the credited deposit); else the first seen.
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

/// Money-safety gate: the credited `funded` must EQUAL the quoted `expected`
/// (PoP is exact-amount), so an under-/over-funded deposit never mints the wrong
/// value — abort with [`PopError::AmountMismatch`] BEFORE issuing. The on-chain
/// BTC stays CLTV-recoverable.
fn verify_funded_amount(expected: u64, funded: u64) -> Result<(), Box<dyn std::error::Error>> {
    if funded != expected {
        return Err(PopError::AmountMismatch {
            expected_sats: expected,
            funded_sats: funded,
        }
        .into());
    }
    Ok(())
}

/// The value-recovery error when a freshly-ISSUED mint token cannot be encoded:
/// the bearer ecash was already issued, so the raw `proofs` are surfaced as JSON
/// (`send_proofs`; no change bucket on this path) rather than vaporized by a
/// stringify panic.
fn token_encode_failure(reason: &str, proofs: &Proofs) -> PopError {
    PopError::TokenEncodeFailed {
        reason: format!("issued mint token: {reason}"),
        send_proofs_json: Some(mint_client::proofs_to_json(proofs)),
        change_proofs_json: None,
    }
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
    let ts = now_unix().checked_add(secs).ok_or_else(|| {
        PopError::invalid_input(format!("duration `{dur}` overflows the expiry timestamp"))
    })?;
    Ok(format_pop_unit(ts))
}

/// Parses + range-checks a `pop_<ts>` unit via the canonical shared grammar
/// ([`pops_core_verify::unit::parse_pop_unit`]). This enforces the BIP-65
/// timestamp floor (`500_000_000`: below it `OP_CHECKLOCKTIMEVERIFY` reads the
/// locktime as a block HEIGHT, so the deposit could never mature on the
/// timestamp path and the BTC would be bricked) and the `u32::MAX` ceiling.
/// Sharing the verifier/mint parser keeps the wallet's unit grammar
/// byte-identical to theirs, so any unit that funds here is one the mint honors.
fn parse_unit_ts(unit: &str) -> Result<u64, Box<dyn std::error::Error>> {
    parse_pop_unit(unit).map_err(|e| PopError::invalid_input(e.to_string()).into())
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
    let secs_per_unit = match unit {
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
    n.checked_mul(secs_per_unit)
        .ok_or_else(|| PopError::invalid_input(format!("duration `{s}` is too large")).into())
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

/// Resolves the mint's 33-byte identity pubkey, TOFU-pinning on first use. The
/// quote response does NOT echo it (it is a mint-side `cm` input), so the funder
/// MUST supply it out-of-band the first time. Order: `--mint-pubkey` (TOFU-pin,
/// mismatch = hard error) → a previously pinned key → error. Without it the
/// address cannot be independently verified — the funder's sole defense.
fn pin_and_resolve_mint_pubkey(
    config: &mut Config,
    base: &str,
    supplied: Option<&str>,
) -> Result<[u8; 33], Box<dyn std::error::Error>> {
    if let Some(hex_str) = supplied {
        let hex_str = hex_str.trim().to_lowercase();
        let bytes = hex::decode(&hex_str)
            .map_err(|e| PopError::invalid_input(format!("--mint-pubkey hex decode failed: {e}")))?;
        let arr: [u8; 33] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PopError::invalid_input("--mint-pubkey must be 33 bytes (compressed)"))?;
        // TOFU-pin: a changed key for a known mint is a hard error (re-confirm).
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

    // Each check is the SAME security stop: the mint's value differs from our
    // independent reconstruction → `address_mismatch`, do NOT fund (`expected` =
    // ours, `got` = the mint's).
    if quote.request != c.address {
        return Err(PopError::AddressMismatch {
            expected: c.address.clone(),
            got: quote.request.clone(),
        }
        .into());
    }

    if let Some(mint_internal_key) = &quote.internal_key {
        let our_internal_key = hex::encode(c.internal_key.serialize());
        if !mint_internal_key.eq_ignore_ascii_case(&our_internal_key) {
            return Err(PopError::AddressMismatch {
                expected: our_internal_key,
                got: mint_internal_key.clone(),
            }
            .into());
        }
    }

    if let Some(mint_leaf_script) = &quote.leaf_script {
        let our_leaf_script = hex::encode(c.leaf_script.as_bytes());
        if !mint_leaf_script.eq_ignore_ascii_case(&our_leaf_script) {
            return Err(PopError::AddressMismatch {
                expected: our_leaf_script,
                got: mint_leaf_script.clone(),
            }
            .into());
        }
    }

    if let Some(mint_funder_pubkey) = &quote.funder_pubkey {
        let our_funder_pubkey = hex::encode(funder_xonly.serialize());
        if !mint_funder_pubkey.eq_ignore_ascii_case(&our_funder_pubkey) {
            return Err(PopError::AddressMismatch {
                expected: our_funder_pubkey,
                got: mint_funder_pubkey.clone(),
            }
            .into());
        }
    }

    // Defensive (reconstruct already used it).
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
        // A duration that would overflow `n * secs_per_unit` is rejected, not
        // wrapped to a small (near/past) expiry.
        assert!(
            parse_duration_secs(&format!("{}d", u64::MAX)).is_err(),
            "overflowing duration must error, not wrap"
        );
    }

    #[test]
    fn unit_ts_parsing() {
        assert_eq!(parse_unit_ts("pop_1782259200").unwrap(), 1_782_259_200);
        assert!(parse_unit_ts("pop_notanumber").is_err());
        assert!(parse_unit_ts("sat").is_err());
        // C1 regression: a sub-500_000_000 ts encodes a block HEIGHT under
        // OP_CLTV (un-minable for millennia → permanent loss), so it MUST be
        // rejected at parse time rather than silently funded.
        assert!(
            parse_unit_ts("pop_400000000").is_err(),
            "sub-floor (block-height) ts must be rejected"
        );
        assert!(parse_unit_ts("pop_499999999").is_err(), "one below the floor is rejected");
        assert!(parse_unit_ts("pop_500000000").is_ok(), "the floor boundary is valid");
        // Above u32::MAX has no valid CLTV locktime encoding.
        assert!(parse_unit_ts("pop_4294967296").is_err(), "above u32::MAX must be rejected");
        // Non-canonical spellings (currency-identity drift) are rejected too.
        assert!(parse_unit_ts("pop_01782259200").is_err(), "leading zero is non-canonical");
    }

    #[test]
    fn verify_funded_amount_passes_on_exact() {
        assert!(verify_funded_amount(50_000, 50_000).is_ok());
    }

    #[test]
    fn verify_funded_amount_fires_on_underfund() {
        // Credited LESS than quoted → amount_mismatch (don't mint the wrong
        // value; the BTC stays CLTV-recoverable).
        let err = verify_funded_amount(50_000, 49_999).unwrap_err();
        let pe = crate::error::from_boxed(err);
        assert_eq!(pe.code(), "amount_mismatch");
        // NOT retriable: re-polling won't change a wrong on-chain credit.
        assert!(!pe.retriable());
        let d = pe.details().unwrap();
        assert_eq!(d["expected_sats"], serde_json::json!(50_000));
        assert_eq!(d["funded_sats"], serde_json::json!(49_999));
    }

    #[test]
    fn verify_funded_amount_fires_on_overfund() {
        // Credited MORE than quoted → also a mismatch (exact-amount).
        let err = verify_funded_amount(50_000, 50_001).unwrap_err();
        let pe = crate::error::from_boxed(err);
        assert_eq!(pe.code(), "amount_mismatch");
        let d = pe.details().unwrap();
        assert_eq!(d["expected_sats"], serde_json::json!(50_000));
        assert_eq!(d["funded_sats"], serde_json::json!(50_001));
    }

    /// Representative proofs (V0 short keyset id → round-trips through the token
    /// codec without needing KeySetInfo).
    fn sample_proofs(amounts: &[u64]) -> Proofs {
        use cdk_common::dhke::hash_to_curve;
        use cdk_common::nuts::{Id, Proof};
        use cdk_common::secret::Secret;
        use cdk_common::Amount as CdkAmount;
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        amounts
            .iter()
            .enumerate()
            .map(|(i, &a)| {
                let mut preimage = [0u8; 33];
                preimage[0] = 1;
                preimage[1] = i as u8;
                let c = hash_to_curve(&preimage).expect("hash_to_curve");
                Proof::new(CdkAmount::from(a), keyset_id, Secret::generate(), c)
            })
            .collect()
    }

    /// On issuance, a token that can't be stringified must surface the issued
    /// ecash as recoverable raw proofs in `token_encode_failed`, never panic.
    #[test]
    fn token_encode_failure_carries_recoverable_proofs() {
        let proofs = sample_proofs(&[16, 32, 2]); // 50 sats total
        let pe = token_encode_failure("cashuB encoding (CBOR) failed", &proofs);

        assert_eq!(pe.code(), "token_encode_failed");
        assert!(!pe.retriable());

        // The issued ecash survives as the send proofs (mint has no change set).
        let d = pe.details().unwrap();
        let send = &d["send_proofs"];
        assert!(
            send.is_array(),
            "send_proofs must be the recoverable proof array"
        );
        assert_eq!(send.as_array().unwrap().len(), 3);
        let sats: u64 = send
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["amount"].as_u64().unwrap())
            .sum();
        assert_eq!(sats, 50);
        assert!(d.get("change_proofs").is_none());
        let (sp, cp) = pe.recovery_proofs_json().expect("carries recovery proofs");
        assert!(sp.is_some());
        assert!(cp.is_none());
    }

    /// The fallible stringify produces a parseable `cashuB` that round-trips.
    #[test]
    fn token_to_string_roundtrips_a_real_token() {
        use cdk_common::mint_url::MintUrl;
        use cdk_common::nuts::Token;
        let proofs = sample_proofs(&[8, 1]); // 9 sats
        let mint_url = MintUrl::from_str("https://mint.example").unwrap();
        let token = Token::new(
            mint_url,
            proofs,
            None,
            CurrencyUnit::Custom("pop_1782668279".to_string()),
        );
        let s = mint_client::token_to_string(&token).expect("encodes");
        assert!(s.starts_with("cashuB"), "got: {s}");
        let back = Token::from_str(&s).expect("parses back");
        assert_eq!(back.value().unwrap().to_u64(), 9);
    }

    #[test]
    fn btc_formatting() {
        assert_eq!(format_btc(100_000_000), "1.00000000");
        assert_eq!(format_btc(10_000), "0.00010000");
        assert_eq!(format_btc(1), "0.00000001");
    }

    /// Asserts the BIP-21 URI a `QuoteOutcome` emits is exactly
    /// `bitcoin:<addr>?amount=<btc>` over the pinned regtest construction vector.
    #[test]
    fn quote_outcome_bip21_uri_is_exact() {
        use crate::recovery::RecoveryFile;
        use pops_core_funder::{reconstruct, ConstructionParams};
        use bitcoin::secp256k1::XOnlyPublicKey;
        use bitcoin::Network;

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
