//! `pop recover` — reclaim CLTV-matured deposits via a taproot script-path spend.
//!
//! Refuses (with an ETA) if the tip's MTP is below `ts_expiry` (BIP-113; never
//! signs an immature deposit). For each matured deposit: rebuild the construction
//! from stored params, derive the funder privkey, fetch the UTXO, assert the
//! on-chain scriptPubKey matches, build + sign the `nLockTime = ts_expiry` spend,
//! broadcast.

use std::path::Path;
use std::str::FromStr;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, ScriptBuf, Txid};
use clap::Parser;
use pops_core_funder::{
    apply_signature, build_unsigned, reconstruct, FeePolicy, RecoverError, RecoverInputs,
};

use crate::chain::{Esplora, FALLBACK_FEERATE_SAT_PER_VB};
use crate::db::{Deposit, DepositState};
use crate::error::PopError;
use crate::network::network_name;
use crate::recovery::{utc_iso8601, RecoveryFile};
use crate::signer::{HotKeySigner, Signer};
use crate::wallet::Wallet;
use crate::SCHEMA_VERSION;

/// Maps a kernel [`RecoverError`] to a [`PopError`] code. Only
/// [`RecoverError::ValueBelowFee`] has a first-class code; every other variant is
/// an internal-invariant or security stop that should never happen for a
/// self-consistent deposit, so it folds into `internal_error` (carrying the
/// kernel's stable `code()` + `Display` for diagnosis). The security stops
/// (`ScriptPubkeyMismatch`, `ScriptMismatch`, `OutputKeyMismatch`,
/// `SignatureInvalid`, `ControlBlockInvalid`, `WrongFunderKey`) are
/// "do-not-broadcast" stops.
fn map_recover_error(e: RecoverError) -> PopError {
    match e {
        RecoverError::ValueBelowFee {
            value_sats,
            fee_sats,
        } => PopError::ValueBelowFee {
            value_sats,
            fee_sats,
        },
        other => PopError::internal(format!("recovery construction failed [{}]: {other}", other.code())),
    }
}

/// Default confirmation target (in blocks) for the mempool feerate estimate.
const DEFAULT_TARGET_BLOCKS: u32 = 6;

/// Max fraction (percent of UTXO value) an AUTO-ESTIMATED fee may consume before
/// `recover` refuses to broadcast (see [`PopError::FeeTooHigh`]). Guards against a
/// hostile/misconfigured `/fee-estimates` endpoint (and tiny UTXOs in a high-fee
/// market) burning the recovered BTC to the miner. The explicit `--fee` path is
/// deliberate intent and bypasses this; the kernel separately rejects fee >=
/// value (`ValueBelowFee`).
const FEE_GUARD_MAX_PERCENT_OF_VALUE: u64 = 50;

/// Arguments for `pop recover`.
#[derive(Debug, Parser)]
pub struct RecoverArgs {
    /// Recover a single deposit by id.
    #[arg(long, value_name = "DEPOSIT_ID", conflicts_with_all = ["all", "from_file"])]
    pub deposit: Option<String>,

    /// Recover all matured deposits.
    #[arg(long, conflicts_with_all = ["deposit", "from_file"])]
    pub all: bool,

    /// Break-glass: recover straight from a deposit's recovery file
    /// (`recovery/<id>.recovery.json`) WITHOUT consulting `wallet.db`. Use this
    /// if the database was lost/corrupted but the seed + recovery file survive.
    /// The seed is still required (it derives the funder key) and the file's
    /// network must match the wallet's.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["deposit", "all"])]
    pub from_file: Option<String>,

    /// Destination address for the recovered BTC (recommended: a fresh
    /// address, since recovery reveals the construction on-chain).
    #[arg(long, value_name = "ADDRESS")]
    pub dest: String,

    /// Absolute fee to subtract from the output, sats. OVERRIDES the
    /// mempool-feerate estimate (and `--target`). Omit to size the fee from
    /// the chain's `/fee-estimates`.
    #[arg(long, value_name = "SATS")]
    pub fee: Option<u64>,

    /// Confirmation target in blocks for the mempool feerate estimate
    /// (default 6). Ignored if `--fee` is given.
    #[arg(long, value_name = "BLOCKS", default_value_t = DEFAULT_TARGET_BLOCKS)]
    pub target: u32,

    /// Build + sign but do NOT broadcast; print the raw tx hex instead.
    #[arg(long)]
    pub no_broadcast: bool,
}

/// Runs `pop recover`.
///
/// # Errors
///
/// Propagates selection, maturity, reconstruction, signing, and broadcast
/// errors.
pub async fn run(
    args: &RecoverArgs,
    wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::open(wallet_dir)?;
    let network = wallet.network();

    // Malformed → invalid_input; wrong-network → network_mismatch. We DON'T
    // surface the raw parse error (it misleadingly says "base58" even for bech32);
    // give an address-type-agnostic message echoing the input.
    let dest_unchecked = Address::from_str(args.dest.trim()).map_err(|_| {
        PopError::invalid_input(format!(
            "--dest is not a valid bitcoin address (got `{}`)",
            args.dest.trim()
        ))
    })?;
    let dest = match dest_unchecked.clone().require_network(network) {
        Ok(addr) => addr,
        Err(_) => {
            return Err(PopError::NetworkMismatch {
                expected: network_name(network).to_string(),
                got: detect_address_network(&dest_unchecked),
            }
            .into());
        }
    };

    let deposits = select_deposits(&wallet, args)?;
    if deposits.is_empty() {
        // Only reachable via `--all`. An empty sweep is a no-op SUCCESS that does
        // NOT touch the chain (so it can never fail with chain_unreachable).
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "tip_height": serde_json::Value::Null,
                    "tip_mtp": serde_json::Value::Null,
                    "results": serde_json::Value::Array(vec![]),
                }))?
            );
        } else {
            println!("nothing recoverable (no funded, un-recovered deposits)");
        }
        return Ok(());
    }

    let esplora = Esplora::new(&wallet.config.esplora_url);
    let (tip_mtp, tip_height) = esplora.tip_mtp_and_height().await?;

    // Resolve the fee policy ONCE for the whole sweep (see `resolve_fee_policy`).
    let fee_policy = resolve_fee_policy(&esplora, args).await;

    let seed = wallet.load_seed()?;

    let single = deposits.len() == 1;
    let mut results = Vec::new();
    for dep in &deposits {
        match recover_one(&wallet, &esplora, &seed, dep, &dest, network, fee_policy, tip_mtp, args.no_broadcast).await {
            Ok(Outcome::Immature { recover_after }) if single => {
                // A single immature deposit is a typed, retriable error (the agent
                // gets matures_at/now); in an --all sweep immature stays a
                // per-deposit status.
                return Err(PopError::CltvNotExpired {
                    matures_at: recover_after,
                    now: tip_mtp,
                }
                .into());
            }
            Ok(outcome) => results.push((dep.id.clone(), outcome)),
            Err(e) => {
                if single {
                    return Err(e);
                }
                eprintln!("deposit {}: {e}", dep.id);
                results.push((dep.id.clone(), Outcome::Failed(e.to_string())));
            }
        }
    }

    if json {
        let arr: Vec<_> = results
            .iter()
            .map(|(id, o)| o.to_json(id))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "tip_height": tip_height,
                "tip_mtp": tip_mtp,
                "results": arr,
            }))?
        );
    } else {
        println!("tip height {tip_height}, MTP {tip_mtp}");
        for (id, o) in &results {
            println!("  {id}: {}", o.human_summary());
        }
    }
    Ok(())
}

/// Best-effort detection of which Bitcoin network an unchecked address is for,
/// for the `network_mismatch` error details. Probes the four supported
/// networks; falls back to "unknown".
fn detect_address_network(addr: &Address<bitcoin::address::NetworkUnchecked>) -> String {
    for net in [
        bitcoin::Network::Bitcoin,
        bitcoin::Network::Testnet,
        bitcoin::Network::Signet,
        bitcoin::Network::Regtest,
    ] {
        if addr.is_valid_for_network(net) {
            return network_name(net).to_string();
        }
    }
    "unknown".to_string()
}

/// Resolves the [`FeePolicy`]: `--fee` is an absolute override; else fetch
/// `/fee-estimates` for `--target` blocks. A fetch/parse failure does NOT fail
/// recovery (the BTC is safe + the spend is RBF-enabled) — warn and fall back to
/// a conservative feerate.
async fn resolve_fee_policy(esplora: &Esplora, args: &RecoverArgs) -> FeePolicy {
    if let Some(sat) = args.fee {
        if args.target != DEFAULT_TARGET_BLOCKS {
            eprintln!(
                "note: --fee {sat} (absolute) overrides --target {} (mempool estimate ignored)",
                args.target
            );
        }
        return FeePolicy::Absolute(sat);
    }

    match esplora.fee_estimates().await {
        Ok(est) => {
            let rate = est.pick_feerate(args.target);
            eprintln!(
                "fee: using mempool estimate {rate:.2} sat/vB (target {} blocks)",
                args.target
            );
            FeePolicy::Feerate(rate)
        }
        Err(e) => {
            eprintln!(
                "WARNING: could not fetch mempool fee estimate ({e}).\n\
                 WARNING: falling back to {FALLBACK_FEERATE_SAT_PER_VB:.2} sat/vB (min-relay floored). \
                 The spend is RBF-enabled, so you can fee-bump if it stalls; or re-run with \
                 --fee <sats> to set an exact fee."
            );
            FeePolicy::Feerate(FALLBACK_FEERATE_SAT_PER_VB)
        }
    }
}

/// The fee math for a single built recovery tx, surfaced in `--json`.
#[derive(Debug, Clone, Copy)]
struct FeeInfo {
    feerate_sat_per_vb: f64,
    vsize: usize,
    fee_sat: u64,
    input_sat: u64,
    output_sat: u64,
}

impl FeeInfo {
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "feerate_sat_per_vb": self.feerate_sat_per_vb,
            "vsize": self.vsize,
            "fee_sat": self.fee_sat,
            "input_sat": self.input_sat,
            "output_sat": self.output_sat,
        })
    }
}

/// Per-deposit outcome.
enum Outcome {
    Broadcast { txid: String, fee: FeeInfo },
    Built { txid: String, tx_hex: String, fee: FeeInfo },
    AlreadySpent,
    Immature { recover_after: u64 },
    Failed(String),
}

impl Outcome {
    fn to_json(&self, id: &str) -> serde_json::Value {
        match self {
            Outcome::Broadcast { txid, fee } => {
                serde_json::json!({"deposit_id": id, "status": "recovered", "recovery_txid": txid, "fee": fee.to_json()})
            }
            Outcome::Built { txid, tx_hex, fee } => {
                serde_json::json!({"deposit_id": id, "status": "built", "txid": txid, "tx_hex": tx_hex, "fee": fee.to_json()})
            }
            Outcome::AlreadySpent => {
                serde_json::json!({"deposit_id": id, "status": "already_spent"})
            }
            Outcome::Immature { recover_after } => serde_json::json!({
                "deposit_id": id, "status": "immature", "recover_after": recover_after
            }),
            Outcome::Failed(msg) => {
                serde_json::json!({"deposit_id": id, "status": "failed", "error": msg})
            }
        }
    }

    /// A one-line human summary for the `--human` recover output.
    fn human_summary(&self) -> String {
        match self {
            Outcome::Broadcast { txid, fee } => {
                format!("recovered (txid {txid}, swept {} sat, fee {} sat)", fee.output_sat, fee.fee_sat)
            }
            Outcome::Built { txid, fee, .. } => {
                format!("built but NOT broadcast (txid {txid}, would sweep {} sat, fee {} sat)", fee.output_sat, fee.fee_sat)
            }
            Outcome::AlreadySpent => "already spent (no UTXO at the funding address)".to_string(),
            Outcome::Immature { recover_after } => {
                format!("immature (recover-after {})", utc_iso8601(*recover_after))
            }
            Outcome::Failed(msg) => format!("failed: {msg}"),
        }
    }
}

/// Recovers a single deposit. Returns the outcome (broadcast, built, immature,
/// already-spent).
#[allow(clippy::too_many_arguments)]
async fn recover_one(
    wallet: &Wallet,
    esplora: &Esplora,
    seed: &[u8],
    dep: &Deposit,
    dest: &Address,
    network: bitcoin::Network,
    fee_policy: FeePolicy,
    tip_mtp: u64,
    no_broadcast: bool,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    // Maturity: MTP must be ≥ ts_expiry (BIP-113). Refuse + ETA otherwise.
    if tip_mtp < dep.ts_expiry {
        let remaining = dep.ts_expiry - tip_mtp;
        eprintln!(
            "deposit {} not yet recoverable: MTP {} < ts_expiry {} (recover-after {}, ~{} to go)",
            dep.id,
            tip_mtp,
            dep.ts_expiry,
            utc_iso8601(dep.ts_expiry),
            human_duration(remaining),
        );
        return Ok(Outcome::Immature {
            recover_after: dep.ts_expiry,
        });
    }

    let internal_key = parse_xonly(&dep.p_internal, "p_internal")?;
    let leaf_script = parse_script(&dep.leaf_script)?;

    // Custody-free at the kernel boundary (build_unsigned → signer.sign →
    // apply_signature); the signer is a trait, here backed by a hot key.
    let signer = HotKeySigner::new(seed, network, dep.funder_index);
    let funder_pubkey = signer
        .funder_pubkey(dep.funder_index)
        .map_err(|e| PopError::internal(format!("funder key derivation failed: {e}")))?
        .xonly;

    // Sweep every UTXO at the address (handles double-funds).
    let utxos = collect_recoverable_utxos(esplora, dep).await?;
    if utxos.is_empty() {
        eprintln!("deposit {}: no spendable UTXO at the funding address (already recovered?).", dep.id);
        // A previously-recorded outpoint now gone ⇒ mark Recovered.
        if dep.funding_txid.is_some() {
            wallet.db.set_state(&dep.id, DepositState::Recovered)?;
            return Ok(Outcome::AlreadySpent);
        }
        return Err(
            PopError::invalid_input(format!("deposit {} has no funding UTXO to recover", dep.id))
                .into(),
        );
    }

    let mut last_txid = String::new();
    let mut last_fee = None;
    for (txid_str, vout, value, spk) in utxos {
        let funding_txid = Txid::from_str(&txid_str)
            .map_err(|e| PopError::internal(format!("stored funding txid invalid: {e}")))?;

        // build_unsigned does all non-signing sanity checks; sign the sighash;
        // apply_signature self-verifies (sig + control-block + vsize).
        let unsigned = build_unsigned(RecoverInputs {
            funder_pubkey,
            funding_txid,
            funding_vout: vout,
            utxo_value_sat: value,
            utxo_script_pubkey: spk,
            leaf_script: leaf_script.clone(),
            internal_key,
            ts_expiry: dep.ts_expiry,
            dest_address: dest.clone(),
            network,
            fee_policy,
        })
        .map_err(map_recover_error)?;
        let sig = signer
            .sign(unsigned.sighash)
            .map_err(|e| PopError::internal(format!("recovery signing failed: {e}")))?;
        let built = apply_signature(unsigned, sig).map_err(map_recover_error)?;

        let fee_info = FeeInfo {
            feerate_sat_per_vb: built.feerate_sat_per_vb,
            vsize: built.vsize,
            fee_sat: built.fee_sat,
            input_sat: value,
            output_sat: built.output_value_sat,
        };

        // Full fee math before any broadcast (stderr).
        eprintln!(
            "deposit {} | utxo {txid_str}:{vout} -> {dest}\n  \
             feerate {:.2} sat/vB x {} vB = {} sat fee | in {} sat -> sweep {} sat",
            dep.id,
            built.feerate_sat_per_vb,
            built.vsize,
            built.fee_sat,
            value,
            built.output_value_sat,
        );

        if no_broadcast {
            eprintln!("  recovery tx (hex, not broadcast): {}", built.tx_hex);
            return Ok(Outcome::Built {
                txid: built.txid.to_string(),
                tx_hex: built.tx_hex,
                fee: fee_info,
            });
        }

        // Guard an AUTO-ESTIMATED fee against eating the UTXO before broadcast (a
        // hostile/misconfigured /fee-estimates endpoint, or a tiny UTXO). Explicit
        // --fee is deliberate intent and bypasses this; --no-broadcast already
        // returned above, so inspecting the tx is never blocked. value > fee >= 1
        // here (the kernel's ValueBelowFee guarantees it), so the percent is in
        // 0..100 and the divisor is non-zero; u128 keeps the multiply exact.
        if matches!(fee_policy, FeePolicy::Feerate(_)) {
            let fee_percent = u128::from(built.fee_sat) * 100 / u128::from(value);
            if fee_percent >= u128::from(FEE_GUARD_MAX_PERCENT_OF_VALUE) {
                return Err(PopError::FeeTooHigh {
                    fee_sats: built.fee_sat,
                    value_sats: value,
                    max_percent: FEE_GUARD_MAX_PERCENT_OF_VALUE,
                }
                .into());
            }
        }

        // On failure, enrich broadcast_failed with the txid (the chain layer
        // can't know it).
        let server = esplora.broadcast(&built.tx_hex).await.map_err(|e| {
            match crate::error::from_boxed(e) {
                PopError::BroadcastFailed { reject_reason, .. } => PopError::BroadcastFailed {
                    reject_reason,
                    txid: Some(built.txid.to_string()),
                },
                other => other,
            }
        })?;
        eprintln!("  broadcast accepted: {server}");
        last_txid = built.txid.to_string();
        last_fee = Some(fee_info);
        wallet.db.set_recovery_txid(&dep.id, &last_txid)?;
    }

    wallet.db.set_state(&dep.id, DepositState::Recovered)?;
    // utxos was non-empty and the broadcast path sets last_fee each iteration.
    let fee = last_fee.expect("broadcast path always records fee info");
    Ok(Outcome::Broadcast {
        txid: last_txid,
        fee,
    })
}

/// The recoverable UTXOs for a deposit: `(txid, vout, value, scriptPubKey)`.
/// Sweeps all UTXOs currently at the funding address (double-fund safe).
async fn collect_recoverable_utxos(
    esplora: &Esplora,
    dep: &Deposit,
) -> Result<Vec<(String, u32, u64, ScriptBuf)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let utxos = esplora.address_utxos(&dep.funding_address).await?;
    for u in utxos {
        // Fetch the scriptPubKey from the tx (the utxo endpoint omits it).
        let (value, spk) = esplora.utxo_value_and_script(&u.txid, u.vout).await?;
        debug_assert_eq!(value, u.value);
        out.push((u.txid, u.vout, value, spk));
    }
    Ok(out)
}

/// Selects deposits to recover: `--from-file` (DB-independent break-glass), a
/// single `--deposit`, or `--all` non-terminal deposits (Minted / Paid / Expired
/// — anything that may hold reclaimable BTC).
fn select_deposits(
    wallet: &Wallet,
    args: &RecoverArgs,
) -> Result<Vec<Deposit>, Box<dyn std::error::Error>> {
    if let Some(path) = &args.from_file {
        let dep = deposit_from_recovery_file(Path::new(path), wallet.network())?;
        return Ok(vec![dep]);
    }
    if let Some(id) = &args.deposit {
        let dep = wallet
            .db
            .get_deposit(id)?
            .ok_or_else(|| PopError::DepositNotFound {
                deposit_id: id.clone(),
            })?;
        return Ok(vec![dep]);
    }
    if args.all {
        let all = wallet.db.list_deposits()?;
        // Candidates: states that may hold reclaimable BTC.
        let candidates = all
            .into_iter()
            .filter(|d| {
                matches!(
                    d.state,
                    DepositState::Minted | DepositState::Paid | DepositState::Expired
                )
            })
            .collect();
        return Ok(candidates);
    }
    Err(PopError::invalid_input("specify --deposit <id>, --all, or --from-file <path>").into())
}

/// Reconstructs a recover-ready [`Deposit`] from a break-glass recovery file,
/// the C3 path that lets `pop recover` honor the file's "recoverable even if the
/// database is lost" guarantee. The construction (internal key, leaf, address) is
/// RECOMPUTED from the file's committed params via [`reconstruct`] — never trusted
/// from the file's projected hex fields — so a tampered projection can't redirect
/// the sweep. DB-only fields the recover path never reads (`quote_id`,
/// `quote_lock_pubkey`) are left empty; `state` is `Minted` (locked) so the
/// deposit is treated as holding recoverable BTC. The subsequent `wallet.db`
/// state writes are no-ops when the row is absent (plain `UPDATE`).
fn deposit_from_recovery_file(
    path: &Path,
    wallet_network: bitcoin::Network,
) -> Result<Deposit, Box<dyn std::error::Error>> {
    let rf = RecoveryFile::load(path)?;
    let params = rf.construction_params()?;
    if params.network != wallet_network {
        return Err(PopError::NetworkMismatch {
            expected: network_name(wallet_network).to_string(),
            got: network_name(params.network).to_string(),
        }
        .into());
    }
    let c = reconstruct(&params);
    let funder_index = parse_funder_index(&rf.funder_derivation_path)?;
    let (funding_txid, funding_vout) = split_outpoint(rf.funding_outpoint.as_deref())?;
    Ok(Deposit {
        id: rf.deposit_id,
        label: rf.label,
        mint_url: rf.mint_url,
        unit: rf.unit,
        ts_expiry: params.ts_expiry,
        amount: rf.amount_sats,
        funder_index,
        funder_pubkey: hex::encode(params.funder_pubkey.serialize()),
        quote_lock_pubkey: String::new(), // not in the recovery file; unused by recover
        p_internal: hex::encode(c.internal_key.serialize()),
        leaf_script: hex::encode(c.leaf_script.as_bytes()),
        nonce: hex::encode(params.nonce),
        mint_pubkey: hex::encode(params.mint_pubkey),
        funding_address: c.address,
        quote_id: String::new(), // not in the recovery file; unused by recover
        state: DepositState::Minted,
        funding_txid,
        funding_vout,
        recovery_txid: None,
        created_at: 0,
    })
}

/// Extracts the trailing non-hardened child index from a funder derivation path
/// like `m/5271376'/1'/0'/0/<index>`.
fn parse_funder_index(path: &str) -> Result<u32, Box<dyn std::error::Error>> {
    path.rsplit('/')
        .next()
        .and_then(|last| last.parse::<u32>().ok())
        .ok_or_else(|| {
            PopError::invalid_input(format!(
                "recovery file funder_derivation_path `{path}` has no numeric child index"
            ))
            .into()
        })
}

/// Splits a recovery file's `txid:vout` outpoint into its parts (`None` until
/// funding confirmed).
fn split_outpoint(
    outpoint: Option<&str>,
) -> Result<(Option<String>, Option<u32>), Box<dyn std::error::Error>> {
    let Some(s) = outpoint else {
        return Ok((None, None));
    };
    let (txid, vout) = s
        .split_once(':')
        .ok_or_else(|| PopError::invalid_input(format!("recovery funding_outpoint `{s}` is not txid:vout")))?;
    let vout: u32 = vout
        .parse()
        .map_err(|_| PopError::invalid_input(format!("recovery funding_outpoint `{s}` has a bad vout")))?;
    Ok((Some(txid.to_string()), Some(vout)))
}

fn parse_xonly(hex_str: &str, field: &str) -> Result<XOnlyPublicKey, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| PopError::internal(format!("{field} hex decode failed: {e}")))?;
    XOnlyPublicKey::from_slice(&bytes)
        .map_err(|e| PopError::internal(format!("{field} is not a valid x-only key: {e}")).into())
}

fn parse_script(hex_str: &str) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| PopError::internal(format!("leaf_script hex decode failed: {e}")))?;
    Ok(ScriptBuf::from_bytes(bytes))
}

/// Human-readable duration for an ETA (days/hours/minutes).
fn human_duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pops_core_funder::ConstructionParams;

    #[test]
    fn human_duration_buckets() {
        assert_eq!(human_duration(0), "0m");
        assert_eq!(human_duration(90), "1m");
        assert_eq!(human_duration(3_600 + 120), "1h 2m");
        assert_eq!(human_duration(2 * 86_400 + 3 * 3_600), "2d 3h");
    }

    #[test]
    fn parse_funder_index_takes_trailing_child() {
        assert_eq!(parse_funder_index("m/5271376'/1'/0'/0/7").unwrap(), 7);
        assert_eq!(parse_funder_index("m/5271376'/0'/0'/0/0").unwrap(), 0);
        assert!(parse_funder_index("m/5271376'/1'/0'/0/0'").is_err(), "hardened tail has no u32 index");
        assert!(parse_funder_index("not-a-path").is_err());
    }

    #[test]
    fn split_outpoint_parses_or_defaults() {
        assert_eq!(split_outpoint(None).unwrap(), (None, None));
        assert_eq!(
            split_outpoint(Some("ab12:3")).unwrap(),
            (Some("ab12".to_string()), Some(3))
        );
        assert!(split_outpoint(Some("no-colon")).is_err());
        assert!(split_outpoint(Some("ab12:notnum")).is_err());
    }

    /// Fixed funder x-only (secp256k1 generator G's x) for a deterministic file.
    fn test_funder() -> XOnlyPublicKey {
        const G_X: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        XOnlyPublicKey::from_slice(&G_X).unwrap()
    }

    fn test_params(network: bitcoin::Network) -> ConstructionParams {
        ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry: 1_782_259_200,
            nonce: [0x42; 32],
            funder_pubkey: test_funder(),
            network,
        }
    }

    /// C3: a deposit rebuilt from the recovery file alone matches the original
    /// construction (address/internal-key/leaf RECOMPUTED, not trusted), carries
    /// the parsed funder index + outpoint, and is treated as a locked deposit.
    #[test]
    fn from_recovery_file_reconstructs_recover_target() {
        let dir = tempfile::tempdir().unwrap();
        let params = test_params(bitcoin::Network::Regtest);
        let original = reconstruct(&params);
        let rf = RecoveryFile::build(
            "dep-c3",
            Some("break-glass"),
            "https://mint.example",
            10_000,
            "pop_1782259200",
            &params,
            "m/5271376'/1'/0'/0/4",
            Some("aabbccdd:1"),
        );
        let path = rf.write(dir.path()).unwrap();

        let dep = deposit_from_recovery_file(&path, bitcoin::Network::Regtest).unwrap();
        assert_eq!(dep.id, "dep-c3");
        assert_eq!(dep.funder_index, 4);
        assert_eq!(dep.ts_expiry, 1_782_259_200);
        assert_eq!(dep.funding_address, original.address, "address recomputed from committed params");
        assert_eq!(dep.p_internal, hex::encode(original.internal_key.serialize()));
        assert_eq!(dep.leaf_script, hex::encode(original.leaf_script.as_bytes()));
        assert_eq!(dep.funding_txid.as_deref(), Some("aabbccdd"));
        assert_eq!(dep.funding_vout, Some(1));
        assert!(dep.is_locked(), "from-file deposit is treated as holding locked BTC");
    }

    /// A recovery file for a different network than the wallet is refused (the
    /// derived key/address would mismatch) with a clear network_mismatch.
    #[test]
    fn from_recovery_file_rejects_network_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let rf = RecoveryFile::build(
            "dep-net",
            None,
            "https://mint.example",
            10_000,
            "pop_1782259200",
            &test_params(bitcoin::Network::Regtest),
            "m/5271376'/1'/0'/0/0",
            None,
        );
        let path = rf.write(dir.path()).unwrap();
        let err = deposit_from_recovery_file(&path, bitcoin::Network::Bitcoin).unwrap_err();
        assert_eq!(crate::error::from_boxed(err).code(), "network_mismatch");
    }
}
