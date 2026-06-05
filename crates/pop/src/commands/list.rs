//! `pop list` / `pop status` — show deposits and their lifecycle state.
//!
//! `list` is a purely local table (no network). `status` is the human
//! dashboard; with esplora reachable it computes the live "Recoverable now"
//! vs "Recoverable-after-<date>" display state from the chain tip's MTP.

use std::path::Path;

use clap::{Parser, ValueEnum};

use crate::chain::Esplora;
use crate::db::{Deposit, DepositState};
use crate::error::PopError;
use crate::mint_client::now_unix;
use crate::recovery::utc_iso8601;
use crate::wallet::Wallet;
use crate::SCHEMA_VERSION;

/// The `--state` filter values (a clap `ValueEnum`, so `--help` enumerates +
/// validates them). Maps 1:1 onto [`DepositState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum StateFilter {
    /// Quote created, no confirmed funding yet.
    Unpaid,
    /// Funding credited; credential not yet issued.
    Paid,
    /// Credential issued (token printed).
    Minted,
    /// The recovery spend was broadcast.
    Recovered,
    /// Funding deadline passed.
    Expired,
}

impl StateFilter {
    /// The corresponding stored [`DepositState`].
    fn to_deposit_state(self) -> DepositState {
        match self {
            StateFilter::Unpaid => DepositState::Unpaid,
            StateFilter::Paid => DepositState::Paid,
            StateFilter::Minted => DepositState::Minted,
            StateFilter::Recovered => DepositState::Recovered,
            StateFilter::Expired => DepositState::Expired,
        }
    }
}

/// Arguments for `pop list`.
#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Filter by lifecycle state (one of: unpaid, paid, minted, recovered,
    /// expired).
    #[arg(long, value_name = "STATE", value_enum)]
    pub state: Option<StateFilter>,
}

/// Arguments for `pop status`.
#[derive(Debug, Parser)]
pub struct StatusArgs {
    /// Show a single deposit in detail.
    #[arg(long, value_name = "DEPOSIT_ID")]
    pub deposit: Option<String>,
}

/// The base label for a deposit's stored state (no chain overlay).
fn state_label(state: DepositState) -> &'static str {
    match state {
        DepositState::Unpaid => "Unpaid",
        DepositState::Paid => "Paid",
        DepositState::Minted => "Minted",
        DepositState::Recovered => "Recovered",
        DepositState::Expired => "Expired",
    }
}

/// The display state for the funder (stored state + chain MTP). The
/// recoverability overlay applies to EVERY locked deposit, funding-gated +
/// matured per the shared [`Deposit::is_locked`] / [`Deposit::is_recoverable_now`]
/// (the SAME definition `balance` uses, so the surfaces can't drift) — so a
/// funded `Paid` carries it, an un-funded `Expired` does not.
fn display_state(dep: &Deposit, mtp: Option<u64>) -> String {
    let base = state_label(dep.state);
    if !dep.is_locked() {
        return base.to_string();
    }
    match mtp {
        Some(m) if dep.is_recoverable_now(m) => format!("{base} / Recoverable now"),
        Some(_) => format!("{base} / Recoverable-after {}", utc_iso8601(dep.ts_expiry)),
        // MTP-unavailable falls back to the unlock-time hint rather than
        // claiming recoverability either way.
        None => format!("{base} / Recoverable-after {}", utc_iso8601(dep.ts_expiry)),
    }
}

/// Runs `pop list` (local-only).
///
/// # Errors
///
/// Propagates db errors.
pub fn run_list(
    args: &ListArgs,
    wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::open(wallet_dir)?;
    let deposits = match args.state {
        Some(s) => wallet.db.list_deposits_by_state(s.to_deposit_state())?,
        None => wallet.db.list_deposits()?,
    };

    if json {
        let arr: Vec<_> = deposits.iter().map(|d| deposit_json(d, None)).collect();
        println!("{}", serde_json::to_string_pretty(&deposit_list_envelope(arr, None))?);
        return Ok(());
    }

    if deposits.is_empty() {
        println!("(no deposits)");
        return Ok(());
    }
    print_table(&deposits, None);
    Ok(())
}

/// Runs `pop status`. With `--deposit`, prints a detailed dashboard for one
/// deposit; otherwise a table. Queries esplora for the tip MTP when reachable.
///
/// # Errors
///
/// Propagates db errors; esplora failures degrade gracefully (no MTP overlay).
pub async fn run_status(
    args: &StatusArgs,
    wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::open(wallet_dir)?;

    // Best-effort tip MTP for the recoverability overlay.
    let mtp = fetch_mtp(&wallet).await;

    if let Some(id) = &args.deposit {
        let dep = wallet
            .db
            .get_deposit(id)?
            .ok_or_else(|| PopError::DepositNotFound {
                deposit_id: id.clone(),
            })?;
        if json {
            // Single-deposit detail: the object + schema_version at top level.
            let mut out = deposit_json(&dep, mtp);
            if let Some(o) = out.as_object_mut() {
                o.insert("schema_version".to_string(), serde_json::json!(SCHEMA_VERSION));
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            print_detail(&dep, mtp);
        }
        return Ok(());
    }

    let deposits = wallet.db.list_deposits()?;
    if json {
        let arr: Vec<_> = deposits.iter().map(|d| deposit_json(d, mtp)).collect();
        println!("{}", serde_json::to_string_pretty(&deposit_list_envelope(arr, mtp))?);
        return Ok(());
    }
    if deposits.is_empty() {
        println!("(no deposits)");
        return Ok(());
    }
    print_table(&deposits, mtp);
    Ok(())
}

/// Best-effort tip-MTP fetch (returns None if esplora is unreachable).
async fn fetch_mtp(wallet: &Wallet) -> Option<u64> {
    let esplora = Esplora::new(&wallet.config.esplora_url);
    match esplora.tip_mtp_and_height().await {
        Ok((mtp, _h)) => Some(mtp),
        Err(e) => {
            eprintln!("(esplora unreachable, recoverability overlay omitted: {e})");
            None
        }
    }
}

fn print_table(deposits: &[Deposit], mtp: Option<u64>) {
    println!(
        "{:<8}  {:<10}  {:<14}  {:<28}  ADDRESS",
        "ID", "AMOUNT", "UNIT", "STATE"
    );
    for d in deposits {
        let short = &d.id[..d.id.len().min(8)];
        let unit_short = if d.unit.len() > 14 {
            &d.unit[..14]
        } else {
            &d.unit
        };
        println!(
            "{:<8}  {:<10}  {:<14}  {:<28}  {}",
            short,
            format!("{} sat", d.amount),
            unit_short,
            display_state(d, mtp),
            d.funding_address,
        );
    }
}

fn print_detail(dep: &Deposit, mtp: Option<u64>) {
    println!("deposit:          {}", dep.id);
    if let Some(l) = &dep.label {
        println!("label:            {l}");
    }
    println!("mint:             {}", dep.mint_url);
    println!("unit:             {}", dep.unit);
    println!("amount:           {} sat", dep.amount);
    println!("state:            {}", display_state(dep, mtp));
    println!("funding address:  {}", dep.funding_address);
    match (&dep.funding_txid, dep.funding_vout) {
        (Some(txid), Some(vout)) => println!("funding outpoint: {txid}:{vout}"),
        _ => println!("funding outpoint: (not yet seen)"),
    }
    println!("recover-after:    {} (ts {})", utc_iso8601(dep.ts_expiry), dep.ts_expiry);
    if !dep.is_locked() {
        println!("recoverable:      n/a (no locked BTC at this deposit)");
    } else if let Some(m) = mtp {
        let now = now_unix();
        if dep.is_recoverable_now(m) {
            println!("recoverable:      YES (chain MTP {m} >= ts_expiry)");
        } else {
            let eta = dep.ts_expiry.saturating_sub(m);
            println!(
                "recoverable:      not yet (MTP {m}, ~{}d to go; wall-clock now {now})",
                eta / 86_400
            );
        }
    }
    if let Some(txid) = &dep.recovery_txid {
        println!("recovery txid:    {txid}");
    }
    println!("funder index:     {}", dep.funder_index);
    println!("funder pubkey:    {}", dep.funder_pubkey);
    println!("P_internal:       {}", dep.p_internal);
    println!("leaf script:      {}", dep.leaf_script);
    println!("nonce:            {}", dep.nonce);
    println!(
        "\nRecover with:     pop recover --deposit {} --dest <fresh-address>",
        dep.id
    );
}

/// Wraps deposits in the envelope `{ schema_version, mtp_available, deposits }`
/// (a top-level array can't carry `schema_version`). `mtp_available` is true iff
/// the tip MTP was fetched; it lives at the envelope level so the flag is present
/// even for an empty ledger. (`list` never fetches MTP → always `false`.)
fn deposit_list_envelope(arr: Vec<serde_json::Value>, mtp: Option<u64>) -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "mtp_available": mtp.is_some(),
        "deposits": arr,
    })
}

fn deposit_json(dep: &Deposit, mtp: Option<u64>) -> serde_json::Value {
    // recoverable_now is the shared funding-gated `is_recoverable_now`, PRESENT-as-
    // null when MTP was unavailable (the key is never omitted — agent parsers check
    // null + `mtp_available`, not key-existence).
    let recoverable_now = mtp.map(|m| dep.is_recoverable_now(m));
    serde_json::json!({
        "id": dep.id,
        "label": dep.label,
        "mint_url": dep.mint_url,
        "unit": dep.unit,
        "ts_expiry": dep.ts_expiry,
        "amount_sats": dep.amount,
        "state": dep.state.as_str(),
        "display_state": display_state(dep, mtp),
        "is_locked": dep.is_locked(),
        "recoverable_now": recoverable_now,
        "mtp_available": mtp.is_some(),
        "funding_address": dep.funding_address,
        "funding_txid": dep.funding_txid,
        "funding_vout": dep.funding_vout,
        "recovery_txid": dep.recovery_txid,
        "recover_after_utc": utc_iso8601(dep.ts_expiry),
        "created_at": dep.created_at,
        "created_at_utc": utc_iso8601(dep.created_at),
        "funder_index": dep.funder_index,
        "funder_pubkey": dep.funder_pubkey,
        "p_internal": dep.p_internal,
        "leaf_script": dep.leaf_script,
        "nonce": dep.nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DepositState;

    fn sample() -> Deposit {
        Deposit {
            id: "dep-1".to_string(),
            label: Some("l".to_string()),
            mint_url: "https://mint.example".to_string(),
            unit: "pop_1782259200".to_string(),
            ts_expiry: 1_782_259_200,
            amount: 10_000,
            funder_index: 0,
            funder_pubkey: "aa".repeat(32),
            quote_lock_pubkey: "02".to_string() + &"bb".repeat(32),
            p_internal: "cc".repeat(32),
            leaf_script: "dd".repeat(20),
            nonce: "42".repeat(32),
            mint_pubkey: "02".to_string() + &"ee".repeat(32),
            funding_address: "tb1pexample".to_string(),
            quote_id: "quote-1".to_string(),
            state: DepositState::Unpaid,
            funding_txid: None,
            funding_vout: None,
            recovery_txid: None,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn deposit_json_exposes_created_at_unix_and_iso() {
        let dep = sample();
        let v = deposit_json(&dep, None);

        // Distinct from ts_expiry (guards a copy-paste).
        assert_eq!(v["created_at"], serde_json::json!(1_700_000_000u64));
        assert_ne!(v["created_at"], v["ts_expiry"]);

        assert_eq!(v["created_at_utc"], serde_json::json!("2023-11-14T22:13:20Z"));
        assert_eq!(v["created_at_utc"], serde_json::json!(utc_iso8601(dep.created_at)));
        assert_ne!(v["created_at_utc"], v["recover_after_utc"]);
    }

    /// A sample in `state` with the funding outpoint recorded (funding sent).
    fn funded(state: DepositState) -> Deposit {
        let mut d = sample();
        d.state = state;
        d.funding_txid = Some("ab".repeat(32));
        d.funding_vout = Some(0);
        d
    }

    /// `mtp_available` reflects whether MTP was fetched (per-deposit + envelope);
    /// recoverable_now is PRESENT-as-null when degraded (key never omitted).
    #[test]
    fn mtp_available_signals_degrade_and_recoverable_is_present_as_null() {
        let dep = funded(DepositState::Minted);

        // Degraded (mtp None): key present + null.
        let v = deposit_json(&dep, None);
        assert_eq!(v["mtp_available"], serde_json::json!(false));
        assert!(v.as_object().unwrap().contains_key("recoverable_now"));
        assert_eq!(v["recoverable_now"], serde_json::json!(null));

        // Live: flag true, recoverability a concrete bool.
        let v = deposit_json(&dep, Some(dep.ts_expiry));
        assert_eq!(v["mtp_available"], serde_json::json!(true));
        assert_eq!(v["recoverable_now"], serde_json::json!(true));

        // The envelope carries the flag even for an empty ledger.
        let empty_degraded = deposit_list_envelope(vec![], None);
        assert_eq!(empty_degraded["mtp_available"], serde_json::json!(false));
        assert!(empty_degraded["deposits"].as_array().unwrap().is_empty());
        let empty_live = deposit_list_envelope(vec![], Some(1_000));
        assert_eq!(empty_live["mtp_available"], serde_json::json!(true));
    }

    /// Recoverability uses the SAME shared `is_recoverable_now` as balance: a
    /// matured `Paid` IS recoverable, an un-funded `Expired` is NEVER.
    #[test]
    fn recoverable_now_matches_balance_shared_definition() {
        let mtp = 1_782_259_200; // == sample ts_expiry (matured, inclusive)

        let paid = funded(DepositState::Paid);
        let v = deposit_json(&paid, Some(mtp));
        assert_eq!(v["recoverable_now"], serde_json::json!(true), "matured Paid is recoverable");
        assert_eq!(v["recoverable_now"], serde_json::json!(paid.is_recoverable_now(mtp)));

        // Un-funded Expired: NOT recoverable even though matured.
        let mut unfunded_expired = sample();
        unfunded_expired.state = DepositState::Expired;
        let v = deposit_json(&unfunded_expired, Some(mtp));
        assert_eq!(v["is_locked"], serde_json::json!(false));
        assert_eq!(
            v["recoverable_now"],
            serde_json::json!(false),
            "un-funded expired holds nothing — never recoverable (matches balance)"
        );

        let funded_expired = funded(DepositState::Expired);
        let v = deposit_json(&funded_expired, Some(mtp));
        assert_eq!(v["recoverable_now"], serde_json::json!(true));

        // Locked but immature: false (not null — MTP was known).
        let v = deposit_json(&funded(DepositState::Minted), Some(mtp - 1));
        assert_eq!(v["recoverable_now"], serde_json::json!(false));
    }

    /// The `display_state` string overlay agrees with the structured field.
    #[test]
    fn display_state_overlay_is_funding_gated() {
        let mtp = 1_782_259_200;

        let s = display_state(&funded(DepositState::Paid), Some(mtp));
        assert_eq!(s, "Paid / Recoverable now");

        // Un-funded expired: bare label.
        let mut unfunded_expired = sample();
        unfunded_expired.state = DepositState::Expired;
        assert_eq!(display_state(&unfunded_expired, Some(mtp)), "Expired");

        let s = display_state(&funded(DepositState::Minted), Some(mtp - 1));
        assert!(s.starts_with("Minted / Recoverable-after "), "got: {s}");

        // Unpaid / Recovered are never locked.
        assert_eq!(display_state(&sample(), Some(mtp)), "Unpaid");
        assert_eq!(display_state(&funded(DepositState::Recovered), Some(mtp)), "Recovered");
    }
}
