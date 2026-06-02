//! `pop list` / `pop status` — show deposits and their lifecycle state.
//!
//! `list` is a purely local table (no network). `status` is the human
//! dashboard; with esplora reachable it computes the live "Recoverable now"
//! vs "Recoverable-after-<date>" display state from the chain tip's MTP.

use std::path::Path;

use clap::Parser;

use crate::chain::Esplora;
use crate::db::{Deposit, DepositState};
use crate::error::PopError;
use crate::mint_client::now_unix;
use crate::recovery::utc_iso8601;
use crate::wallet::Wallet;
use crate::SCHEMA_VERSION;

/// Arguments for `pop list`.
#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Filter by lifecycle state.
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,
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

/// The display state surfaced to the funder (a derived view over the stored
/// state + the chain MTP).
///
/// The recoverability overlay applies to EVERY locked deposit — funding-gated
/// and matured per the shared [`Deposit::is_locked`] / [`Deposit::is_recoverable_now`]
/// (the SAME definition `balance` uses, so the two surfaces can't drift). That
/// means `Paid` (funded, mintable) also carries it, and an `Expired` row that was
/// never funded does NOT (it holds no BTC to recover). `Unpaid`/`Recovered` are
/// never locked, so they get no overlay.
fn display_state(dep: &Deposit, mtp: Option<u64>) -> String {
    let base = state_label(dep.state);
    if !dep.is_locked() {
        // Unpaid / Recovered / un-funded Expired: nothing locked to recover.
        return base.to_string();
    }
    match mtp {
        Some(m) if dep.is_recoverable_now(m) => format!("{base} / Recoverable now"),
        Some(_) => format!("{base} / Recoverable-after {}", utc_iso8601(dep.ts_expiry)),
        // MTP unavailable: we can't assert maturity, so fall back to the
        // unlock-time hint rather than claiming recoverability either way.
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
    let deposits = match &args.state {
        Some(s) => {
            let st = DepositState::parse(&s.to_lowercase()).map_err(|_| {
                PopError::invalid_input(format!(
                    "unknown --state `{s}` (unpaid|paid|minted|recovered|expired)"
                ))
            })?;
            wallet.db.list_deposits_by_state(st)?
        }
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
            // Single-deposit detail: the deposit object with schema_version
            // merged in at the top level.
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
        // No locked BTC (unpaid / recovered / un-funded expired): nothing to sweep.
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

/// Wraps a list of deposit objects in the contract envelope:
/// `{ "schema_version": 1, "mtp_available": <bool>, "deposits": [...] }`. A
/// top-level array can't carry `schema_version`, so the list/status table output
/// is an object with the deposits under `deposits`.
///
/// `mtp_available` is `true` iff the chain-tip MTP was fetched (the recoverability
/// overlay is live); `false` when esplora was unreachable (the per-deposit
/// `recoverable_now` is then `null`). It is at the envelope level so the flag is
/// present even for an empty ledger — matching `balance`'s top-level
/// `mtp_available` / `recoverable_now|null` pattern. (`list` is local-only and
/// never fetches MTP, so it always reports `false`.)
fn deposit_list_envelope(arr: Vec<serde_json::Value>, mtp: Option<u64>) -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "mtp_available": mtp.is_some(),
        "deposits": arr,
    })
}

fn deposit_json(dep: &Deposit, mtp: Option<u64>) -> serde_json::Value {
    // Recoverability is funding-gated + matured (the shared `is_recoverable_now`,
    // identical to `balance`). It is PRESENT-as-null when the chain MTP was
    // unavailable — an agent's parser always finds the key and checks for null +
    // `mtp_available`, never key-existence. A locked-but-immature deposit is
    // `false`; an un-funded/un-locked deposit is also `false` (nothing to sweep).
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

        // Unix creation time, distinct from ts_expiry (guards a ts_expiry copy-paste).
        assert_eq!(v["created_at"], serde_json::json!(1_700_000_000u64));
        assert_ne!(v["created_at"], v["ts_expiry"]);

        // ISO-8601 rendering of created_at via the shared helper.
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

    /// `mtp_available` reflects whether the chain MTP was fetched, at BOTH the
    /// per-deposit level and the list envelope; and the recoverability field is
    /// PRESENT-as-null (key never omitted) when degraded — the balance pattern,
    /// so an agent's parser checks null + the flag, never key-existence.
    #[test]
    fn mtp_available_signals_degrade_and_recoverable_is_present_as_null() {
        let dep = funded(DepositState::Minted); // ts_expiry 1_782_259_200

        // Degraded (esplora unreachable → mtp None).
        let v = deposit_json(&dep, None);
        assert_eq!(v["mtp_available"], serde_json::json!(false));
        // Key is PRESENT and null (not omitted) — agent parser invariant.
        assert!(v.as_object().unwrap().contains_key("recoverable_now"));
        assert_eq!(v["recoverable_now"], serde_json::json!(null));

        // Live (mtp known) → flag true, recoverability a concrete bool.
        let v = deposit_json(&dep, Some(dep.ts_expiry));
        assert_eq!(v["mtp_available"], serde_json::json!(true));
        assert_eq!(v["recoverable_now"], serde_json::json!(true));

        // The list envelope carries the flag too (present even for an empty ledger).
        let empty_degraded = deposit_list_envelope(vec![], None);
        assert_eq!(empty_degraded["mtp_available"], serde_json::json!(false));
        assert!(empty_degraded["deposits"].as_array().unwrap().is_empty());
        let empty_live = deposit_list_envelope(vec![], Some(1_000));
        assert_eq!(empty_live["mtp_available"], serde_json::json!(true));
    }

    /// status's recoverability uses the SAME funding-gated + matured definition as
    /// balance (the shared `Deposit::is_recoverable_now`): `Paid` IS included once
    /// matured (a divergence the old state-only overlay had — it excluded Paid),
    /// and an un-funded `Expired` deposit is NEVER recoverable even past maturity.
    #[test]
    fn recoverable_now_matches_balance_shared_definition() {
        let mtp = 1_782_259_200; // == sample ts_expiry (matured, boundary-inclusive)

        // Paid + matured: recoverable (the old overlay wrongly excluded Paid).
        let paid = funded(DepositState::Paid);
        let v = deposit_json(&paid, Some(mtp));
        assert_eq!(v["recoverable_now"], serde_json::json!(true), "matured Paid is recoverable");
        // And the json field agrees with the shared db helper it delegates to.
        assert_eq!(v["recoverable_now"], serde_json::json!(paid.is_recoverable_now(mtp)));

        // Un-funded Expired: NOT recoverable even though matured (no BTC to sweep).
        let mut unfunded_expired = sample();
        unfunded_expired.state = DepositState::Expired;
        let v = deposit_json(&unfunded_expired, Some(mtp));
        assert_eq!(v["is_locked"], serde_json::json!(false));
        assert_eq!(
            v["recoverable_now"],
            serde_json::json!(false),
            "un-funded expired holds nothing — never recoverable (matches balance)"
        );

        // Funded Expired + matured: recoverable.
        let funded_expired = funded(DepositState::Expired);
        let v = deposit_json(&funded_expired, Some(mtp));
        assert_eq!(v["recoverable_now"], serde_json::json!(true));

        // Locked but immature: false (not null — MTP was known).
        let v = deposit_json(&funded(DepositState::Minted), Some(mtp - 1));
        assert_eq!(v["recoverable_now"], serde_json::json!(false));
    }

    /// The `display_state` string overlay agrees with the structured recoverability
    /// (both off the shared helper): a matured Paid reads "Recoverable now"; an
    /// un-funded Expired gets NO overlay (it is not locked).
    #[test]
    fn display_state_overlay_is_funding_gated() {
        let mtp = 1_782_259_200;

        // Matured Paid now carries the recoverability overlay.
        let s = display_state(&funded(DepositState::Paid), Some(mtp));
        assert_eq!(s, "Paid / Recoverable now");

        // Un-funded expired: bare label, no "Recoverable now" claim.
        let mut unfunded_expired = sample();
        unfunded_expired.state = DepositState::Expired;
        assert_eq!(display_state(&unfunded_expired, Some(mtp)), "Expired");

        // Immature funded minted: "Recoverable-after <date>".
        let s = display_state(&funded(DepositState::Minted), Some(mtp - 1));
        assert!(s.starts_with("Minted / Recoverable-after "), "got: {s}");

        // Unpaid / Recovered are never locked → bare labels.
        assert_eq!(display_state(&sample(), Some(mtp)), "Unpaid");
        assert_eq!(display_state(&funded(DepositState::Recovered), Some(mtp)), "Recovered");
    }
}
