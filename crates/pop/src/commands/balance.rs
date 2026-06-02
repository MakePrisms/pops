//! `pop balance` — an aggregated, agent-friendly summary over the local ledger.
//!
//! Where `list`/`status` are per-deposit, `balance` rolls the whole ledger into
//! one object: how much BTC is still locked (funded but not recovered), counts
//! and sat sums per lifecycle state, how much is mintable right now (the
//! paid-not-minted set), and — best-effort against the chain tip — how much is
//! recoverable right now (funded-not-recovered deposits whose CLTV has matured).
//!
//! Like `status`, the chain overlay degrades gracefully: if esplora is
//! unreachable we cannot compute median-time-past (MTP), so `recoverable_now`
//! becomes `null` and `mtp_available` is `false` (a warning goes to stderr). We
//! do NOT raise `chain_unreachable` — balance is a best-effort read, not a
//! correctness-critical operation.
//!
//! ## Scope: ON-CHAIN DEPOSITS ONLY
//!
//! `balance` accounts the **on-chain CLTV deposits** this wallet tracks — it does
//! NOT count spendable ecash. This wallet *mints-and-prints* `cashuB` tokens and
//! holds **no token custody** (db: "no tokens stored"), so already-minted
//! spendable-pops are not part of any balance number here. (If/when a phase-2
//! `pay` command gives the wallet ecash custody, `balance` would surface
//! spendable-pops then.) So `balance` answers "how much BTC have I got locked /
//! mintable / recoverable", NOT "how much spendable ecash do I hold".
//!
//! ## Lifecycle → money mapping
//!
//! - `unpaid`    — quoted, no confirmed funding → BTC not in the address → NOT locked.
//! - `paid`      — funding credited, not yet minted → BTC LOCKED; mintable now.
//! - `minted`    — credential issued, BTC locked until `ts_expiry` → BTC LOCKED.
//! - `recovered` — the script-path sweep was broadcast → BTC reclaimed → NOT locked.
//! - `expired`   — funding deadline passed → BTC LOCKED **iff** funds were sent
//!   (`funding_txid` set); an un-funded expired quote holds NOTHING → NOT locked.
//!
//! So **locked** (`total_locked_sats`, and the candidate set for
//! `recoverable_now`) = funded-and-not-recovered = `paid + minted + funded-expired`
//! (BTC still in the CLTV address). The test is funding-gated, not state-gated
//! (an expired-but-never-funded deposit must NOT inflate the locked total), and
//! lives in one place — [`Deposit::is_locked`] — shared with `status`.
//! `mintable_now` = `paid`. A locked deposit is recoverable once chain MTP ≥ its
//! `ts_expiry` (BIP-113, the same maturity gate `recover` uses).

use std::path::Path;

use clap::Parser;

use crate::chain::Esplora;
use crate::db::{Deposit, DepositState};
use crate::wallet::Wallet;
use crate::SCHEMA_VERSION;

/// Arguments for `pop balance` (no per-command flags; respects the globals).
#[derive(Debug, Parser)]
pub struct BalanceArgs {}

/// A `{ count, sats }` pair for one bucket of deposits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Bucket {
    /// Number of deposits in this bucket.
    count: u64,
    /// Sum of their funded amounts, sats.
    sats: u64,
}

impl Bucket {
    /// Folds one deposit's amount into the bucket.
    fn add(&mut self, amount: u64) {
        self.count += 1;
        self.sats = self.sats.saturating_add(amount);
    }

    /// JSON `{ "count", "sats" }`.
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({ "count": self.count, "sats": self.sats })
    }
}

/// The fully aggregated balance summary. Built purely from a deposit slice +
/// an optional chain MTP, so the aggregation is unit-testable without a db or
/// network.
#[derive(Debug, Clone)]
struct Summary {
    /// Per-state buckets, indexed by [`DepositState`] (see [`Self::bucket`]).
    unpaid: Bucket,
    paid: Bucket,
    minted: Bucket,
    recovered: Bucket,
    expired: Bucket,
    /// Funded-but-not-recovered total (`paid + minted + funded-expired`).
    total_locked_sats: u64,
    /// Funded-but-not-minted (`paid`) — the mintable-now set.
    mintable_now: Bucket,
    /// Funded-not-recovered deposits with `ts_expiry <= mtp`. `None` ⟺ MTP was
    /// unavailable (esplora unreachable).
    recoverable_now: Option<Bucket>,
}

impl Summary {
    /// Aggregates a deposit slice. `mtp` is the chain tip's median-time-past
    /// when known; `None` (esplora unreachable) leaves `recoverable_now` unknown.
    fn build(deposits: &[Deposit], mtp: Option<u64>) -> Self {
        let mut unpaid = Bucket::default();
        let mut paid = Bucket::default();
        let mut minted = Bucket::default();
        let mut recovered = Bucket::default();
        let mut expired = Bucket::default();
        let mut total_locked_sats: u64 = 0;
        // Only computed when MTP is known; a `Some(default)` means "MTP known,
        // zero deposits matured", distinct from `None` ("MTP unknown").
        let mut recoverable = mtp.map(|_| Bucket::default());

        for d in deposits {
            match d.state {
                DepositState::Unpaid => unpaid.add(d.amount),
                DepositState::Paid => paid.add(d.amount),
                DepositState::Minted => minted.add(d.amount),
                DepositState::Recovered => recovered.add(d.amount),
                DepositState::Expired => expired.add(d.amount),
            }

            // Locked = funded (BTC in the CLTV address) and not yet recovered.
            // Funding-gated via the shared `Deposit::is_locked` (so balance and
            // status can't drift): an expired-but-never-funded deposit is excluded.
            if d.is_locked() {
                total_locked_sats = total_locked_sats.saturating_add(d.amount);
                // Recoverable now = a locked deposit whose CLTV has matured
                // (MTP >= ts_expiry, BIP-113 — the gate `recover` enforces).
                if let (Some(rb), Some(m)) = (recoverable.as_mut(), mtp) {
                    if d.is_recoverable_now(m) {
                        rb.add(d.amount);
                    }
                }
            }
        }

        Summary {
            unpaid,
            paid,
            minted,
            recovered,
            expired,
            total_locked_sats,
            // mintable_now is exactly the paid bucket (funded, not yet minted).
            mintable_now: paid,
            recoverable_now: recoverable,
        }
    }

    /// The success envelope object (see the module + SKILL docs for the schema).
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "total_locked_sats": self.total_locked_sats,
            "by_state": {
                "unpaid": self.unpaid.to_json(),
                "paid": self.paid.to_json(),
                "minted": self.minted.to_json(),
                "recovered": self.recovered.to_json(),
                "expired": self.expired.to_json(),
            },
            "mintable_now": self.mintable_now.to_json(),
            "recoverable_now": self.recoverable_now.map(Bucket::to_json),
            "mtp_available": self.recoverable_now.is_some(),
        })
    }

    /// Renders the human-readable summary to stdout.
    fn print_human(&self) {
        println!("PoP wallet balance");
        println!("  total locked:    {} sat", self.total_locked_sats);
        println!(
            "  mintable now:    {} sat ({} deposit{})",
            self.mintable_now.sats,
            self.mintable_now.count,
            plural(self.mintable_now.count)
        );
        match &self.recoverable_now {
            Some(rb) => println!(
                "  recoverable now: {} sat ({} deposit{})",
                rb.sats,
                rb.count,
                plural(rb.count)
            ),
            None => println!("  recoverable now: unknown (chain tip unavailable)"),
        }
        println!();
        println!("  {:<10}  {:>6}  {:>14}", "STATE", "COUNT", "SATS");
        for (name, b) in [
            ("unpaid", self.unpaid),
            ("paid", self.paid),
            ("minted", self.minted),
            ("recovered", self.recovered),
            ("expired", self.expired),
        ] {
            println!("  {name:<10}  {:>6}  {:>14}", b.count, b.sats);
        }
    }
}

/// `"s"` unless `n == 1`, for terse human pluralization.
fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Runs `pop balance`. Aggregates the local ledger; best-effort overlays the
/// chain-tip MTP for `recoverable_now` (degrading to `null` if esplora is
/// unreachable, exactly like `status`).
///
/// # Errors
///
/// `wallet_not_initialized` if no wallet exists at the dir; otherwise propagates
/// db errors (which resolve to `internal_error`). Esplora failures do NOT error
/// — they degrade the recoverability overlay.
pub async fn run(
    _args: &BalanceArgs,
    wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::open(wallet_dir)?;

    // Best-effort tip MTP for the recoverability overlay (None if unreachable).
    let mtp = fetch_mtp(&wallet).await;

    let deposits = wallet.db.list_deposits()?;
    let summary = Summary::build(&deposits, mtp);

    if json {
        println!("{}", serde_json::to_string_pretty(&summary.to_json())?);
    } else {
        summary.print_human();
    }
    Ok(())
}

/// Best-effort tip-MTP fetch (returns `None` if esplora is unreachable, warning
/// to stderr). Mirrors `commands::list`'s degrade path — balance never hard-fails
/// on a chain read, and never raises `chain_unreachable`.
async fn fetch_mtp(wallet: &Wallet) -> Option<u64> {
    let esplora = Esplora::new(&wallet.config.esplora_url);
    match esplora.tip_mtp_and_height().await {
        Ok((mtp, _h)) => Some(mtp),
        Err(e) => {
            eprintln!("(esplora unreachable, recoverable_now omitted: {e})");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a deposit fixture in `state` with `amount` sats and `ts_expiry`.
    /// `funding_txid` is `None` (un-funded); use [`fund`] to mark funding sent.
    /// Only the fields the aggregation reads are meaningful; the rest are filler.
    fn dep(state: DepositState, amount: u64, ts_expiry: u64) -> Deposit {
        Deposit {
            id: format!("dep-{}-{amount}-{ts_expiry}", state.as_str()),
            label: None,
            mint_url: "https://mint.example".to_string(),
            unit: format!("pop_{ts_expiry}"),
            ts_expiry,
            amount,
            funder_index: 0,
            funder_pubkey: "aa".repeat(32),
            quote_lock_pubkey: "02".to_string() + &"bb".repeat(32),
            p_internal: "cc".repeat(32),
            leaf_script: "dd".repeat(20),
            nonce: "42".repeat(32),
            mint_pubkey: "02".to_string() + &"ee".repeat(32),
            funding_address: "tb1pexample".to_string(),
            quote_id: "quote-1".to_string(),
            state,
            funding_txid: None,
            funding_vout: None,
            recovery_txid: None,
            created_at: 1_700_000_000,
        }
    }

    /// Marks `d` as funding-sent (sets `funding_txid`/`funding_vout`) — the gate
    /// that makes an `Expired` deposit count as locked.
    fn fund(mut d: Deposit) -> Deposit {
        d.funding_txid = Some("ab".repeat(32));
        d.funding_vout = Some(0);
        d
    }

    /// A representative ledger spanning every state, with distinct amounts so a
    /// mis-bucketed deposit changes a sum. Includes BOTH a funded-expired row
    /// (BTC was sent → counts as locked) AND an un-funded expired row
    /// (`funding_txid` None → holds nothing → must NOT count), exercising the
    /// funding-gated `is_locked` fix.
    fn fixture() -> Vec<Deposit> {
        vec![
            dep(DepositState::Unpaid, 100, 1_000),
            dep(DepositState::Paid, 200, 1_000),   // matured at mtp>=1000
            dep(DepositState::Paid, 400, 5_000),   // immature at mtp=2000
            dep(DepositState::Minted, 800, 1_500), // matured at mtp>=1500
            dep(DepositState::Minted, 1_600, 9_000), // immature at mtp=2000
            dep(DepositState::Recovered, 3_200, 1_000),
            fund(dep(DepositState::Expired, 6_400, 1_200)), // funded+matured → LOCKED
            dep(DepositState::Expired, 256, 1_100),         // UN-funded → NOT locked
        ]
    }

    /// by_state buckets count and sum correctly per lifecycle state.
    #[test]
    fn by_state_counts_and_sats() {
        let s = Summary::build(&fixture(), None);
        assert_eq!((s.unpaid.count, s.unpaid.sats), (1, 100));
        assert_eq!((s.paid.count, s.paid.sats), (2, 600)); // 200 + 400
        assert_eq!((s.minted.count, s.minted.sats), (2, 2_400)); // 800 + 1600
        assert_eq!((s.recovered.count, s.recovered.sats), (1, 3_200));
        // by_state buckets PURELY by stored state, so both expired rows land here
        // (6400 funded + 256 un-funded) regardless of the locked/funding gate.
        assert_eq!((s.expired.count, s.expired.sats), (2, 6_656));
    }

    /// total_locked_sats = paid + minted + funded-expired (funding sent, not
    /// recovered); it excludes unpaid (unfunded), recovered (swept out), AND an
    /// expired row whose funding was never sent.
    #[test]
    fn total_locked_excludes_unpaid_and_recovered() {
        let s = Summary::build(&fixture(), None);
        // 200 + 400 + 800 + 1600 + 6400 = 9400. The un-funded expired 256 is
        // EXCLUDED (the funding-gated fix) even though it is in the expired state.
        assert_eq!(s.total_locked_sats, 9_400);
        // Sanity: it is NOT the grand total (which would include unpaid+recovered+
        // the un-funded expired).
        let grand: u64 = fixture().iter().map(|d| d.amount).sum();
        assert_eq!(grand, 12_956);
        assert_ne!(s.total_locked_sats, grand);
    }

    /// The locked total is funding-gated, not state-gated: an `Expired` deposit
    /// with `funding_txid` set counts, an otherwise-identical one with no funding
    /// does NOT — pinning the money-overcount fix directly.
    #[test]
    fn expired_counts_as_locked_only_when_funded() {
        let funded = fund(dep(DepositState::Expired, 5_000, 1_000));
        let unfunded = dep(DepositState::Expired, 5_000, 1_000);

        let only_funded = Summary::build(std::slice::from_ref(&funded), None);
        assert_eq!(only_funded.total_locked_sats, 5_000, "funded-expired is locked");

        let only_unfunded = Summary::build(std::slice::from_ref(&unfunded), None);
        assert_eq!(
            only_unfunded.total_locked_sats, 0,
            "un-funded expired holds no locked BTC (the overcount fix)"
        );
        // It still shows in the expired by_state bucket (a state count, not money).
        assert_eq!((only_unfunded.expired.count, only_unfunded.expired.sats), (1, 5_000));
    }

    /// mintable_now is exactly the paid bucket (funded, not yet minted).
    #[test]
    fn mintable_now_is_the_paid_set() {
        let s = Summary::build(&fixture(), None);
        assert_eq!((s.mintable_now.count, s.mintable_now.sats), (2, 600));
        assert_eq!(s.mintable_now, s.paid);
    }

    /// With MTP known, recoverable_now selects locked (funding-sent) deposits
    /// whose ts_expiry <= MTP (and ONLY those — immature locked ones, a recovered
    /// deposit even if matured, AND a matured-but-un-funded expired row, are all
    /// excluded).
    #[test]
    fn recoverable_now_filters_by_mtp() {
        // MTP = 2000: matured+locked = paid@1000(200), minted@1500(800),
        // funded-expired@1200(6400). Immature (ts_expiry 5000/9000) excluded;
        // recovered@1000 excluded though matured; un-funded expired@1100(256)
        // excluded though matured (it holds no BTC — the funding-gate fix).
        let s = Summary::build(&fixture(), Some(2_000));
        let rb = s.recoverable_now.expect("mtp known => Some");
        assert_eq!((rb.count, rb.sats), (3, 7_400)); // 200 + 800 + 6400
    }

    /// The MTP boundary is inclusive (ts_expiry == MTP is recoverable), matching
    /// `recover`'s `mtp >= ts_expiry` gate.
    #[test]
    fn recoverable_now_boundary_is_inclusive() {
        let deps = vec![
            dep(DepositState::Minted, 10, 1_000), // exactly at MTP
            dep(DepositState::Minted, 20, 1_001), // one past MTP
        ];
        let s = Summary::build(&deps, Some(1_000));
        let rb = s.recoverable_now.unwrap();
        assert_eq!((rb.count, rb.sats), (1, 10));
    }

    /// MTP unavailable (esplora unreachable) => recoverable_now is None and the
    /// JSON renders it as null with mtp_available=false; the local-only fields
    /// (by_state, total_locked, mintable_now) are still fully populated.
    #[test]
    fn mtp_unavailable_degrades_to_null() {
        let s = Summary::build(&fixture(), None);
        assert!(s.recoverable_now.is_none());

        let v = s.to_json();
        assert_eq!(v["mtp_available"], json!(false));
        assert_eq!(v["recoverable_now"], json!(null));
        // Local-only aggregation is unaffected by the missing chain tip.
        assert_eq!(v["total_locked_sats"], json!(9_400));
        assert_eq!(v["mintable_now"], json!({ "count": 2, "sats": 600 }));
        assert_eq!(v["by_state"]["minted"], json!({ "count": 2, "sats": 2_400 }));
    }

    /// The full success envelope shape with MTP present: schema_version, the
    /// five by_state buckets, mintable/recoverable objects, mtp_available=true.
    #[test]
    fn json_envelope_shape_with_mtp() {
        let s = Summary::build(&fixture(), Some(2_000));
        let v = s.to_json();

        assert_eq!(v["schema_version"], json!(SCHEMA_VERSION));
        assert_eq!(v["total_locked_sats"], json!(9_400));
        assert_eq!(v["mtp_available"], json!(true));
        assert_eq!(v["recoverable_now"], json!({ "count": 3, "sats": 7_400 }));
        assert_eq!(v["mintable_now"], json!({ "count": 2, "sats": 600 }));

        let by_state = v["by_state"].as_object().expect("by_state is an object");
        let mut keys: Vec<&str> = by_state.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["expired", "minted", "paid", "recovered", "unpaid"]);
        for st in &keys {
            assert!(by_state[*st].get("count").is_some(), "{st} missing count");
            assert!(by_state[*st].get("sats").is_some(), "{st} missing sats");
        }
    }

    /// An empty ledger is all-zero buckets; with MTP known, recoverable_now is a
    /// zeroed bucket (NOT null) — null is reserved for "MTP unavailable".
    #[test]
    fn empty_ledger_is_zeroed_not_null() {
        let s = Summary::build(&[], Some(1_000));
        assert_eq!(s.total_locked_sats, 0);
        let v = s.to_json();
        assert_eq!(v["recoverable_now"], json!({ "count": 0, "sats": 0 }));
        assert_eq!(v["mtp_available"], json!(true));
        assert_eq!(v["by_state"]["paid"], json!({ "count": 0, "sats": 0 }));
    }
}
