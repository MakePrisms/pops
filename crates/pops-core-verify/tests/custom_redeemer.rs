//! A worked second [`Redeemer`] implementation — the template a consumer (e.g.
//! agicash) copies to plug its own ecash into the seam without touching
//! `pops-core-verify`. It lives in an integration test (a separate crate that
//! sees only the public API), so it doubles as proof the seam is implementable
//! independently: it is deliberately NOT `CashuCredential`, yet honors the same
//! value-safety contract documented on [`Redeemer::verify_and_redeem`].
//!
//! The redemption here is an in-memory voucher ledger rather than a mint swap,
//! so the impl stays self-contained. A real impl performs the actual redeem
//! (for cashu, the atomic NUT-03 swap with NUT-12 output-DLEQ verification); the
//! ledger stands in for that source of truth while preserving every observable
//! guarantee: atomic single-use redemption, exact-amount enforcement,
//! double-spend rejection, unit/mint matching, and no value-loss on error.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use pops_core_verify::charge::{ChargeError, RedeemedProofs};
use pops_core_verify::redeemer::{ChargeRequirement, Redeemed, Redeemer};

/// One redeemable voucher in the ledger: the value it carries and the canonical
/// proofs the caller receives custody of on redemption.
#[derive(Clone)]
struct Voucher {
    amount: u64,
    unit: String,
    mint: String,
    fresh_proofs: String,
    active_keyset_id: String,
}

/// A minimal [`Redeemer`] backed by an in-memory voucher ledger. Each voucher
/// redeems at most once (the `spent` set), modelling the atomic unspentness a
/// real source enforces at redeem time.
struct VoucherRedeemer {
    vouchers: HashMap<String, Voucher>,
    spent: Mutex<HashSet<String>>,
}

impl VoucherRedeemer {
    /// Build a ledger from issued vouchers, nothing spent yet.
    fn new(vouchers: HashMap<String, Voucher>) -> Self {
        Self {
            vouchers,
            spent: Mutex::new(HashSet::new()),
        }
    }
}

// Matches the seam's threading on each target: `Send` futures on native,
// single-threaded `?Send` on wasm32.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Redeemer for VoucherRedeemer {
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError> {
        // Unknown credential string: nothing to redeem (contract 5/structural).
        let voucher = self
            .vouchers
            .get(presented)
            .ok_or_else(|| ChargeError::MalformedCredential("unknown voucher".to_string()))?;

        // Unit + mint must satisfy the requirement before any state changes
        // (contract 5). Empty `req.mints` means "any mint".
        if voucher.unit != req.unit {
            return Err(ChargeError::WrongUnit {
                expected: req.unit.clone(),
                got: voucher.unit.clone(),
            });
        }
        if !req.mints.is_empty() && !req.mints.contains(&voucher.mint) {
            return Err(ChargeError::MintNotAllowed {
                got: voucher.mint.clone(),
                allowed: req.mints.clone(),
            });
        }

        // Exact amount: overpay and underpay are both rejected (contract 3).
        if voucher.amount != req.amount {
            return Err(ChargeError::AmountMismatch {
                required: req.amount,
                presented: voucher.amount,
                amount: req.amount,
                expected_swap_fee: 0,
            });
        }

        // Atomic single-use redeem (contracts 1 + 4): the spent-set insert is the
        // commit point. It runs LAST, only after every check above passed, so any
        // earlier error returns with the voucher still unspent (contracts 1 + 6).
        // `insert` returning false means it was already spent — a double-spend.
        {
            let mut spent = self.spent.lock().expect("spent lock not poisoned");
            if !spent.insert(presented.to_string()) {
                return Err(ChargeError::DoubleSpend);
            }
        }

        // The proofs are the value the CALLER now holds and persists (custody is
        // the caller's). A real impl returns the freshly-swapped, output-DLEQ-
        // verified proofs here (contract 2); the ledger returns the voucher's
        // canonical proofs, already trusted in this model.
        let proofs = RedeemedProofs {
            fresh_proofs: voucher.fresh_proofs.clone(),
            amount: voucher.amount,
            unit: voucher.unit.clone(),
            active_keyset_id: voucher.active_keyset_id.clone(),
            token_hash: token_hash_hex(presented),
        };

        Ok(Redeemed {
            unit: voucher.unit.clone(),
            amount: voucher.amount,
            proofs,
        })
    }
}

/// SHA-256 of the presented string, lowercase hex — a stable settlement
/// reference that leaks no secret (mirrors what the cdk impl records).
fn token_hash_hex(presented: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(presented.as_bytes());
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        s.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble<16"));
        s.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble<16"));
    }
    s
}

/// A one-voucher ledger for the tests.
fn sample_ledger() -> VoucherRedeemer {
    let mut vouchers = HashMap::new();
    vouchers.insert(
        "voucher-abc".to_string(),
        Voucher {
            amount: 10,
            unit: "pop_1700000000".to_string(),
            mint: "https://mint-a.example.com".to_string(),
            fresh_proofs: "cashuBexample".to_string(),
            active_keyset_id: "009a1f293253e41e".to_string(),
        },
    );
    VoucherRedeemer::new(vouchers)
}

fn sample_requirement() -> ChargeRequirement {
    ChargeRequirement {
        amount: 10,
        unit: "pop_1700000000".to_string(),
        mints: vec!["https://mint-a.example.com".to_string()],
        payment_id: None,
        description: None,
        single_use: true,
    }
}

#[tokio::test]
async fn custom_redeemer_honors_the_contract() {
    let redeemer = sample_ledger();
    let req = sample_requirement();

    // Happy path: exact amount, allowed mint, matching unit → Redeemed whose
    // amount equals the requirement (contract 3) and whose proofs the caller now
    // holds (custody).
    let redeemed = redeemer
        .verify_and_redeem("voucher-abc", &req)
        .await
        .expect("a valid voucher redeems");
    assert_eq!(redeemed.amount, req.amount);
    assert_eq!(redeemed.unit, req.unit);
    assert_eq!(redeemed.proofs.amount, req.amount);
    assert_eq!(redeemed.proofs.fresh_proofs, "cashuBexample");

    // Double-spend: the same voucher a second time is rejected (contract 4).
    let err = redeemer
        .verify_and_redeem("voucher-abc", &req)
        .await
        .expect_err("a spent voucher must be rejected");
    assert!(
        matches!(err, ChargeError::DoubleSpend),
        "expected DoubleSpend, got {err:?}"
    );
}

#[tokio::test]
async fn custom_redeemer_rejects_amount_mismatch_without_spending() {
    let redeemer = sample_ledger();
    let mut req = sample_requirement();
    req.amount = 9; // voucher carries 10 → mismatch with the requirement

    // Exact-amount enforcement (contract 3): rejected, not silently accepted.
    let err = redeemer
        .verify_and_redeem("voucher-abc", &req)
        .await
        .expect_err("an amount mismatch must be rejected");
    assert!(
        matches!(err, ChargeError::AmountMismatch { .. }),
        "expected AmountMismatch, got {err:?}"
    );

    // No value-loss on the error path (contracts 1 + 6): the voucher is still
    // unspent, so the correct requirement still redeems it.
    let ok_req = sample_requirement();
    redeemer
        .verify_and_redeem("voucher-abc", &ok_req)
        .await
        .expect("the voucher remained unspent after the rejected attempt");
}
