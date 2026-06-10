//! The ecash-agnostic verify seam: the [`Redeemer`] trait + its
//! decoupled request/result types.
//!
//! A `Redeemer` verifies a presented credential string against a
//! [`ChargeRequirement`] and, on success, redeems it — returning a
//! [`Redeemed`] whose payload is the cross-slice
//! [`crate::charge::RedeemedProofs`] contract. The only ecash-specific logic
//! lives in the impl ([`CashuCredential`][crate::cashu_credential::CashuCredential]);
//! the trait + these types name no `cashu` type (all `String`/`u64`), so a
//! second ecash method could implement the same seam without touching this
//! module.
//!
//! Errors are [`crate::charge::ChargeError`] — the contract the verifier SDK /
//! HTTP envelope maps off (status / problem-type / retryability).

use crate::charge::{ChargeError, RedeemedProofs};
use serde::{Deserialize, Serialize};

/// What the verifier requires from a holder for a single charge, decoupled
/// from any ecash type (the cashu-typed sibling is
/// [`CashuRequirement`][crate::challenge::CashuRequirement], used only to
/// build the `creqA`). All fields are plain data. `amount` is the minimum
/// net value a credential must cover; excess is retained.
///
/// `Serialize`/`Deserialize` so the wasm `verify_and_redeem` export can accept
/// the requirement as a JSON string from the JS route (the cross-slice seam
/// stays plain-data — this is just the wire form for it). `Option` fields are
/// `#[serde(default)]` so a route may omit them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChargeRequirement {
    /// Amount of value required (the minimum net the server must receive).
    pub amount: u64,
    /// Currency unit the presented credential must carry. For PoP this is
    /// `pop_<unix_ts>`.
    pub unit: String,
    /// Mints the verifier accepts (string identity, a URL). Empty means
    /// "any mint".
    #[serde(default)]
    pub mints: Vec<String>,
    /// Optional payment correlation id.
    #[serde(default)]
    pub payment_id: Option<String>,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the challenge is one-shot.
    #[serde(default)]
    pub single_use: bool,
}

/// The result of a successful [`Redeemer::verify_and_redeem`].
///
/// `unit` + `amount` echo the validated facts; `proofs` is the cross-slice
/// [`RedeemedProofs`] payload the SDK needs to confirm value + emit a receipt
/// (it carries `fresh_proofs`, `active_keyset_id`, and `token_hash`).
#[derive(Debug, Clone)]
pub struct Redeemed {
    /// Unit of the redeemed value (echoes the requirement's `unit`).
    pub unit: String,
    /// Net value the operator received: at least the requirement's `amount`
    /// (excess presented value is retained, so this MAY exceed it).
    pub amount: u64,
    /// The cross-slice redeemed-proofs payload (fresh proofs, active keyset,
    /// token hash) — `crate::charge::RedeemedProofs`.
    pub proofs: RedeemedProofs,
    /// Verdict of the redemption-output integrity check (for cashu: NUT-12
    /// DLEQ on the swap-RETURNED blind signatures). `false` is a SOURCE-trust
    /// incident, not a payment failure (`draft-cashu-charge-01`
    /// §security-dleq): the payment settled and the resource is served; hosts
    /// surface this flag (it rides the middleware's `Extension<Redeemed>`) so
    /// the operator can alert and quarantine the source. Implementations
    /// without such a check report `true`.
    pub dleq_ok: bool,
}

/// Verify a presented credential against a [`ChargeRequirement`] and, on
/// success, redeem it.
///
/// On native the trait is `Send + Sync`-friendly (`#[async_trait]`); on
/// `wasm32` it is `#[async_trait(?Send)]` (single-threaded, matching the
/// [`MintClient`][crate::mint_client::MintClient] seam it composes over).
///
/// The Cashu impl is [`CashuCredential`][crate::cashu_credential::CashuCredential];
/// a second ecash method would slot in at this trait.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait Redeemer {
    /// Verify `presented` (a credential string — for cashu, a `cashuB…`
    /// token) against `req`, redeem it, and return what the operator now
    /// holds. Errors are the committed [`ChargeError`] contract.
    ///
    /// # Value-safety contract
    ///
    /// Every implementation MUST satisfy these invariants. They are what makes
    /// the seam safe to swap (the cdk impl and any other ecash impl alike); an
    /// impl that breaks one is incorrect, regardless of what it returns:
    ///
    /// 1. **Atomic redeem** — the value is redeemed in one atomic operation;
    ///    partial redemption is impossible. On any failure the credential is
    ///    left unspent at its source (no value-loss).
    /// 2. **Output integrity verified and REPORTED** — the returned proofs'
    ///    integrity check (NUT-12 DLEQ for cashu) always RUNS, and its verdict
    ///    is returned as [`Redeemed::dleq_ok`]. A failed verdict MUST NOT fail
    ///    the redemption (`draft-cashu-charge-01` §security-dleq: the
    ///    credential was already consumed by the successful redemption, so
    ///    erroring would both destroy the value and fail a settled payment);
    ///    it is surfaced to the operator instead (flag + WARN log).
    /// 3. **Value covered** — `Redeemed.amount` is the net value received and
    ///    is at least `req.amount`. An under-funded credential returns a
    ///    [`ChargeError`]; value above the requirement is accepted and
    ///    retained (the spec's no-change model), surfaced in `Redeemed.amount`.
    /// 4. **Double-spend caught** — an already-spent or replayed credential
    ///    returns a [`ChargeError`].
    /// 5. **Unit + mint match** — the credential's unit and source satisfy
    ///    `req`, or it returns a [`ChargeError`].
    /// 6. **No value-loss on any error path** — every `Err(ChargeError)` leaves
    ///    no orphaned or half-redeemed value.
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError>;
}

/// `wasm32` variant of [`Redeemer`]: `?Send` futures (single-threaded).
#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait Redeemer {
    /// See the native variant.
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError>;
}
