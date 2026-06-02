//! The ecash-agnostic verify seam: the [`Credential`] trait + its
//! decoupled request/result types.
//!
//! This is the Axis-A generalization: a `Credential` verifies a presented
//! credential string against a [`ChargeRequirement`] and, on success, redeems
//! it — returning a [`Redeemed`] whose payload is the cross-slice
//! [`pops_core_types::RedeemedProofs`] contract. The only ecash-specific logic
//! lives in the impl ([`CashuCredential`][crate::cashu_credential::CashuCredential]);
//! the trait + these types name no `cashu` type (all `String`/`u64`), so a
//! second ecash method could implement the same seam without touching this
//! module.
//!
//! Errors are [`pops_core_types::ChargeError`] — the committed contract the
//! verifier SDK / HTTP envelope maps off (status / problem-type / retryability).

use pops_core_types::{ChargeError, RedeemedProofs};
use serde::{Deserialize, Serialize};

/// What the verifier requires from a holder for a single charge, decoupled
/// from any ecash type (the cashu-typed sibling is
/// [`CashuRequirement`][crate::challenge::CashuRequirement], used only to
/// build the `creqA`). All fields are plain data.
///
/// `Serialize`/`Deserialize` so the wasm `verify_and_redeem` export can accept
/// the requirement as a JSON string from the JS route (the cross-slice seam
/// stays plain-data — this is just the wire form for it). `Option` fields are
/// `#[serde(default)]` so a route may omit them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChargeRequirement {
    /// Exact amount of value required (net the server must receive).
    pub amount: u64,
    /// Currency unit the presented credential must carry. For PoP this is
    /// `pop_<unix_ts>`.
    pub unit: String,
    /// Mints the verifier accepts (string identity — URL today). Empty means
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

/// The result of a successful [`Credential::verify_and_redeem`].
///
/// `unit` + `amount` echo the validated facts; `proofs` is the cross-slice
/// [`RedeemedProofs`] payload the SDK needs to confirm value + emit a receipt
/// (it carries `fresh_proofs`, `active_keyset_id`, and `token_hash`).
#[derive(Debug, Clone)]
pub struct Redeemed {
    /// Unit of the redeemed value (echoes the requirement's `unit`).
    pub unit: String,
    /// Net value the operator received (the requested `amount`).
    pub amount: u64,
    /// The cross-slice redeemed-proofs payload (fresh proofs, active keyset,
    /// token hash) — `pops_core_types::RedeemedProofs`.
    pub proofs: RedeemedProofs,
}

/// Verify a presented credential against a [`ChargeRequirement`] and, on
/// success, redeem it.
///
/// On native the trait is `Send + Sync`-friendly (`#[async_trait]`); on
/// `wasm32` it is `#[async_trait(?Send)]` (single-threaded, matching the
/// [`MintClient`][crate::mint_client::MintClient] seam it composes over).
///
/// One impl exists for the MVP ([`CashuCredential`][crate::cashu_credential::CashuCredential]);
/// the trait is the place a second ecash method would slot in.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait Credential {
    /// Verify `presented` (a credential string — for cashu, a `cashuB…`
    /// token) against `req`, redeem it, and return what the operator now
    /// holds. Errors are the committed [`ChargeError`] contract.
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError>;
}

/// `wasm32` variant of [`Credential`]: `?Send` futures (single-threaded).
#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait Credential {
    /// See the native variant.
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError>;
}
