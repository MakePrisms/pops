//! PoPs ecash-agnostic verify core.
//!
//! HTTP-402 verify+redeem for ecash credentials. The core challenges holders
//! with a `WWW-Authenticate: Payment` envelope and, on retry, verifies the
//! presented credential and redeems it (for the Cashu impl, the redemption is
//! a NUT-03 swap whose success proves unspentness + unexpired `final_expiry`).
//!
//! "Charge-ness" is the surrounding `Payment` envelope + the [`Redeemer`]
//! seam; the only ecash-specific logic lives in [`cashu_credential`]. Public
//! types are decoupled from `cashu::{Amount,MintUrl,CurrencyUnit}` (→
//! `String`/`u64`) and produced against the [`pops_core_types`] contract
//! (`ChargeError` / `RedeemedProofs`).
//!
//! Two compile surfaces:
//! - `native` (default): adds the cdk-backed [`cdk_mint_client`], the axum
//!   [`middleware`], and the cashu-typed [`challenge`] codec.
//! - `wasm`: a wasm-bindgen surface exporting the cashu-free envelope codec and
//!   the full `verify_and_redeem`.
//!
//! [`Redeemer`]: crate::redeemer::Redeemer

#![warn(missing_docs)]

pub mod cashu_credential;
pub mod challenge;
pub mod envelope;
pub mod error;
pub mod mint_client;
pub mod redeemer;
// The cashu-pure NUT-03 swap ceremony + its raw-HTTP (`MintHttp`) seam. Always
// compiled: the crypto is shared by the native cdk client and the wasm
// injected-fetch client, and `cashu` itself compiles to wasm.
pub mod swap_ceremony;

// `cdk_mint_client` (cdk wallet HTTP) and `middleware` (axum) are the only
// truly native-only modules; everything else stays `always` because `cashu`
// compiles to wasm.
#[cfg(feature = "native")]
pub mod cdk_mint_client;
#[cfg(feature = "native")]
pub mod middleware;

// The injected-`fetch` MintClient + the wasm-bindgen export surface. Gated on
// the feature, not the target, so a native `--features wasm` typecheck sees
// them; the `fetch` bodies only run on wasm32.
#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "wasm")]
pub mod wasm_mint_client;
