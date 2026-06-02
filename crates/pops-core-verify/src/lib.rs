//! PoPs ecash-agnostic verify core.
//!
//! HTTP-402 verify+redeem for ecash credentials. The core challenges holders
//! with a `WWW-Authenticate: Payment` envelope and, on retry, verifies the
//! presented credential and redeems it (for the Cashu impl, the redemption is
//! a NUT-03 swap whose success proves unspentness + unexpired `final_expiry`).
//!
//! "Charge-ness" is the surrounding `Payment` envelope + the [`Credential`]
//! seam; the only ecash-specific logic lives in [`cashu_credential`]. Public
//! types are decoupled from `cashu::{Amount,MintUrl,CurrencyUnit}` (→
//! `String`/`u64`) and produced against the [`pops_core_types`] contract
//! (`ChargeError` / `RedeemedProofs`).
//!
//! Two compile surfaces:
//! - `native` (default): adds the cdk-backed [`cdk_mint_client`], the axum
//!   [`middleware`], and the cashu-typed [`challenge`] codec.
//! - `wasm`: a wasm-bindgen surface (the cashu-free envelope codec in Step 1;
//!   the full `verify_and_redeem` in Step 2).
//!
//! [`Credential`]: crate::credential::Credential

#![warn(missing_docs)]

pub mod cashu_credential;
pub mod challenge;
pub mod credential;
pub mod envelope;
pub mod error;
pub mod mint_client;
// The cashu-pure NUT-03 swap ceremony + its raw-HTTP (`MintHttp`) seam. Always
// compiled: the crypto is shared by the native cdk client and the wasm
// injected-fetch client, and `cashu` itself compiles to wasm.
pub mod swap_ceremony;

// `cdk_mint_client` (cdk wallet HTTP) and `middleware` (axum) are the only
// truly native-only modules. `challenge` is cashu-typed but cashu compiles to
// wasm, so it stays `always` — `cashu_credential` (the verify engine, also
// `always`) depends on it, and Step 2 exposes that engine on wasm. The wasm
// EXPORT surface (`wasm`) still re-exports only the cashu-free envelope codec.
#[cfg(feature = "native")]
pub mod cdk_mint_client;
#[cfg(feature = "native")]
pub mod middleware;

// The injected-`fetch` MintClient + the wasm-bindgen export surface. Both are
// wasm-feature-only (the fetch client needs js-sys/web-sys; the exports need
// wasm-bindgen). `wasm_mint_client` is gated on the feature, not the target,
// so a native `--features wasm` typecheck still sees it — but its `fetch`
// bodies only run on wasm32.
#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "wasm")]
pub mod wasm_mint_client;
