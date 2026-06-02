//! `pops-gateway` — a native (no-WASM) reverse proxy that gates an operator's
//! unmodified API with pops/cashu payment.
//!
//! The gateway is a THIN HOST around the existing verify gate in
//! `pops-core-verify`: it reuses `CashuCredential<CdkMintClient>` (verify +
//! NUT-03 swap), the cashu-typed challenge codec, and the request envelope, and
//! adds only the host concerns — config, durable proof persistence
//! (persist-before-forward), upstream forwarding, health/readiness, and JSON
//! structured logs. Operator-run, non-custodial: redeemed bearer proofs settle
//! into the operator's `proofs_sink` (their money).
//!
//! See [`config`] for the declarative surface, [`gateway`] for the per-request
//! orchestration, and [`build_router`] to assemble the axum app.

#![warn(missing_docs)]

pub mod config;
pub mod gateway;
pub mod health;
pub mod proofs_sink;
pub mod routes;

use std::sync::Arc;

use axum::routing::{any, get};
use axum::Router;

use pops_core_verify::credential::Credential;

use crate::gateway::{handle, AppState};
use crate::health::{healthz, readyz};

/// Assemble the gateway's axum [`Router`] from shared [`AppState`].
///
/// Routes:
/// - `GET /healthz` and `GET /readyz` are gateway-own (matched first, never
///   forwarded).
/// - everything else falls through to the catch-all [`handle`], which applies
///   the gating policy then forwards to the upstream.
///
/// Generic over the credential `C` so production wires
/// `CashuCredential<CdkMintClient>` and tests inject a mock-backed credential.
pub fn build_router<C>(state: Arc<AppState<C>>) -> Router
where
    C: Credential + Send + Sync + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<C>))
        // Catch-all for every other path + method → the gated forward handler.
        .fallback(any(handle::<C>))
        .with_state(state)
}
