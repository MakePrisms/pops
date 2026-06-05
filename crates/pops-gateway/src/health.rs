//! Gateway-own health + readiness endpoints (never forwarded upstream).
//!
//! - `GET /healthz` → `200 OK` whenever the process is up.
//! - `GET /readyz` → `200 OK` if the mint is reachable (a cheap
//!   `GET <mint_url>/v1/keysets`), else `503`. Lets an orchestrator gate
//!   traffic on the mint dependency being live.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::StatusCode;

use pops_core_verify::redeemer::Redeemer;

use crate::gateway::AppState;

/// `GET /healthz` — process liveness. Always `200`.
pub async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// `GET /readyz` — mint reachability. Probes `<mint_url>/v1/keysets` with a
/// short timeout; `200` on any HTTP response from the mint, `503` if it cannot
/// be reached. (We only care that the mint answered, not the body — an
/// unreachable mint is the dependency we gate on.)
pub async fn readyz<C>(State(state): State<Arc<AppState<C>>>) -> Response
where
    C: Redeemer,
{
    let mint = state.config.mint_url.to_string();
    let url = format!("{}/v1/keysets", mint.trim_end_matches('/'));

    let resp = state
        .upstream
        .get(&url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => (StatusCode::OK, "ready").into_response(),
        Ok(r) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("mint returned {}", r.status()),
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("mint unreachable: {e}"),
        )
            .into_response(),
    }
}
