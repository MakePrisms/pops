//! The gateway's per-request orchestration: gate → persist → forward.
//!
//! This is the THIN HOST around the existing verify gate. The verify logic
//! itself is fully reused from `pops-core-verify`
//! ([`CashuCredential::verify_and_redeem`]); this module only:
//!
//! 1. decides whether a path is gated ([`crate::routes`]);
//! 2. on a gated path, runs the gate (no/invalid credential → 402 with the
//!    prebuilt challenge; else parse + `verify_and_redeem`);
//! 3. **on success, persists `fresh_proofs` durably BEFORE forwarding** (spec
//!    refinement #2);
//! 4. forwards the ORIGINAL request to `upstream_url` and streams the response
//!    back;
//! 5. maps a [`ChargeError`] to HTTP exactly as the Vercel `route.ts`
//!    `errorToResponse` does (mint-unreachable → 503 + Retry-After; malformed
//!    request → 400; everything else → 402 + fresh challenge).
//!
//! The 402 wire shape (`WWW-Authenticate: Payment …`) and the ChargeError
//! mapping mirror `pops-core-verify`'s `middleware.rs` and the Vercel route.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};

use pops_core_types::ChargeError;
use pops_core_verify::cashu_credential::{charge_requirement_from_cashu, CashuCredential};
use pops_core_verify::cdk_mint_client::CdkMintClient;
use pops_core_verify::challenge::{encode_challenge, CashuRequirement};
use pops_core_verify::credential::Credential;
use pops_core_verify::envelope::{
    encode_request_envelope, parse_payment_authorization, AuthParseError, PAYMENT_SCHEME,
};

use crate::config::ValidatedConfig;
use crate::proofs_sink::ProofsSink;
use crate::routes::{gate_for, Gate};

/// `realm` advertised in the `WWW-Authenticate: Payment` challenge. v1 uses a
/// fixed identifier (the verify core does the same); operator-configurable
/// realm is out of scope for the gateway MVP.
pub const REALM: &str = "pops-gateway";

/// The `intent` value — a one-shot charge.
pub const INTENT_CHARGE: &str = "charge";

/// A fixed challenge `id`. The gate does NOT enforce challenge-id binding
/// (stateless v1, same as the verify core + the Vercel demo), so a constant id
/// is sufficient and keeps the prebuilt header truly constant.
pub const CHALLENGE_ID: &str = "pops-gateway";

/// Everything a request handler needs, built once at startup and shared
/// (`Arc`) across requests.
///
/// `C` is the credential seam — production wires
/// `CashuCredential<CdkMintClient>` ([`AppState::production`]); tests inject a
/// `CashuCredential<MockMintClient>`.
pub struct AppState<C: Credential> {
    /// The pre-parsed config (upstream URL, routes, requirement, …).
    pub config: ValidatedConfig,
    /// The credential that verifies + redeems on retry.
    pub credential: Arc<C>,
    /// Durable sink for redeemed proofs (persist-before-forward).
    pub sink: Arc<ProofsSink>,
    /// The prebuilt `WWW-Authenticate: Payment …` value (built ONCE from the
    /// requirement at startup; cloned onto every 402).
    pub www_authenticate: HeaderValue,
    /// HTTP client used to forward gated requests upstream.
    pub upstream: reqwest::Client,
}

impl<C: Credential> AppState<C> {
    /// Build the shared state from a validated config + credential + sink. The
    /// `WWW-Authenticate` value is prebuilt here.
    pub fn new(config: ValidatedConfig, credential: C, sink: ProofsSink) -> Self {
        let www_authenticate = build_www_authenticate(&config.requirement);
        Self {
            config,
            credential: Arc::new(credential),
            sink: Arc::new(sink),
            www_authenticate,
            upstream: reqwest::Client::new(),
        }
    }
}

impl AppState<CashuCredential<CdkMintClient>> {
    /// Production wiring: the real cdk-backed credential.
    pub fn production(config: ValidatedConfig, sink: ProofsSink) -> Self {
        Self::new(config, CashuCredential::new(CdkMintClient::new()), sink)
    }
}

/// Build the `WWW-Authenticate: Payment id="…", realm="…", method="cashu",
/// intent="charge", request="<creqA-envelope>"` value once, from the
/// requirement. Mirrors `middleware::challenge_response` + the Vercel
/// `wwwAuthenticate`.
fn build_www_authenticate(requirement: &CashuRequirement) -> HeaderValue {
    let creq_a = encode_challenge(requirement);
    let request_envelope = encode_request_envelope(&creq_a);
    let header = format!(
        r#"{PAYMENT_SCHEME} id="{CHALLENGE_ID}", realm="{REALM}", method="cashu", intent="{INTENT_CHARGE}", request="{request_envelope}""#
    );
    // All components are base64url-nopad / ASCII; from_str validates as a guard.
    HeaderValue::from_str(&header)
        .expect("WWW-Authenticate value is ASCII (creqA envelope is base64url-nopad)")
}

/// The axum catch-all handler. Every request (except the gateway-own health
/// endpoints, which are routed separately) flows through here.
pub async fn handle<C>(State(state): State<Arc<AppState<C>>>, req: Request) -> Response
where
    C: Credential + Send + Sync + 'static,
{
    let path = req.uri().path().to_string();

    match gate_for(&path, &state.config.routes) {
        // Public path: forward straight through, no gate, no persist.
        Gate::Public => forward(&state, req).await,
        // Gated path: run the full gate first.
        Gate::Charge => gate_then_forward(state, req).await,
    }
}

/// The gated path: enforce payment, persist on success, then forward.
async fn gate_then_forward<C>(state: Arc<AppState<C>>, req: Request) -> Response
where
    C: Credential + Send + Sync + 'static,
{
    // ── Step 1: extract + validate the Authorization: Payment credential. ──
    let token = match extract_token(req.headers()) {
        Ok(t) => t,
        // No header / non-Payment scheme → a bare 402 (no failure body).
        Err(TokenExtract::NoAttempt) => return challenge_402(&state, None),
        // A malformed Payment attempt → 402 + a reason.
        Err(TokenExtract::Malformed(reason)) => return challenge_402(&state, Some(&reason)),
    };

    // ── Step 2: verify + NUT-03 swap via the reused credential. ──
    let charge_req = charge_requirement_from_cashu(&state.config.requirement);
    let redeemed = match state.credential.verify_and_redeem(&token, &charge_req).await {
        Ok(r) => r,
        Err(e) => return charge_error_to_response(&state, e),
    };

    // ── Step 3: PERSIST fresh_proofs DURABLY *before* forwarding. ──
    // (spec refinement #2: a crash between forward and persist loses
    // already-consumed proofs.) On failure we do NOT forward and emit the
    // proofs + token_hash to stderr as a last resort so value is never silently
    // lost.
    if let Err(e) = state.sink.persist(&redeemed.proofs) {
        eprintln!(
            "FATAL persist failure (value at risk): {e}\n  token_hash={}\n  fresh_proofs={}",
            redeemed.proofs.token_hash, redeemed.proofs.fresh_proofs
        );
        tracing::error!(
            token_hash = %redeemed.proofs.token_hash,
            error = %e,
            "persist failed; refusing to forward; fresh_proofs emitted to stderr"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            "failed to persist redeemed proofs",
        )
            .into_response();
    }

    tracing::info!(
        token_hash = %redeemed.proofs.token_hash,
        amount = redeemed.proofs.amount,
        unit = %redeemed.proofs.unit,
        active_keyset_id = %redeemed.proofs.active_keyset_id,
        "charge settled and persisted; forwarding upstream"
    );

    // ── Step 4: forward the ORIGINAL request, stream the response back. ──
    forward(&state, req).await
}

/// Forward `req` verbatim (method/path+query/headers/body) to `upstream_url`
/// and stream the upstream response back. Used for both gated (post-persist)
/// and public requests.
async fn forward<C>(state: &AppState<C>, req: Request) -> Response
where
    C: Credential,
{
    let (parts, body) = req.into_parts();
    let target = match upstream_target(&state.config.upstream_url, &parts.uri) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "could not build upstream URL");
            return (StatusCode::BAD_GATEWAY, "bad upstream URL").into_response();
        }
    };

    // Buffer the request body (request bodies for these APIs are small; the
    // RESPONSE is what we stream). axum's Body → bytes.
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to read request body");
            return (StatusCode::BAD_REQUEST, "could not read request body").into_response();
        }
    };

    let upstream_req = state
        .upstream
        .request(map_method(&parts.method), target)
        .headers(forward_request_headers(&parts.headers))
        .body(body_bytes.to_vec());

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            // Upstream down/unreachable. Proofs (if any) are ALREADY persisted —
            // the operator keeps the value; the client loses the pop. This is
            // the documented v1 edge (spec refinement #3). 504 if it was a
            // timeout, else 502.
            let status = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            tracing::warn!(error = %e, %status, "upstream request failed");
            return (status, format!("upstream unavailable: {e}")).into_response();
        }
    };

    // Map status + headers, then stream the body.
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = forward_response_headers(upstream_resp.headers());

    let stream = upstream_resp.bytes_stream();
    let axum_body = Body::from_stream(stream);

    let mut response = Response::new(axum_body);
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

/// Build the upstream target URL = `upstream_url` base joined with the incoming
/// request's path + query. The base's own path prefix (if any) is preserved.
fn upstream_target(base: &reqwest::Url, incoming: &Uri) -> Result<reqwest::Url, String> {
    let mut url = base.clone();
    // Join the incoming path onto the base path. We append the incoming path to
    // the base path so a base like `http://up/api` + `/x` → `http://up/api/x`,
    // and a bare base `http://up/` + `/x` → `http://up/x`.
    let base_path = url.path().trim_end_matches('/');
    let incoming_path = incoming.path();
    let joined = format!("{base_path}{incoming_path}");
    url.set_path(&joined);
    url.set_query(incoming.query());
    Ok(url)
}

/// `http::Method` (axum) → `reqwest::Method`. Both are the `http` crate's
/// `Method` re-exported, so this is a cheap clone in practice.
fn map_method(m: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(m.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

/// Headers to forward to the upstream: everything except hop-by-hop headers and
/// `host` (reqwest sets the correct upstream `host`). `authorization` is
/// dropped on the gated path (it carried the spent pop, not an upstream cred);
/// for simplicity we drop it on all forwards — the upstream is the operator's
/// own unmodified API and never sees the pop credential.
fn forward_request_headers(incoming: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in incoming.iter() {
        if is_hop_by_hop(name.as_str()) || name == header::HOST || name == header::AUTHORIZATION {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Headers to copy from the upstream response back to the client: everything
/// except hop-by-hop + `transfer-encoding`/`content-length` (the streaming body
/// re-frames length/encoding).
fn forward_response_headers(upstream: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n) || n == "content-length" {
            continue;
        }
        // Re-wrap into the `http` crate's header types axum uses.
        if let (Ok(hn), Ok(hv)) = (
            header::HeaderName::from_bytes(name.as_ref()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out.append(hn, hv);
        }
    }
    out
}

/// RFC 7230 §6.1 hop-by-hop headers — never forwarded end-to-end.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Outcome of trying to pull a cashu token out of the `Authorization` header.
enum TokenExtract {
    /// No header, or a non-`Payment` scheme — identical to "no payment attempt".
    NoAttempt,
    /// A `Payment` attempt that failed to parse — surfaced as a 402 + reason.
    Malformed(String),
}

/// Extract the `cashuB…` token from `Authorization: Payment <blob>`. Mirrors
/// the verify middleware's Steps 1-3.
fn extract_token(headers: &HeaderMap) -> Result<String, TokenExtract> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Err(TokenExtract::NoAttempt);
    };
    let value = raw
        .to_str()
        .map_err(|_| TokenExtract::Malformed("invalid Authorization header encoding".into()))?;
    match parse_payment_authorization(value) {
        Ok(creds) => Ok(creds.payload.cashu_token),
        // Some other scheme (Basic/Bearer) — treat as no attempt.
        Err(AuthParseError::UnknownScheme) => Err(TokenExtract::NoAttempt),
        Err(e) => Err(TokenExtract::Malformed(e.to_string())),
    }
}

/// Build a 402 carrying the prebuilt challenge + a JSON body. Mirrors the
/// Vercel route's `challenge402`: body `{"error":"payment_required", realm,
/// [code, detail]}`. `Cache-Control: no-store` always.
fn challenge_402<C>(state: &AppState<C>, failure: Option<&str>) -> Response
where
    C: Credential,
{
    let body = match failure {
        Some(detail) => format!(
            r#"{{"error":"payment_required","detail":{},"realm":"{REALM}"}}"#,
            json_string(detail)
        ),
        None => format!(r#"{{"error":"payment_required","realm":"{REALM}"}}"#),
    };
    (
        StatusCode::PAYMENT_REQUIRED,
        [
            (header::WWW_AUTHENTICATE, state.www_authenticate.clone()),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

/// Map a [`ChargeError`] to an HTTP response, mirroring the Vercel
/// `errorToResponse` + the verify middleware's `charge_error_to_response`:
///
/// - [`ChargeError::MintUnreachable`] → `503` + `Retry-After` (token NOT
///   consumed, retryable). NEVER a 402.
/// - [`ChargeError::MalformedRequest`] → `400` (server-side config / method).
/// - everything else (incl. malformed-credential, verification failures) →
///   `402` + a fresh challenge.
fn charge_error_to_response<C>(state: &AppState<C>, e: ChargeError) -> Response
where
    C: Credential,
{
    match &e {
        // (A) transport → 503, retryable.
        ChargeError::MintUnreachable { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, HeaderValue::from_static("2")),
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            format!(
                r#"{{"error":"mint_unavailable","detail":{}}}"#,
                json_string(&e.to_string())
            ),
        )
            .into_response(),

        // (C) not a well-formed payment attempt → 400, not 402.
        ChargeError::MalformedRequest(_) => (
            StatusCode::BAD_REQUEST,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            format!(
                r#"{{"error":"bad_request","detail":{}}}"#,
                json_string(&e.to_string())
            ),
        )
            .into_response(),

        // (B + rest of C) verification / malformed-credential → 402 + challenge.
        _ => challenge_402(state, Some(&e.to_string())),
    }
}

/// Minimal JSON string escaper for embedding a detail message in a hand-built
/// JSON body. Handles the characters that would break JSON; everything else is
/// passed through. (Bodies are advisory; we keep the dep surface small.)
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
