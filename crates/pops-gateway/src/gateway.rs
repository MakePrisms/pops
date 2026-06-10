//! The gateway's per-request orchestration: gate → persist → forward.
//!
//! A THIN HOST around the reused verify gate
//! ([`CashuCredential::verify_and_redeem`]): it decides whether a path is gated,
//! runs the gate, **persists `fresh_proofs` durably BEFORE forwarding**, then
//! proxies the ORIGINAL request to `upstream_url` and streams back. The
//! `ChargeError` → status/problem-type mapping (503/400/402 + RFC-9457 body) is
//! the single-sourced [`pops_core_verify::problem`] map, shared with the core
//! middlewares.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};

use pops_core_verify::binding::{issue_challenge, validate_challenge_echo};
use pops_core_verify::charge::ChargeError;
use pops_core_verify::cashu_credential::{charge_requirement_from_cashu, CashuCredential};
use pops_core_verify::cdk_mint_client::CdkMintClient;
use pops_core_verify::challenge::encode_charge_request;
use pops_core_verify::http_status::charge_error_status;
use pops_core_verify::middleware::count_payment_credentials;
use pops_core_verify::problem::{Problem, PROBLEM_JSON};
use pops_core_verify::redeemer::Redeemer;
use pops_core_verify::envelope::{
    parse_payment_authorization, AuthParseError, PaymentCredentials, CASHU_METHOD,
};

use crate::config::ValidatedConfig;
use crate::proofs_sink::ProofsSink;
use crate::routes::{gate_for, Gate};

/// `realm` advertised in the challenge.
pub const REALM: &str = "pops-gateway";

/// The `intent` value — a one-shot charge.
pub const INTENT_CHARGE: &str = "charge";

/// Per-request shared state, built once at startup (`Arc`). `C` is the credential
/// seam (production: `CashuCredential<CdkMintClient>` via [`AppState::production`]).
pub struct AppState<C: Redeemer> {
    /// The pre-parsed config (carries the binding key + challenge TTL).
    pub config: ValidatedConfig,
    /// The credential that verifies + redeems on retry.
    pub credential: Arc<C>,
    /// Durable sink for redeemed proofs (persist-before-forward).
    pub sink: Arc<ProofsSink>,
    /// The request object emitted in every challenge (constant per config; the
    /// per-challenge id + expires are stamped per request).
    pub request_object: String,
    /// HTTP client for forwarding gated requests upstream.
    pub upstream: reqwest::Client,
}

impl<C: Redeemer> AppState<C> {
    /// Build the shared state. The forwarding client gets the configured request
    /// + connect timeout so a hung upstream is bounded (and `504` is reachable).
    pub fn new(config: ValidatedConfig, credential: C, sink: ProofsSink) -> Self {
        let request_object = encode_charge_request(&config.requirement).expect(
            "ValidatedConfig guarantees a non-empty mint set (charge.mints defaults to [mint_url])",
        );
        let upstream = build_upstream_client(config.upstream_timeout);
        Self {
            config,
            credential: Arc::new(credential),
            sink: Arc::new(sink),
            request_object,
            upstream,
        }
    }
}

/// The forwarding client, with `timeout` as BOTH request + connect timeout
/// (`None` ⇒ no timeout). A builder failure falls back to a default client
/// rather than panic — the timeout is a safety bound, not a correctness invariant.
fn build_upstream_client(timeout: Option<std::time::Duration>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Some(t) = timeout {
        builder = builder.timeout(t).connect_timeout(t);
    }
    builder.build().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to build upstream client with timeout; using default");
        reqwest::Client::new()
    })
}

impl AppState<CashuCredential<CdkMintClient>> {
    /// Production wiring: the real cdk-backed credential, with the configured
    /// per-token `max_proofs` DoS cap enforced pre-swap.
    pub fn production(config: ValidatedConfig, sink: ProofsSink) -> Self {
        let credential =
            CashuCredential::with_max_proofs(CdkMintClient::new(), config.max_proofs);
        Self::new(config, credential, sink)
    }
}

/// Build one fresh `WWW-Authenticate: Payment …` value: the constant request
/// object (the shared `draft-cashu-charge-01` codec — the same object the core
/// middleware emits, so the two hosts speak ONE wire) plus a per-request
/// `expires` (`now + challenge_ttl`) and the framework's stateless HMAC `id`
/// binding every issued param under the configured key.
fn fresh_www_authenticate<C: Redeemer>(state: &AppState<C>) -> HeaderValue {
    let issued = issue_challenge(
        &state.config.binding_key,
        REALM,
        CASHU_METHOD,
        INTENT_CHARGE,
        &state.request_object,
        state.config.challenge_ttl,
    );
    // All components are base64url-nopad / ASCII; from_str validates as a guard.
    HeaderValue::from_str(&issued.header_value)
        .expect("WWW-Authenticate value is ASCII (request object is base64url-nopad)")
}

/// The axum catch-all handler. Every request (except the gateway-own health
/// endpoints, which are routed separately) flows through here.
pub async fn handle<C>(State(state): State<Arc<AppState<C>>>, req: Request) -> Response
where
    C: Redeemer + Send + Sync + 'static,
{
    let path = req.uri().path().to_string();

    match gate_for(&path, &state.config.routes) {
        Gate::Public => forward(&state, req).await,
        Gate::Charge => gate_then_forward(state, req).await,
    }
}

/// The gated path: enforce payment, persist on success, then forward.
///
/// The ordering is load-bearing for value-safety + DoS-resistance:
/// 1. extract the credential and authenticate its challenge echo first — a
///    bare/malformed/unbound request 402s without ever buffering its body (an
///    unauthenticated caller can't make us buffer up to the cap);
/// 2. buffer the body (capped) before the swap — over-cap → 413, read failure →
///    4xx, both while the pop is still unspent (so we never spend a pop on a
///    request we then can't read);
/// 3. swap + persist (before forwarding);
/// 4. forward the already-buffered body (no read can fail after the charge).
async fn gate_then_forward<C>(state: Arc<AppState<C>>, req: Request) -> Response
where
    C: Redeemer + Send + Sync + 'static,
{
    let (parts, body) = req.into_parts();

    // Extract the credential first (a bare/malformed request errors without
    // buffering its body).
    let credentials = match extract_credentials(&parts.headers) {
        Ok(c) => c,
        Err(TokenExtract::NoAttempt) => return challenge_402(&state, None),
        Err(TokenExtract::Failed(e)) => return charge_error_to_response(&state, e),
    };

    // Spec verification step 3, before the body buffer and any swap:
    // authenticate the echoed challenge (recompute the id-HMAC; tampered /
    // inconsistent → invalid-challenge) and check `expires` freshness
    // (stale → payment-expired).
    if let Err(e) = validate_challenge_echo(&state.config.binding_key, &credentials.challenge)
    {
        return charge_error_to_response(&state, e);
    }
    let token = credentials.payload.token;

    // Buffer the body (capped) before the swap, while the pop is still unspent.
    let body_bytes = match read_body_capped(body, state.config.max_body_bytes).await {
        Ok(b) => b,
        Err(BodyReadError::TooLarge) => return payload_too_large(state.config.max_body_bytes),
        Err(BodyReadError::Read(e)) => {
            tracing::warn!(error = %e, "failed to read request body before charge");
            return (StatusCode::BAD_REQUEST, "could not read request body").into_response();
        }
    };

    // Swap (verify + redeem).
    let charge_requirement = charge_requirement_from_cashu(&state.config.requirement);
    let redeemed = match state
        .credential
        .verify_and_redeem(&token, &charge_requirement)
        .await
    {
        Ok(r) => r,
        Err(e) => return charge_error_to_response(&state, e),
    };

    // Persist before forwarding — a crash between forward and persist would lose
    // already-consumed proofs. On failure, do NOT forward; emit the proofs +
    // token_hash to stderr so value is never silently lost.
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

    // Forward the already-buffered body (no read can fail after the charge).
    forward_buffered(&state, parts, body_bytes).await
}

/// Forward a PUBLIC request (no gate, no persist). The body cap is the primary
/// guard against an unbounded-body OOM on this unauthenticated path.
async fn forward<C>(state: &AppState<C>, req: Request) -> Response
where
    C: Redeemer,
{
    let (parts, body) = req.into_parts();
    let body_bytes = match read_body_capped(body, state.config.max_body_bytes).await {
        Ok(b) => b,
        Err(BodyReadError::TooLarge) => return payload_too_large(state.config.max_body_bytes),
        Err(BodyReadError::Read(e)) => {
            tracing::warn!(error = %e, "failed to read request body");
            return (StatusCode::BAD_REQUEST, "could not read request body").into_response();
        }
    };
    forward_buffered(state, parts, body_bytes).await
}

/// Why a request body could not be turned into bytes.
enum BodyReadError {
    /// The body exceeded the configured `max_body_bytes` cap → `413`.
    TooLarge,
    /// An underlying read/stream error (client disconnect, etc.) → `4xx`.
    Read(axum::Error),
}

/// Buffer a request `body` into `Bytes`, capped at `max` (the OOM guard).
/// `to_bytes` errors on BOTH a stream error AND an over-cap body, so
/// [`is_length_limit_error`] disambiguates over-cap → `413` from a 4xx.
async fn read_body_capped(body: Body, max: usize) -> Result<axum::body::Bytes, BodyReadError> {
    match axum::body::to_bytes(body, max).await {
        Ok(b) => Ok(b),
        Err(e) if is_length_limit_error(&e) => Err(BodyReadError::TooLarge),
        Err(e) => Err(BodyReadError::Read(e)),
    }
}

/// Whether a `to_bytes` error is the over-cap length-limit vs a stream error.
/// axum's `LengthLimitError` has no public type, so sniff the error chain's
/// `Display`. An unrecognized error is treated as a read error (4xx) — safe,
/// since on a gated path we have not yet charged.
fn is_length_limit_error(e: &axum::Error) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = src {
        if err.to_string().contains("length limit exceeded") {
            return true;
        }
        src = err.source();
    }
    false
}

/// `413 Payload Too Large` with a tiny JSON body naming the cap.
fn payload_too_large(max: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        format!(r#"{{"error":"payload_too_large","max_body_bytes":{max}}}"#),
    )
        .into_response()
}

/// Forward an already-buffered request to `upstream_url` and stream the response
/// back. The body is in memory so no read can fail here — crucial because on the
/// gated path the pop is ALREADY spent by now.
async fn forward_buffered<C>(
    state: &AppState<C>,
    parts: http::request::Parts,
    body_bytes: axum::body::Bytes,
) -> Response
where
    C: Redeemer,
{
    let target = match upstream_target(&state.config.upstream_url, &parts.uri) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "could not build upstream URL");
            return (StatusCode::BAD_GATEWAY, "bad upstream URL").into_response();
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
            // Upstream down. The proofs are ALREADY persisted — the operator keeps
            // the value; the client loses the pop. 504 on timeout, else 502.
            let status = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            tracing::warn!(error = %e, %status, "upstream request failed");
            return (status, format!("upstream unavailable: {e}")).into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = forward_response_headers(upstream_resp.headers());

    let stream = upstream_resp.bytes_stream();
    let axum_body = Body::from_stream(stream);

    let mut response = Response::new(axum_body);
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

/// Upstream target = `upstream_url` base joined with the incoming path + query,
/// preserving the base's path prefix (e.g. `http://up/api` + `/x` →
/// `http://up/api/x`).
fn upstream_target(base: &reqwest::Url, incoming: &Uri) -> Result<reqwest::Url, String> {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    let incoming_path = incoming.path();
    let joined = format!("{base_path}{incoming_path}");
    url.set_path(&joined);
    url.set_query(incoming.query());
    Ok(url)
}

/// `http::Method` → `reqwest::Method` (both re-export the `http` crate's type).
fn map_method(m: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(m.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

/// Headers forwarded upstream: all except hop-by-hop, `host` (reqwest sets it),
/// and `authorization` (it carried the spent pop, never an upstream cred — so the
/// upstream never sees the credential).
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

/// Response headers copied back to the client: all except hop-by-hop +
/// `content-length` (the streaming body re-frames length).
fn forward_response_headers(upstream: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n) || n == "content-length" {
            continue;
        }
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

/// Outcome of trying to pull payment credentials out of the `Authorization`
/// header.
enum TokenExtract {
    /// No header, or a non-`Payment` scheme — identical to "no payment attempt".
    NoAttempt,
    /// A `Payment` attempt that failed — the [`ChargeError`] picks the
    /// status/problem-type via the shared map (malformed credential → 402,
    /// non-"cashu" method → 400 method-unsupported, >1 credential → 400).
    Failed(ChargeError),
}

/// Extract the full credentials object from `Authorization: Payment <blob>` (the
/// echoed challenge feeds the binding check; `payload.token` feeds the redeem).
/// A non-Payment scheme is treated as no attempt; more than one Payment
/// credential is a malformed request frame per the framework (counted by the
/// shared [`count_payment_credentials`]).
fn extract_credentials(headers: &HeaderMap) -> Result<PaymentCredentials, TokenExtract> {
    if count_payment_credentials(headers) > 1 {
        return Err(TokenExtract::Failed(ChargeError::MalformedRequest(
            "request bears more than one Authorization: Payment credential".to_string(),
        )));
    }

    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Err(TokenExtract::NoAttempt);
    };
    let value = raw.to_str().map_err(|_| {
        TokenExtract::Failed(ChargeError::MalformedCredential(
            "invalid Authorization header encoding".into(),
        ))
    })?;
    match parse_payment_authorization(value) {
        Ok(creds) => Ok(creds),
        Err(AuthParseError::UnknownScheme) => Err(TokenExtract::NoAttempt),
        Err(AuthParseError::WrongMethod(method)) => {
            Err(TokenExtract::Failed(ChargeError::MethodUnsupported {
                method,
            }))
        }
        Err(e) => Err(TokenExtract::Failed(ChargeError::MalformedCredential(
            e.to_string(),
        ))),
    }
}

/// Build a 402 carrying a FRESH challenge (per-request HMAC id + expires;
/// always `Cache-Control: no-store`). The body is RFC-9457
/// `application/problem+json` from the shared [`pops_core_verify::problem`]
/// map: the supplied failure problem, or the framework's `payment-required`
/// type on a bare "no attempt yet" challenge.
fn challenge_402<C>(state: &AppState<C>, problem: Option<&Problem>) -> Response
where
    C: Redeemer,
{
    let body = match problem {
        Some(p) => p.to_json(),
        None => Problem::payment_required(format!("payment required for realm {REALM:?}"))
            .to_json(),
    };
    (
        StatusCode::PAYMENT_REQUIRED,
        [
            (header::WWW_AUTHENTICATE, fresh_www_authenticate(state)),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PROBLEM_JSON),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

/// Map a [`ChargeError`] to an HTTP response from the single-sourced
/// [`pops_core_verify::problem`] map (shared with the core middlewares so the
/// hosts cannot drift): [`ChargeError::MintUnreachable`] → `503` + `Retry-After`
/// (token NOT consumed; NEVER a 402), [`ChargeError::MalformedRequest`] /
/// [`ChargeError::MethodUnsupported`] → `400`, everything else (verification /
/// malformed-credential) → `402` + a fresh challenge. Every body is RFC-9457
/// `application/problem+json` with the absolute problem-type URI.
fn charge_error_to_response<C>(state: &AppState<C>, e: ChargeError) -> Response
where
    C: Redeemer,
{
    let problem = Problem::for_error(&e);
    let status = charge_error_status(&e);
    match status {
        StatusCode::PAYMENT_REQUIRED => challenge_402(state, Some(&problem)),
        StatusCode::SERVICE_UNAVAILABLE => (
            status,
            [
                (header::RETRY_AFTER, HeaderValue::from_static("2")),
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(PROBLEM_JSON),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            problem.to_json(),
        )
            .into_response(),
        _ => (
            status,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(PROBLEM_JSON),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            problem.to_json(),
        )
            .into_response(),
    }
}
