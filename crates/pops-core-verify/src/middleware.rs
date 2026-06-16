//! Axum middleware gating a route behind a `Payment` authentication challenge
//! for the cashu method (native only). Drop into an `axum::Router` with
//! [`axum::middleware::from_fn_with_state`].
//!
//! Flow: a request without `Authorization: Payment <blob>` gets a 402 carrying a
//! `WWW-Authenticate: Payment` challenge (whose `request="…"` is the
//! `draft-cashu-charge-00` request object built from the
//! [`CashuRequirement`]). Every challenge is stateless-bound per the framework:
//! its `id` is the HMAC-SHA256 over the issued auth-params under the state's
//! [`BindingKey`], and it carries an RFC 3339 `expires` (`now + challenge_ttl`).
//! The client retries with the credentials blob; the middleware authenticates
//! the echoed challenge (recompute the id-HMAC; check `expires` freshness),
//! then verify+redeems through the generic [`Redeemer`] seam and, on success,
//! attaches the [`Redeemed`] to `request.extensions_mut()` and emits a
//! `Payment-Receipt`. A tampered/inconsistent echo → `invalid-challenge` 402;
//! a stale `expires` → `payment-expired` 402.
//!
//! Status mapping (the single-sourced [`crate::problem`] map): a verification
//! or malformed-credential failure → 402 + a fresh re-challenge; a transport
//! failure to reach the mint → 503; a malformed request frame or a non-"cashu"
//! method → 400. Every error body is RFC-9457 `application/problem+json`
//! carrying the absolute `draft-cashu-charge-00` problem-type URI. Every 402
//! carries `Cache-Control: no-store`; the 200 carries `Cache-Control: private`.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use http::{header::HeaderValue, StatusCode};
use crate::charge::ChargeError;
use serde::Serialize;

use crate::binding::{
    issue_challenge, validate_challenge_echo, BindingKey, DEFAULT_CHALLENGE_TTL,
};
use crate::cashu_credential::{charge_requirement_from_cashu, CashuCredential};
use crate::cdk_mint_client::CdkMintClient;
use crate::http_status::charge_error_status;
use crate::challenge::{encode_charge_request, CashuRequirement};
use crate::problem::{Problem, PROBLEM_JSON};
use crate::redeemer::{Redeemed, Redeemer};
use crate::envelope::{
    parse_payment_authorization, AuthParseError, EchoedChallenge, CASHU_METHOD, PAYMENT_SCHEME,
};

/// Default `realm` emitted in `WWW-Authenticate: Payment`. Hardcoded.
/// TODO: wire `realm` through middleware state so operators can set it.
pub const DEFAULT_REALM: &str = "pops-core-verify";

/// The `intent` the verifier emits: `charge` = the server consumes the payment
/// as a one-shot charge (transfer-on-use).
pub const INTENT_CHARGE: &str = "charge";

/// Request-time state: the [`CashuRequirement`] to advertise on 402, the
/// [`Redeemer`] that verifies + redeems on retry, and the challenge-binding
/// facts (server key + TTL).
///
/// Generic over `C` so a second ecash method slots in with no middleware change;
/// constructed once at router-build time and shared (`Arc`).
#[derive(Debug)]
pub struct ChargeMiddlewareState<C: Redeemer> {
    /// What the verifier requires; built into the 402's `request="…"` `creqA`.
    pub requirement: CashuRequirement,
    /// The credential the middleware delegates to on retry.
    pub credential: Arc<C>,
    /// The server secret challenge ids are HMAC-bound under. Defaults to a
    /// fresh per-boot key ([`BindingKey::generate`]); an operator supplies a
    /// configured key via [`Self::with_binding_key`] to keep challenges valid
    /// across restarts.
    pub binding_key: BindingKey,
    /// Challenge lifetime stamped into `expires` (default
    /// [`DEFAULT_CHALLENGE_TTL`], 300 s).
    pub challenge_ttl: Duration,
}

impl<C: Redeemer> ChargeMiddlewareState<C> {
    /// Wraps `credential` in an [`Arc`] and pairs it with the requirement,
    /// generating a per-boot [`BindingKey`] and the default challenge TTL.
    pub fn new(requirement: CashuRequirement, credential: C) -> Self {
        Self {
            requirement,
            credential: Arc::new(credential),
            binding_key: BindingKey::generate(),
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
        }
    }

    /// Use an operator-configured binding key instead of the per-boot one
    /// (outstanding challenges then survive a restart).
    pub fn with_binding_key(mut self, key: BindingKey) -> Self {
        self.binding_key = key;
        self
    }

    /// Override the challenge TTL stamped into `expires`.
    pub fn with_challenge_ttl(mut self, ttl: Duration) -> Self {
        self.challenge_ttl = ttl;
        self
    }
}

/// Build a native [`ChargeMiddlewareState`] for the default
/// `CashuCredential<CdkMintClient>` (mint HTTP bounded by
/// [`crate::cdk_mint_client::DEFAULT_MINT_HTTP_TIMEOUT`]).
pub fn require_charge_state(
    requirement: CashuRequirement,
) -> ChargeMiddlewareState<CashuCredential<CdkMintClient>> {
    ChargeMiddlewareState::new(requirement, CashuCredential::new(CdkMintClient::new()))
}

/// As [`require_charge_state`] with an explicit per-call mint HTTP timeout. A
/// mint that stops answering then surfaces as the 503 mint-unavailable path
/// within the bound instead of hanging the request.
pub fn require_charge_state_with_mint_timeout(
    requirement: CashuRequirement,
    mint_http_timeout: Duration,
) -> ChargeMiddlewareState<CashuCredential<CdkMintClient>> {
    ChargeMiddlewareState::new(
        requirement,
        CashuCredential::new(CdkMintClient::with_timeout(mint_http_timeout)),
    )
}

/// Axum middleware entry point enforcing the Payment Authentication envelope.
/// The `'static` bound on `C` is what `from_fn_with_state` requires to spawn
/// the handler future.
pub async fn require_charge<C>(
    State(ctx): State<Arc<ChargeMiddlewareState<C>>>,
    mut req: Request,
    next: Next,
) -> Response
where
    C: Redeemer + Send + Sync + 'static,
{
    // More than one `Authorization: Payment` credential is a malformed REQUEST
    // frame → 400 per the framework (clients MUST send exactly one).
    if count_payment_credentials(req.headers()) > 1 {
        return charge_error_to_response(
            ChargeError::MalformedRequest(
                "request bears more than one Authorization: Payment credential".to_string(),
            ),
            &ctx,
        );
    }

    // A missing header or any non-`Payment` scheme is "no payment attempt" → 402.
    let Some(header_raw) = req.headers().get(http::header::AUTHORIZATION) else {
        return challenge_response(&ctx, None);
    };

    let header_value = match header_raw.to_str() {
        Ok(v) => v,
        Err(_) => {
            return charge_error_to_response(
                ChargeError::MalformedCredential(
                    "invalid Authorization header encoding".to_string(),
                ),
                &ctx,
            );
        }
    };

    // `UnknownScheme` (Basic/Bearer/…) is control-flow-identical to no header at
    // all; a non-"cashu" method is the framework's method-unsupported (400);
    // every OTHER parse error is a malformed credential → 402 re-challenge.
    let credentials = match parse_payment_authorization(header_value) {
        Ok(c) => c,
        Err(AuthParseError::UnknownScheme) => {
            return challenge_response(&ctx, None);
        }
        Err(AuthParseError::WrongMethod(method)) => {
            return charge_error_to_response(ChargeError::MethodUnsupported { method }, &ctx)
        }
        Err(e) => {
            return charge_error_to_response(
                ChargeError::MalformedCredential(e.to_string()),
                &ctx,
            )
        }
    };

    // Spec verification step 3, BEFORE any swap: authenticate the echoed
    // challenge (recompute the id-HMAC over every echoed param — tampered /
    // inconsistent / expires-less → invalid-challenge), then check `expires`
    // freshness (stale → payment-expired).
    if let Err(e) = validate_challenge_echo(&ctx.binding_key, &credentials.challenge) {
        return charge_error_to_response(e, &ctx);
    }

    // Verify + redeem via the generic seam; the `ChargeError` variant decides the
    // status (see `charge_error_to_response`).
    let charge_req = charge_requirement_from_cashu(&ctx.requirement);
    let redeemed = match ctx
        .credential
        .verify_and_redeem(&credentials.payload.token, &charge_req)
        .await
    {
        Ok(r) => r,
        Err(e) => return charge_error_to_response(e, &ctx),
    };

    // The receipt facts come from the redeemed proofs + the echoed challenge id;
    // `externalId` is the issuance-side correlation id (the requirement's).
    let receipt_header = payment_receipt_header(
        &redeemed,
        &credentials.challenge.id,
        ctx.requirement.external_id.as_deref(),
    );

    // Downstream reads this via `Extension<Redeemed>`.
    req.extensions_mut().insert(redeemed);
    let mut response = next.run(req).await;

    // `Payment-Receipt` + `Cache-Control: private` ride the settled SUCCESS
    // response only — the spec's receipt § forbids the receipt on error
    // responses (a downstream 4xx/5xx after settlement carries neither).
    // `from_str`/`from_static` are guarded: a header that won't build is dropped
    // rather than failing the served route.
    if response.status().is_success() {
        if let Ok(value) = HeaderValue::from_str(&receipt_header) {
            response.headers_mut().insert(PAYMENT_RECEIPT_HEADER, value);
        }
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("private"),
        );
    }
    response
}

/// The `Payment-Receipt` response-header name.
pub const PAYMENT_RECEIPT_HEADER: http::header::HeaderName =
    http::header::HeaderName::from_static("payment-receipt");

/// Count the `Authorization` values whose scheme token is `Payment` —
/// the framework allows at most one Payment credential per request (more is a
/// malformed request frame → 400). Shared by every axum-facing host (this
/// middleware and `pops-gateway`) so the counting rule cannot drift.
pub fn count_payment_credentials(headers: &http::HeaderMap) -> usize {
    headers
        .get_all(http::header::AUTHORIZATION)
        .iter()
        .filter(|v| {
            v.to_str().is_ok_and(|s| {
                s.split_whitespace()
                    .next()
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case(PAYMENT_SCHEME))
            })
        })
        .count()
}

/// The `Payment-Receipt` JSON. `reference` is the redeemed `token_hash` (a
/// settlement id exposing no secret); `externalId` is omitted when absent.
#[derive(Debug, Serialize)]
struct PaymentReceipt<'a> {
    method: &'a str,
    #[serde(rename = "challengeId")]
    challenge_id: &'a str,
    reference: &'a str,
    status: &'a str,
    timestamp: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    external_id: Option<&'a str>,
}

/// Build the `Payment-Receipt` header value: base64url-nopad over the
/// JCS-canonical (RFC 8785) receipt JSON, per the spec's Encoding § (the same
/// canonicalization the request object and credential blob use). `challenge_id`
/// echoes the credential's challenge `id`; `external_id` rides the receipt iff
/// the issuance carried a correlation id. Shared by both Rust hosts (this
/// middleware and `pops-gateway`).
pub fn payment_receipt_header(
    redeemed: &Redeemed,
    challenge_id: &str,
    external_id: Option<&str>,
) -> String {
    let receipt = PaymentReceipt {
        method: CASHU_METHOD,
        challenge_id,
        reference: &redeemed.proofs.token_hash,
        status: "success",
        timestamp: Utc::now().to_rfc3339(),
        external_id,
    };
    let json = serde_jcs::to_string(&receipt).expect("PaymentReceipt always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Build a 402 carrying a fresh challenge (always `Cache-Control: no-store`).
/// The challenge `id` is the framework's stateless HMAC binding over the
/// issued params under the state's [`BindingKey`], and `expires` is stamped
/// `now + challenge_ttl` (MUST under stateless operation). `problem`, when
/// set, is the RFC-9457 `application/problem+json` body naming why the
/// previous attempt failed; a bare "no attempt yet" 402 has an empty body.
fn challenge_response<C: Redeemer>(
    ctx: &ChargeMiddlewareState<C>,
    problem: Option<&Problem>,
) -> Response {
    // The one encode failure is a requirement naming no mints — server
    // misconfiguration, never the client's fault → 500, not a payment status.
    let request = match encode_charge_request(&ctx.requirement) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to encode challenge request object: {e}"),
            )
                .into_response();
        }
    };

    // TODO: wire `realm` through middleware state.
    let realm = DEFAULT_REALM;

    let issued = issue_challenge(
        &ctx.binding_key,
        realm,
        CASHU_METHOD,
        INTENT_CHARGE,
        &request,
        ctx.challenge_ttl,
    );

    // Values are all ASCII-printable; the `from_str` validation is a
    // belt-and-braces guard against a future encoder regression.
    let www_auth = match HeaderValue::from_str(&issued.header_value) {
        Ok(hv) => hv,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode WWW-Authenticate challenge header",
            )
                .into_response();
        }
    };

    let cache_control = HeaderValue::from_static("no-store");

    match problem {
        Some(p) => (
            StatusCode::PAYMENT_REQUIRED,
            [
                (http::header::WWW_AUTHENTICATE, www_auth),
                (http::header::CACHE_CONTROL, cache_control),
                (
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(PROBLEM_JSON),
                ),
            ],
            p.to_json(),
        )
            .into_response(),
        None => (
            StatusCode::PAYMENT_REQUIRED,
            [
                (http::header::WWW_AUTHENTICATE, www_auth),
                (http::header::CACHE_CONTROL, cache_control),
            ],
            String::new(),
        )
            .into_response(),
    }
}

/// Map a [`ChargeError`] to an HTTP response with an RFC-9457
/// `application/problem+json` body from the single-sourced
/// [`crate::problem`] map (`draft-cashu-charge-00` §Errors). The three
/// non-collapsing concerns drive the status: `MintUnreachable` is 503 (transport,
/// token NOT consumed, NEVER a 402) and carries `Retry-After`;
/// `MalformedRequest`/`MethodUnsupported` are 400 (not a well-formed payment
/// attempt); everything else (verification / malformed-credential) is a 402 with
/// a fresh re-challenge. The 402 carries the problem body alongside the fresh
/// `WWW-Authenticate`; a 503/400 carries the problem body with
/// `Cache-Control: no-store`.
fn charge_error_to_response<C: Redeemer>(
    e: ChargeError,
    ctx: &ChargeMiddlewareState<C>,
) -> Response {
    let problem = Problem::for_error(&e);
    let status = charge_error_status(&e);
    if status == StatusCode::PAYMENT_REQUIRED {
        return challenge_response(ctx, Some(&problem));
    }
    let mut response = (
        status,
        [
            (
                http::header::CONTENT_TYPE,
                HeaderValue::from_static(PROBLEM_JSON),
            ),
            (
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ),
        ],
        problem.to_json(),
    )
        .into_response();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().insert(
            http::header::RETRY_AFTER,
            HeaderValue::from_static("2"),
        );
    }
    response
}

/// Pluck the echoed challenge fields out of a parsed credentials blob — for test
/// helpers; the middleware doesn't consult them past `parse_payment_authorization`'s
/// `method` check.
#[allow(dead_code)]
pub(crate) fn echoed_challenge_for_test(creds: &crate::envelope::PaymentCredentials) -> &EchoedChallenge {
    &creds.challenge
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use axum::extract::Extension;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use cashu::dhke::hash_to_curve;
    use cashu::nuts::nut02::{Id, KeySetInfo};
    use cashu::nuts::Proof;
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
    use http::{header::AUTHORIZATION, Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::cashu_credential::CashuCredential;
    use crate::challenge::CashuRequirement;
    use crate::redeemer::Redeemed;
    use crate::envelope::{encode_payment_credentials, CashuPayload, PaymentCredentials};
    use crate::mint_client::{MintClient, MintClientError, SwapOutcome};

    // ---- Mock MintClient (mirrors the validator's test helper) -------

    enum SwapResponse {
        Echo,
        Unreachable,
        /// Post-submit (indeterminate) failure → exercises the 503 mapping.
        UnreachableIndeterminate,
        RejectedSwap,
        /// The mint typed the rejection as already-spent → exercises the
        /// double-spend detail.
        AlreadySpent,
        /// Keyset-class rejection (retired / final_expiry passed) → exercises
        /// the payment-expired mapping.
        KeysetRetiredOrExpired,
        /// Swap-output DLEQ verdict failed → serve-and-flag path: the swap
        /// SUCCEEDED, the response is the success path, `dleq_ok` is false.
        DleqInvalid,
    }

    struct MockMintClient {
        swap_response: SwapResponse,
    }

    impl MockMintClient {
        fn new(swap_response: SwapResponse) -> Self {
            Self { swap_response }
        }
    }

    #[async_trait]
    impl MintClient for MockMintClient {
        async fn keysets(
            &self,
            _mint_url: &MintUrl,
        ) -> Result<Vec<KeySetInfo>, MintClientError> {
            Ok(Vec::new())
        }

        async fn swap(
            &self,
            _mint_url: &MintUrl,
            proofs: Proofs,
        ) -> Result<SwapOutcome, MintClientError> {
            match self.swap_response {
                SwapResponse::Echo => Ok(SwapOutcome {
                    proofs,
                    dleq_ok: true,
                }),
                SwapResponse::Unreachable => Err(MintClientError::Unreachable(
                    "mock unreachable".into(),
                )),
                SwapResponse::UnreachableIndeterminate => Err(
                    MintClientError::UnreachableIndeterminate("mock indeterminate".into()),
                ),
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
                SwapResponse::AlreadySpent => {
                    Err(MintClientError::AlreadySpent("mock already spent".into()))
                }
                SwapResponse::KeysetRetiredOrExpired => Err(
                    MintClientError::KeysetRetiredOrExpired("mock keyset retired".into()),
                ),
                SwapResponse::DleqInvalid => Ok(SwapOutcome {
                    proofs,
                    dleq_ok: false,
                }),
            }
        }
    }

    // ---- Fixtures ----------------------------------------------------

    fn pop_unit() -> CurrencyUnit {
        CurrencyUnit::Custom("pop_1700000000".to_string())
    }

    fn mint_a() -> MintUrl {
        MintUrl::from_str("https://mint-a.example.com").expect("valid mint url")
    }

    fn make_proof(amount: u64, index: u8) -> Proof {
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let mut preimage = [0u8; 33];
        preimage[0] = 1;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
    }

    /// A NUT-10 P2PK-locked proof (bearer-only intent must reject it pre-swap).
    fn p2pk_locked_proof(amount: u64, index: u8) -> Proof {
        use cashu::nuts::nut10::SpendingConditions;
        use cashu::nuts::SecretKey;

        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let pk = SecretKey::generate().public_key();
        let nut10_secret: Secret = SpendingConditions::new_p2pk(pk, None)
            .try_into()
            .expect("P2PK condition serializes to a NUT-10 secret");
        let mut preimage = [0u8; 33];
        preimage[0] = 3;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, nut10_secret, c)
    }

    fn make_token(mint: MintUrl, unit: CurrencyUnit, proofs: Proofs) -> Token {
        Token::new(mint, proofs, None, unit)
    }

    fn requirement(unit: CurrencyUnit, mints: Vec<MintUrl>, amount: u64) -> CashuRequirement {
        CashuRequirement {
            unit,
            mints,
            amount: Amount::from(amount),
            external_id: None,
            description: None,
        }
    }

    /// The credential type the middleware tests drive: a `CashuCredential`
    /// backed by the mock mint client.
    type TestCredential = CashuCredential<MockMintClient>;

    /// Router with the middleware in front of an echo handler that writes the
    /// redeemed amount into the body, so tests can assert the `Redeemed` made it
    /// through the extensions.
    fn router_with(state: Arc<ChargeMiddlewareState<TestCredential>>) -> Router {
        async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
            format!("ok:{}", redeemed.amount)
        }
        Router::new()
            .route("/gated", get(echo))
            .layer(from_fn_with_state(state, require_charge::<TestCredential>))
    }

    /// Build a state with the supplied swap response and the standard
    /// requirement (`pop_1700000000`, mint_a, amount=10).
    fn state_with(swap: SwapResponse) -> Arc<ChargeMiddlewareState<TestCredential>> {
        let mock = MockMintClient::new(swap);
        let credential = CashuCredential::new(mock);
        Arc::new(ChargeMiddlewareState::new(
            requirement(pop_unit(), vec![mint_a()], 10),
            credential,
        ))
    }

    /// As [`state_with`] but the credential enforces a per-token `max_proofs`
    /// cap (the wired DoS guard).
    fn state_with_max_proofs(
        swap: SwapResponse,
        max_proofs: usize,
    ) -> Arc<ChargeMiddlewareState<TestCredential>> {
        let mock = MockMintClient::new(swap);
        let credential = CashuCredential::with_max_proofs(mock, max_proofs);
        Arc::new(ChargeMiddlewareState::new(
            requirement(pop_unit(), vec![mint_a()], 10),
            credential,
        ))
    }

    /// Build a GET /gated request with no body.
    fn bare_request() -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request")
    }

    /// Build a GET /gated request with the supplied raw `Authorization`
    /// header value.
    fn request_with_authorization(value: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/gated")
            .header(AUTHORIZATION, value)
            .body(Body::empty())
            .expect("build request with header")
    }

    /// Wrap a raw `cashuB…` token in the Payment envelope around an UNISSUED
    /// (never-challenged) echo — fails the stateless binding by construction.
    /// For the pre-binding paths (>1-credential 400) and the
    /// unissued-echo-rejection test itself.
    fn unissued_echo_header(token: &str) -> String {
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "test-challenge-id".into(),
                realm: DEFAULT_REALM.into(),
                method: "cashu".into(),
                intent: INTENT_CHARGE.into(),
                request: "echoed-request-object".into(),
                digest: None,
                opaque: None,
                expires: None,
                description: None,
            },
            payload: CashuPayload {
                token: token.into(),
            },
            source: None,
        };
        format!("Payment {}", encode_payment_credentials(&creds))
    }

    /// Fetch a REAL challenge off the router (bare request → 402) and parse
    /// its auth-params — the first half of the client dance.
    async fn fetch_challenge(app: &Router) -> crate::envelope::PaymentParams {
        let response = app
            .clone()
            .oneshot(bare_request())
            .await
            .expect("challenge fetch");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        crate::envelope::parse_payment_params(&header).expect("challenge params parse")
    }

    /// Echo issued params verbatim into the credential's challenge object.
    fn echo_of(params: &crate::envelope::PaymentParams) -> EchoedChallenge {
        EchoedChallenge {
            id: params.id.clone(),
            realm: params.realm.clone(),
            method: params.method.clone(),
            intent: params.intent.clone(),
            request: params.request.clone(),
            digest: params.digest.clone(),
            opaque: params.opaque.clone(),
            expires: params.expires.clone(),
            description: params.description.clone(),
        }
    }

    /// The `Authorization: Payment …` header value for `echo` + `token`.
    fn header_for_echo(echo: EchoedChallenge, token: &str) -> String {
        let creds = PaymentCredentials {
            challenge: echo,
            payload: CashuPayload {
                token: token.into(),
            },
            source: None,
        };
        format!("Payment {}", encode_payment_credentials(&creds))
    }

    /// The full client dance: fetch a real challenge from `app`, echo its
    /// params faithfully, and build the authenticated retry request carrying
    /// `token`.
    async fn request_with_token(app: &Router, token: &str) -> HttpRequest<Body> {
        let params = fetch_challenge(app).await;
        request_with_authorization(&header_for_echo(echo_of(&params), token))
    }

    /// GET /gated with raw header bytes (for the non-utf8 case). `header()`
    /// rejects non-ASCII at builder time, so reach down to `from_bytes`.
    fn request_with_raw_authorization(value: &[u8]) -> HttpRequest<Body> {
        let mut req = HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request");
        let hv = http::HeaderValue::from_bytes(value).expect("non-utf8 header bytes are valid");
        req.headers_mut().insert(AUTHORIZATION, hv);
        req
    }

    /// Pluck the `WWW-Authenticate` header off a response as a string
    /// — convenience for the many tests that assert on its shape.
    fn www_authenticate(response: &Response) -> String {
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate present")
            .to_str()
            .expect("WWW-Authenticate is ASCII")
            .to_string()
    }

    // ---- Core 402 challenge shape ------------------------------------

    #[tokio::test]
    async fn no_authorization_header_returns_402_with_www_authenticate() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        assert!(header.starts_with("Payment "), "got: {header}");
        assert!(header.contains(r#"id=""#), "missing id: {header}");
        assert!(header.contains(r#"realm=""#), "missing realm: {header}");
        assert!(
            header.contains(r#"method="cashu""#),
            "missing method=cashu: {header}"
        );
        assert!(
            header.contains(r#"intent="charge""#),
            "missing intent=charge: {header}"
        );
        assert!(header.contains(r#"request=""#), "missing request: {header}");
    }

    #[tokio::test]
    async fn www_authenticate_includes_id_realm_method_intent_request() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);

        for (field, prefix) in &[
            ("id", r#"id=""#),
            ("realm", r#"realm=""#),
            ("method", r#"method=""#),
            ("intent", r#"intent=""#),
            ("request", r#"request=""#),
        ] {
            let start = header
                .find(prefix)
                .unwrap_or_else(|| panic!("missing {field} param in {header}"));
            let rest = &header[start + prefix.len()..];
            let end = rest
                .find('"')
                .unwrap_or_else(|| panic!("unterminated {field} param in {header}"));
            let value = &rest[..end];
            assert!(
                !value.is_empty(),
                "{field} value must be non-empty in {header}"
            );
        }
    }

    #[tokio::test]
    async fn realm_default_is_pops_core_verify() {
        // Lock the default `realm` so an operator-configurable change is a
        // visible diff later.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);
        assert!(
            header.contains(r#"realm="pops-core-verify""#),
            "got: {header}"
        );
    }

    #[tokio::test]
    async fn www_authenticate_request_is_spec_request_object() {
        // The `request` param decodes as the draft-cashu-charge-00 request object
        // (amount/currency/mints + the inner creqA), with the mints-superset
        // satisfied.
        use crate::challenge::decode_charge_request;
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);
        let start = header.find(r#"request=""#).expect("has request param");
        let after = &header[start + r#"request=""#.len()..];
        let end = after.find('"').expect("terminated request param");
        let request_value = &after[..end];
        let decoded = decode_charge_request(request_value).expect("decodes request object");
        assert_eq!(decoded.amount, cashu::Amount::from(10));
        assert_eq!(decoded.unit, pop_unit());
        assert_eq!(decoded.mints, vec![mint_a()]);
        assert!(
            decoded.creq_a.starts_with("creqA"),
            "methodDetails.request must be a creqA, got: {}",
            decoded.creq_a
        );
    }

    #[tokio::test]
    async fn response_402_has_cache_control_no_store() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let cache = response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .expect("Cache-Control present on 402");
        assert_eq!(
            cache.to_str().expect("ASCII"),
            "no-store",
            "Cache-Control: no-store on 402"
        );
    }

    // ---- Happy path --------------------------------------------------

    #[tokio::test]
    async fn valid_token_passes_through_to_handler() {
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), make_proof(2, 1)],
        );
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert_eq!(&body_bytes[..], b"ok:10");
    }

    // ---- Challenge binding (stateless HMAC id + expires) --------------

    /// Read the problem body of a response as JSON.
    async fn problem_body(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("problem+json body")
    }

    #[tokio::test]
    async fn challenge_emits_hmac_id_and_future_expires() {
        let app = router_with(state_with(SwapResponse::Echo));
        let params = fetch_challenge(&app).await;
        // The id is base64url-nopad over 32 HMAC-SHA256 bytes — not a UUID.
        let id_bytes = URL_SAFE_NO_PAD
            .decode(&params.id)
            .expect("id is base64url-nopad");
        assert_eq!(id_bytes.len(), 32, "id is an HMAC-SHA256 output");
        // expires is REQUIRED under stateless operation, RFC 3339, future.
        let expires = params.expires.as_deref().expect("challenge carries expires");
        let ts = chrono::DateTime::parse_from_rfc3339(expires).expect("expires is RFC 3339");
        assert!(ts.with_timezone(&Utc) > Utc::now(), "expires is in the future");
    }

    #[tokio::test]
    async fn faithful_echo_of_issued_challenge_passes() {
        // The fresh-challenge happy path: fetch → echo verbatim → 200.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unissued_challenge_echo_returns_invalid_challenge() {
        // An echo this server never issued (the old fake-fixture shape) fails
        // the id recomputation → invalid-challenge 402 + fresh challenge.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&unissued_echo_header(
                &token.to_string(),
            )))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());
        let problem = problem_body(response).await;
        assert_eq!(
            problem["type"],
            "https://paymentauth.org/problems/invalid-challenge"
        );
    }

    #[tokio::test]
    async fn tampering_each_echoed_slot_returns_invalid_challenge() {
        // Per HMAC slot reachable through this host: realm, intent, request,
        // expires (value), digest (injected), opaque (injected), and the id
        // itself. (`method` is covered separately: a non-"cashu" method is the
        // framework's method-unsupported 400 at parse time.)
        type Tamper = (&'static str, fn(&mut EchoedChallenge));
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let tampers: Vec<Tamper> = vec![
            ("realm", |e| e.realm = "evil.example".into()),
            ("intent", |e| e.intent = "authorize".into()),
            ("request", |e| e.request.push('x')),
            ("expires", |e| {
                e.expires = Some("2999-01-01T00:00:00Z".into())
            }),
            ("digest", |e| e.digest = Some("sha-256=:forged:".into())),
            ("opaque", |e| e.opaque = Some("Zm9yZ2Vk".into())),
            ("id", |e| e.id = "QQ".repeat(22)),
        ];
        for (slot, tamper) in tampers {
            let app = router_with(state_with(SwapResponse::Echo));
            let params = fetch_challenge(&app).await;
            let mut echo = echo_of(&params);
            tamper(&mut echo);
            let response = app
                .oneshot(request_with_authorization(&header_for_echo(
                    echo,
                    &token.to_string(),
                )))
                .await
                .expect("oneshot");
            assert_eq!(
                response.status(),
                StatusCode::PAYMENT_REQUIRED,
                "tampered {slot} must 402"
            );
            let problem = problem_body(response).await;
            assert_eq!(
                problem["type"], "https://paymentauth.org/problems/invalid-challenge",
                "tampered {slot} must be invalid-challenge"
            );
        }
    }

    #[tokio::test]
    async fn echo_missing_expires_returns_invalid_challenge() {
        // Every stateless challenge is issued WITH expires; an echo without it
        // is not a faithful echo (and payment-expired would be wrong: nothing
        // authentic has expired).
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let params = fetch_challenge(&app).await;
        let mut echo = echo_of(&params);
        echo.expires = None;
        let response = app
            .oneshot(request_with_authorization(&header_for_echo(
                echo,
                &token.to_string(),
            )))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let problem = problem_body(response).await;
        assert_eq!(
            problem["type"],
            "https://paymentauth.org/problems/invalid-challenge"
        );
    }

    #[tokio::test]
    async fn stale_expires_returns_payment_expired_before_any_redeem() {
        // TTL zero: the issued challenge is authentic but instantly stale —
        // payment-expired (NOT invalid-challenge); the redeemer is never
        // reached.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let state = Arc::new(
            ChargeMiddlewareState::new(
                requirement(pop_unit(), vec![mint_a()], 10),
                CashuCredential::new(MockMintClient::new(SwapResponse::Echo)),
            )
            .with_challenge_ttl(std::time::Duration::ZERO),
        );
        let app = router_with(state);
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());
        let problem = problem_body(response).await;
        assert_eq!(
            problem["type"],
            "https://paymentauth.org/problems/payment-expired"
        );
    }

    #[tokio::test]
    async fn configured_binding_key_survives_state_rebuild() {
        // Two states sharing one configured key accept each other's
        // challenges (the restart-with-configured-key story); a state with a
        // different (generated) key rejects them.
        let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);

        let issuing = router_with(Arc::new(
            ChargeMiddlewareState::new(
                requirement(pop_unit(), vec![mint_a()], 10),
                CashuCredential::new(MockMintClient::new(SwapResponse::Echo)),
            )
            .with_binding_key(BindingKey::from_hex(key_hex).expect("hex key")),
        ));
        let params = fetch_challenge(&issuing).await;
        let header = header_for_echo(echo_of(&params), &token.to_string());

        let same_key = router_with(Arc::new(
            ChargeMiddlewareState::new(
                requirement(pop_unit(), vec![mint_a()], 10),
                CashuCredential::new(MockMintClient::new(SwapResponse::Echo)),
            )
            .with_binding_key(BindingKey::from_hex(key_hex).expect("hex key")),
        ));
        let response = same_key
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a configured key honors challenges across instances"
        );

        let other_key = router_with(state_with(SwapResponse::Echo));
        let response = other_key
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(
            response.status(),
            StatusCode::PAYMENT_REQUIRED,
            "a different key rejects the foreign challenge"
        );
    }

    // ---- Validation-failure mapping (all → 402 + re-challenge) -------

    #[tokio::test]
    async fn invalid_header_encoding_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_raw_authorization(&[0xFFu8, 0xFE, 0xFD]))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());
    }

    #[tokio::test]
    async fn malformed_token_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, "cashuB!!!notbase64!!!").await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("malformed credential"),
            "expected malformed-credential message, got: {body}"
        );
    }

    #[tokio::test]
    async fn validation_failure_returns_402_not_400() {
        // A unit-mismatched token is a verification failure → 402, NOT 400.
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        assert!(header.contains(r#"method="cashu""#));
        assert_eq!(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .expect("Cache-Control")
                .to_str()
                .unwrap(),
            "no-store"
        );
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("wrong unit"),
            "expected wrong-unit body, got: {body}"
        );
    }

    #[tokio::test]
    async fn mint_unreachable_returns_503() {
        // Transport failure → 503 (see `charge_error_to_response`).
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Unreachable));
        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("mint unavailable"),
            "expected mint-unavailable message, got: {body}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hung_mint_returns_503_mint_unavailable_within_timeout() {
        // END-TO-END through the REAL CdkMintClient: a mint that accepts TCP
        // but never answers must produce the 503 mint-unavailable path within
        // the configured mint HTTP timeout plus margin — never hang the
        // request. (The token is NOT consumed: the hang is on the pre-swap
        // keysets GET, the determinate arm.)
        use crate::cdk_mint_client::CdkMintClient;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hung mint");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _held_open = socket;
                    std::future::pending::<()>().await;
                });
            }
        });

        let hung_mint =
            MintUrl::from_str(&format!("http://127.0.0.1:{port}")).expect("local mint url");
        let token = make_token(hung_mint.clone(), pop_unit(), vec![make_proof(10, 0)]);

        type CdkCredential = CashuCredential<CdkMintClient>;
        let state: Arc<ChargeMiddlewareState<CdkCredential>> =
            Arc::new(ChargeMiddlewareState::new(
                requirement(pop_unit(), vec![hung_mint], 10),
                CashuCredential::new(CdkMintClient::with_timeout(
                    std::time::Duration::from_millis(250),
                )),
            ));
        async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
            format!("ok:{}", redeemed.amount)
        }
        let app = Router::new()
            .route("/gated", get(echo))
            .layer(from_fn_with_state(state, require_charge::<CdkCredential>));

        let request = request_with_token(&app, &token.to_string()).await;
        let started = std::time::Instant::now();
        let response = app.oneshot(request).await.expect("oneshot");
        let elapsed = started.elapsed();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a hung mint is the mint-unavailable path"
        );
        assert!(
            response.headers().get(http::header::RETRY_AFTER).is_some(),
            "the 503 carries Retry-After"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "must answer within the 250ms mint timeout plus margin, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn mint_rejected_returns_402_with_neutral_detail() {
        // A non-keyset swap rejection the mint did NOT type as already-spent is
        // the spec's step-8 catch-all → verification-failed 402 with a
        // neutral detail (no double-spend claim the mint never made).
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::RejectedSwap));
        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("the mint rejected the swap"),
            "expected the neutral rejected-swap detail, got: {body}"
        );
        assert!(
            !body.contains("double-spend"),
            "an untyped rejection must not claim a double-spend, got: {body}"
        );
        assert!(
            body.contains("https://paymentauth.org/problems/verification-failed"),
            "a swap rejection answers with the verification-failed type, got: {body}"
        );
    }

    #[tokio::test]
    async fn already_spent_rejection_returns_402_with_double_spend_detail() {
        // The mint typed the rejection as already-spent (NUT 11001 /
        // cdk TokenAlreadySpent) → the spent-specific detail; same
        // verification-failed 402.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::AlreadySpent));
        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("double-spend"),
            "expected the double-spend detail, got: {body}"
        );
        assert!(
            body.contains("https://paymentauth.org/problems/verification-failed"),
            "an already-spent rejection answers with the verification-failed type, got: {body}"
        );
    }

    #[tokio::test]
    async fn keyset_retired_swap_rejection_returns_402_verification_failed() {
        // Spec step 8 + Keyset Rotation §: a swap rejected for keyset
        // retirement or passed final_expiry answers verification-failed (with a
        // fresh challenge), NOT payment-expired — that type is now the sole
        // stale-challenge-echo cause. The cause is named in the problem detail.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::KeysetRetiredOrExpired));
        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        assert!(
            header.starts_with("Payment "),
            "a fresh challenge must accompany the 402: {header}"
        );
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("https://paymentauth.org/problems/verification-failed"),
            "a keyset-class rejection answers with the verification-failed type, got: {body}"
        );
        assert!(
            !body.contains("payment-expired"),
            "must not map to payment-expired (single-cause: stale challenge), got: {body}"
        );
        assert!(
            body.contains("keyset retired or final_expiry passed"),
            "the problem detail must name the cause, got: {body}"
        );
    }

    #[tokio::test]
    async fn swap_output_dleq_failure_serves_resource_with_flag_in_extension() {
        // Spec step 8: a failed or missing DLEQ proof on the swap-returned
        // signatures indicates a misbehaving mint, not a payment failure — the
        // HTTP response is the NORMAL success path (200 + receipt), the gated
        // handler runs, and the false verdict rides `Extension<Redeemed>.dleq_ok`
        // for the operator surface.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        async fn echo_flag(Extension(redeemed): Extension<Redeemed>) -> String {
            format!("ok:{}:dleq_ok={}", redeemed.amount, redeemed.dleq_ok)
        }
        let app = Router::new()
            .route("/gated", get(echo_flag))
            .layer(from_fn_with_state(
                state_with(SwapResponse::DleqInvalid),
                require_charge::<TestCredential>,
            ));

        let request = request_with_token(&app, &encoded).await;
        let response = app.oneshot(request).await.expect("oneshot");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the payment settled; §security-dleq forbids failing it (MUST NOT \
             respond with a payment-failure status after a successful swap)"
        );
        assert!(
            response.headers().get("payment-receipt").is_some(),
            "a settled payment carries its receipt"
        );

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert_eq!(
            body, "ok:10:dleq_ok=false",
            "the resource is served and the extension carries the false verdict"
        );
    }

    #[tokio::test]
    async fn locked_proof_returns_402_and_does_not_serve_resource() {
        // LockedToken is a verification failure → 402; swap never attempted,
        // handler never runs.
        let token = make_token(mint_a(), pop_unit(), vec![p2pk_locked_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(!body.starts_with("ok:"), "gated resource must NOT be served");
        assert!(
            body.contains("locked") || body.to_ascii_lowercase().contains("nut-10"),
            "body should name the locked-token failure, got: {body}"
        );
    }

    #[tokio::test]
    async fn too_many_proofs_returns_402_and_does_not_serve_resource() {
        // 3-proof token against a cap of 2 → TooManyProofs → 402; swap not
        // attempted, handler not run.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(2, 0), make_proof(4, 1), make_proof(4, 2)],
        );
        let app = router_with(state_with_max_proofs(SwapResponse::Echo, 2));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(!body.starts_with("ok:"), "gated resource must NOT be served");
        assert!(
            body.contains("too many proofs"),
            "body should name the too-many-proofs failure, got: {body}"
        );
    }

    #[tokio::test]
    async fn indeterminate_swap_failure_returns_503() {
        // indeterminate: true is still 503 at the HTTP layer — the flag never
        // changes status, only the operator's checkstate obligation.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::UnreachableIndeterminate));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "indeterminate is still a 503 (the flag never changes status)"
        );
    }

    // ---- Envelope-shape rejection (legacy param form etc.) -----------

    #[tokio::test]
    async fn non_payment_scheme_returns_402_with_no_failure_body() {
        // An unsupported scheme is identical to no attempt → empty body.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Bearer abcdef"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&response);
        assert!(header.starts_with(r#"Payment id=""#));
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert!(
            body_bytes.is_empty(),
            "bare 402 (no attempt) should have empty body, got: {body_bytes:?}"
        );
    }

    #[tokio::test]
    async fn authorization_must_be_opaque_base64url_blob() {
        // The `method=…, token=…` param form is not accepted (base64 decode trips).
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(
                r#"Payment method="cashu", token="cashuBabc""#,
            ))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn base64url_decode_failure_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Payment !!!notbase64!!!"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(
            body.contains("base64url"),
            "expected base64 error message, got: {body}"
        );
    }

    #[tokio::test]
    async fn json_parse_failure_returns_402() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let blob = URL_SAFE_NO_PAD.encode(b"not a json object");
        let header = format!("Payment {blob}");

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8>");
        assert!(
            body.contains("JSON is malformed"),
            "expected JSON error message, got: {body}"
        );
    }

    #[tokio::test]
    async fn json_missing_challenge_field_returns_402() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let blob = URL_SAFE_NO_PAD.encode(br#"{"payload":{"token":"cashuBabc"}}"#);
        let header = format!("Payment {blob}");

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn json_missing_payload_field_returns_402() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"}}"#,
        );
        let header = format!("Payment {blob}");

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn non_cashu_method_returns_400_method_unsupported() {
        // Valid envelope but `method="tempo"` → the framework's
        // method-unsupported (HTTP 400), NOT a 402 malformed-credential.
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "id".into(),
                realm: "r".into(),
                method: "tempo".into(),
                intent: "charge".into(),
                request: "r".into(),
                digest: None,
                opaque: None,
                expires: None,
                description: None,
            },
            payload: CashuPayload {
                token: "cashuBabc".into(),
            },
            source: None,
        };
        let header = format!("Payment {}", encode_payment_credentials(&creds));

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let problem: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("problem+json body");
        assert_eq!(
            problem["type"],
            "https://paymentauth.org/problems/method-unsupported"
        );
        assert_eq!(problem["status"], 400);
        assert!(
            problem["detail"].as_str().unwrap_or("").contains("tempo"),
            "detail names the offending method: {problem}"
        );
    }

    #[tokio::test]
    async fn multiple_payment_credentials_return_400_bad_request() {
        // Framework: clients MUST send only one Authorization: Payment
        // credential; two of them are a malformed request frame → 400 with the
        // about:blank type (no registered slug), never the invalid-challenge 402.
        // The frame check precedes the binding check, so an unissued echo works.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let header = unissued_echo_header(&token.to_string());
        let mut req = HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request");
        req.headers_mut().append(
            AUTHORIZATION,
            http::HeaderValue::from_str(&header).expect("ascii"),
        );
        req.headers_mut().append(
            AUTHORIZATION,
            http::HeaderValue::from_str(&header).expect("ascii"),
        );

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(req).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let problem: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("problem+json body");
        assert_eq!(problem["type"], "about:blank");
        assert_eq!(problem["status"], 400);
    }

    #[tokio::test]
    async fn one_payment_credential_among_other_schemes_still_verifies() {
        // The >1 rule counts PAYMENT credentials only; a Basic header alongside
        // the one Payment credential is not a malformed frame. (The Payment
        // value must come first for the single-get parse to see it.)
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let params = fetch_challenge(&app).await;
        let header = header_for_echo(echo_of(&params), &token.to_string());
        let mut req = HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request");
        req.headers_mut().append(
            AUTHORIZATION,
            http::HeaderValue::from_str(&header).expect("ascii"),
        );
        req.headers_mut().append(
            AUTHORIZATION,
            http::HeaderValue::from_static("Basic dXNlcjpwdw=="),
        );

        let response = app.oneshot(req).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn payment_with_empty_credentials_returns_402() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization("Payment"))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    // ---- Value-coverage enforcement ------------------------------------

    #[tokio::test]
    async fn exact_amount_presentation_passes_through() {
        // Exactly the required amount (8+2=10) → 200; the verifier makes no change.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), make_proof(2, 1)],
        );
        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert_eq!(
            &body_bytes[..],
            b"ok:10",
            "handler sees the full exact amount the verifier swapped"
        );
    }

    #[tokio::test]
    async fn overfunded_presentation_is_accepted_and_excess_retained() {
        // Spec step 7: value above `amount + swap_fee` is accepted and
        // retained — a 20-against-10 token redeems whole and serves the
        // resource; the handler sees the full redeemed value.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(16, 0), make_proof(4, 1)],
        );
        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert_eq!(
            &body_bytes[..],
            b"ok:20",
            "the WHOLE over-funded value is redeemed and retained"
        );
    }

    #[tokio::test]
    async fn underfunded_presentation_returns_402_payment_insufficient() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(8, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let problem: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("problem+json body");
        assert_eq!(
            problem["type"],
            "https://paymentauth.org/problems/payment-insufficient",
            "an under-funded token is the framework's payment-insufficient"
        );
        assert_eq!(problem["status"], 402);
    }

    #[tokio::test]
    async fn mint_unreachable_503_carries_retry_after_and_no_custom_type() {
        // Spec Errors §: mint unreachability carries no problem type — plain
        // 503 + Retry-After, body about:blank.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Unreachable));
        let request = request_with_token(&app, &token.to_string()).await;
        let response = app.oneshot(request).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.headers().get(http::header::RETRY_AFTER).is_some(),
            "a 503 SHOULD carry Retry-After"
        );
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let problem: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("problem+json body");
        assert_eq!(
            problem["type"], "about:blank",
            "mint unreachability has no custom problem-type URI"
        );
    }

    // ---- Payment-Receipt encoding (spec Encoding §: JCS before base64url) --

    #[test]
    fn payment_receipt_bytes_are_jcs_canonical() {
        // Hand-derived from RFC 8785: keys sort lexicographically —
        // challengeId < externalId < method < reference < status < timestamp —
        // matching the spec's decoded receipt example, NOT the struct's
        // declaration order.
        let receipt = PaymentReceipt {
            method: CASHU_METHOD,
            challenge_id: "kM9xPqWvT2nJrHsY4aDfEb",
            reference: "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
            status: "success",
            timestamp: "2026-03-10T21:00:00Z".to_string(),
            external_id: Some("order_12345"),
        };
        let json = serde_jcs::to_string(&receipt).expect("receipt serializes");
        assert_eq!(
            json,
            r#"{"challengeId":"kM9xPqWvT2nJrHsY4aDfEb","externalId":"order_12345","method":"cashu","reference":"9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7","status":"success","timestamp":"2026-03-10T21:00:00Z"}"#
        );
    }

    #[test]
    fn payment_receipt_header_is_base64url_nopad_of_jcs_bytes() {
        let redeemed = Redeemed {
            unit: "pop_1700000000".into(),
            amount: 10,
            proofs: crate::charge::RedeemedProofs {
                fresh_proofs: "cashuBfresh".into(),
                amount: 10,
                unit: "pop_1700000000".into(),
                active_keyset_id: "009a1f293253e41e".into(),
                token_hash: "ref-hash".into(),
            },
            dleq_ok: true,
        };
        let header = payment_receipt_header(&redeemed, "ch-1", Some("inv-7"));
        let bytes = URL_SAFE_NO_PAD.decode(&header).expect("base64url-nopad");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        // The timestamp is stamped at build time; everything around it is the
        // pinned JCS order with the supplied facts.
        assert!(
            json.starts_with(
                r#"{"challengeId":"ch-1","externalId":"inv-7","method":"cashu","reference":"ref-hash","status":"success","timestamp":""#
            ),
            "receipt bytes must be JCS-ordered, got: {json}"
        );
        assert!(json.ends_with(r#""}"#), "got: {json}");
    }
}
