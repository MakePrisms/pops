//! Axum middleware gating a route behind a `Payment` authentication challenge
//! for the cashu method (native only). Drop into an `axum::Router` with
//! [`axum::middleware::from_fn_with_state`].
//!
//! Flow: a request without `Authorization: Payment <blob>` gets a 402 carrying a
//! `WWW-Authenticate: Payment` challenge (whose `request="…"` is the
//! `draft-cashu-charge-01` request object built from the
//! [`CashuRequirement`]). The client retries
//! with the credentials blob; the middleware verify+redeems through the generic
//! [`Redeemer`] seam and, on success, attaches the
//! [`Redeemed`] to `request.extensions_mut()` and
//! emits a `Payment-Receipt`.
//!
//! Status mapping (the single-sourced [`crate::problem`] map): a verification
//! or malformed-credential failure → 402 + a fresh re-challenge; a transport
//! failure to reach the mint → 503; a malformed request frame or a non-"cashu"
//! method → 400. Every error body is RFC-9457 `application/problem+json`
//! carrying the absolute `draft-cashu-charge-01` problem-type URI. Every 402
//! carries `Cache-Control: no-store`; the 200 carries `Cache-Control: private`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use http::{header::HeaderValue, StatusCode};
use crate::charge::ChargeError;
use serde::Serialize;
use uuid::Uuid;

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

/// Request-time state: the [`CashuRequirement`] to advertise on 402 and the
/// [`Redeemer`] that verifies + redeems on retry.
///
/// Generic over `C` so a second ecash method slots in with no middleware change;
/// constructed once at router-build time and shared (`Arc`).
#[derive(Debug)]
pub struct ChargeMiddlewareState<C: Redeemer> {
    /// What the verifier requires; built into the 402's `request="…"` `creqA`.
    pub requirement: CashuRequirement,
    /// The credential the middleware delegates to on retry.
    pub credential: Arc<C>,
}

impl<C: Redeemer> ChargeMiddlewareState<C> {
    /// Wraps `credential` in an [`Arc`] and pairs it with the requirement.
    pub fn new(requirement: CashuRequirement, credential: C) -> Self {
        Self {
            requirement,
            credential: Arc::new(credential),
        }
    }
}

/// Build a native [`ChargeMiddlewareState`] for the default
/// `CashuCredential<CdkMintClient>`.
pub fn require_charge_state(
    requirement: CashuRequirement,
) -> ChargeMiddlewareState<CashuCredential<CdkMintClient>> {
    ChargeMiddlewareState::new(requirement, CashuCredential::new(CdkMintClient::new()))
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
            &ctx.requirement,
        );
    }

    // A missing header or any non-`Payment` scheme is "no payment attempt" → 402.
    let Some(header_raw) = req.headers().get(http::header::AUTHORIZATION) else {
        return challenge_response(&ctx.requirement, None);
    };

    let header_value = match header_raw.to_str() {
        Ok(v) => v,
        Err(_) => {
            return charge_error_to_response(
                ChargeError::MalformedCredential(
                    "invalid Authorization header encoding".to_string(),
                ),
                &ctx.requirement,
            );
        }
    };

    // `UnknownScheme` (Basic/Bearer/…) is control-flow-identical to no header at
    // all; a non-"cashu" method is the framework's method-unsupported (400);
    // every OTHER parse error is a malformed credential → 402 re-challenge.
    let credentials = match parse_payment_authorization(header_value) {
        Ok(c) => c,
        Err(AuthParseError::UnknownScheme) => {
            return challenge_response(&ctx.requirement, None);
        }
        Err(AuthParseError::WrongMethod(method)) => {
            return charge_error_to_response(
                ChargeError::MethodUnsupported { method },
                &ctx.requirement,
            )
        }
        Err(e) => {
            return charge_error_to_response(
                ChargeError::MalformedCredential(e.to_string()),
                &ctx.requirement,
            )
        }
    };

    // An echoed `challenge.expires` in the PAST is a `payment-expired`, caught
    // BEFORE any swap.
    if let Some(expires) = &credentials.challenge.expires {
        if challenge_is_expired(expires) {
            return charge_error_to_response(ChargeError::ChallengeExpired, &ctx.requirement);
        }
    }

    // Verify + redeem via the generic seam; the `ChargeError` variant decides the
    // status (see `charge_error_to_response`).
    let charge_req = charge_requirement_from_cashu(&ctx.requirement);
    let redeemed = match ctx
        .credential
        .verify_and_redeem(&credentials.payload.cashu_token, &charge_req)
        .await
    {
        Ok(r) => r,
        Err(e) => return charge_error_to_response(e, &ctx.requirement),
    };

    // The receipt facts come from the redeemed proofs + the echoed challenge id;
    // `externalId` is the issuance-side correlation id (the requirement's).
    let receipt_header = payment_receipt_header(
        &redeemed,
        &credentials.challenge.id,
        ctx.requirement.payment_id.as_deref(),
    );

    // Downstream reads this via `Extension<Redeemed>`.
    req.extensions_mut().insert(redeemed);
    let mut response = next.run(req).await;

    // `Payment-Receipt` + `Cache-Control: private` ride the settled response.
    // `from_str`/`from_static` are guarded: a header that won't build is dropped
    // rather than failing the served route.
    if let Ok(value) = HeaderValue::from_str(&receipt_header) {
        response.headers_mut().insert(PAYMENT_RECEIPT_HEADER, value);
    }
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("private"),
    );
    response
}

/// The `Payment-Receipt` response-header name.
const PAYMENT_RECEIPT_HEADER: http::header::HeaderName =
    http::header::HeaderName::from_static("payment-receipt");

/// Count the `Authorization` values whose scheme token is `Payment` —
/// the framework allows at most one Payment credential per request.
fn count_payment_credentials(headers: &http::HeaderMap) -> usize {
    headers
        .get_all(http::header::AUTHORIZATION)
        .iter()
        .filter(|v| {
            v.to_str().is_ok_and(|s| {
                s.trim()
                    .split_whitespace()
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

/// Build the `Payment-Receipt` header value: base64url-nopad over the receipt
/// JSON. `challenge_id` echoes the credential's challenge `id`; `external_id`
/// rides the receipt iff the issuance carried a correlation id.
fn payment_receipt_header(
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
    let json = serde_json::to_string(&receipt).expect("PaymentReceipt always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Whether an echoed RFC-3339 `expires` is in the past against the wall clock.
/// An UNPARSEABLE timestamp is treated as expired — a malformed echo is not a
/// faithful challenge echo.
fn challenge_is_expired(expires: &str) -> bool {
    match DateTime::parse_from_rfc3339(expires) {
        Ok(ts) => ts.with_timezone(&Utc) <= Utc::now(),
        Err(_) => true,
    }
}

/// Build a 402 carrying a fresh challenge (always `Cache-Control: no-store`).
/// `problem`, when set, is the RFC-9457 `application/problem+json` body naming
/// why the previous attempt failed; a bare "no attempt yet" 402 has an empty
/// body.
fn challenge_response(requirement: &CashuRequirement, problem: Option<&Problem>) -> Response {
    // A random UUIDv4 `id` suffices; the challenge is not cryptographically
    // bound to its params (no HMAC over them).
    let id = Uuid::new_v4().to_string();

    // The one encode failure is a requirement naming no mints — server
    // misconfiguration, never the client's fault → 500, not a payment status.
    let request = match encode_charge_request(requirement) {
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

    let header = format!(
        r#"{} id="{}", realm="{}", method="cashu", intent="{}", request="{}""#,
        PAYMENT_SCHEME, id, realm, INTENT_CHARGE, request,
    );

    // Values are all ASCII-printable; the `from_str` validation is a
    // belt-and-braces guard against a future encoder regression.
    let www_auth = match HeaderValue::from_str(&header) {
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
/// [`crate::problem`] map (`draft-cashu-charge-01` §Errors). The three
/// non-collapsing concerns drive the status: `MintUnreachable` is 503 (transport,
/// token NOT consumed, NEVER a 402); `MalformedRequest`/`MethodUnsupported` are
/// 400 (not a well-formed payment attempt); everything else (verification /
/// malformed-credential) is a 402 with a fresh re-challenge. The 402 carries the
/// problem body alongside the fresh `WWW-Authenticate`; a 503/400 carries the
/// problem body with `Cache-Control: no-store`.
fn charge_error_to_response(e: ChargeError, requirement: &CashuRequirement) -> Response {
    let problem = Problem::for_error(&e);
    let status = charge_error_status(&e);
    if status == StatusCode::PAYMENT_REQUIRED {
        return challenge_response(requirement, Some(&problem));
    }
    (
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
        .into_response()
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
    use crate::mint_client::{MintClient, MintClientError};

    // ---- Mock MintClient (mirrors the validator's test helper) -------

    enum SwapResponse {
        Echo,
        Unreachable,
        /// Post-submit (indeterminate) failure → exercises the 503 mapping.
        UnreachableIndeterminate,
        RejectedSwap,
        /// Swap-output DLEQ gate rejected the mint's blind signatures →
        /// money-safety path: 402 + re-challenge, resource NOT served.
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
        ) -> Result<Proofs, MintClientError> {
            match self.swap_response {
                SwapResponse::Echo => Ok(proofs),
                SwapResponse::Unreachable => Err(MintClientError::Unreachable(
                    "mock unreachable".into(),
                )),
                SwapResponse::UnreachableIndeterminate => Err(
                    MintClientError::UnreachableIndeterminate("mock indeterminate".into()),
                ),
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
                SwapResponse::DleqInvalid => Err(MintClientError::SwapOutputDleqInvalid(
                    "mock swap-output DLEQ invalid".into(),
                )),
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
            payment_id: None,
            description: None,
            single_use: true,
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

    /// Wrap a raw `cashuB…` token in the Payment envelope with a fake-but-shapely
    /// echoed challenge. The middleware does not validate `challenge.id`, so any
    /// well-formed echo works.
    fn payment_header_with_token(token: &str) -> String {
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
            },
            payload: CashuPayload {
                cashu_token: token.into(),
            },
            source: None,
        };
        format!("Payment {}", encode_payment_credentials(&creds))
    }

    /// Build a GET /gated request whose `Authorization` header is the
    /// Payment Authentication envelope around `token`.
    fn request_with_token(token: &str) -> HttpRequest<Body> {
        request_with_authorization(&payment_header_with_token(token))
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
        // The `request` param decodes as the draft-cashu-charge-01 request object
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
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        assert_eq!(&body_bytes[..], b"ok:10");
    }

    #[tokio::test]
    async fn authorization_blob_echoes_challenge_id() {
        // challenge-id binding is not enforced, but the round-trip must still 200.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "echoed-id-from-client".into(),
                realm: DEFAULT_REALM.into(),
                method: "cashu".into(),
                intent: INTENT_CHARGE.into(),
                request: "echoed-request".into(),
                digest: None,
                opaque: None,
                expires: None,
            },
            payload: CashuPayload {
                cashu_token: encoded,
            },
            source: None,
        };
        let header = format!("Payment {}", encode_payment_credentials(&creds));

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_authorization(&header))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
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
        let response = app
            .oneshot(request_with_token("cashuB!!!notbase64!!!"))
            .await
            .expect("oneshot");
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
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
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
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
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

    #[tokio::test]
    async fn mint_rejected_returns_402() {
        // A rejected swap is a verification failure → 402 + re-challenge.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::RejectedSwap));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("double-spend"),
            "expected double-spend (SAFE interim for any swap rejection) message, got: {body}"
        );
    }

    #[tokio::test]
    async fn swap_output_dleq_invalid_returns_402_and_does_not_serve_resource() {
        // Money-safety end-to-end: a missing/invalid swap-output DLEQ maps to
        // ChargeError::DleqInvalid → 402 + re-challenge, and the gated handler
        // MUST NOT run, so a malicious/buggy mint never gets the resource served
        // against unsigned ecash.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::DleqInvalid));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            !body.starts_with("ok:"),
            "gated resource must NOT be served on a DLEQ failure, got: {body}"
        );
        assert!(
            body.to_ascii_lowercase().contains("dleq"),
            "expected a DLEQ failure message, got: {body}"
        );
    }

    #[tokio::test]
    async fn locked_proof_returns_402_and_does_not_serve_resource() {
        // LockedToken is a verification failure → 402; swap never attempted,
        // handler never runs.
        let token = make_token(mint_a(), pop_unit(), vec![p2pk_locked_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&token.to_string()))
            .await
            .expect("oneshot");
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
        let response = app
            .oneshot(request_with_token(&token.to_string()))
            .await
            .expect("oneshot");
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
        let response = app
            .oneshot(request_with_token(&token.to_string()))
            .await
            .expect("oneshot");
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
        let blob = URL_SAFE_NO_PAD.encode(br#"{"payload":{"cashu_token":"cashuBabc"}}"#);
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
            },
            payload: CashuPayload {
                cashu_token: "cashuBabc".into(),
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
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let header = payment_header_with_token(&token.to_string());
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
        let header = payment_header_with_token(&token.to_string());
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

        let app = router_with(state_with(SwapResponse::Echo));
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

    // ---- Exact-amount enforcement ------------------------------------

    #[tokio::test]
    async fn exact_amount_presentation_passes_through() {
        // Exactly the required amount (8+2=10) → 200; the verifier makes no change.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), make_proof(2, 1)],
        );
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&token.to_string()))
            .await
            .expect("oneshot");
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
    async fn overfunded_presentation_returns_402() {
        // Exact-amount: a 20-against-10 over-funded token is rejected, NOT
        // change-made — the holder splits to 10 locally before presenting.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(16, 0), make_proof(4, 1)],
        );
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("amount mismatch"),
            "expected amount-mismatch body, got: {body}"
        );
    }

    #[tokio::test]
    async fn underfunded_presentation_returns_402() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(8, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        assert!(
            body.contains("amount mismatch"),
            "expected amount-mismatch body, got: {body}"
        );
    }
}
