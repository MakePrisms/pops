//! Axum middleware that gates a route behind a `Payment` authentication
//! challenge for the cashu method (native only).
//!
//! Drop into an `axum::Router` with [`axum::middleware::from_fn_with_state`]
//! to enforce the v1 happy path:
//!
//! 1. Request arrives without an `Authorization: Payment <blob>`
//!    header — middleware responds `402 Payment Required` and places
//!    `WWW-Authenticate: Payment id="…", realm="…", method="cashu",
//!    intent="charge", request="<base64url-nopad>"` on the response
//!    along with `Cache-Control: no-store`. The `request` value wraps
//!    the [`CashuRequirement`][crate::challenge::CashuRequirement] in its
//!    `creqA…` encoding via [`encode_request_envelope`].
//! 2. Client retries the same URL and method with `Authorization:
//!    Payment <base64url-nopad-JSON>` where the JSON has the shape
//!    described in [`crate::envelope::PaymentCredentials`]. The
//!    middleware extracts the `cashuB…` token from
//!    `payload.cashu_token`, runs verify+redeem through the generic
//!    [`Credential`] seam, and on success attaches the
//!    [`Redeemed`][crate::credential::Redeemed] result to
//!    `request.extensions_mut()` so the downstream handler can read it via
//!    `Extension<Redeemed>`.
//!
//! ## Failure mapping
//!
//! The middleware returns `402 Payment Required` with a fresh
//! `WWW-Authenticate: Payment` re-challenge on *any* validation failure
//! — bad header, bad token, wrong unit, wrong mint, wrong amount (the
//! charge is exact-amount, so an over- or under-funded token is rejected),
//! malformed proof, or a mint that refused the swap. Only transport-level
//! failures to reach the mint (DNS/TCP/TLS/timeout) surface as
//! `503 Service Unavailable`.
//!
//! Every 402 carries `Cache-Control: no-store`.
//!
//! ## Response body
//!
//! 402 bodies are plain-text descriptions of why the previous attempt
//! failed (e.g. `unit mismatch: expected pop_…, got sat`).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{header::HeaderValue, StatusCode};
use pops_core_types::ChargeError;
use uuid::Uuid;

use crate::cashu_credential::{charge_requirement_from_cashu, CashuCredential};
use crate::cdk_mint_client::CdkMintClient;
use crate::challenge::{encode_challenge, CashuRequirement};
use crate::credential::Credential;
use crate::envelope::{
    encode_request_envelope, parse_payment_authorization, AuthParseError, EchoedChallenge,
    PAYMENT_SCHEME,
};

/// Default `realm` value emitted in `WWW-Authenticate: Payment`. The
/// value is operator-defined; this hardcoded identifier serves v1 until
/// operator-configurable wiring lands (see TODO at use site).
pub const DEFAULT_REALM: &str = "pops-core-verify";

/// `intent` value the verifier emits. `charge` means "the server
/// consumes the payment as a one-shot charge" — matches the
/// transfer-on-use semantics.
pub const INTENT_CHARGE: &str = "charge";

/// State the middleware needs at request time: the [`CashuRequirement`]
/// to advertise on 402 (it builds the cashu `creqA`) and the
/// [`Credential`] that verifies + redeems the presented credential on retry.
///
/// Generic over `C: Credential` — the MVP wires a single
/// `CashuCredential<CdkMintClient>` (see [`require_charge`]); a second ecash
/// method would slot a different `C` in with no middleware change.
///
/// Constructed once at router-build time and shared (`Arc`) across requests.
#[derive(Debug)]
pub struct ChargeMiddlewareState<C: Credential> {
    /// What the verifier requires from the holder. Used to build the
    /// `creqA` wrapped into the `request="…"` auth-param of
    /// `WWW-Authenticate: Payment` on the 402.
    pub requirement: CashuRequirement,
    /// The credential the middleware delegates to once the client retries
    /// with an `Authorization: Payment` proof header.
    pub credential: Arc<C>,
}

impl<C: Credential> ChargeMiddlewareState<C> {
    /// Convenience constructor: wraps `credential` in an [`Arc`] and
    /// pairs it with the [`CashuRequirement`] to advertise.
    pub fn new(requirement: CashuRequirement, credential: C) -> Self {
        Self {
            requirement,
            credential: Arc::new(credential),
        }
    }
}

/// Build a native [`ChargeMiddlewareState`] for the default
/// `CashuCredential<CdkMintClient>` from a cashu requirement — the MVP
/// wiring convenience. Mirrors the demo's router-build step.
pub fn require_charge_state(
    requirement: CashuRequirement,
) -> ChargeMiddlewareState<CashuCredential<CdkMintClient>> {
    ChargeMiddlewareState::new(requirement, CashuCredential::new(CdkMintClient::new()))
}

/// Axum middleware entry point: enforces the Payment Authentication
/// envelope on the request.
///
/// Register with `axum::middleware::from_fn_with_state(state, require_charge)`
/// where `state` is `Arc<ChargeMiddlewareState<C>>`. The `'static` bound on
/// `C` is what axum's `from_fn_with_state` requires to spawn the handler
/// future.
pub async fn require_charge<C>(
    State(ctx): State<Arc<ChargeMiddlewareState<C>>>,
    mut req: Request,
    next: Next,
) -> Response
where
    C: Credential + Send + Sync + 'static,
{
    // Step 1: client must present an `Authorization: Payment <blob>`
    // header. Missing header or any non-`Payment` scheme is treated as
    // "no payment attempt" → 402 with a fresh challenge.
    let Some(header_raw) = req.headers().get(http::header::AUTHORIZATION) else {
        return challenge_response(&ctx.requirement, None);
    };

    // Step 2: header must be valid UTF-8. A non-UTF-8 value never
    // carries a valid Payment auth envelope, so it gets a 402
    // re-challenge.
    let header_value = match header_raw.to_str() {
        Ok(v) => v,
        Err(_) => {
            return challenge_response(
                &ctx.requirement,
                Some("invalid Authorization header encoding"),
            );
        }
    };

    // Step 3: parse the Payment Authentication envelope. `UnknownScheme`
    // means "the client used Basic/Bearer/whatever — they didn't try
    // Payment", which is identical from a control-flow perspective to
    // "no header at all". Every other parse error is a validation
    // failure and must be a 402 re-challenge.
    let credentials = match parse_payment_authorization(header_value) {
        Ok(c) => c,
        Err(AuthParseError::UnknownScheme) => {
            return challenge_response(&ctx.requirement, None);
        }
        Err(e) => return challenge_response(&ctx.requirement, Some(&e.to_string())),
    };

    // Step 4: verify + redeem the presented credential via the generic
    // `Credential` seam. The decoupled `ChargeRequirement` is derived from
    // the advertised cashu requirement. Decode/structural/swap failures all
    // surface as `ChargeError`; the contract's variant decides the status
    // (`MintUnreachable` → 503, `MalformedRequest` → 400, everything else →
    // 402 + re-challenge).
    let charge_req = charge_requirement_from_cashu(&ctx.requirement);
    let redeemed = match ctx
        .credential
        .verify_and_redeem(&credentials.payload.cashu_token, &charge_req)
        .await
    {
        Ok(r) => r,
        Err(e) => return charge_error_to_response(e, &ctx.requirement),
    };

    // Step 5: hand the redeemed result to downstream handlers. They can
    // extract it via `Extension<Redeemed>`. The verifier makes no change —
    // the holder presented the exact amount and is responsible for any local
    // split done before presentation.
    req.extensions_mut().insert(redeemed);
    next.run(req).await
}

/// Build a 402 response carrying a fresh Payment Authentication
/// challenge. Always emits `Cache-Control: no-store`.
///
/// `failure_reason`, when provided, becomes the response body — it
/// lets the client see why the previous attempt was rejected. A bare
/// "no attempt yet" 402 (the client never sent an `Authorization`
/// header) gets an empty body.
fn challenge_response(requirement: &CashuRequirement, failure_reason: Option<&str>) -> Response {
    // `id` must be a unique challenge identifier; a random UUIDv4
    // suffices. Stateless binding (computing `id` as an HMAC over the
    // challenge params) is a deliberate non-goal for v1.
    let id = Uuid::new_v4().to_string();

    let creq_a = encode_challenge(requirement);
    let request_envelope = encode_request_envelope(&creq_a);

    // TODO(operator-configurable): wire `realm` through middleware
    // state once an operator-side config story lands. A fixed
    // identifier is fine for v1.
    let realm = DEFAULT_REALM;

    let header = format!(
        r#"{} id="{}", realm="{}", method="cashu", intent="{}", request="{}""#,
        PAYMENT_SCHEME, id, realm, INTENT_CHARGE, request_envelope,
    );

    // All values produced above are base64url-nopad alphabet or
    // ASCII-printable. `HeaderValue::from_str` still validates as a
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

    let body = failure_reason.unwrap_or("").to_string();

    (
        StatusCode::PAYMENT_REQUIRED,
        [
            (http::header::WWW_AUTHENTICATE, www_auth),
            (http::header::CACHE_CONTROL, cache_control),
        ],
        body,
    )
        .into_response()
}

/// Map a [`ChargeError`] (the committed cross-slice contract) to an HTTP
/// response.
///
/// The contract's three non-collapsing concerns drive the status:
/// - `MintUnreachable` → `503 Service Unavailable` (transport; the client
///   keeps its token and may retry — NEVER a 402).
/// - `MalformedRequest` → `400 Bad Request` (framework status; the request
///   was not a well-formed payment attempt — e.g. a malformed server-side
///   requirement).
/// - every other (verification / malformed-credential) variant → `402
///   Payment Required` with a fresh `WWW-Authenticate: Payment` re-challenge.
///
/// The 402 body is the `ChargeError` Display string so the client can see
/// why the previous attempt was rejected. Every 402 carries
/// `Cache-Control: no-store` (via [`challenge_response`]).
fn charge_error_to_response(e: ChargeError, requirement: &CashuRequirement) -> Response {
    match &e {
        // (A) transport → 503, retryable, token NOT consumed.
        ChargeError::MintUnreachable { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response()
        }
        // (C) not a well-formed payment attempt at all → 400 framework status.
        ChargeError::MalformedRequest(_) => {
            (StatusCode::BAD_REQUEST, e.to_string()).into_response()
        }
        // (B + the rest of C) verification / malformed-credential → 402 +
        // fresh re-challenge.
        _ => challenge_response(requirement, Some(&e.to_string())),
    }
}

/// Pluck the echoed challenge fields out of a successfully-parsed
/// credentials blob. Surfaced for test helpers; the middleware itself
/// doesn't need to consult them past the `method` check that
/// [`parse_payment_authorization`] already did.
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
    use crate::credential::Redeemed;
    use crate::envelope::{encode_payment_credentials, CashuPayload, PaymentCredentials};
    use crate::mint_client::{MintClient, MintClientError};

    // ---- Mock MintClient (mirrors the validator's test helper) -------

    enum SwapResponse {
        Echo,
        Unreachable,
        /// A post-submit (indeterminate) swap transport failure — exercises the
        /// `MintUnreachable { indeterminate: true }` → 503 mapping end-to-end.
        UnreachableIndeterminate,
        RejectedSwap,
        /// Swap-output DLEQ gate rejected the mint's returned blind signatures
        /// (missing/invalid DLEQ). Drives the end-to-end money-safety path:
        /// must yield 402 + re-challenge with the resource NOT served.
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

    /// Construct an axum router with the middleware in front of a tiny
    /// echo handler. The handler returns 200 on success and writes the
    /// redeemed amount into the body so tests can assert the `Redeemed`
    /// result made it through the extensions.
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

    /// Wrap a raw `cashuB…` token in the Payment Authentication
    /// envelope, echoing a fake-but-shapely challenge. The middleware
    /// does not validate that `challenge.id` matches what it previously
    /// issued, so any well-formed echo works.
    fn payment_header_with_token(token: &str) -> String {
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "test-challenge-id".into(),
                realm: DEFAULT_REALM.into(),
                method: "cashu".into(),
                intent: INTENT_CHARGE.into(),
                request: "echoed-request-envelope".into(),
            },
            payload: CashuPayload {
                cashu_token: token.into(),
            },
        };
        format!("Payment {}", encode_payment_credentials(&creds))
    }

    /// Build a GET /gated request whose `Authorization` header is the
    /// Payment Authentication envelope around `token`.
    fn request_with_token(token: &str) -> HttpRequest<Body> {
        request_with_authorization(&payment_header_with_token(token))
    }

    /// Build a GET /gated request with raw header bytes (used for the
    /// non-utf8 test case).
    fn request_with_raw_authorization(value: &[u8]) -> HttpRequest<Body> {
        // `header()` rejects non-ASCII at builder time; reach down to
        // HeaderValue::from_bytes which accepts arbitrary bytes.
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
        // Cover all five required challenge fields.
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
        // Each required challenge field appears with a non-empty value.
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
        // Lock the default `realm` so an operator-configurable change
        // later is a visible diff. Doc-comment on DEFAULT_REALM
        // explains the operator-configurable plan.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);
        assert!(
            header.contains(r#"realm="pops-core-verify""#),
            "got: {header}"
        );
    }

    #[tokio::test]
    async fn www_authenticate_request_is_base64url_nopad_envelope() {
        // The `request` param's contents are base64url-nopad encoded
        // JSON `{ "cashu_request": "creqA..." }` — confirm the encoded
        // string round-trips back to a creqA payload.
        use crate::envelope::decode_request_envelope;
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        let header = www_authenticate(&response);
        let start = header.find(r#"request=""#).expect("has request param");
        let after = &header[start + r#"request=""#.len()..];
        let end = after.find('"').expect("terminated request param");
        let request_value = &after[..end];
        let creq_a = decode_request_envelope(request_value).expect("decodes envelope");
        assert!(
            creq_a.starts_with("creqA"),
            "envelope must wrap a creqA payload, got: {creq_a}"
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
        // The middleware does not enforce challenge-id binding, but the
        // round-trip must work: we hand the server a credentials blob
        // with our test id, get 200, and the handler runs.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "echoed-id-from-client".into(),
                realm: DEFAULT_REALM.into(),
                method: "cashu".into(),
                intent: INTENT_CHARGE.into(),
                request: "echoed-request".into(),
            },
            payload: CashuPayload {
                cashu_token: encoded,
            },
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
        // 0xFF is not valid UTF-8.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_raw_authorization(&[0xFFu8, 0xFE, 0xFD]))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        // Must come with a fresh re-challenge.
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
        // A structurally-OK but unit-mismatched token must come back as
        // 402 + re-challenge, NOT 400.
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        // Fresh challenge present.
        let header = www_authenticate(&response);
        assert!(header.contains(r#"method="cashu""#));
        // Cache-Control still no-store.
        assert_eq!(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .expect("Cache-Control")
                .to_str()
                .unwrap(),
            "no-store"
        );
        // Body explains the failure.
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
        // Transport failure: stays as 503 per the comments on
        // validation_error_to_response.
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
        // Swap rejected (expired, double-spent, etc.) is a *validation*
        // failure — 402 with a fresh re-challenge so the client can try
        // a different proof.
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
        // Money-safety end-to-end: the mint returned blind signatures whose
        // DLEQ is missing/invalid, the swap-output gate rejected them, and that
        // maps to ChargeError::DleqInvalid → 402 + fresh re-challenge. The
        // gated handler MUST NOT run (no `ok:` body), so a malicious/buggy mint
        // never gets the resource served against unsigned ecash.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let encoded = token.to_string();

        let app = router_with(state_with(SwapResponse::DleqInvalid));
        let response = app
            .oneshot(request_with_token(&encoded))
            .await
            .expect("oneshot");

        // Verification failure (not transport): 402, NOT 503/200.
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        // A fresh re-challenge is present.
        assert!(response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .is_some());

        let body_bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        let body = std::str::from_utf8(&body_bytes).unwrap_or("<non-utf8 body>");
        // The handler never ran — the gated resource was NOT served.
        assert!(
            !body.starts_with("ok:"),
            "gated resource must NOT be served on a DLEQ failure, got: {body}"
        );
        // The failure reason names the DLEQ problem.
        assert!(
            body.to_ascii_lowercase().contains("dleq"),
            "expected a DLEQ failure message, got: {body}"
        );
    }

    #[tokio::test]
    async fn locked_proof_returns_402_and_does_not_serve_resource() {
        // A NUT-10 P2PK-locked proof is a verification failure (LockedToken) →
        // 402 + fresh re-challenge; the swap is never attempted and the gated
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
        // A 3-proof token against a credential capped at 2 → TooManyProofs →
        // 402; swap not attempted, handler not run.
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
        // An indeterminate swap-POST transport failure maps to MintUnreachable
        // { indeterminate: true } → still 503 at the HTTP layer (the
        // indeterminate flag never changes status, only the operator's
        // checkstate obligation). Drive it through the real ceremony by stubbing
        // the mock at MintHttp::post_swap level is overkill here; instead the
        // validator-level mock returns the indeterminate error directly.
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
        // An unsupported scheme is identical to no attempt. Body should
        // be empty (no failure to describe).
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
        // The `method="cashu", token="..."` param form is not accepted —
        // base64 decode trips → 402 re-challenge.
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
    async fn wrong_method_returns_402() {
        // `Payment` scheme + valid envelope + `method="tempo"` →
        // validation failure → 402 re-challenge.
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "id".into(),
                realm: "r".into(),
                method: "tempo".into(),
                intent: "charge".into(),
                request: "r".into(),
            },
            payload: CashuPayload {
                cashu_token: "cashuBabc".into(),
            },
        };
        let header = format!("Payment {}", encode_payment_credentials(&creds));

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
            body.contains("must be 'cashu'"),
            "expected wrong-method message, got: {body}"
        );
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
        // Present exactly the required amount (8+2 = 10) → 200 OK, body
        // reports the full 10 the verifier swapped. The verifier makes no
        // change, so no change header exists to assert against.
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
        // Present 16+4 = 20 against a requirement of 10. The charge is
        // exact-amount: the verifier does NOT make change — it rejects the
        // over-funded token with a 402 re-challenge. The holder must split
        // down to exactly 10 locally before presenting.
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
        // Fresh re-challenge present.
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
        // Present 8 against a requirement of 10 — under the exact amount.
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
