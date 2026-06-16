//! `draft-cashu-charge-00` wire-conformance tests, driving only the public API
//! (a separate crate sees the same surface a consumer does).
//!
//! Covers the conformance bar this build raises: the spec request-object
//! round-trip + JCS-canonical bytes (`methodDetails.paymentRequest` only, mints
//! gone from the wire); the emitted creqA carrying `a`/`u`/non-empty-`m`; the
//! credential echo carrying the optional `digest`/`opaque`/`expires`/`source`;
//! and — driving the `require_charge` (and `require_charge_xcashu`) middleware
//! through a router with a canned [`Redeemer`] — the `Payment-Receipt` shape +
//! `Cache-Control: private` on 200, an echoed `challenge.expires` in the past →
//! `payment-expired` `application/problem+json`, each [`ChargeError`] mapping
//! to its ABSOLUTE spec problem-type URI + status, and both in-crate hosts
//! emitting identical mappings. The money core is NOT exercised here (it is
//! unchanged); the canned redeemer stands in so the test isolates the WIRE.

use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cashu::{Amount, CurrencyUnit, MintUrl};
use http::{header::AUTHORIZATION, Request, StatusCode};
use tower::ServiceExt;

use pops_core_verify::charge::{ChargeError, RedeemedProofs};
use pops_core_verify::challenge::{
    decode_charge_request, encode_challenge, encode_charge_request, CashuRequirement,
};
use pops_core_verify::envelope::{
    decode_request_object, encode_payment_credentials, encode_request_object,
    parse_payment_authorization, parse_payment_params, CashuPayload, EchoedChallenge,
    MethodDetails, PaymentCredentials, RequestObject,
};
use pops_core_verify::middleware::{require_charge, ChargeMiddlewareState};
use pops_core_verify::redeemer::{ChargeRequirement, Redeemed, Redeemer};

// ─────────────────────────── fixtures ───────────────────────────────────────

fn pop_unit() -> CurrencyUnit {
    CurrencyUnit::Custom("pop_1782668279".to_string())
}

fn mint_a() -> MintUrl {
    MintUrl::from_str("https://mint.example").expect("valid mint url")
}

fn requirement() -> CashuRequirement {
    CashuRequirement {
        unit: pop_unit(),
        mints: vec![mint_a()],
        amount: Amount::from(100),
        external_id: Some("inv-42".to_string()),
        description: Some("read access".to_string()),
    }
}

// ───────────────────── canned Redeemer (isolates the wire) ───────────────────

/// A [`Redeemer`] whose outcome is fixed up front, so the middleware tests
/// exercise the ENVELOPE/emission, never the money core.
enum Outcome {
    /// Redeem succeeds, returning a canned `Redeemed` worth `amount`.
    Ok { amount: u64, unit: String },
    /// Redeem fails with the given error (the variant under test).
    Err(fn() -> ChargeError),
}

struct CannedRedeemer {
    outcome: Outcome,
}

#[async_trait::async_trait]
impl Redeemer for CannedRedeemer {
    async fn verify_and_redeem(
        &self,
        presented: &str,
        _req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError> {
        match &self.outcome {
            Outcome::Ok { amount, unit } => Ok(Redeemed {
                unit: unit.clone(),
                amount: *amount,
                proofs: RedeemedProofs {
                    fresh_proofs: "cashuBcanned".to_string(),
                    amount: *amount,
                    unit: unit.clone(),
                    active_keyset_id: "009a1f293253e41e".to_string(),
                    // A stable, recognizable settlement reference for the receipt.
                    token_hash: format!("hash-of-{}", presented.len()),
                },
                dleq_ok: true,
            }),
            Outcome::Err(make) => Err(make()),
        }
    }
}

/// A router that gates an echo handler behind `require_charge` with the canned
/// redeemer.
fn router(outcome: Outcome) -> Router {
    router_with_ttl(outcome, None)
}

/// As [`router`] with an explicit challenge TTL (for the expiry tests).
fn router_with_ttl(outcome: Outcome, ttl: Option<std::time::Duration>) -> Router {
    async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
        format!("ok:{}", redeemed.amount)
    }
    let mut state = ChargeMiddlewareState::new(requirement(), CannedRedeemer { outcome });
    if let Some(ttl) = ttl {
        state = state.with_challenge_ttl(ttl);
    }
    Router::new()
        .route("/gated", get(echo))
        .layer(from_fn_with_state(
            Arc::new(state),
            require_charge::<CannedRedeemer>,
        ))
}

/// Fetch a REAL challenge off the router (bare request → 402) and parse its
/// auth-params.
async fn fetch_challenge(app: &Router) -> pops_core_verify::envelope::PaymentParams {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/gated")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("challenge fetch");
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let header = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate present")
        .to_str()
        .expect("ASCII")
        .to_string();
    parse_payment_params(&header).expect("challenge params parse")
}

/// Build the `Authorization: Payment` header echoing `params` verbatim around
/// `token` — the faithful client half of the dance.
fn auth_header_for(
    params: &pops_core_verify::envelope::PaymentParams,
    token: &str,
) -> String {
    let creds = PaymentCredentials {
        challenge: EchoedChallenge {
            id: params.id.clone(),
            realm: params.realm.clone(),
            method: params.method.clone(),
            intent: params.intent.clone(),
            request: params.request.clone(),
            digest: params.digest.clone(),
            opaque: params.opaque.clone(),
            expires: params.expires.clone(),
            description: params.description.clone(),
        },
        payload: CashuPayload {
            token: token.into(),
        },
        source: None,
    };
    format!("Payment {}", encode_payment_credentials(&creds))
}

fn body_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("body is JSON")
}

// ──────────────────── request object (spec Request Schema + Encoding) ────────

#[test]
fn spec_request_object_round_trips_and_is_jcs_canonical() {
    // requirement → 402 request param → decoded amount/unit/mints + creqA.
    let request = encode_charge_request(&requirement()).expect("requirement encodes");

    let decoded = decode_charge_request(&request).expect("request object decodes");
    assert_eq!(decoded.amount, Amount::from(100));
    assert_eq!(decoded.unit, pop_unit());
    assert_eq!(decoded.mints, vec![mint_a()], "mints derive from the creqA `m`");
    assert_eq!(decoded.external_id.as_deref(), Some("inv-42"));
    assert!(decoded.creq_a.starts_with("creqA"));

    // The base64url-nopad payload is the JCS-canonical bytes: keys sorted at both
    // levels, ECMAScript number/string forms, no insignificant whitespace, and
    // methodDetails carrying exactly ONE field — paymentRequest. (Expected JSON
    // hand-written from the spec's Request Schema example.)
    let obj = decode_request_object(&request).expect("request object struct");
    let bytes = URL_SAFE_NO_PAD.decode(&request).expect("base64url decodes");
    let json = std::str::from_utf8(&bytes).expect("utf8");
    let expected = format!(
        r#"{{"amount":"100","currency":"pop_1782668279","description":"read access","externalId":"inv-42","methodDetails":{{"paymentRequest":"{}"}}}}"#,
        obj.method_details.payment_request
    );
    assert_eq!(json, expected, "request object must be JCS-canonical");
    assert!(
        !json.contains("\"mints\""),
        "methodDetails.mints is deleted from the wire: {json}"
    );

    // It is base64url-nopad (no '+', '/', '=').
    for c in request.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "non-base64url char {c:?} in {request}"
        );
    }
}

#[test]
fn emitted_creqa_carries_amount_unit_and_nonempty_mints() {
    // Spec Method Details: the server MUST encode `a` and `u` and MUST populate
    // `m` with a non-empty mint set; transports MUST be empty; nut10 MUST be
    // absent. Decode the emitted creqA independently and check each.
    use cashu::nuts::nut18::PaymentRequest;
    use std::str::FromStr as _;

    let request = encode_charge_request(&requirement()).expect("requirement encodes");
    let obj = decode_request_object(&request).expect("request object struct");
    let creq = PaymentRequest::from_str(&obj.method_details.payment_request)
        .expect("paymentRequest is a parseable creqA");

    assert_eq!(creq.amount, Some(Amount::from(100)), "creqA carries `a`");
    assert_eq!(creq.unit, Some(pop_unit()), "creqA carries `u`");
    assert_eq!(creq.mints, vec![mint_a()], "creqA carries a non-empty `m`");
    assert!(creq.transports.is_empty(), "transport set must be empty (in-band)");
    assert!(creq.nut10.is_none(), "bearer profile: nut10 must be absent");
}

#[test]
fn requirement_without_mints_cannot_be_emitted() {
    // Emit-side a/u/m enforcement: `m` must be non-empty, so a no-mints
    // requirement fails at encode (server misconfiguration, caught early).
    let mut req = requirement();
    req.mints = vec![];
    assert!(
        encode_charge_request(&req).is_err(),
        "a requirement naming no mints must not encode into a challenge"
    );
}

#[test]
fn request_object_rejects_top_level_fields_disagreeing_with_creqa() {
    // The creqA is authoritative; top-level amount/currency must match it
    // (amounts compared as integers). Hand-build a disagreeing object.
    let creq = encode_challenge(&requirement()); // a=100, u=pop_1782668279
    for (amount, currency) in [("101", "pop_1782668279"), ("100", "sat")] {
        let object = RequestObject {
            amount: amount.into(),
            currency: currency.into(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                payment_request: creq.clone(),
            },
        };
        let encoded = encode_request_object(&object);
        assert!(
            decode_charge_request(&encoded).is_err(),
            "amount/currency disagreeing with the creqA must be rejected \
             (amount={amount}, currency={currency})"
        );
    }
}

// ──────────────────── credential echo with optional fields ──────────────────

#[test]
fn credential_echo_round_trips_optional_fields() {
    let creds = PaymentCredentials {
        challenge: EchoedChallenge {
            id: "id".into(),
            realm: "r".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "req".into(),
            digest: Some("sha-256-digest".into()),
            opaque: Some("server-opaque".into()),
            expires: Some("2999-01-01T00:00:00Z".into()),
            description: Some("weather report".into()),
        },
        payload: CashuPayload {
            token: "cashuBtok".into(),
        },
        source: Some("did:example:abc".into()),
    };
    let header = format!("Payment {}", encode_payment_credentials(&creds));
    let parsed = parse_payment_authorization(&header).expect("parses");
    assert_eq!(parsed.challenge.digest.as_deref(), Some("sha-256-digest"));
    assert_eq!(parsed.challenge.opaque.as_deref(), Some("server-opaque"));
    assert_eq!(
        parsed.challenge.expires.as_deref(),
        Some("2999-01-01T00:00:00Z")
    );
    assert_eq!(parsed.source.as_deref(), Some("did:example:abc"));
    assert_eq!(parsed.payload.token, "cashuBtok");
}

// ──────────────────────── Payment-Receipt (D-5) ──────────────────────────────

#[tokio::test]
async fn success_emits_payment_receipt_and_cache_control_private() {
    let app = router(Outcome::Ok {
        amount: 100,
        unit: "pop_1782668279".to_string(),
    });
    let params = fetch_challenge(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header_for(&params, "cashuBany"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Cache-Control: private on the 200 (draft-cashu-charge-00 §Receipt).
    assert_eq!(
        resp.headers()
            .get(http::header::CACHE_CONTROL)
            .expect("Cache-Control on 200")
            .to_str()
            .unwrap(),
        "private"
    );

    // Payment-Receipt: base64url-nopad JSON with the spec shape.
    let receipt_raw = resp
        .headers()
        .get("payment-receipt")
        .expect("Payment-Receipt header present")
        .to_str()
        .unwrap()
        .to_string();
    let receipt_bytes = URL_SAFE_NO_PAD
        .decode(&receipt_raw)
        .expect("Payment-Receipt is base64url-nopad");
    let receipt = body_json(&receipt_bytes);
    assert_eq!(receipt["method"], "cashu");
    assert_eq!(
        receipt["challengeId"], params.id,
        "receipt echoes the issued (HMAC-bound) challenge id"
    );
    assert_eq!(receipt["status"], "success");
    assert!(
        receipt["reference"].as_str().unwrap().starts_with("hash-of-"),
        "reference is the token_hash, got {receipt}"
    );
    assert!(
        receipt["timestamp"].is_string(),
        "receipt carries an RFC-3339 timestamp"
    );
    // externalId echoes the issuance correlation id (the requirement's).
    assert_eq!(receipt["externalId"], "inv-42");

    // The gated resource WAS served.
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    assert_eq!(&body[..], b"ok:100");
}

#[tokio::test]
async fn downstream_error_after_settlement_carries_no_receipt() {
    // Spec receipt §: the receipt rides the 200 and MUST NOT appear on error
    // responses — a handler that 500s after a successful redeem answers
    // without `Payment-Receipt` (and without the receipt's
    // `Cache-Control: private`).
    use axum::response::IntoResponse;
    async fn failing(Extension(_redeemed): Extension<Redeemed>) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, "downstream boom").into_response()
    }
    let state = ChargeMiddlewareState::new(
        requirement(),
        CannedRedeemer {
            outcome: Outcome::Ok {
                amount: 100,
                unit: "pop_1782668279".to_string(),
            },
        },
    );
    let app = Router::new()
        .route("/gated", get(failing))
        .layer(from_fn_with_state(
            Arc::new(state),
            require_charge::<CannedRedeemer>,
        ));

    let params = fetch_challenge(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header_for(&params, "cashuBany"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        resp.headers().get("payment-receipt").is_none(),
        "no Payment-Receipt on an error response"
    );
    assert_ne!(
        resp.headers()
            .get(http::header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap_or_default()),
        Some("private"),
        "the receipt's Cache-Control: private must not ride an error response"
    );
}

// ─────────────────── challenge.expires in the past (D-6) ──────────────────────

#[tokio::test]
async fn expired_echoed_challenge_returns_payment_expired_problem() {
    // A zero-TTL router issues authentic-but-instantly-stale challenges: the
    // faithful echo passes the HMAC, fails freshness → payment-expired BEFORE
    // any redeem (the canned redeemer is Ok, so a 402 proves it never ran).
    let app = router_with_ttl(
        Outcome::Ok {
            amount: 100,
            unit: "pop_1782668279".to_string(),
        },
        Some(std::time::Duration::ZERO),
    );
    let params = fetch_challenge(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header_for(&params, "cashuBany"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json"
    );
    // A 402 still re-challenges.
    assert!(resp.headers().get(http::header::WWW_AUTHENTICATE).is_some());
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem = body_json(&body);
    assert_eq!(
        problem["type"],
        "https://paymentauth.org/problems/payment-expired"
    );
    assert_eq!(problem["status"], 402);
}

#[tokio::test]
async fn unexpired_echoed_challenge_passes_through() {
    // The fresh-challenge pass: a faithful echo of an unexpired challenge
    // (default 300 s TTL) reaches the redeemer and serves.
    let app = router(Outcome::Ok {
        amount: 100,
        unit: "pop_1782668279".to_string(),
    });
    let params = fetch_challenge(&app).await;
    assert!(params.expires.is_some(), "stateless challenge carries expires");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header_for(&params, "cashuBany"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─────────────── each ChargeError → its problem-type + status ────────────────

/// Drive the `Payment` middleware with a canned error and return
/// (status, problem json). The full dance: fetch a real challenge, echo it
/// faithfully (passing the binding), and let the canned redeemer fail.
async fn problem_for(make: fn() -> ChargeError) -> (StatusCode, serde_json::Value) {
    let app = router(Outcome::Err(make));
    let params = fetch_challenge(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header_for(&params, "cashuBany"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    // Every error body is application/problem+json.
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json",
        "error body must be problem+json (status {status})"
    );
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    (status, body_json(&body))
}

/// Drive the NUT-24 `X-Cashu` middleware with the same canned error and return
/// (status, problem json) — the cross-surface comparison arm.
async fn xcashu_problem_for(make: fn() -> ChargeError) -> (StatusCode, serde_json::Value) {
    use pops_core_verify::middleware_xcashu::require_charge_xcashu;
    async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
        format!("ok:{}", redeemed.amount)
    }
    let state = Arc::new(ChargeMiddlewareState::new(
        requirement(),
        CannedRedeemer {
            outcome: Outcome::Err(make),
        },
    ));
    let app = Router::new().route("/gated", get(echo)).layer(from_fn_with_state(
        state,
        require_charge_xcashu::<CannedRedeemer>,
    ));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header("x-cashu", "cashuBany")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json",
        "X-Cashu error body must be problem+json (status {status})"
    );
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    (status, body_json(&body))
}

/// Every wire-distinct [`ChargeError`] case (the canned constructors the
/// surface-equality tests iterate).
fn all_charge_error_cases() -> Vec<fn() -> ChargeError> {
    vec![
        || ChargeError::MintUnreachable {
            mint_url: "https://mint.example".into(),
            transport_detail: "timeout".into(),
            indeterminate: false,
        },
        || ChargeError::PaymentInsufficient {
            required: 100,
            presented: 90,
            amount: 100,
            expected_swap_fee: 0,
        },
        || ChargeError::WrongUnit {
            expected: "pop_1782668279".into(),
            got: "sat".into(),
        },
        || ChargeError::MintNotAllowed {
            got: "https://evil.example".into(),
            allowed: vec!["https://mint.example".into()],
        },
        || ChargeError::MintUrlUserinfo {
            url: "https://user@mint.example".into(),
        },
        || ChargeError::LockedToken,
        || ChargeError::FeeTooHigh {
            keyset_id: "009a1f293253e41e".into(),
            input_fee_ppk: 100,
        },
        || ChargeError::ShortKeysetIdUnresolved {
            short_id: "00aabbccddeeff00".into(),
        },
        || ChargeError::DoubleSpend,
        || ChargeError::SwapRejected("mint said no".into()),
        || ChargeError::Expired,
        || ChargeError::ChallengeExpired,
        || ChargeError::InvalidChallenge,
        || ChargeError::MalformedCredential("bad".into()),
        || ChargeError::TooManyProofs { got: 99, max: 8 },
        || ChargeError::MethodUnsupported {
            method: "tempo".into(),
        },
        || ChargeError::MalformedRequest("bad config".into()),
    ]
}

#[tokio::test]
async fn charge_errors_map_to_spec_problem_types_and_statuses() {
    // (ABSOLUTE problem-type URI, HTTP status) per draft-cashu-charge-00
    // §Errors + the framework's status table. The method defines NO problem
    // types of its own: mint unreachability is a plain 503 (about:blank body,
    // no custom URI) and an under-funded token is the framework's
    // payment-insufficient; MalformedRequest is a 400 with NO registered type
    // (about:blank), never the invalid-challenge slug; a non-"cashu" method is
    // the framework's method-unsupported 400.
    type ErrorCase = (fn() -> ChargeError, &'static str, u16);
    let cases: Vec<ErrorCase> = vec![
        (
            || ChargeError::MintUnreachable {
                mint_url: "https://mint.example".into(),
                transport_detail: "timeout".into(),
                indeterminate: false,
            },
            "about:blank",
            503,
        ),
        (
            || ChargeError::PaymentInsufficient {
                required: 100,
                presented: 90,
                amount: 100,
                expected_swap_fee: 0,
            },
            "https://paymentauth.org/problems/payment-insufficient",
            402,
        ),
        (
            || ChargeError::WrongUnit {
                expected: "pop_1782668279".into(),
                got: "sat".into(),
            },
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::MintNotAllowed {
                got: "https://evil.example".into(),
                allowed: vec!["https://mint.example".into()],
            },
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::MintUrlUserinfo {
                url: "https://user@mint.example".into(),
            },
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::LockedToken,
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::FeeTooHigh {
                keyset_id: "009a1f293253e41e".into(),
                input_fee_ppk: 100,
            },
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::ShortKeysetIdUnresolved {
                short_id: "00aabbccddeeff00".into(),
            },
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::DoubleSpend,
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::SwapRejected("mint said no".into()),
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::Expired,
            "https://paymentauth.org/problems/verification-failed",
            402,
        ),
        (
            || ChargeError::ChallengeExpired,
            "https://paymentauth.org/problems/payment-expired",
            402,
        ),
        (
            || ChargeError::InvalidChallenge,
            "https://paymentauth.org/problems/invalid-challenge",
            402,
        ),
        (
            || ChargeError::MalformedCredential("bad".into()),
            "https://paymentauth.org/problems/malformed-credential",
            402,
        ),
        (
            || ChargeError::TooManyProofs { got: 99, max: 8 },
            "https://paymentauth.org/problems/malformed-credential",
            402,
        ),
        (
            || ChargeError::MethodUnsupported {
                method: "tempo".into(),
            },
            "https://paymentauth.org/problems/method-unsupported",
            400,
        ),
        (
            || ChargeError::MalformedRequest("bad config".into()),
            "about:blank",
            400,
        ),
    ];

    for (make, problem_type, status) in cases {
        let (got_status, problem) = problem_for(make).await;
        assert_eq!(
            got_status.as_u16(),
            status,
            "{problem_type}: expected status {status}, got {got_status}"
        );
        assert_eq!(
            problem["type"], problem_type,
            "expected problem-type {problem_type}, got {problem}"
        );
        assert_eq!(
            problem["status"], status,
            "problem `status` member must mirror the HTTP status"
        );
        assert!(problem["title"].is_string(), "problem carries a title");
        assert!(problem["detail"].is_string(), "problem carries a detail");
    }
}

#[tokio::test]
async fn payment_and_xcashu_surfaces_emit_identical_mappings() {
    // The single-source guarantee, observed END-TO-END: for every ChargeError,
    // both in-crate hosts answer with the same (status, type, title, status
    // member) — and both equal the shared problem_mapping table the gateway
    // and wasm surfaces also consume.
    use pops_core_verify::problem::problem_mapping;
    for make in all_charge_error_cases() {
        let mapping = problem_mapping(&make());
        let (payment_status, payment_problem) = problem_for(make).await;
        let (xcashu_status, xcashu_problem) = xcashu_problem_for(make).await;

        assert_eq!(
            payment_status, xcashu_status,
            "status drift between Payment and X-Cashu hosts for {}",
            make()
        );
        assert_eq!(
            payment_problem, xcashu_problem,
            "problem-body drift between Payment and X-Cashu hosts for {}",
            make()
        );
        assert_eq!(payment_status.as_u16(), mapping.status, "{}", make());
        assert_eq!(payment_problem["type"], mapping.type_uri, "{}", make());
        assert_eq!(payment_problem["title"], mapping.title, "{}", make());
        assert_eq!(payment_problem["status"], mapping.status, "{}", make());
    }
}

#[tokio::test]
async fn mint_unreachable_is_503_with_no_store_never_a_402() {
    // The load-bearing invariant: a transport failure is a 503 (token NOT
    // consumed), NEVER collapsed into a 402 — and per the spec's Errors § it
    // carries NO problem type (about:blank body, no cashu/ URI).
    let (status, problem) = problem_for(|| ChargeError::MintUnreachable {
        mint_url: "https://mint.example".into(),
        transport_detail: "connect refused".into(),
        indeterminate: false,
    })
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem["type"], "about:blank");
}

// ─────────────────── bare 402 (no attempt) has no problem body ───────────────

#[tokio::test]
async fn bare_request_is_402_challenge_with_spec_request_object() {
    let app = router(Outcome::Ok {
        amount: 100,
        unit: "pop_1782668279".to_string(),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        resp.headers()
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    // The challenge's `request` param decodes as the spec request object.
    let www = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let params = parse_payment_params(&www).expect("parses params");
    let decoded = decode_charge_request(&params.request).expect("request object decodes");
    assert_eq!(decoded.amount, Amount::from(100));
    assert_eq!(decoded.mints, vec![mint_a()]);
    // No attempt → empty body (not a problem).
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    assert!(body.is_empty(), "bare 402 has no body, got {body:?}");
}
