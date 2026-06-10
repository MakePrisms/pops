//! `draft-cashu-charge-01` wire-conformance tests, driving only the public API
//! (a separate crate sees the same surface a consumer does).
//!
//! Covers the conformance bar this build raises: the spec request-object
//! round-trip + JCS-canonical bytes; the credential echo carrying the optional
//! `digest`/`opaque`/`expires`/`source`; the `methodDetails.mints` superset
//! rejection; and — driving the `require_charge` middleware through a router with
//! a canned [`Redeemer`] — the `Payment-Receipt` shape + `Cache-Control:
//! private` on 200, an echoed `challenge.expires` in the past → `payment-expired`
//! `application/problem+json`, and each [`ChargeError`] mapping to its spec
//! problem-type + status. The money core is NOT exercised here (it is unchanged);
//! the canned redeemer stands in so the test isolates the WIRE.

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
        payment_id: Some("inv-42".to_string()),
        description: Some("read access".to_string()),
        single_use: true,
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
            }),
            Outcome::Err(make) => Err(make()),
        }
    }
}

/// A router that gates an echo handler behind `require_charge` with the canned
/// redeemer.
fn router(outcome: Outcome) -> Router {
    async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
        format!("ok:{}", redeemed.amount)
    }
    let state = Arc::new(ChargeMiddlewareState::new(
        requirement(),
        CannedRedeemer { outcome },
    ));
    Router::new()
        .route("/gated", get(echo))
        .layer(from_fn_with_state(state, require_charge::<CannedRedeemer>))
}

/// Build an `Authorization: Payment` header around a token with a shapely echoed
/// challenge; `expires` rides the echo when supplied.
fn auth_header(token: &str, expires: Option<&str>) -> String {
    let creds = PaymentCredentials {
        challenge: EchoedChallenge {
            id: "ch-conf".into(),
            realm: "pops-core-verify".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "echoed-request".into(),
            digest: None,
            opaque: None,
            expires: expires.map(str::to_string),
        },
        payload: CashuPayload {
            cashu_token: token.into(),
        },
        source: None,
    };
    format!("Payment {}", encode_payment_credentials(&creds))
}

fn body_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("body is JSON")
}

// ──────────────────── request object (D-3 / D-4 / D-8 mints) ─────────────────

#[test]
fn spec_request_object_round_trips_and_is_jcs_canonical() {
    // requirement → 402 request param → decoded amount/unit/mints + creqA.
    let request = encode_charge_request(&requirement());

    let decoded = decode_charge_request(&request).expect("request object decodes");
    assert_eq!(decoded.amount, Amount::from(100));
    assert_eq!(decoded.unit, pop_unit());
    assert_eq!(decoded.mints, vec![mint_a()]);
    assert_eq!(decoded.external_id.as_deref(), Some("inv-42"));
    assert!(decoded.creq_a.starts_with("creqA"));

    // The base64url-nopad payload is the JCS-canonical bytes: keys sorted at both
    // levels, ECMAScript number/string forms, no insignificant whitespace.
    let obj = decode_request_object(&request).expect("request object struct");
    let bytes = URL_SAFE_NO_PAD.decode(&request).expect("base64url decodes");
    let json = std::str::from_utf8(&bytes).expect("utf8");
    let expected = format!(
        r#"{{"amount":"100","currency":"pop_1782668279","description":"read access","externalId":"inv-42","methodDetails":{{"mints":["https://mint.example"],"request":"{}"}}}}"#,
        obj.method_details.request
    );
    assert_eq!(json, expected, "request object must be JCS-canonical");

    // It is base64url-nopad (no '+', '/', '=').
    for c in request.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "non-base64url char {c:?} in {request}"
        );
    }
}

#[test]
fn request_object_rejects_mints_subset() {
    // The creqA names mint.example; methodDetails names a DIFFERENT mint only, so
    // it is not a superset → reject (draft-cashu-charge-01 §Request Schema).
    let creq = encode_challenge(&requirement());
    let object = RequestObject {
        amount: "100".into(),
        currency: "pop_1782668279".into(),
        description: None,
        external_id: None,
        method_details: MethodDetails {
            request: creq,
            mints: vec!["https://other.example".into()],
        },
    };
    let encoded = encode_request_object(&object);
    assert!(
        decode_charge_request(&encoded).is_err(),
        "a mints-subset request object must be rejected"
    );
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
        },
        payload: CashuPayload {
            cashu_token: "cashuBtok".into(),
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
    assert_eq!(parsed.payload.cashu_token, "cashuBtok");
}

// ──────────────────────── Payment-Receipt (D-5) ──────────────────────────────

#[tokio::test]
async fn success_emits_payment_receipt_and_cache_control_private() {
    let app = router(Outcome::Ok {
        amount: 100,
        unit: "pop_1782668279".to_string(),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header("cashuBany", None))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Cache-Control: private on the 200 (draft-cashu-charge-01 §Receipt).
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
    assert_eq!(receipt["challengeId"], "ch-conf");
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

// ─────────────────── challenge.expires in the past (D-6) ──────────────────────

#[tokio::test]
async fn expired_echoed_challenge_returns_payment_expired_problem() {
    // An echoed `expires` in the PAST → payment-expired, BEFORE any redeem. The
    // canned redeemer is set to Ok so a 402 here proves the swap never ran.
    let app = router(Outcome::Ok {
        amount: 100,
        unit: "pop_1782668279".to_string(),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(
                    AUTHORIZATION,
                    auth_header("cashuBany", Some("2000-01-01T00:00:00Z")),
                )
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
    assert_eq!(problem["type"], "cashu/payment-expired");
    assert_eq!(problem["status"], 402);
}

#[tokio::test]
async fn unexpired_echoed_challenge_passes_through() {
    // A future `expires` does NOT block the success path.
    let app = router(Outcome::Ok {
        amount: 100,
        unit: "pop_1782668279".to_string(),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(
                    AUTHORIZATION,
                    auth_header("cashuBany", Some("2999-01-01T00:00:00Z")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─────────────── each ChargeError → its problem-type + status ────────────────

/// Drive the middleware with a canned error and return (status, problem json).
async fn problem_for(make: fn() -> ChargeError) -> (StatusCode, serde_json::Value) {
    let app = router(Outcome::Err(make));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/gated")
                .header(AUTHORIZATION, auth_header("cashuBany", None))
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

#[tokio::test]
async fn charge_errors_map_to_spec_problem_types_and_statuses() {
    // (problem-type, HTTP status) per draft-cashu-charge-01 §Errors.
    type ErrorCase = (fn() -> ChargeError, &'static str, u16);
    let cases: Vec<ErrorCase> = vec![
        (
            || ChargeError::MintUnreachable {
                mint_url: "https://mint.example".into(),
                transport_detail: "timeout".into(),
                indeterminate: false,
            },
            "cashu/mint-unavailable",
            503,
        ),
        (
            || ChargeError::AmountMismatch {
                required: 100,
                presented: 90,
                amount: 100,
                expected_swap_fee: 0,
            },
            "cashu/amount-mismatch",
            402,
        ),
        (
            || ChargeError::WrongUnit {
                expected: "pop_1782668279".into(),
                got: "sat".into(),
            },
            "cashu/verification-failed",
            402,
        ),
        (
            || ChargeError::MintNotAllowed {
                got: "https://evil.example".into(),
                allowed: vec!["https://mint.example".into()],
            },
            "cashu/verification-failed",
            402,
        ),
        (|| ChargeError::MultiMintOrUnit, "cashu/verification-failed", 402),
        (|| ChargeError::LockedToken, "cashu/verification-failed", 402),
        (
            || ChargeError::DleqInvalid,
            "cashu/verification-failed",
            402,
        ),
        (|| ChargeError::DoubleSpend, "cashu/verification-failed", 402),
        (|| ChargeError::Expired, "cashu/payment-expired", 402),
        (|| ChargeError::ChallengeExpired, "cashu/payment-expired", 402),
        (
            || ChargeError::InvalidChallenge,
            "cashu/invalid-challenge",
            402,
        ),
        (
            || ChargeError::MalformedCredential("bad".into()),
            "cashu/malformed-credential",
            402,
        ),
        (
            || ChargeError::TooManyProofs { got: 99, max: 8 },
            "cashu/malformed-credential",
            402,
        ),
        (
            || ChargeError::MalformedRequest("bad config".into()),
            "cashu/invalid-challenge",
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
async fn mint_unreachable_is_503_with_no_store_never_a_402() {
    // The load-bearing invariant: a transport failure is a 503 (token NOT
    // consumed), NEVER collapsed into a 402.
    let (status, problem) = problem_for(|| ChargeError::MintUnreachable {
        mint_url: "https://mint.example".into(),
        transport_detail: "connect refused".into(),
        indeterminate: false,
    })
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem["type"], "cashu/mint-unavailable");
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
