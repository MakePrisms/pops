//! Black-box integration tests for the NUT-24 `X-Cashu` HTTP transport,
//! driving the public [`require_charge_xcashu`] middleware through an
//! `axum::Router` over a mock [`MintClient`]. Covers the value-safety matrix:
//! the `402` challenge shape, the happy path, exact-amount rejection (over- and
//! under-pay), unit/mint/DLEQ/double-spend rejections (resource never served),
//! the cashuB-only rule, malformed input, and the load-bearing
//! mint-unreachable → `503` (token NOT consumed) rule.

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::middleware::from_fn_with_state;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use cashu::dhke::hash_to_curve;
use cashu::nuts::nut02::{Id, KeySetInfo};
use cashu::nuts::Proof;
use cashu::secret::Secret;
use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
use http::{Request, StatusCode};
use tower::ServiceExt;

use pops_core_verify::cashu_credential::CashuCredential;
use pops_core_verify::challenge::CashuRequirement;
use pops_core_verify::middleware::ChargeMiddlewareState;
use pops_core_verify::middleware_xcashu::require_charge_xcashu;
use pops_core_verify::mint_client::{MintClient, MintClientError};
use pops_core_verify::redeemer::Redeemed;
use pops_core_verify::xcashu::X_CASHU;

/// Canned swap outcome for the mock mint.
enum SwapResponse {
    /// Echo the inputs back (a successful swap that preserves amount).
    Echo,
    /// DETERMINATE unreachable: the token was NOT consumed.
    Unreachable,
    /// Mint refused the swap (double-spent / expired).
    RejectedSwap,
    /// Swap-output DLEQ verification failed (money-safety path).
    DleqInvalid,
}

/// Mock [`MintClient`] that counts how many times the swap endpoint completed
/// successfully — so a test can prove a token was (not) consumed.
struct MockMintClient {
    swap_response: SwapResponse,
    swaps_succeeded: Arc<AtomicUsize>,
}

impl MockMintClient {
    fn new(swap_response: SwapResponse) -> (Self, Arc<AtomicUsize>) {
        let swaps_succeeded = Arc::new(AtomicUsize::new(0));
        (
            Self {
                swap_response,
                swaps_succeeded: swaps_succeeded.clone(),
            },
            swaps_succeeded,
        )
    }
}

#[async_trait]
impl MintClient for MockMintClient {
    async fn keysets(&self, _mint_url: &MintUrl) -> Result<Vec<KeySetInfo>, MintClientError> {
        Ok(Vec::new())
    }

    async fn swap(&self, _mint_url: &MintUrl, proofs: Proofs) -> Result<Proofs, MintClientError> {
        match self.swap_response {
            SwapResponse::Echo => {
                self.swaps_succeeded.fetch_add(1, Ordering::SeqCst);
                Ok(proofs)
            }
            SwapResponse::Unreachable => {
                Err(MintClientError::Unreachable("mock unreachable".into()))
            }
            SwapResponse::RejectedSwap => {
                Err(MintClientError::RejectedSwap("mock rejected".into()))
            }
            SwapResponse::DleqInvalid => Err(MintClientError::SwapOutputDleqInvalid(
                "mock swap-output DLEQ invalid".into(),
            )),
        }
    }
}

type TestCredential = CashuCredential<MockMintClient>;

fn pop_unit() -> CurrencyUnit {
    CurrencyUnit::Custom("pop_1700000000".to_string())
}

fn mint_a() -> MintUrl {
    MintUrl::from_str("https://mint-a.example.com").expect("valid mint url")
}

fn mint_b() -> MintUrl {
    MintUrl::from_str("https://mint-b.example.com").expect("valid mint url")
}

fn make_proof(amount: u64, index: u8) -> Proof {
    let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
    let mut preimage = [0u8; 33];
    preimage[0] = 1;
    preimage[1] = index;
    let c = hash_to_curve(&preimage).expect("hash_to_curve");
    Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
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

/// Router with the X-Cashu middleware in front of an echo handler that writes
/// the redeemed amount, so a test can confirm the resource was (not) served.
fn router_for(swap: SwapResponse) -> (Router, Arc<AtomicUsize>) {
    let (mock, swaps) = MockMintClient::new(swap);
    let state = Arc::new(ChargeMiddlewareState::new(
        requirement(pop_unit(), vec![mint_a()], 10),
        CashuCredential::new(mock),
    ));
    async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
        format!("ok:{}", redeemed.amount)
    }
    let app = Router::new().route("/gated", get(echo)).layer(from_fn_with_state(
        state,
        require_charge_xcashu::<TestCredential>,
    ));
    (app, swaps)
}

fn bare_request() -> Request<Body> {
    Request::builder()
        .uri("/gated")
        .body(Body::empty())
        .expect("build request")
}

/// GET /gated carrying the raw token as the bare `X-Cashu` header (NUT-24 wire).
fn request_with_xcashu(value: &str) -> Request<Body> {
    Request::builder()
        .uri("/gated")
        .header(X_CASHU, value)
        .body(Body::empty())
        .expect("build request with X-Cashu header")
}

fn x_cashu_header(response: &Response) -> Option<String> {
    response
        .headers()
        .get(X_CASHU)
        .map(|v| v.to_str().expect("X-Cashu is ASCII").to_string())
}

async fn body_string(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 4096)
        .await
        .expect("collect body");
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "<non-utf8 body>".to_string())
}

// ---- 402 carries X-Cashu: creqA ------------------------------------

#[tokio::test]
async fn challenge_402_carries_xcashu_creqa() {
    let (app, _swaps) = router_for(SwapResponse::Echo);
    let response = app.oneshot(bare_request()).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let header = x_cashu_header(&response).expect("402 carries X-Cashu");
    assert!(
        header.starts_with("creqA"),
        "X-Cashu challenge must be a bare creqA, got: {header}"
    );
    // It really is a PaymentRequest, not an opaque blob.
    let parsed = cashu::nuts::nut18::PaymentRequest::from_str(&header)
        .expect("X-Cashu challenge decodes as a NUT-18 PaymentRequest");
    assert_eq!(parsed.amount, Some(Amount::from(10)));
    assert_eq!(parsed.unit, Some(pop_unit()));
    // Cache-Control: no-store on the 402.
    let cache = response
        .headers()
        .get(http::header::CACHE_CONTROL)
        .expect("Cache-Control on 402");
    assert_eq!(cache.to_str().unwrap(), "no-store");
}

// ---- valid cashuB → 200 + Redeemed ---------------------------------

#[tokio::test]
async fn valid_cashub_returns_200_and_serves_resource() {
    let token = make_token(mint_a(), pop_unit(), vec![make_proof(8, 0), make_proof(2, 1)]);
    let (app, swaps) = router_for(SwapResponse::Echo);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "ok:10");
    assert_eq!(
        swaps.load(Ordering::SeqCst),
        1,
        "the happy path swaps (consumes) the token exactly once"
    );
}

// ---- value coverage: overpay → accepted, underpay → reject ----------

#[tokio::test]
async fn overpay_is_accepted_and_excess_retained() {
    // 20 against a required 10: value above the requirement is accepted and
    // retained (spec step 8) — the whole token swaps and the resource serves.
    let token = make_token(mint_a(), pop_unit(), vec![make_proof(16, 0), make_proof(4, 1)]);
    let (app, swaps) = router_for(SwapResponse::Echo);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_string(response).await,
        "ok:20",
        "the WHOLE over-funded value is redeemed and retained"
    );
    assert_eq!(swaps.load(Ordering::SeqCst), 1, "the over-funded accept path swaps once");
}

#[tokio::test]
async fn underpay_is_rejected_and_resource_not_served() {
    let token = make_token(mint_a(), pop_unit(), vec![make_proof(8, 0)]);
    let (app, swaps) = router_for(SwapResponse::Echo);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served on underpay");
    assert!(
        body.contains("payment-insufficient"),
        "expected the payment-insufficient problem body, got: {body}"
    );
    assert_eq!(swaps.load(Ordering::SeqCst), 0, "under-funded token rejected pre-swap");
}

// ---- wrong unit / wrong mint → reject ------------------------------

#[tokio::test]
async fn wrong_unit_is_rejected_and_resource_not_served() {
    let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
    let (app, _swaps) = router_for(SwapResponse::Echo);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served");
    assert!(body.contains("wrong unit"), "expected wrong-unit body, got: {body}");
}

#[tokio::test]
async fn wrong_mint_is_rejected_and_resource_not_served() {
    let token = make_token(mint_b(), pop_unit(), vec![make_proof(10, 0)]);
    let (app, _swaps) = router_for(SwapResponse::Echo);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served");
    assert!(
        body.contains("mint not allowed"),
        "expected mint-not-allowed body, got: {body}"
    );
}

// ---- DLEQ-invalid → non-serving (resource NOT served) --------------

#[tokio::test]
async fn dleq_invalid_does_not_serve_resource() {
    let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
    let (app, _swaps) = router_for(SwapResponse::DleqInvalid);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(x_cashu_header(&response).is_some(), "DLEQ failure re-challenges");
    let body = body_string(response).await;
    assert!(
        !body.starts_with("ok:"),
        "a malicious/buggy mint must NOT get the resource served against unsigned ecash"
    );
    assert!(body.to_ascii_lowercase().contains("dleq"), "expected DLEQ body, got: {body}");
}

// ---- double-spend → reject -----------------------------------------

#[tokio::test]
async fn double_spend_is_rejected_and_resource_not_served() {
    let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
    let (app, _swaps) = router_for(SwapResponse::RejectedSwap);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served");
    assert!(body.contains("double-spend"), "expected double-spend body, got: {body}");
}

// ---- mint-unreachable → 503, token NOT consumed --------------------

#[tokio::test]
async fn mint_unreachable_returns_503_and_token_not_consumed() {
    let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
    let (app, swaps) = router_for(SwapResponse::Unreachable);
    let response = app
        .oneshot(request_with_xcashu(&token.to_string()))
        .await
        .expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a transport blip is a 503, never a 402/400 that would burn a valid token"
    );
    // A 503 must NOT re-challenge: re-presenting the SAME token is correct.
    assert!(
        x_cashu_header(&response).is_none(),
        "a 503 carries no X-Cashu re-challenge (the token is still good)"
    );
    assert_eq!(
        swaps.load(Ordering::SeqCst),
        0,
        "a determinate-unreachable swap never completed: the token was NOT consumed"
    );
}

// ---- cashuA → reject -----------------------------------------------

/// A real, well-formed `cashuA`/TokenV3 vector (cashu-0.16.0). Out of contract
/// (cashuB-only), so it must reject — and never reach the mint.
const CASHU_A_V3: &str = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ==";

#[tokio::test]
async fn cashua_is_rejected_and_token_not_consumed() {
    let (app, swaps) = router_for(SwapResponse::Echo);
    let response = app.oneshot(request_with_xcashu(CASHU_A_V3)).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served");
    assert!(
        body.to_ascii_lowercase().contains("cashua")
            || body.contains("cashuB")
            || body.contains("TokenV3"),
        "body should name the cashuB-only rule, got: {body}"
    );
    assert_eq!(swaps.load(Ordering::SeqCst), 0, "cashuA never reaches the mint");
}

// ---- malformed header → non-serving --------------------------------

#[tokio::test]
async fn malformed_token_header_does_not_serve() {
    let (app, _swaps) = router_for(SwapResponse::Echo);
    let response = app
        .oneshot(request_with_xcashu("cashuB!!!notbase64!!!"))
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served");
    assert!(
        body.contains("malformed credential"),
        "expected malformed-credential body, got: {body}"
    );
}

#[tokio::test]
async fn empty_header_value_does_not_serve() {
    let (app, _swaps) = router_for(SwapResponse::Echo);
    let response = app.oneshot(request_with_xcashu("   ")).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let body = body_string(response).await;
    assert!(!body.starts_with("ok:"), "resource must NOT be served on an empty X-Cashu");
}
