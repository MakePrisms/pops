//! Axum middleware gating a route behind the NUT-24 `X-Cashu` HTTP transport
//! for the cashu method (native only). Drop into an `axum::Router` with
//! [`axum::middleware::from_fn_with_state`].
//!
//! Flow: a request without an `X-Cashu` header gets a `402` carrying
//! `X-Cashu: <creqA…>` — the bare NUT-18 payment request, no JSON wrapper. The
//! client retries with `X-Cashu: <cashuB…>`; the middleware verify+redeems
//! through the generic [`Redeemer`] seam and, on success, attaches the
//! [`Redeemed`][crate::redeemer::Redeemed] to `request.extensions_mut()`.
//!
//! This transport shares the [`ChargeMiddlewareState`] and the [`Redeemer`]
//! money core with the `Payment` middleware; only the wire differs (single
//! `X-Cashu` header both directions, vs `WWW-Authenticate`/`Authorization`).
//!
//! Status mapping (stricter and safer than NUT-24's bare `400`) — the
//! single-sourced [`crate::problem`] map, shared with every other host:
//! `MintUnreachable` → `503` + `Retry-After` (transport blip, token NOT
//! consumed — never a `400`/`402` that says "re-pay" against a valid token);
//! `MalformedRequest` → `400` (server-side requirement is misconfigured); every
//! other validation failure → `402` + a fresh `X-Cashu: <creqA>` re-challenge.
//! Value follows the spec's step-8 rule: an under-funded token is a
//! `PaymentInsufficient` rejection; value above the requirement is accepted
//! and retained (the server makes no change). Every `402` carries
//! `Cache-Control: no-store`, and every failure body is RFC-9457
//! `application/problem+json` with the absolute problem-type URI (NUT-24
//! leaves the body unspecified, so the richer body is compatible).
//!
//! [`Redeemer`]: crate::redeemer::Redeemer

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{header::HeaderValue, HeaderName, StatusCode};
use crate::charge::ChargeError;

use crate::cashu_credential::charge_requirement_from_cashu;
use crate::challenge::CashuRequirement;
use crate::http_status::charge_error_status;
use crate::middleware::ChargeMiddlewareState;
use crate::problem::{Problem, PROBLEM_JSON};
use crate::redeemer::Redeemer;
use crate::xcashu::{xcashu_challenge_value, xcashu_token_from_header};

/// The `X-Cashu` header name, parsed once. Holds both the `creqA…` challenge
/// (response) and the `cashuB…` payment (request).
fn x_cashu_header() -> HeaderName {
    HeaderName::from_static("x-cashu")
}

/// Axum middleware entry point enforcing the NUT-24 `X-Cashu` transport. The
/// `'static` bound on `C` is what `from_fn_with_state` requires to spawn the
/// handler future.
pub async fn require_charge_xcashu<C>(
    State(ctx): State<Arc<ChargeMiddlewareState<C>>>,
    mut req: Request,
    next: Next,
) -> Response
where
    C: Redeemer + Send + Sync + 'static,
{
    // A missing `X-Cashu` header is "no payment attempt" → 402 + challenge.
    let Some(header_raw) = req.headers().get(x_cashu_header()) else {
        return challenge_response(&ctx.requirement, None);
    };

    // A non-ASCII header is not a well-formed token presentation → 402
    // re-challenge (a token is base64url, always ASCII).
    let header_value = match header_raw.to_str() {
        Ok(v) => v,
        Err(_) => {
            return charge_error_to_response(
                ChargeError::MalformedCredential("invalid X-Cashu header encoding".to_string()),
                &ctx.requirement,
            );
        }
    };

    // The codec only trims; an empty value is the one parse failure it sees.
    // Like every other malformed presentation it is non-serving → 402.
    let token = match xcashu_token_from_header(header_value) {
        Ok(t) => t,
        Err(e) => {
            return charge_error_to_response(
                ChargeError::MalformedCredential(e.to_string()),
                &ctx.requirement,
            )
        }
    };

    // Verify + redeem via the generic seam; the `ChargeError` variant decides the
    // status (see `charge_error_to_response`). The token's structural validation
    // (cashuB-only prefix, CBOR shape) happens inside `verify_and_redeem`.
    let charge_req = charge_requirement_from_cashu(&ctx.requirement);
    let redeemed = match ctx.credential.verify_and_redeem(&token, &charge_req).await {
        Ok(r) => r,
        Err(e) => return charge_error_to_response(e, &ctx.requirement),
    };

    // Downstream reads this via `Extension<Redeemed>`.
    req.extensions_mut().insert(redeemed);
    next.run(req).await
}

/// Build a `402` carrying a fresh `X-Cashu: <creqA>` challenge (always
/// `Cache-Control: no-store`). `problem`, when set, becomes the
/// `application/problem+json` body naming why the previous attempt failed; a
/// bare "no attempt yet" `402` gets an empty body. NUT-24 has no challenge id /
/// realm / echo, so the header value is the bare `creqA`.
fn challenge_response(requirement: &CashuRequirement, problem: Option<&Problem>) -> Response {
    let creq_a = xcashu_challenge_value(requirement);

    // The `creqA` is base64url, always a valid header value; the `from_str`
    // validation is a belt-and-braces guard against a future encoder regression.
    let x_cashu = match HeaderValue::from_str(&creq_a) {
        Ok(hv) => hv,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode X-Cashu challenge header",
            )
                .into_response();
        }
    };

    let cache_control = HeaderValue::from_static("no-store");

    match problem {
        Some(p) => (
            StatusCode::PAYMENT_REQUIRED,
            [
                (x_cashu_header(), x_cashu),
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
                (x_cashu_header(), x_cashu),
                (http::header::CACHE_CONTROL, cache_control),
            ],
            String::new(),
        )
            .into_response(),
    }
}

/// Map a [`ChargeError`] to an HTTP response from the single-sourced
/// [`crate::problem`] map (every failure body is `application/problem+json`):
/// `MintUnreachable` → `503` + `Retry-After` (transport, token NOT consumed,
/// NEVER a `402`), `MalformedRequest`/`MethodUnsupported` → `400`, everything
/// else (verification / malformed-credential / insufficient value) → `402` + a
/// fresh `X-Cashu: <creqA>` re-challenge. A non-402 carries NO re-challenge —
/// on a 503 re-presenting the SAME token is correct.
fn charge_error_to_response(e: ChargeError, requirement: &CashuRequirement) -> Response {
    let problem = Problem::for_error(&e);
    let status = charge_error_status(&e);
    if status == StatusCode::PAYMENT_REQUIRED {
        return challenge_response(requirement, Some(&problem));
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
    use http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::cashu_credential::CashuCredential;
    use crate::challenge::CashuRequirement;
    use crate::middleware::ChargeMiddlewareState;
    use crate::mint_client::{MintClient, MintClientError};
    use crate::redeemer::Redeemed;
    use crate::xcashu::X_CASHU;

    // ---- Mock MintClient (mirrors the Payment middleware's helper) ----

    enum SwapResponse {
        Echo,
        Unreachable,
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
        async fn keysets(&self, _mint_url: &MintUrl) -> Result<Vec<KeySetInfo>, MintClientError> {
            Ok(Vec::new())
        }

        async fn swap(
            &self,
            _mint_url: &MintUrl,
            proofs: Proofs,
        ) -> Result<Proofs, MintClientError> {
            match self.swap_response {
                SwapResponse::Echo => Ok(proofs),
                SwapResponse::Unreachable => {
                    Err(MintClientError::Unreachable("mock unreachable".into()))
                }
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

    type TestCredential = CashuCredential<MockMintClient>;

    /// Router with the X-Cashu middleware in front of an echo handler that
    /// writes the redeemed amount into the body, so tests can assert the
    /// `Redeemed` made it through the extensions.
    fn router_with(state: Arc<ChargeMiddlewareState<TestCredential>>) -> Router {
        async fn echo(Extension(redeemed): Extension<Redeemed>) -> String {
            format!("ok:{}", redeemed.amount)
        }
        Router::new().route("/gated", get(echo)).layer(from_fn_with_state(
            state,
            require_charge_xcashu::<TestCredential>,
        ))
    }

    /// Build a state with the supplied swap response and the standard
    /// requirement (`pop_1700000000`, mint_a, amount=10).
    fn state_with(swap: SwapResponse) -> Arc<ChargeMiddlewareState<TestCredential>> {
        let credential = CashuCredential::new(MockMintClient::new(swap));
        Arc::new(ChargeMiddlewareState::new(
            requirement(pop_unit(), vec![mint_a()], 10),
            credential,
        ))
    }

    fn bare_request() -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/gated")
            .body(Body::empty())
            .expect("build request")
    }

    /// Build a GET /gated request carrying the raw `cashuB…` token as the bare
    /// `X-Cashu` header value (the NUT-24 wire — no envelope).
    fn request_with_xcashu(value: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .uri("/gated")
            .header(X_CASHU, value)
            .body(Body::empty())
            .expect("build request with X-Cashu header")
    }

    /// Pluck the `X-Cashu` header off a response as a string.
    fn x_cashu_value(response: &Response) -> String {
        response
            .headers()
            .get(super::x_cashu_header())
            .expect("X-Cashu present")
            .to_str()
            .expect("X-Cashu is ASCII")
            .to_string()
    }

    async fn body_string(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .expect("collect body");
        String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "<non-utf8 body>".to_string())
    }

    // ---- 402 challenge shape (carries X-Cashu: creqA) ----------------

    #[tokio::test]
    async fn no_xcashu_header_returns_402_carrying_creqa() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let header = x_cashu_value(&response);
        assert!(
            header.starts_with("creqA"),
            "402 must carry a bare creqA in X-Cashu, got: {header}"
        );
    }

    #[tokio::test]
    async fn challenge_402_has_cache_control_no_store() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let cache = response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .expect("Cache-Control present on 402");
        assert_eq!(cache.to_str().expect("ASCII"), "no-store");
    }

    #[tokio::test]
    async fn bare_challenge_has_empty_body() {
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(bare_request()).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(
            body_string(response).await.is_empty(),
            "a no-attempt 402 should have an empty body"
        );
    }

    // ---- Happy path: valid cashuB → 200 + Redeemed -------------------

    #[tokio::test]
    async fn valid_cashub_token_passes_through_to_handler() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(8, 0), make_proof(2, 1)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_xcashu(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_string(response).await, "ok:10");
    }

    // ---- Error mapping ----------------------------------------------

    #[tokio::test]
    async fn empty_xcashu_header_returns_402_and_does_not_serve() {
        // A present-but-empty header is a malformed presentation → 402, NOT 400.
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app.oneshot(request_with_xcashu("   ")).await.expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(super::x_cashu_header()).is_some());
        let body = body_string(response).await;
        assert!(!body.starts_with("ok:"), "resource must NOT be served");
    }

    #[tokio::test]
    async fn malformed_token_returns_402_and_does_not_serve() {
        let app = router_with(state_with(SwapResponse::Echo));
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
    async fn cashua_token_is_rejected_as_402() {
        // cashuA/TokenV3 is out of contract (cashuB-only); decode_token rejects
        // it at the prefix → MalformedCredential → 402.
        const CASHU_A_V3: &str = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ==";
        let app = router_with(state_with(SwapResponse::Echo));
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
    }

    #[tokio::test]
    async fn wrong_unit_returns_402_and_does_not_serve() {
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
        let response = app
            .oneshot(request_with_xcashu(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(super::x_cashu_header()).is_some());
        let body = body_string(response).await;
        assert!(!body.starts_with("ok:"), "resource must NOT be served");
        assert!(body.contains("wrong unit"), "expected wrong-unit body, got: {body}");
    }

    #[tokio::test]
    async fn wrong_mint_returns_402_and_does_not_serve() {
        let other_mint = MintUrl::from_str("https://mint-b.example.com").expect("valid mint url");
        let token = make_token(other_mint, pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Echo));
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

    #[tokio::test]
    async fn dleq_invalid_returns_402_and_does_not_serve_resource() {
        // Money-safety: a missing/invalid swap-output DLEQ → 402 re-challenge,
        // and the gated handler MUST NOT run.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::DleqInvalid));
        let response = app
            .oneshot(request_with_xcashu(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(super::x_cashu_header()).is_some());
        let body = body_string(response).await;
        assert!(!body.starts_with("ok:"), "resource must NOT be served on a DLEQ failure");
        assert!(
            body.to_ascii_lowercase().contains("dleq"),
            "expected a DLEQ failure body, got: {body}"
        );
    }

    #[tokio::test]
    async fn double_spend_returns_402_and_does_not_serve() {
        // A rejected swap (double-spend / expired) → 402 re-challenge.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::RejectedSwap));
        let response = app
            .oneshot(request_with_xcashu(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = body_string(response).await;
        assert!(!body.starts_with("ok:"), "resource must NOT be served");
        assert!(body.contains("double-spend"), "expected double-spend body, got: {body}");
    }

    // ---- Mint-unreachable → 503, token NOT consumed ------------------

    #[tokio::test]
    async fn mint_unreachable_returns_503_not_402() {
        // Transport blip: 503, NEVER a 402/400 that would tell the holder to
        // re-pay against a still-valid token. The load-bearing 503-never rule.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::Unreachable));
        let response = app
            .oneshot(request_with_xcashu(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        // A 503 carries no re-challenge — re-presenting the SAME token is correct.
        assert!(
            response.headers().get(super::x_cashu_header()).is_none(),
            "a 503 must NOT carry an X-Cashu re-challenge (the token is still good)"
        );
        let body = body_string(response).await;
        assert!(
            body.contains("mint unavailable"),
            "expected mint-unavailable body, got: {body}"
        );
    }

    #[tokio::test]
    async fn indeterminate_unreachable_is_still_503() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let app = router_with(state_with(SwapResponse::UnreachableIndeterminate));
        let response = app
            .oneshot(request_with_xcashu(&token.to_string()))
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
