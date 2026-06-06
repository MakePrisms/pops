//! Integration tests for `pops-gateway`.
//!
//! A REAL throwaway upstream (a tiny axum server on an ephemeral 127.0.0.1
//! port) sits behind the gateway; the gateway's `MintClient` is a MOCK (the
//! verify crate's own mock pattern, replicated here since it is test-private).
//! Together they assert the spec's behaviors (a)-(e):
//!
//! - (a) bare request → 402 + `WWW-Authenticate`;
//! - (b) valid credential → a `fresh_proofs` LINE in `proofs_sink` AND the
//!   upstream is hit AND its body is returned;
//! - (c) `MintUnreachable` → 503, NO `proofs_sink` write, NOT forwarded;
//! - (d) malformed config → a named-field error (the binary exits nonzero on
//!   this; here we assert `Config::validate` surfaces the field);
//! - (e) persist-before-forward: an upstream failure still leaves the proofs
//!   persisted.

use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::routing::any;
use axum::Router;
use cashu::dhke::hash_to_curve;
use cashu::nuts::nut02::{Id, KeySetInfo};
use cashu::nuts::Proof;
use cashu::secret::Secret;
use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
use http::{header::AUTHORIZATION, Request, StatusCode};
use tower::ServiceExt; // oneshot

use pops_core_verify::cashu_credential::CashuCredential;
use pops_core_verify::challenge::CashuRequirement;
use pops_core_verify::envelope::{
    encode_payment_credentials, CashuPayload, EchoedChallenge, PaymentCredentials,
};
use pops_core_verify::mint_client::{MintClient, MintClientError};

use pops_gateway::build_router;
use pops_gateway::config::{Config, RouteConfig, ValidatedConfig};
use pops_gateway::gateway::AppState;
use pops_gateway::proofs_sink::ProofsSink;

// ───────────────────────── Mock MintClient ──────────────────────────────────
// Replicates the verify crate's test-private mock (it cannot be imported).

enum SwapResponse {
    /// Echo presented proofs back as the "new" proofs (success).
    Echo,
    /// Transport failure → ChargeError::MintUnreachable.
    Unreachable,
}

struct MockMintClient {
    swap_response: SwapResponse,
    swap_calls: Arc<AtomicUsize>,
}

impl MockMintClient {
    fn new(swap_response: SwapResponse) -> (Self, Arc<AtomicUsize>) {
        let swap_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                swap_response,
                swap_calls: swap_calls.clone(),
            },
            swap_calls,
        )
    }
}

#[async_trait]
impl MintClient for MockMintClient {
    async fn keysets(&self, _mint_url: &MintUrl) -> Result<Vec<KeySetInfo>, MintClientError> {
        Ok(Vec::new())
    }

    async fn swap(&self, _mint_url: &MintUrl, proofs: Proofs) -> Result<Proofs, MintClientError> {
        self.swap_calls.fetch_add(1, Ordering::SeqCst);
        match self.swap_response {
            SwapResponse::Echo => Ok(proofs),
            SwapResponse::Unreachable => {
                Err(MintClientError::Unreachable("mock unreachable".into()))
            }
        }
    }
}

// ───────────────────────── Fixtures ─────────────────────────────────────────

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

/// A valid presented token worth exactly 10 against `pop_1700000000` / mint_a.
fn valid_token_string() -> String {
    make_token(
        mint_a(),
        pop_unit(),
        vec![make_proof(8, 0), make_proof(2, 1)],
    )
    .to_string()
}

/// Wrap a raw cashuB token in the `Payment` auth envelope.
fn payment_header(token: &str) -> String {
    let creds = PaymentCredentials {
        challenge: EchoedChallenge {
            id: "test-id".into(),
            realm: "pops-gateway".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "echoed".into(),
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

/// The standard requirement: pop_1700000000, mint_a, amount 10.
fn requirement() -> CashuRequirement {
    CashuRequirement {
        unit: pop_unit(),
        mints: vec![mint_a()],
        amount: Amount::from(10),
        payment_id: None,
        description: Some("gateway test".into()),
        single_use: true,
    }
}

/// Build a ValidatedConfig pointing `upstream_url` at `upstream`, `proofs_sink`
/// at `sink_path`, with the standard requirement + supplied routes.
fn validated_config(
    upstream: &str,
    sink_path: &std::path::Path,
    routes: Vec<RouteConfig>,
) -> ValidatedConfig {
    ValidatedConfig {
        upstream_url: reqwest::Url::parse(upstream).expect("upstream url"),
        mint_url: mint_a(),
        proofs_sink: sink_path.to_path_buf(),
        listen: "127.0.0.1:0".into(),
        max_body_bytes: pops_gateway::config::DEFAULT_MAX_BODY_BYTES,
        upstream_timeout: Some(std::time::Duration::from_secs(
            pops_gateway::config::DEFAULT_UPSTREAM_TIMEOUT_SECS,
        )),
        requirement: requirement(),
        max_proofs: pops_gateway::config::DEFAULT_MAX_PROOFS,
        routes,
    }
}

/// Build the gateway router with a mock-backed credential.
fn gateway(
    upstream: &str,
    sink_path: &std::path::Path,
    swap: SwapResponse,
    routes: Vec<RouteConfig>,
) -> (Router, Arc<AtomicUsize>) {
    let (mock, swap_calls) = MockMintClient::new(swap);
    let credential = CashuCredential::new(mock);
    let sink = ProofsSink::open(sink_path).expect("open sink");
    let state = Arc::new(AppState::new(
        validated_config(upstream, sink_path, routes),
        credential,
        sink,
    ));
    (build_router(state), swap_calls)
}

/// Build the gateway with a custom `max_body_bytes` cap (for the 413 tests).
fn gateway_with_cap(
    upstream: &str,
    sink_path: &std::path::Path,
    swap: SwapResponse,
    routes: Vec<RouteConfig>,
    max_body_bytes: usize,
) -> (Router, Arc<AtomicUsize>) {
    let (mock, swap_calls) = MockMintClient::new(swap);
    let credential = CashuCredential::new(mock);
    let sink = ProofsSink::open(sink_path).expect("open sink");
    let mut cfg = validated_config(upstream, sink_path, routes);
    cfg.max_body_bytes = max_body_bytes;
    let state = Arc::new(AppState::new(cfg, credential, sink));
    (build_router(state), swap_calls)
}

// ─────────────── Mock upstream (a real ephemeral server) ─────────────────────

/// Spawn a tiny upstream that echoes a fixed body + records that it was hit.
/// Returns its base URL and a hit-counter.
async fn spawn_upstream(body: &'static str) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_handler = hits.clone();
    let app = Router::new().fallback(any(move || {
        let hits = hits_for_handler.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            body
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), hits)
}

fn read_lines(path: &std::path::Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => s.lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

// ───────────────────────── Tests ────────────────────────────────────────────

// (a) bare request → 402 + WWW-Authenticate.
#[tokio::test]
async fn bare_request_returns_402_with_www_authenticate() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let www = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.starts_with("Payment "), "got: {www}");
    assert!(www.contains(r#"method="cashu""#), "got: {www}");
    assert!(www.contains(r#"intent="charge""#), "got: {www}");
    assert!(www.contains(r#"request=""#), "got: {www}");
    // Cache-Control: no-store on the 402.
    assert_eq!(
        resp.headers()
            .get(http::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    // Neither the mint nor the upstream was contacted.
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on bare req");
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "upstream not hit on 402");
    // Nothing persisted.
    assert!(read_lines(&sink).is_empty(), "no proofs on a bare request");
}

// (b) valid credential → fresh_proofs line + upstream hit + body returned.
#[tokio::test]
async fn valid_credential_persists_then_forwards_and_returns_body() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("THE-SECRET-PAYLOAD").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, payment_header(&valid_token_string()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Upstream's body is returned with its 200.
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&body[..], b"THE-SECRET-PAYLOAD");

    // The mint swap ran and the upstream was hit.
    assert_eq!(swap_calls.load(Ordering::SeqCst), 1, "swap executed once");
    assert_eq!(up_hits.load(Ordering::SeqCst), 1, "upstream hit once");

    // Exactly one persisted JSONL record with the required fields.
    let lines = read_lines(&sink);
    assert_eq!(lines.len(), 1, "one fresh_proofs line persisted");
    let v: serde_json::Value = serde_json::from_str(&lines[0]).expect("valid JSON record");
    assert!(v["received_at"].is_number());
    assert_eq!(v["amount"], 10);
    assert_eq!(v["unit"], "pop_1700000000");
    assert!(
        v["fresh_proofs"].as_str().unwrap().starts_with("cashuB"),
        "fresh_proofs is a cashuB token"
    );
    assert_eq!(
        v["token_hash"].as_str().unwrap().len(),
        64,
        "token_hash is 64 hex chars"
    );
    assert!(v["active_keyset_id"].as_str().is_some());
}

// (c) MintUnreachable → 503, no persist, not forwarded.
#[tokio::test]
async fn mint_unreachable_returns_503_no_persist_no_forward() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, _swap_calls) = gateway(&upstream, &sink, SwapResponse::Unreachable, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, payment_header(&valid_token_string()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    // 503 carries Retry-After (token NOT consumed, retryable).
    assert_eq!(
        resp.headers()
            .get(http::header::RETRY_AFTER)
            .expect("Retry-After present")
            .to_str()
            .unwrap(),
        "2"
    );
    // Upstream was NOT forwarded to, and nothing was persisted.
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "no forward on 503");
    assert!(read_lines(&sink).is_empty(), "no proofs persisted on 503");
}

// (e) persist-before-forward: upstream DOWN still leaves proofs persisted.
#[tokio::test]
async fn upstream_down_still_persists_proofs() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    // Point at a port nothing is listening on → forward fails (502/504).
    let dead_upstream = "http://127.0.0.1:1"; // port 1: connection refused.
    let (app, swap_calls) = gateway(dead_upstream, &sink, SwapResponse::Echo, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, payment_header(&valid_token_string()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Forward failed → a gateway error status (502 or 504).
    assert!(
        resp.status() == StatusCode::BAD_GATEWAY || resp.status() == StatusCode::GATEWAY_TIMEOUT,
        "expected 502/504 on dead upstream, got {}",
        resp.status()
    );
    // The swap DID run (we charged) ...
    assert_eq!(swap_calls.load(Ordering::SeqCst), 1, "charge executed");
    // ... and CRUCIALLY the proofs are persisted despite the failed forward.
    let lines = read_lines(&sink);
    assert_eq!(
        lines.len(),
        1,
        "persist-before-forward: proofs survive an upstream failure"
    );
}

// Public route forwards WITHOUT a gate (no credential, no persist).
#[tokio::test]
async fn public_route_forwards_without_gate() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("FREE-CONTENT").await;
    let routes = vec![RouteConfig {
        path: "/free/*".into(),
        public: true,
    }];
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, routes);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/free/page")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&body[..], b"FREE-CONTENT");
    // No gate ran: no swap, no persist, but the upstream WAS hit.
    assert_eq!(
        swap_calls.load(Ordering::SeqCst),
        0,
        "public path not gated"
    );
    assert_eq!(up_hits.load(Ordering::SeqCst), 1, "public path forwarded");
    assert!(read_lines(&sink).is_empty());
}

// Health endpoints are gateway-own (never forwarded), and 402 does not leak.
#[tokio::test]
async fn healthz_is_gateway_own() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, _swap) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&body[..], b"ok");
    // /healthz never touches the upstream.
    assert_eq!(up_hits.load(Ordering::SeqCst), 0);
}

// (d) malformed config surfaces a named-field error (the binary exits nonzero
//     on this; here we assert the validation layer the binary calls).
#[tokio::test]
async fn malformed_config_names_the_field() {
    // amount = 0 is the canonical malformed value.
    let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-gateway-test-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 0
"#;
    let cfg = Config::from_toml_str(toml).expect("parses structurally");
    let err = cfg.validate().expect_err("amount=0 must fail validation");
    assert_eq!(err.field, "charge.amount");
    assert!(err.to_string().starts_with("config field charge.amount:"));
}

// ───────────────────── Body-cap (413) tests — MAJOR 1 ────────────────────────

// A PUBLIC request whose body exceeds max_body_bytes → 413, upstream NOT hit.
// (The public/unauthenticated path is the OOM-DoS surface the cap closes.)
#[tokio::test]
async fn oversized_body_on_public_path_returns_413_not_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("FREE").await;
    let routes = vec![RouteConfig {
        path: "/free/*".into(),
        public: true,
    }];
    // Cap at 64 bytes; send 256.
    let (app, _swap) = gateway_with_cap(&upstream, &sink, SwapResponse::Echo, routes, 64);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/free/upload")
                .body(Body::from(vec![b'x'; 256]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&body).unwrap()).expect("413 body is JSON");
    assert_eq!(v["error"], "payload_too_large");
    assert_eq!(v["max_body_bytes"], 64);
    // The oversized body was rejected BEFORE reaching upstream.
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "413 not forwarded");
}

// A GATED request whose body exceeds the cap → 413 BEFORE the swap: the pop is
// NOT consumed and nothing is persisted. This is the value-safety property —
// we never charge for a request we are going to reject for being too large.
#[tokio::test]
async fn oversized_body_on_gated_path_returns_413_before_charge() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    // Cap at 64 bytes; send a valid credential + a 4 KiB body.
    let (app, swap_calls) = gateway_with_cap(&upstream, &sink, SwapResponse::Echo, vec![], 64);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/protected")
                .header(AUTHORIZATION, payment_header(&valid_token_string()))
                .body(Body::from(vec![b'x'; 4096]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // CRUCIAL: no swap (pop unspent), no persist, no forward.
    assert_eq!(
        swap_calls.load(Ordering::SeqCst),
        0,
        "413 must precede the charge — pop not consumed"
    );
    assert!(
        read_lines(&sink).is_empty(),
        "nothing persisted for an over-cap request"
    );
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "not forwarded");
}

// A body AT/under the cap still forwards normally (the cap doesn't break
// legitimate request bodies — guards against an off-by-one rejecting valid load).
#[tokio::test]
async fn body_at_cap_forwards_normally() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("OK").await;
    let routes = vec![RouteConfig {
        path: "/free/*".into(),
        public: true,
    }];
    // Cap 128, body exactly 128.
    let (app, _swap) = gateway_with_cap(&upstream, &sink, SwapResponse::Echo, routes, 128);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/free/ok")
                .body(Body::from(vec![b'y'; 128]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a body at the cap is allowed"
    );
    assert_eq!(up_hits.load(Ordering::SeqCst), 1, "forwarded to upstream");
}
