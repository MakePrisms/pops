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
use pops_core_verify::mint_client::{MintClient, MintClientError, SwapOutcome};

use pops_core_verify::binding::BindingKey;
use pops_core_verify::envelope::{parse_payment_params, PaymentParams};

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
    /// Success whose swap-output DLEQ verdict failed — the serve-and-flag
    /// path; the settle log must carry `dleq_ok=false`.
    DleqInvalid,
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

    async fn swap(
        &self,
        _mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<SwapOutcome, MintClientError> {
        self.swap_calls.fetch_add(1, Ordering::SeqCst);
        match self.swap_response {
            SwapResponse::Echo => Ok(SwapOutcome {
                proofs,
                dleq_ok: true,
            }),
            SwapResponse::Unreachable => {
                Err(MintClientError::Unreachable("mock unreachable".into()))
            }
            SwapResponse::DleqInvalid => Ok(SwapOutcome {
                proofs,
                dleq_ok: false,
            }),
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

/// Wrap a raw cashuB token in the `Payment` auth envelope around an UNISSUED
/// echo — fails the gateway's stateless binding by construction. For the
/// pre-binding paths (>1-credential 400) and the rejection test itself.
fn unissued_echo_header(token: &str) -> String {
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
            description: None,
        },
        payload: CashuPayload {
            token: token.into(),
        },
        source: None,
    };
    format!("Payment {}", encode_payment_credentials(&creds))
}

/// Fetch a REAL challenge off the gateway (bare request → 402) and parse its
/// auth-params — the first half of the client dance.
async fn fetch_challenge(app: &Router) -> PaymentParams {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("challenge fetch");
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let www = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate present")
        .to_str()
        .expect("ASCII")
        .to_string();
    parse_payment_params(&www).expect("challenge params parse")
}

/// The full client dance: fetch a real challenge from `app` and build the
/// `Authorization` header echoing every issued param verbatim around `token`.
async fn paid_header(app: &Router, token: &str) -> String {
    let params = fetch_challenge(app).await;
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

/// The standard requirement: pop_1700000000, mint_a, amount 10.
fn requirement() -> CashuRequirement {
    CashuRequirement {
        unit: pop_unit(),
        mints: vec![mint_a()],
        amount: Amount::from(10),
        external_id: None,
        description: Some("gateway test".into()),
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
        mint_http_timeout: std::time::Duration::from_secs(
            pops_gateway::config::DEFAULT_MINT_HTTP_TIMEOUT_SECS,
        ),
        requirement: requirement(),
        max_proofs: pops_gateway::config::DEFAULT_MAX_PROOFS,
        routes,
        binding_key: BindingKey::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("test binding key"),
        challenge_ttl: std::time::Duration::from_secs(
            pops_gateway::config::DEFAULT_CHALLENGE_TTL_SECS,
        ),
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
    // The bare-402 body is the framework's payment-required problem.
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json"
    );
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(
        problem["type"],
        "https://paymentauth.org/problems/payment-required"
    );
    assert_eq!(problem["status"], 402);
    // Neither the mint nor the upstream was contacted.
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on bare req");
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "upstream not hit on 402");
    // Nothing persisted.
    assert!(read_lines(&sink).is_empty(), "no proofs on a bare request");
}

// The gateway's challenge is the SHARED draft-cashu-charge-00 request object —
// the flat {"cashu_request": ...} dialect is dead.
#[tokio::test]
async fn gateway_challenge_request_param_is_the_spec_request_object() {
    use pops_core_verify::challenge::decode_charge_request;
    use pops_core_verify::envelope::parse_payment_params;

    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, _up_hits) = spawn_upstream("SECRET").await;
    let (app, _swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let www = resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate present")
        .to_str()
        .unwrap()
        .to_string();
    let params = parse_payment_params(&www).expect("Payment params parse");
    let decoded = decode_charge_request(&params.request)
        .expect("request param decodes via the shared spec codec");
    assert_eq!(decoded.amount, Amount::from(10));
    assert_eq!(decoded.unit, pop_unit());
    assert_eq!(decoded.mints, vec![mint_a()], "mints derive from the creqA");
    assert!(decoded.creq_a.starts_with("creqA"));
}

// (b) valid credential → fresh_proofs line + upstream hit + body returned.
#[tokio::test]
async fn valid_credential_persists_then_forwards_and_returns_body() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("THE-SECRET-PAYLOAD").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let auth = paid_header(&app, &valid_token_string()).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, auth)
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

// Spec receipt §: the paid SUCCESS response carries Payment-Receipt +
// Cache-Control: private, the latter OVERRIDING the upstream's own
// Cache-Control (a paid response must never be shared-cacheable).
#[tokio::test]
async fn paid_success_carries_receipt_and_private_overrides_upstream_cache_control() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");

    // An upstream that answers 200 with a PUBLIC Cache-Control.
    let app_upstream = Router::new().fallback(any(|| async {
        (
            [(http::header::CACHE_CONTROL, "public, max-age=600")],
            "PAID-CONTENT",
        )
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app_upstream).await;
    });

    let (app, _swaps) = gateway(&format!("http://{addr}"), &sink, SwapResponse::Echo, vec![]);

    // Inline the client dance so the challenge id is in hand for the receipt
    // echo assertion.
    let params = fetch_challenge(&app).await;
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
            token: valid_token_string(),
        },
        source: None,
    };
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(
                    AUTHORIZATION,
                    format!("Payment {}", encode_payment_credentials(&creds)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(http::header::CACHE_CONTROL)
            .expect("Cache-Control on the paid 200")
            .to_str()
            .unwrap(),
        "private",
        "the upstream's public Cache-Control must not survive on a paid response"
    );

    let receipt_raw = resp
        .headers()
        .get("payment-receipt")
        .expect("Payment-Receipt on the paid 200")
        .to_str()
        .unwrap()
        .to_string();
    let receipt_bytes = URL_SAFE_NO_PAD
        .decode(&receipt_raw)
        .expect("Payment-Receipt is base64url-nopad");
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).expect("receipt JSON");
    assert_eq!(receipt["method"], "cashu");
    assert_eq!(receipt["status"], "success");
    assert_eq!(
        receipt["challengeId"], params.id,
        "the receipt echoes the issued challenge id"
    );
    assert_eq!(
        receipt["reference"].as_str().unwrap().len(),
        64,
        "reference is the 64-hex token_hash"
    );
    assert!(receipt["timestamp"].is_string());

    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&body[..], b"PAID-CONTENT");
}

// (c) MintUnreachable → 503, no persist, not forwarded.
#[tokio::test]
async fn mint_unreachable_returns_503_no_persist_no_forward() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, _swap_calls) = gateway(&upstream, &sink, SwapResponse::Unreachable, vec![]);

    let auth = paid_header(&app, &valid_token_string()).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, auth)
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

    let auth = paid_header(&app, &valid_token_string()).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, auth)
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
    // A paid-but-failed response is an ERROR response: no receipt rides it.
    assert!(
        resp.headers().get("payment-receipt").is_none(),
        "no Payment-Receipt on a post-charge error response"
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
    // Cap at 64 bytes; send a validly-bound credential + a 4 KiB body.
    let (app, swap_calls) = gateway_with_cap(&upstream, &sink, SwapResponse::Echo, vec![], 64);

    let auth = paid_header(&app, &valid_token_string()).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/protected")
                .header(AUTHORIZATION, auth)
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

// ───────────── error map: the gateway emits the shared problem wire ──────────

/// A [`Redeemer`] whose failure is fixed up front, so the map test drives every
/// `ChargeError` through the REAL gateway response path.
struct CannedFailRedeemer {
    make: fn() -> pops_core_verify::charge::ChargeError,
}

#[async_trait]
impl pops_core_verify::redeemer::Redeemer for CannedFailRedeemer {
    async fn verify_and_redeem(
        &self,
        _presented: &str,
        _req: &pops_core_verify::redeemer::ChargeRequirement,
    ) -> Result<pops_core_verify::redeemer::Redeemed, pops_core_verify::charge::ChargeError> {
        Err((self.make)())
    }
}

#[tokio::test]
async fn gateway_emits_the_shared_problem_mapping_for_every_charge_error() {
    // The gateway's (status, problem body) must equal the single-sourced
    // problem_mapping table for every variant — the same table the core
    // middlewares are tested against, so all hosts emit identically.
    use pops_core_verify::charge::ChargeError;
    use pops_core_verify::problem::problem_mapping;

    let cases: Vec<fn() -> ChargeError> = vec![
        || ChargeError::MintUnreachable {
            mint_url: "https://mint-a.example.com".into(),
            transport_detail: "timeout".into(),
            indeterminate: false,
        },
        || ChargeError::PaymentInsufficient {
            required: 10,
            presented: 8,
            amount: 10,
            expected_swap_fee: 0,
        },
        || ChargeError::WrongUnit {
            expected: "pop_1700000000".into(),
            got: "sat".into(),
        },
        || ChargeError::MintNotAllowed {
            got: "https://evil.example".into(),
            allowed: vec!["https://mint-a.example.com".into()],
        },
        || ChargeError::MintUrlUserinfo {
            url: "https://user@mint-a.example.com".into(),
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
    ];

    for make in cases {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("proofs.jsonl");
        let (upstream, _hits) = spawn_upstream("SECRET").await;
        let credential = CannedFailRedeemer { make };
        let sink = ProofsSink::open(&sink_path).expect("open sink");
        let state = Arc::new(AppState::new(
            validated_config(&upstream, &sink_path, vec![]),
            credential,
            sink,
        ));
        let app = build_router(state);

        let auth = paid_header(&app, &valid_token_string()).await;
    let resp = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(AUTHORIZATION, auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let mapping = problem_mapping(&make());
        assert_eq!(
            resp.status().as_u16(),
            mapping.status,
            "gateway status drift for {}",
            make()
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_TYPE)
                .expect("Content-Type present")
                .to_str()
                .unwrap(),
            "application/problem+json",
            "gateway error body must be problem+json for {}",
            make()
        );
        let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        let problem: serde_json::Value =
            serde_json::from_slice(&body).expect("gateway problem body");
        assert_eq!(problem["type"], mapping.type_uri, "{}", make());
        assert_eq!(problem["title"], mapping.title, "{}", make());
        assert_eq!(problem["status"], mapping.status, "{}", make());
        assert!(problem["detail"].is_string(), "{}", make());
    }
}

#[tokio::test]
async fn gateway_non_cashu_method_returns_400_method_unsupported() {
    // A credential naming method="tempo" → the framework's method-unsupported
    // 400, identical to the core middleware's mapping.
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let creds = PaymentCredentials {
        challenge: EchoedChallenge {
            id: "test-id".into(),
            realm: "pops-gateway".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: "echoed".into(),
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

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(
        problem["type"],
        "https://paymentauth.org/problems/method-unsupported"
    );
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on a 400");
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "not forwarded on a 400");
    assert!(read_lines(&sink).is_empty(), "nothing persisted on a 400");
}

// ───────────── challenge binding (per-request HMAC id + expires) ─────────────

#[tokio::test]
async fn gateway_challenges_carry_per_request_hmac_ids_and_expires() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, _hits) = spawn_upstream("SECRET").await;
    let (app, _swaps) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let first = fetch_challenge(&app).await;
    // The id is a 32-byte HMAC output, not the dead fixed "pops-gateway".
    let id_bytes = URL_SAFE_NO_PAD
        .decode(&first.id)
        .expect("id is base64url-nopad");
    assert_eq!(id_bytes.len(), 32, "id is an HMAC-SHA256 output");
    assert_ne!(first.id, "pops-gateway");
    // Stateless operation: every challenge carries expires.
    assert!(first.expires.is_some(), "challenge carries expires");
}

#[tokio::test]
async fn gateway_rejects_unbound_challenge_echo_as_invalid_challenge() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, unissued_echo_header(&valid_token_string()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(
        problem["type"],
        "https://paymentauth.org/problems/invalid-challenge"
    );
    // The token was never swapped or forwarded — binding precedes the charge.
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on a bad echo");
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "not forwarded");
    assert!(read_lines(&sink).is_empty(), "nothing persisted");
}

#[tokio::test]
async fn gateway_rejects_tampered_request_echo_as_invalid_challenge() {
    // Echo a REAL challenge but swap in a different request blob — the
    // redirection the binding exists to catch.
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, _hits) = spawn_upstream("SECRET").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let params = fetch_challenge(&app).await;
    let creds = PaymentCredentials {
        challenge: EchoedChallenge {
            id: params.id.clone(),
            realm: params.realm.clone(),
            method: params.method.clone(),
            intent: params.intent.clone(),
            request: format!("{}x", params.request),
            digest: None,
            opaque: None,
            expires: params.expires.clone(),
            description: None,
        },
        payload: CashuPayload {
            token: valid_token_string(),
        },
        source: None,
    };
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(
                    AUTHORIZATION,
                    format!("Payment {}", encode_payment_credentials(&creds)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(
        problem["type"],
        "https://paymentauth.org/problems/invalid-challenge"
    );
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on a tampered echo");
}

#[tokio::test]
async fn gateway_stale_challenge_returns_payment_expired() {
    // Zero TTL ⇒ authentic-but-instantly-stale challenges: a faithful echo
    // passes the HMAC, fails freshness → payment-expired, token untouched.
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, _hits) = spawn_upstream("SECRET").await;
    let (mock, swap_calls) = MockMintClient::new(SwapResponse::Echo);
    let credential = CashuCredential::new(mock);
    let proofs_sink = ProofsSink::open(&sink).expect("open sink");
    let mut cfg = validated_config(&upstream, &sink, vec![]);
    cfg.challenge_ttl = std::time::Duration::ZERO;
    let state = Arc::new(AppState::new(cfg, credential, proofs_sink));
    let app = build_router(state);

    let auth = paid_header(&app, &valid_token_string()).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(
        problem["type"],
        "https://paymentauth.org/problems/payment-expired"
    );
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on a stale echo");
}

// Framework: a request bearing more than one Authorization: Payment credential
// is rejected with 400 (about:blank body), before any binding or swap.
#[tokio::test]
async fn gateway_multiple_payment_credentials_return_400() {
    let dir = tempfile::tempdir().unwrap();
    let sink = dir.path().join("proofs.jsonl");
    let (upstream, up_hits) = spawn_upstream("SECRET").await;
    let (app, swap_calls) = gateway(&upstream, &sink, SwapResponse::Echo, vec![]);

    let header = paid_header(&app, &valid_token_string()).await;
    let mut req = Request::builder()
        .uri("/protected")
        .body(Body::empty())
        .unwrap();
    req.headers_mut().append(
        AUTHORIZATION,
        http::HeaderValue::from_str(&header).expect("ascii"),
    );
    req.headers_mut().append(
        AUTHORIZATION,
        http::HeaderValue::from_str(&header).expect("ascii"),
    );

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem body");
    assert_eq!(problem["type"], "about:blank");
    assert_eq!(problem["status"], 400);
    assert_eq!(swap_calls.load(Ordering::SeqCst), 0, "no swap on a 400");
    assert_eq!(up_hits.load(Ordering::SeqCst), 0, "not forwarded on a 400");
    assert!(read_lines(&sink).is_empty(), "nothing persisted on a 400");
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

// ─────────────── The settle log carries the DLEQ verdict ────────────────────

/// A minimal subscriber capturing INFO-and-above events as `field=value`
/// strings, so the test can assert the gateway's settle line without pulling
/// in a subscriber crate.
struct InfoCapture {
    events: Arc<std::sync::Mutex<Vec<String>>>,
}

impl tracing::Subscriber for InfoCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Collect(String);
        impl tracing::field::Visit for Collect {
            fn record_debug(
                &mut self,
                field: &tracing::field::Field,
                value: &dyn std::fmt::Debug,
            ) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={:?} ", field.name(), value);
            }
        }
        let mut collected = Collect(String::new());
        event.record(&mut collected);
        self.events.lock().expect("capture lock").push(collected.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn settle_log_carries_dleq_ok_verdict() {
    // §security-dleq serve-and-flag at the gateway: a swap whose returned
    // signatures failed DLEQ still settles (200, persisted, forwarded), and
    // the operator-facing settle line carries `dleq_ok=false` so the incident
    // is visible. The settle line is the gateway's ONLY dleq_ok surface.
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(InfoCapture {
        events: events.clone(),
    });

    let settled_with = |events: &Arc<std::sync::Mutex<Vec<String>>>, verdict: &str| {
        events
            .lock()
            .expect("capture lock")
            .iter()
            .any(|e| e.contains("charge settled") && e.contains(verdict))
    };

    let dir = tempfile::tempdir().unwrap();
    // tracing caches per-callsite interest globally; a parallel test's cold
    // hit on the settle callsite can cache `never` before this thread's
    // dispatcher registers. Rebuild + retry bounds that race out without
    // weakening the assertion.
    for attempt in 0..5 {
        tracing::callsite::rebuild_interest_cache();

        let sink = dir.path().join(format!("proofs-{attempt}.jsonl"));
        let (upstream, _hits) = spawn_upstream("GATED OK").await;
        let (app, _swaps) = gateway(&upstream, &sink, SwapResponse::DleqInvalid, vec![]);

        let header = paid_header(&app, &valid_token_string()).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(AUTHORIZATION, header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a failed swap-output DLEQ verdict still settles and serves"
        );
        assert_eq!(
            read_lines(&sink).len(),
            1,
            "the redeemed value is persisted despite the failed verdict"
        );

        if settled_with(&events, "dleq_ok=false") {
            break;
        }
    }

    let captured = events.lock().expect("capture lock");
    let settle_line = captured
        .iter()
        .find(|e| e.contains("charge settled"))
        .unwrap_or_else(|| panic!("no settle line captured, got: {captured:?}"));
    assert!(
        settle_line.contains("dleq_ok=false"),
        "the settle line must carry the DLEQ verdict, got: {settle_line}"
    );
    assert!(
        settle_line.contains("token_hash="),
        "the settle line correlates by token_hash, got: {settle_line}"
    );
}
