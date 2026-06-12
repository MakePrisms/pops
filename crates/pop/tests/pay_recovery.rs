//! End-to-end recovery-path tests for `pop pay`'s swap-to-exact flow.
//!
//! The wallet is STATELESS in ecash: once `build_exact_payment` runs a NUT-03
//! swap, the held input proofs are SPENT and the freshly-minted send/change
//! ecash exists ONLY as the in-memory token strings. So EVERY post-swap exit —
//! the success path and every error path — MUST surface BOTH `send_token` and
//! `change_token`, in BOTH json and `--human` modes. These tests prove that by
//! standing up a tiny in-process TCP stub that plays BOTH roles:
//!
//! - **gateway**: answers the initial `GET` with a `402` + a real
//!   `WWW-Authenticate: Payment` challenge, and answers the authenticated retry
//!   per the scenario (200 / 4xx / 5xx / dropped-connection).
//! - **mint**: serves `/v1/keysets`, `/v1/keys/<id>`, and signs `/v1/swap`
//!   outputs with a real keyset (DLEQ-valid), so the swap actually produces
//!   spendable proofs the wallet unblinds into the two tokens.
//!
//! Both roles share one `127.0.0.1:<port>`; the `--token`'s mint url and the
//! charge's accepted mint both point there, so a single listener suffices.
//!
//! Scenarios:
//!   (a) swap → retry transport error (connection dropped) → `gateway_retry_failed`
//!       carrying BOTH tokens (json + human);
//!   (b) swap → gateway rejects (402/500) → `gateway_rejected_payment` carrying
//!       BOTH tokens (json + human);
//!   (c) swap → gateway 200 → `paid:true` surfacing `change_token` (json + human).

use std::str::FromStr;
use std::sync::mpsc;
use std::thread;

use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use cdk_common::dhke::sign_message;
use cdk_common::mint_url::MintUrl;
use cdk_common::nuts::nut02::{KeySetVersion, MintKeySet};
use cdk_common::nuts::{
    BlindSignature, CurrencyUnit, Id, KeySet, KeySetInfo, Keys, Proof, Proofs, SwapRequest,
    SwapResponse, Token,
};
use cdk_common::secret::Secret;
use cdk_common::{Amount, PublicKey, SecretKey};
use pops_core_verify::challenge::{encode_charge_request, CashuRequirement};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The exact charge every scenario uses.
const CHARGE_AMOUNT: u64 = 600;
/// The held `--token`'s total value (> charge ⟹ the swap path runs, with change).
const TOKEN_TOTAL: u64 = 1000;
/// The pop unit under test.
fn pop_unit() -> CurrencyUnit {
    CurrencyUnit::Custom("pop_1788000000".to_string())
}

/// What the stub gateway should do on the AUTHENTICATED retry.
#[derive(Clone, Copy, Debug)]
enum RetryBehavior {
    /// Answer 200 with a resource body (happy path).
    Ok200,
    /// Answer a non-2xx status with a rejection body (gateway rejected).
    Reject(u16),
    /// Drop the connection without responding (transport error on `.send()`).
    Drop,
}

/// The mint's keyset material: a real signing keyset so the swap is genuine.
struct TestMint {
    keyset: MintKeySet,
}

impl TestMint {
    fn new() -> Self {
        let secp = Secp256k1::new();
        // A deterministic-enough xpriv from fixed seed bytes (test-only).
        let xpriv = Xpriv::new_master(Network::Regtest, &[7u8; 32]).expect("xpriv");
        // Power-of-two denominations covering 600/400 splits.
        let amounts: Vec<u64> = (0..11).map(|i| 1u64 << i).collect(); // 1..1024
        let keyset = MintKeySet::generate(
            &secp,
            xpriv,
            pop_unit(),
            &amounts,
            0, // 0-fee pop keyset
            None,
            KeySetVersion::Version00,
        );
        TestMint { keyset }
    }

    fn id(&self) -> Id {
        self.keyset.id
    }

    /// Public `Keys` map (for `/v1/keys` + the input token's wire fidelity).
    fn public_keys(&self) -> Keys {
        Keys::from(self.keyset.keys.clone())
    }

    /// The `/v1/keysets` info row (active, this unit).
    fn keyset_info(&self) -> KeySetInfo {
        KeySetInfo {
            id: self.id(),
            unit: pop_unit(),
            active: true,
            input_fee_ppk: 0,
            final_expiry: None,
        }
    }

    /// The `/v1/keys/<id>` keyset row.
    fn keyset_keys(&self) -> KeySet {
        KeySet {
            id: self.id(),
            unit: pop_unit(),
            active: Some(true),
            keys: self.public_keys(),
            input_fee_ppk: 0,
            final_expiry: None,
        }
    }

    /// Signs the swap outputs and returns the response. Ignores input validity
    /// (a stub) — it only signs the requested blinded outputs, DLEQ-valid.
    fn sign_swap(&self, req: &SwapRequest) -> SwapResponse {
        let mut sigs: Vec<BlindSignature> = Vec::with_capacity(req.outputs().len());
        for bm in req.outputs() {
            let pair = self
                .keyset
                .keys
                .get(&bm.amount)
                .unwrap_or_else(|| panic!("stub mint has no key for amount {}", bm.amount));
            let c = sign_message(&pair.secret_key, &bm.blinded_secret).expect("sign");
            let sig = BlindSignature::new(
                bm.amount,
                c,
                self.id(),
                &bm.blinded_secret,
                pair.secret_key.clone(),
            )
            .expect("dleq");
            sigs.push(sig);
        }
        SwapResponse::new(sigs)
    }
}

/// Builds a structurally-valid `cashuB` input token worth `TOKEN_TOTAL` on the
/// mint's keyset. The proof `C` values are dummy points (the stub mint never
/// verifies inputs); what matters is the mint url, unit, keyset id, and amounts.
fn build_input_token(mint: &TestMint, mint_url: &str) -> String {
    // Greedy power-of-two split of TOKEN_TOTAL into keyset denominations.
    let mut remaining = TOKEN_TOTAL;
    let mut denoms: Vec<u64> = Vec::new();
    let mut bit = 1u64 << 20;
    while bit > 0 {
        if remaining >= bit {
            denoms.push(bit);
            remaining -= bit;
        }
        bit >>= 1;
    }
    assert_eq!(remaining, 0, "TOKEN_TOTAL must split into pow2 denoms");

    let id = mint.id();
    let proofs: Proofs = denoms
        .into_iter()
        .map(|amt| {
            let dummy_c: PublicKey = SecretKey::generate().public_key();
            Proof::new(Amount::from(amt), id, Secret::generate(), dummy_c)
        })
        .collect();

    let mint_url_typed = MintUrl::from_str(mint_url).expect("mint url");
    Token::new(mint_url_typed, proofs, None, pop_unit()).to_string()
}

/// The `WWW-Authenticate: Payment …` header value for a charge of `CHARGE_AMOUNT`
/// in `pop_unit()` accepting exactly `mint_url`. The `request` param is the
/// `draft-cashu-charge-01` request object.
fn challenge_header(mint_url: &str) -> String {
    let req = CashuRequirement {
        unit: pop_unit(),
        mints: vec![MintUrl::from_str(mint_url).expect("mint url")],
        amount: Amount::from(CHARGE_AMOUNT),
        external_id: Some("ch-recovery".to_string()),
        description: None,
    };
    let request = encode_charge_request(&req).expect("requirement encodes");
    format!(
        r#"Payment id="ch-recovery", realm="pops", method="cashu", intent="charge", request="{request}""#
    )
}

/// Reads an HTTP request head (until CRLFCRLF), then the body of declared
/// Content-Length (if any). Returns `(request_line, headers_lower, body)`.
async fn read_http_request(
    stream: &mut TcpStream,
) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Read until we have the header terminator.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_string();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }
    // Read the rest of the body up to content_length.
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some((request_line, headers, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn write_response(
    stream: &mut TcpStream,
    status_line: &str,
    extra_headers: &str,
    body: &str,
) {
    let resp = format!(
        "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Runs the stub server until the `pay` flow completes (it serves a fixed,
/// finite sequence of requests then stops). Returns the bound base URL via the
/// channel. Lives on its own current-thread tokio runtime in a background
/// thread so the test body can shell out to `pop` synchronously.
fn spawn_stub(retry: RetryBehavior) -> String {
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let base = format!("http://127.0.0.1:{port}");
            tx.send(base.clone()).expect("send base");

            let mint = TestMint::new();

            // Serve until the authenticated retry has been handled (then exit).
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let Some((request_line, headers, body)) = read_http_request(&mut stream).await
                else {
                    continue;
                };
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let has_auth = headers.iter().any(|(k, _)| k == "authorization");

                if path.starts_with("/v1/keysets") {
                    let body = serde_json::json!({ "keysets": [mint.keyset_info()] });
                    write_response(
                        &mut stream,
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        &body.to_string(),
                    )
                    .await;
                    continue;
                }
                if path.starts_with("/v1/keys/") {
                    let body = serde_json::json!({ "keysets": [mint.keyset_keys()] });
                    write_response(
                        &mut stream,
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        &body.to_string(),
                    )
                    .await;
                    continue;
                }
                if path.starts_with("/v1/swap") && method == "POST" {
                    let req: SwapRequest = serde_json::from_slice(&body).expect("swap req parse");
                    let resp = mint.sign_swap(&req);
                    let body = serde_json::to_string(&resp).expect("swap resp ser");
                    write_response(
                        &mut stream,
                        "200 OK",
                        "Content-Type: application/json\r\n",
                        &body,
                    )
                    .await;
                    continue;
                }

                // The protected resource.
                if !has_auth {
                    // Initial hit → 402 with the challenge.
                    let hdr = challenge_header(&base);
                    let extra = format!("WWW-Authenticate: {hdr}\r\n");
                    write_response(
                        &mut stream,
                        "402 Payment Required",
                        &extra,
                        "payment required",
                    )
                    .await;
                    continue;
                }

                // Authenticated retry → scenario behavior, then stop serving.
                match retry {
                    RetryBehavior::Ok200 => {
                        write_response(&mut stream, "200 OK", "", "RESOURCE-BODY-OK").await;
                    }
                    RetryBehavior::Reject(code) => {
                        let line = format!("{code} Rejected");
                        write_response(&mut stream, &line, "", "gateway says: still owe").await;
                    }
                    RetryBehavior::Drop => {
                        // Drop the stream WITHOUT responding → reqwest `.send()`
                        // (or body read) sees a transport error.
                        drop(stream);
                    }
                }
                break;
            }
        });
    });
    rx.recv().expect("stub base url")
}

/// Path to the compiled `pop` binary under test.
fn pop_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pop")
}

struct PayOutput {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Runs `pop pay <url> --token <tok> [--human]` against the stub and returns I/O.
fn run_pay(base: &str, token: &str, human: bool) -> PayOutput {
    let url = format!("{base}/resource");
    let mut cmd = std::process::Command::new(pop_bin());
    cmd.arg("pay").arg(&url).arg("--token").arg(token);
    if human {
        cmd.arg("--human");
    }
    // A throwaway wallet dir (pay reads none, but keep HOME from escaping).
    let dir = tempfile::tempdir().expect("tempdir");
    cmd.arg("--wallet-dir").arg(dir.path()).env_remove("HOME");
    let out = cmd.output().expect("spawn pop");
    PayOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn parse_json(stdout: &str) -> serde_json::Value {
    let t = stdout.trim_end_matches('\n');
    serde_json::from_str(t).unwrap_or_else(|e| panic!("stdout not single json: {e}\n{stdout}"))
}

// ---------------------------------------------------------------------------
// (a) swap → retry transport error → BOTH tokens in json AND human.
// ---------------------------------------------------------------------------

#[test]
fn swap_then_retry_transport_error_surfaces_both_tokens_json() {
    let base = spawn_stub(RetryBehavior::Drop);
    let mint = TestMint::new();
    let token = build_input_token(&mint, &base);

    let out = run_pay(&base, &token, false);
    // gateway_retry_failed is token-bearing (VALUE AT RISK): exit 6.
    assert_eq!(
        out.code, 6,
        "expected value-at-risk exit 6; stderr:\n{}",
        out.stderr
    );
    let v = parse_json(&out.stdout);
    let err = &v["error"];
    assert_eq!(err["code"], serde_json::json!("gateway_retry_failed"));
    // CRITICAL: NOT retriable — the input proofs are already spent.
    assert_eq!(err["retriable"], serde_json::json!(false));
    // BOTH tokens present and non-empty.
    let send = err["details"]["send_token"].as_str().expect("send_token");
    let change = err["details"]["change_token"]
        .as_str()
        .expect("change_token");
    assert!(send.starts_with("cashuB"), "send_token is a cashuB: {send}");
    assert!(
        change.starts_with("cashuB"),
        "change_token is a cashuB: {change}"
    );
    assert_ne!(send, change, "send and change are distinct tokens");
}

#[test]
fn swap_then_retry_transport_error_surfaces_both_tokens_human() {
    let base = spawn_stub(RetryBehavior::Drop);
    let mint = TestMint::new();
    let token = build_input_token(&mint, &base);

    let out = run_pay(&base, &token, true);
    // gateway_retry_failed is token-bearing (VALUE AT RISK): exit 6.
    assert_eq!(out.code, 6, "expected value-at-risk exit 6");
    // Human mode prints NOTHING parseable on stdout for errors.
    assert!(
        out.stdout.trim().is_empty(),
        "human errors go to stderr; stdout:\n{}",
        out.stdout
    );
    // BOTH cashuB tokens must appear verbatim on stderr (recoverable in human mode).
    let cashu_count = out.stderr.matches("cashuB").count();
    assert!(
        cashu_count >= 2,
        "human stderr must print BOTH recovery tokens; got {cashu_count}:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("send token"),
        "labels the send token:\n{}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// (b) swap → gateway rejects → BOTH tokens in json AND human.
// ---------------------------------------------------------------------------

#[test]
fn swap_then_gateway_reject_surfaces_both_tokens_json() {
    for code in [402u16, 500u16] {
        let base = spawn_stub(RetryBehavior::Reject(code));
        let mint = TestMint::new();
        let token = build_input_token(&mint, &base);

        let out = run_pay(&base, &token, false);
        // gateway_rejected_payment is token-bearing (VALUE AT RISK): exit 6.
        assert_eq!(
            out.code, 6,
            "expected value-at-risk exit 6 ({code}); stderr:\n{}",
            out.stderr
        );
        let v = parse_json(&out.stdout);
        let err = &v["error"];
        assert_eq!(
            err["code"],
            serde_json::json!("gateway_rejected_payment"),
            "status {code} maps to gateway_rejected_payment"
        );
        assert_eq!(err["retriable"], serde_json::json!(false));
        assert_eq!(err["details"]["status"], serde_json::json!(code));
        let send = err["details"]["send_token"]
            .as_str()
            .expect("send_token present");
        let change = err["details"]["change_token"]
            .as_str()
            .expect("change_token present");
        assert!(send.starts_with("cashuB"));
        assert!(change.starts_with("cashuB"));
        assert_ne!(send, change);
    }
}

#[test]
fn swap_then_gateway_reject_surfaces_both_tokens_human() {
    let base = spawn_stub(RetryBehavior::Reject(402));
    let mint = TestMint::new();
    let token = build_input_token(&mint, &base);

    let out = run_pay(&base, &token, true);
    // gateway_rejected_payment is token-bearing (VALUE AT RISK): exit 6.
    assert_eq!(out.code, 6, "expected value-at-risk exit 6");
    assert!(out.stdout.trim().is_empty(), "human errors go to stderr");
    let cashu_count = out.stderr.matches("cashuB").count();
    assert!(
        cashu_count >= 2,
        "human stderr must print BOTH recovery tokens; got {cashu_count}:\n{}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// (c) swap → gateway 200 → change_token surfaced (json AND human).
// ---------------------------------------------------------------------------

#[test]
fn swap_then_success_surfaces_change_token_json() {
    let base = spawn_stub(RetryBehavior::Ok200);
    let mint = TestMint::new();
    let token = build_input_token(&mint, &base);

    let out = run_pay(&base, &token, false);
    assert_eq!(
        out.code, 0,
        "expected success exit; stderr:\n{}",
        out.stderr
    );
    let v = parse_json(&out.stdout);
    assert_eq!(v["paid"], serde_json::json!(true));
    assert_eq!(v["amount"], serde_json::json!(CHARGE_AMOUNT));
    let change = v["change_token"].as_str().expect("change_token surfaced");
    assert!(change.starts_with("cashuB"), "change is a cashuB: {change}");
    assert_eq!(v["body"], serde_json::json!("RESOURCE-BODY-OK"));
}

#[test]
fn swap_then_success_surfaces_change_token_human() {
    let base = spawn_stub(RetryBehavior::Ok200);
    let mint = TestMint::new();
    let token = build_input_token(&mint, &base);

    let out = run_pay(&base, &token, true);
    assert_eq!(
        out.code, 0,
        "expected success exit; stderr:\n{}",
        out.stderr
    );
    // Success prints to stdout in human mode; the change token must be there.
    assert!(
        out.stdout.contains("PAID"),
        "human success says PAID:\n{}",
        out.stdout
    );
    let cashu_count = out.stdout.matches("cashuB").count();
    assert!(
        cashu_count >= 1,
        "human success must print the change token; got {cashu_count}:\n{}",
        out.stdout
    );
    assert!(out.stdout.contains("RESOURCE-BODY-OK"));
}
