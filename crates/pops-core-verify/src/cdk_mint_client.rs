//! Real `cdk`-backed [`MintClient`] implementation (native only).
//!
//! Wraps [`cdk::wallet::HttpClient`] — the same HTTP surface the cdk
//! wallet uses to talk to a mint — and exposes only the calls the verify
//! core needs: `/v1/keysets`, `/v1/keys/{id}`, and `/v1/swap`.
//!
//! A fresh [`cdk::wallet::HttpClient`] is constructed per call. Mints
//! are addressed by the [`MintUrl`] passed in; the validator (or its
//! caller) decides which mint to talk to per token, so caching a
//! pinned client on this struct would be wrong.
//!
//! **Error mapping.** `cdk::Error` is a large enum covering wallet
//! storage, signatures, parsing, transport, and mint responses. We
//! collapse it into the coarse [`MintClientError`] split the
//! validator cares about:
//!
//! * [`cdk::Error::is_definitive_failure`] true → [`MintClientError::RejectedSwap`]
//!   (HTTP 4xx, crypto/parse errors, anything the mint definitely
//!   refused on its end).
//! * False → [`MintClientError::Unreachable`] (HTTP 5xx, transport,
//!   timeout, ambiguous network condition). Re-trying may succeed.
//!
//! **Swap ceremony.** The blinded-output generation + `construct_proofs`
//! unblind live in the transport-generic
//! [`swap_to_redeem`] helper;
//! `CdkMintClient` supplies only the three raw HTTP calls via [`MintHttp`] and
//! delegates [`MintClient::swap`] to that shared ceremony. The wasm client
//! (`WasmMintClient`) drives the
//! *same* ceremony over an injected `fetch`.
//!
//! The implementation assumes a zero-fee keyset (PoP v1 fixes fees at 0).

use std::time::Duration;

use async_trait::async_trait;
use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeysetResponse};
use cashu::nuts::nut03::{SwapRequest, SwapResponse};
use cashu::{MintUrl, Proofs};
use cdk::wallet::{HttpClient, MintConnector};

use crate::mint_client::{MintClient, MintClientError, SwapOutcome};
use crate::swap_ceremony::{swap_to_redeem, MintHttp};

/// Default bound on each mint HTTP call (keysets / keys / swap), 10 s. A mint
/// that never answers must surface as the 503 mint-unavailable path, not hang
/// the request indefinitely.
pub const DEFAULT_MINT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// `cdk`-backed [`MintClient`].
///
/// Holds only the per-call HTTP timeout — every call builds a fresh
/// [`cdk::wallet::HttpClient`] for the supplied [`MintUrl`]. Stateless
/// design keeps the validator free to talk to many mints without a
/// per-mint registration step.
#[derive(Debug, Clone, Copy)]
pub struct CdkMintClient {
    /// Bound on each individual mint HTTP call.
    timeout: Duration,
}

impl Default for CdkMintClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CdkMintClient {
    /// Construct with the [`DEFAULT_MINT_HTTP_TIMEOUT`]. Costs nothing; the
    /// actual [`HttpClient`] is built per request inside the trait methods.
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_MINT_HTTP_TIMEOUT)
    }

    /// Construct with an explicit per-call mint HTTP timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// The configured per-call mint HTTP timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Build the per-mint [`HttpClient`] used to issue HTTP calls.
    /// Kept private so callers cannot accidentally hold onto an
    /// HttpClient pinned to one mint.
    fn http(mint_url: &MintUrl) -> HttpClient {
        HttpClient::new(mint_url.clone(), None)
    }

    /// Run `fut` (one mint HTTP call) under the configured timeout. Elapsed →
    /// [`MintClientError::Unreachable`]: the same transport-failure arm a
    /// connect failure takes, so the existing 503 + consumed-vs-unknown
    /// contract applies unchanged (the ceremony re-tags a swap-POST failure as
    /// indeterminate; the pre-POST GETs stay determinate).
    async fn bounded<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, cdk::Error>>,
    ) -> Result<T, MintClientError> {
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(result) => result.map_err(map_cdk_err),
            Err(_elapsed) => Err(MintClientError::Unreachable(format!(
                "mint HTTP call timed out after {:?}",
                self.timeout
            ))),
        }
    }
}

/// Translate a [`cdk::Error`] into the coarse [`MintClientError`]
/// the validator understands.
///
/// The keyset-class variants come first: cdk's transport parses the mint's
/// NUT error body (`{"code", "detail"}`) and maps code 12001
/// (keyset-not-known) → [`cdk::Error::UnknownKeySet`] and 12002
/// (keyset-inactive) → [`cdk::Error::InactiveKeyset`];
/// [`cdk::Error::KeysetUnknown`] is cdk's wallet-local twin of 12001. All
/// three mean the keyset has retired or its `final_expiry` has passed — a
/// `verification-failed` swap rejection per `draft-cashu-charge-01` step 8,
/// kept in its own arm so the cause is named in the problem `detail`. No
/// registered NUT error code names `final_expiry` itself, so these keyset
/// codes are the entire wire signal; a mint rejecting an expired keyset under
/// any other code stays in the rejected catch-all, also `verification-failed`.
///
/// The already-spent rejection (NUT code 11001 → [`cdk::Error::TokenAlreadySpent`])
/// keeps its own arm so the spent case carries the honest double-spend detail;
/// the rest split on `is_definitive_failure` (4xx and parse/crypto errors →
/// rejected; 5xx/timeout/transport → unreachable).
fn map_cdk_err(e: cdk::Error) -> MintClientError {
    if matches!(e, cdk::Error::TokenAlreadySpent) {
        MintClientError::AlreadySpent(e.to_string())
    } else if matches!(
        e,
        cdk::Error::UnknownKeySet | cdk::Error::KeysetUnknown(_) | cdk::Error::InactiveKeyset
    ) {
        MintClientError::KeysetRetiredOrExpired(e.to_string())
    } else if e.is_definitive_failure() {
        MintClientError::RejectedSwap(e.to_string())
    } else {
        MintClientError::Unreachable(e.to_string())
    }
}

/// The raw mint HTTP, via cdk's [`HttpClient`]/[`MintConnector`]. These three
/// methods are the entire native transport surface the shared swap ceremony
/// ([`swap_to_redeem`]) drives.
#[async_trait]
impl MintHttp for CdkMintClient {
    async fn get_keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<KeysetResponse, MintClientError> {
        self.bounded(Self::http(mint_url).get_mint_keysets()).await
    }

    async fn get_keyset_keys(
        &self,
        mint_url: &MintUrl,
        keyset_id: Id,
    ) -> Result<KeySet, MintClientError> {
        self.bounded(Self::http(mint_url).get_mint_keyset(keyset_id))
            .await
    }

    async fn post_swap(
        &self,
        mint_url: &MintUrl,
        request: SwapRequest,
    ) -> Result<SwapResponse, MintClientError> {
        self.bounded(Self::http(mint_url).post_swap(request)).await
    }
}

#[async_trait]
impl MintClient for CdkMintClient {
    async fn keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<Vec<KeySetInfo>, MintClientError> {
        Ok(self.get_keysets(mint_url).await?.keysets)
    }

    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<SwapOutcome, MintClientError> {
        // Delegate to the transport-generic ceremony: the crypto is shared with
        // the wasm client; this struct supplies only the raw HTTP above.
        swap_to_redeem(self, mint_url, proofs).await
    }
}

#[cfg(test)]
mod tests {
    //! Mint-HTTP-timeout behavior against REAL local listeners (the whole
    //! reqwest/cdk transport stack runs): a mint that accepts but never
    //! answers must surface as `Unreachable` within the configured bound
    //! (pre-swap GET = determinate), and a mint that answers the GETs but
    //! hangs on the swap POST must surface as `UnreachableIndeterminate`
    //! (inputs submitted, outcome unknown) — the consumed-vs-unknown contract
    //! unchanged under timeout.

    use std::str::FromStr;
    use std::time::{Duration, Instant};

    use axum::routing::{get, post};
    use axum::Router;
    use cashu::dhke::hash_to_curve;
    use cashu::nuts::nut01::Keys;
    use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeysetResponse};
    use cashu::nuts::KeysResponse;
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proof, PublicKey, SecretKey};

    use super::{map_cdk_err, CdkMintClient, DEFAULT_MINT_HTTP_TIMEOUT};
    use crate::mint_client::{MintClient, MintClientError};

    // ---- the cdk::Error → MintClientError classification --------------------
    //
    // What cdk 0.16 exposes for the spec's step-8 cause classification: its transport parses
    // the mint's NUT error body and surfaces the two REGISTERED keyset codes as
    // typed variants — 12001 keyset-not-known → `cdk::Error::UnknownKeySet`,
    // 12002 keyset-inactive → `cdk::Error::InactiveKeyset` (plus the
    // wallet-local `KeysetUnknown(Id)` twin). There is NO registered NUT error
    // code for "final_expiry passed" specifically, so those keyset codes are
    // the entire honest wire signal for "keyset retired or expired".
    // Already-spent (11001 → `TokenAlreadySpent`) is the one OTHER typed
    // rejection, kept distinct so its detail can honestly say double-spend;
    // every remaining definitive rejection stays in the `RejectedSwap`
    // catch-all. Both map to the spec's else-branch `verification-failed`.

    #[test]
    fn keyset_class_cdk_errors_classify_as_retired_or_expired() {
        for e in [
            cdk::Error::UnknownKeySet,
            cdk::Error::KeysetUnknown(keyset_id()),
            cdk::Error::InactiveKeyset,
        ] {
            let detail = e.to_string();
            match map_cdk_err(e) {
                MintClientError::KeysetRetiredOrExpired(msg) => {
                    assert_eq!(msg, detail, "the cdk detail must be carried through")
                }
                other => panic!("expected KeysetRetiredOrExpired, got {other:?}"),
            }
        }
    }

    #[test]
    fn already_spent_classifies_as_its_own_spent_arm() {
        // 11001 is the ONE rejection cdk types as already-spent; it carries the
        // honest double-spend detail downstream.
        assert!(
            matches!(
                map_cdk_err(cdk::Error::TokenAlreadySpent),
                MintClientError::AlreadySpent(_)
            ),
            "a typed already-spent rejection must classify as AlreadySpent"
        );
    }

    #[test]
    fn other_definitive_rejections_stay_rejected_swap() {
        for e in [
            cdk::Error::TransactionUnbalanced(10, 8, 0),
            cdk::Error::HttpError(Some(400), "Bad Request".into()),
        ] {
            assert!(
                matches!(map_cdk_err(e), MintClientError::RejectedSwap(_)),
                "a non-keyset, non-spent definitive rejection must stay RejectedSwap"
            );
        }
    }

    #[test]
    fn ambiguous_cdk_errors_stay_unreachable() {
        for e in [
            cdk::Error::Timeout,
            cdk::Error::HttpError(Some(503), "Service Unavailable".into()),
            cdk::Error::HttpError(None, "connection refused".into()),
        ] {
            assert!(
                matches!(map_cdk_err(e), MintClientError::Unreachable(_)),
                "an ambiguous transport condition must stay Unreachable"
            );
        }
    }

    #[test]
    fn default_timeout_is_ten_seconds() {
        // The build contract's default bound on each mint HTTP call.
        assert_eq!(DEFAULT_MINT_HTTP_TIMEOUT, Duration::from_secs(10));
        assert_eq!(CdkMintClient::new().timeout(), Duration::from_secs(10));
    }

    #[test]
    fn with_timeout_is_respected() {
        assert_eq!(
            CdkMintClient::with_timeout(Duration::from_millis(250)).timeout(),
            Duration::from_millis(250)
        );
    }

    /// Bind a listener that ACCEPTS connections and then never writes a byte.
    async fn hung_listener() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hung listener");
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
        port
    }

    fn mint_url_for(port: u16) -> MintUrl {
        MintUrl::from_str(&format!("http://127.0.0.1:{port}")).expect("local mint url")
    }

    #[tokio::test]
    async fn hung_mint_keysets_times_out_as_determinate_unreachable() {
        let port = hung_listener().await;
        let client = CdkMintClient::with_timeout(Duration::from_millis(250));

        let started = Instant::now();
        let err = client
            .keysets(&mint_url_for(port))
            .await
            .expect_err("a mint that never answers must error");
        let elapsed = started.elapsed();

        match err {
            MintClientError::Unreachable(msg) => {
                assert!(
                    msg.contains("timed out"),
                    "the error should name the timeout, got: {msg}"
                );
            }
            other => panic!("a pre-swap GET timeout is DETERMINATE Unreachable, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "must give up within the 250ms bound plus margin, took {elapsed:?}"
        );
    }

    // ---- the answering-then-hanging mint (swap-POST timeout) ----------

    /// Deterministic per-amount mint secret key (same construction as the
    /// ceremony's mock: amount into the low bytes of a fixed non-zero scalar).
    fn mint_secret_for_amount(amount: u64) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x11;
        bytes[31] = amount as u8;
        bytes[30] = (amount >> 8) as u8;
        SecretKey::from_slice(&bytes).expect("non-zero scalar is a valid secret key")
    }

    fn test_unit() -> CurrencyUnit {
        CurrencyUnit::Custom("pop_1700000000".to_string())
    }

    fn public_keys() -> Keys {
        let map = [1u64, 2, 4, 8]
            .into_iter()
            .map(|a| {
                let pk: PublicKey = mint_secret_for_amount(a).public_key();
                (Amount::from(a), pk)
            })
            .collect();
        Keys::new(map)
    }

    fn keyset_id() -> Id {
        Id::v1_from_keys(&public_keys())
    }

    /// A real axum mint serving NUT-02 keysets + NUT-01 keys, with the supplied
    /// NUT-03 swap route.
    async fn mint_with_swap_route(swap_route: axum::routing::MethodRouter) -> u16 {
        let keysets_body = serde_json::to_string(&KeysetResponse {
            keysets: vec![KeySetInfo {
                id: keyset_id(),
                unit: test_unit(),
                active: true,
                input_fee_ppk: 0,
                final_expiry: None,
            }],
        })
        .expect("keysets serialize");
        let keys_body = serde_json::to_string(&KeysResponse {
            keysets: vec![KeySet {
                id: keyset_id(),
                unit: test_unit(),
                active: Some(true),
                keys: public_keys(),
                input_fee_ppk: 0,
                final_expiry: None,
            }],
        })
        .expect("keys serialize");

        let json = |body: String| ([(http::header::CONTENT_TYPE, "application/json")], body);
        let app = Router::new()
            .route(
                "/v1/keysets",
                get(move || async move { json(keysets_body.clone()) }),
            )
            .route(
                "/v1/keys/:id",
                get(move || async move { json(keys_body.clone()) }),
            )
            .route("/v1/swap", swap_route);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock mint");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock mint");
        });
        port
    }

    /// The mint whose swap endpoint never responds.
    async fn hang_on_swap_mint() -> u16 {
        mint_with_swap_route(post(|| async {
            std::future::pending::<String>().await
        }))
        .await
    }

    /// A mint whose swap endpoint answers HTTP 400 with the given NUT error
    /// body (`{"code": <u16>, "detail": "…"}`).
    async fn reject_swap_mint(error_body: &'static str) -> u16 {
        mint_with_swap_route(post(move || async move {
            (
                http::StatusCode::BAD_REQUEST,
                [(http::header::CONTENT_TYPE, "application/json")],
                error_body,
            )
        }))
        .await
    }

    /// An input proof on the advertised keyset (the C point is arbitrary; the
    /// hang happens before any input validation).
    fn input_proof(amount: u64, index: u8) -> Proof {
        let mut preimage = [0u8; 33];
        preimage[0] = 2;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id(), Secret::generate(), c)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hung_swap_post_times_out_as_indeterminate() {
        // The GETs answer, the swap POST hangs: the inputs were SUBMITTED, so
        // the timeout must surface as INDETERMINATE — the operator must
        // checkstate, never assume the token is still good.
        let port = hang_on_swap_mint().await;
        let client = CdkMintClient::with_timeout(Duration::from_millis(500));

        let started = Instant::now();
        let err = client
            .swap(
                &mint_url_for(port),
                vec![input_proof(8, 0), input_proof(2, 1)],
            )
            .await
            .expect_err("a hung swap POST must error");
        let elapsed = started.elapsed();

        assert!(
            matches!(err, MintClientError::UnreachableIndeterminate(_)),
            "a swap-POST timeout must be re-tagged indeterminate, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "must give up within the bound plus margin, took {elapsed:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn swap_rejected_with_keyset_inactive_code_classifies_as_expired() {
        // The whole wire path: the mint answers the swap POST with NUT error
        // code 12002 (keyset-inactive); cdk's transport parses the body into
        // `InactiveKeyset`, and the client surfaces the Expired classification
        // (a verification-failed condition on the wire).
        let port =
            reject_swap_mint(r#"{"code":12002,"detail":"Keyset is inactive"}"#).await;
        let client = CdkMintClient::new();

        let err = client
            .swap(
                &mint_url_for(port),
                vec![input_proof(8, 0), input_proof(2, 1)],
            )
            .await
            .expect_err("a 12002-rejected swap must error");
        match err {
            MintClientError::KeysetRetiredOrExpired(msg) => {
                assert!(
                    msg.contains("Inactive Keyset"),
                    "cdk's typed detail must surface, got: {msg}"
                );
            }
            other => panic!("expected KeysetRetiredOrExpired, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn swap_rejected_with_already_spent_code_classifies_as_spent() {
        // NUT error code 11001 (token already spent) is the spec's
        // verification-failed family with the spent-specific detail — it must
        // NOT classify as expired, nor collapse into the neutral catch-all.
        let port =
            reject_swap_mint(r#"{"code":11001,"detail":"Token is already spent"}"#).await;
        let client = CdkMintClient::new();

        let err = client
            .swap(
                &mint_url_for(port),
                vec![input_proof(8, 0), input_proof(2, 1)],
            )
            .await
            .expect_err("an 11001-rejected swap must error");
        assert!(
            matches!(err, MintClientError::AlreadySpent(_)),
            "an already-spent rejection must classify as AlreadySpent, got {err:?}"
        );
    }
}
