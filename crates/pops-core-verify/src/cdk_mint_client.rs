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
//! **Swap ceremony.** This client no longer hand-rolls the ceremony. As of
//! build-plan §3.1 the blinded-output generation + `construct_proofs` unblind
//! live in the transport-generic [`swap_to_redeem`][crate::swap_ceremony::swap_to_redeem]
//! helper; `CdkMintClient` supplies only the three raw HTTP calls via
//! [`MintHttp`] and delegates [`MintClient::swap`] to that shared ceremony.
//! The wasm client ([`WasmMintClient`][crate::wasm_mint_client::WasmMintClient])
//! drives the *same* ceremony over an injected `fetch`.
//!
//! The implementation assumes a zero-fee keyset (PoP v1 fixes fees at 0).

use async_trait::async_trait;
use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeysetResponse};
use cashu::nuts::nut03::{SwapRequest, SwapResponse};
use cashu::{MintUrl, Proofs};
use cdk::wallet::{HttpClient, MintConnector};

use crate::mint_client::{MintClient, MintClientError};
use crate::swap_ceremony::{swap_to_redeem, MintHttp};

/// `cdk`-backed [`MintClient`].
///
/// Holds no state — every call builds a fresh
/// [`cdk::wallet::HttpClient`] for the supplied [`MintUrl`]. Stateless
/// design keeps the validator free to talk to many mints without a
/// per-mint registration step.
#[derive(Debug, Default, Clone, Copy)]
pub struct CdkMintClient;

impl CdkMintClient {
    /// Construct a fresh client. Costs nothing; the actual
    /// [`HttpClient`] is built per request inside the trait methods.
    pub fn new() -> Self {
        Self
    }

    /// Build the per-mint [`HttpClient`] used to issue HTTP calls.
    /// Kept private so callers cannot accidentally hold onto an
    /// HttpClient pinned to one mint.
    fn http(mint_url: &MintUrl) -> HttpClient {
        HttpClient::new(mint_url.clone(), None)
    }
}

/// Translate a [`cdk::Error`] into the coarse [`MintClientError`]
/// the validator understands. Uses `is_definitive_failure` as the
/// split point (4xx and parse/crypto errors → rejected;
/// 5xx/timeout/transport → unreachable).
fn map_cdk_err(e: cdk::Error) -> MintClientError {
    if e.is_definitive_failure() {
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
        Self::http(mint_url)
            .get_mint_keysets()
            .await
            .map_err(map_cdk_err)
    }

    async fn get_keyset_keys(
        &self,
        mint_url: &MintUrl,
        keyset_id: Id,
    ) -> Result<KeySet, MintClientError> {
        Self::http(mint_url)
            .get_mint_keyset(keyset_id)
            .await
            .map_err(map_cdk_err)
    }

    async fn post_swap(
        &self,
        mint_url: &MintUrl,
        request: SwapRequest,
    ) -> Result<SwapResponse, MintClientError> {
        Self::http(mint_url)
            .post_swap(request)
            .await
            .map_err(map_cdk_err)
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
    ) -> Result<Proofs, MintClientError> {
        // Delegate to the transport-generic ceremony (build-plan §3.1): the
        // crypto is shared with the wasm client; this struct supplies only
        // the raw HTTP above.
        swap_to_redeem(self, mint_url, proofs).await
    }
}
