//! Mint client abstraction used by the verify core. A successful swap proves the
//! proofs are unexpired (`final_expiry`) and unspent (nullifier replay), yielding
//! new proofs under the verifier's secrets — the charge is transfer-on-use.
//!
//! The trait takes [`MintUrl`] + [`Proofs`] (not a decoded [`Token`][cashu::Token])
//! so implementations fetch keyset info up front; [`MintClient::keysets`] is its
//! own method because V1 short keyset IDs need the full [`KeySetInfo`] list to
//! resolve before [`Token::proofs`][cashu::Token::proofs] returns them.
//!
//! `?Send` on wasm32, `Send + Sync` on native (so the validator can be shared
//! across async tasks). A concrete `cdk`-backed impl lives in
//! [`crate::cdk_mint_client`].

use async_trait::async_trait;
use cashu::nuts::nut02::KeySetInfo;
use cashu::{MintUrl, Proofs};
use thiserror::Error;

/// Abstraction over the calls the verify core makes to a Cashu mint.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait MintClient: Send + Sync {
    /// Fetch the mint's keyset list (to resolve V1 short keyset IDs; without a
    /// matching [`KeySetInfo`] the proofs cannot decode). An empty `Vec` is valid
    /// ("no V1 IDs resolvable"), not an error.
    async fn keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<Vec<KeySetInfo>, MintClientError>;

    /// Swap `proofs` for new verifier-held proofs. The mint atomically consumes
    /// the inputs (failing if spent/expired/invalid).
    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<Proofs, MintClientError>;
}

/// Abstraction over the calls the verify core makes to a Cashu mint
/// (`wasm32` variant: `?Send` futures, single-threaded).
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait MintClient {
    /// Fetch the mint's keyset list. See the native variant for details.
    async fn keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<Vec<KeySetInfo>, MintClientError>;

    /// Swap `proofs` at `mint_url` for new proofs. See the native variant.
    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<Proofs, MintClientError>;
}

/// Errors returned by [`MintClient`] implementations.
#[derive(Debug, Error)]
pub enum MintClientError {
    /// Mint unreachable on a DETERMINATE call — BEFORE the swap inputs were
    /// submitted (a GET, or a connect failure that never left our side). The
    /// token was NOT consumed; retry with the SAME token is authoritative.
    #[error("mint unreachable: {0}")]
    Unreachable(String),

    /// A transport failure on the swap POST ITSELF (5xx / read-timeout AFTER
    /// sending), so the outcome is INDETERMINATE: the mint MAY have consumed the
    /// inputs. Kept distinct so the validator surfaces `indeterminate: true` —
    /// same 503+retry, but the operator MUST checkstate before assuming the token
    /// is good (spec §Durability). Raised ONLY around `post_swap`.
    #[error("mint unreachable (indeterminate swap outcome): {0}")]
    UnreachableIndeterminate(String),

    /// The mint refused the swap (expired, double-spent, bad signature, keyset
    /// rotated, etc.).
    #[error("mint rejected swap: {0}")]
    RejectedSwap(String),

    /// A returned blind signature failed DLEQ verification (NUT-12 proof MISSING
    /// or INVALID against the advertised key).
    ///
    /// SECURITY-CRITICAL, deliberately distinct from [`Self::RejectedSwap`]: the
    /// mint did NOT prove it signed the outputs with the advertised key, so the
    /// proofs are not provably valid bearer value and MUST NOT be redeemed (no
    /// redeemed value without a verified DLEQ). Maps to `DleqInvalid { SwapOutput }`
    /// (402, resource not served), NOT a double-spend.
    #[error("swap-output DLEQ verification failed: {0}")]
    SwapOutputDleqInvalid(String),
}
