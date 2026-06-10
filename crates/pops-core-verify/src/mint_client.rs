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

/// What a successful swap yields: the fresh verifier-held proofs plus the
/// NUT-12 verdict on the blind signatures the mint returned.
///
/// `dleq_ok: false` is a MINT-TRUST INCIDENT, not a payment failure
/// (`draft-cashu-charge-01` §security-dleq): the client's inputs were genuine
/// and were consumed by the successful swap; only the mint controls the
/// signatures it returns. Callers serve the resource, surface the flag to the
/// operator (alert + quarantine the mint), and MUST NOT answer with a payment
/// failure — the swap succeeded, so a 402 here would charge the client twice
/// for a settled payment.
#[derive(Debug, Clone)]
pub struct SwapOutcome {
    /// The unblinded swap outputs, under fresh verifier secrets.
    pub proofs: Proofs,
    /// Whether EVERY swap-returned blind signature carried a NUT-12 DLEQ that
    /// verifies against the active keyset's advertised key. `false` = missing
    /// or invalid on at least one signature.
    pub dleq_ok: bool,
}

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
    /// the inputs (failing if spent/expired/invalid). The returned
    /// [`SwapOutcome::dleq_ok`] reports the swap-output DLEQ verdict.
    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<SwapOutcome, MintClientError>;
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
    ) -> Result<SwapOutcome, MintClientError>;
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
    /// is good. Raised ONLY around `post_swap`.
    #[error("mint unreachable (indeterminate swap outcome): {0}")]
    UnreachableIndeterminate(String),

    /// The mint refused the swap WITHOUT typing the reason as already-spent or
    /// keyset-class (bad signature, unbalanced, etc.) — the definitive-rejection
    /// catch-all. The token was NOT consumed.
    #[error("mint rejected swap: {0}")]
    RejectedSwap(String),

    /// The mint refused the swap because an input proof is ALREADY SPENT (NUT
    /// error code 11001 / `cdk::Error::TokenAlreadySpent`). Kept apart from
    /// [`Self::RejectedSwap`] so only a mint-typed double-spend ever reads as
    /// one.
    #[error("mint rejected swap: proof already spent: {0}")]
    AlreadySpent(String),

    /// The mint refused the call with a KEYSET-class error (NUT error codes
    /// 12001 keyset-not-known / 12002 keyset-inactive): the keyset has retired
    /// or its `final_expiry` has passed. `draft-cashu-charge-01` step 9 makes
    /// this a `payment-expired` condition, distinct from the double-spend /
    /// other-rejection family that is `verification-failed`. The token was NOT
    /// consumed; the client re-presents the SAME token against a fresh
    /// challenge once, then abandons it.
    #[error("mint rejected swap (keyset retired or final_expiry passed): {0}")]
    KeysetRetiredOrExpired(String),

    /// The active keyset charges an `input_fee_ppk` over the supported maximum
    /// (0 in the fee-free profile), detected BEFORE the swap is submitted. The
    /// token was NOT consumed. Distinct from [`Self::RejectedSwap`] so the
    /// policy reject never reads as a double-spend.
    #[error(
        "fee-bearing keyset {keyset_id} disallowed: input_fee_ppk {input_fee_ppk} \
         exceeds the fee-free profile"
    )]
    FeeTooHigh {
        /// Keyset whose fee exceeded the profile (hex id).
        keyset_id: String,
        /// The disallowed `input_fee_ppk` the mint publishes for it.
        input_fee_ppk: u64,
    },
}
