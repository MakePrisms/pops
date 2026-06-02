//! Shared NUT-03 swap ceremony — the crypto, lifted out of any one
//! transport so native (`cdk`) and wasm (injected `fetch`) clients share it.
//!
//! The ceremony (resolve the active output keyset → blind fresh outputs →
//! POST the swap → unblind the mint's signatures into spendable proofs) is
//! `cashu`-pure: it touches `PreMintSecrets::random`, `SwapRequest`, and
//! `cashu::dhke::construct_proofs`, never an HTTP type. The only thing that
//! differs between native and wasm is the *transport* — the three raw mint
//! HTTP calls — so that is the seam:
//!
//! * [`MintHttp`] is the thin raw-transport trait (`get_keysets` /
//!   `get_keyset_keys` / `post_swap`) returning `cashu` wire types.
//! * [`swap_to_redeem`] is the shared, transport-generic ceremony that holds
//!   ALL the crypto. [`CdkMintClient`][crate::cdk_mint_client::CdkMintClient]
//!   and [`WasmMintClient`][crate::wasm_mint_client::WasmMintClient] each
//!   implement only the three `MintHttp` methods and delegate their
//!   [`MintClient::swap`][crate::mint_client::MintClient::swap] to this fn.
//!
//! This is the build-plan §3.1 extraction: "lift the swap ceremony out of
//! `CdkMintClient::swap` into a SHARED helper that takes the client for HTTP
//! and keeps the crypto cashu-pure". The validator's `MintClient` seam (which
//! the unit-test mocks stub at the `swap`→`Proofs` level) is left untouched —
//! the ceremony sits a layer *below* it, between a concrete client and the
//! mint, so the 72 folded tests remain the regression guard.

use async_trait::async_trait;
use cashu::amount::{FeeAndAmounts, SplitTarget};
use cashu::dhke::construct_proofs;
use cashu::nuts::nut00::PreMintSecrets;
use cashu::nuts::nut01::Keys;
use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeySetInfosMethods, KeysetResponse};
use cashu::nuts::nut03::{SwapRequest, SwapResponse};
use cashu::nuts::ProofsMethods;
use cashu::{MintUrl, Proofs};

use crate::mint_client::MintClientError;

/// The raw mint HTTP the swap ceremony needs, abstracted so the crypto stays
/// transport-agnostic. Three calls only — the NUT-02 keyset list, a single
/// keyset's NUT-01 keys, and the NUT-03 swap.
///
/// Implementors return the `cashu` wire types and map their transport
/// failures onto the coarse [`MintClientError`] split (unreachable vs.
/// mint-refused). The ceremony in [`swap_to_redeem`] owns everything else.
///
/// On `wasm32` the trait is `#[async_trait(?Send)]` (single-threaded, matching
/// the [`MintClient`][crate::mint_client::MintClient] seam it backs); on native
/// it is `Send + Sync`.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait MintHttp: Send + Sync {
    /// `GET /v1/keysets` — the mint's keyset list (NUT-02).
    async fn get_keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<KeysetResponse, MintClientError>;

    /// `GET /v1/keys/{id}` — one keyset's signing keys (NUT-01). Used to
    /// unblind the swap response under the active output keyset.
    async fn get_keyset_keys(
        &self,
        mint_url: &MintUrl,
        keyset_id: Id,
    ) -> Result<KeySet, MintClientError>;

    /// `POST /v1/swap` — submit inputs + blinded outputs, get blind
    /// signatures back (NUT-03).
    async fn post_swap(
        &self,
        mint_url: &MintUrl,
        request: SwapRequest,
    ) -> Result<SwapResponse, MintClientError>;
}

/// `wasm32` variant of [`MintHttp`]: `?Send` futures (single-threaded).
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait MintHttp {
    /// `GET /v1/keysets` — see the native variant.
    async fn get_keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<KeysetResponse, MintClientError>;

    /// `GET /v1/keys/{id}` — see the native variant.
    async fn get_keyset_keys(
        &self,
        mint_url: &MintUrl,
        keyset_id: Id,
    ) -> Result<KeySet, MintClientError>;

    /// `POST /v1/swap` — see the native variant.
    async fn post_swap(
        &self,
        mint_url: &MintUrl,
        request: SwapRequest,
    ) -> Result<SwapResponse, MintClientError>;
}

/// Resolve the active output keyset for the unit carried on the input
/// keyset id.
///
/// Returns the active keyset's id, its signing [`Keys`] (needed to unblind
/// the swap response), and the canonical ascending denomination list (its
/// signing amounts). The input keyset may have rotated; outputs are always
/// requested against the currently-active keyset for the same unit. Errors
/// if the input keyset is unknown, no active keyset exists for the unit, or
/// the keyset charges a non-zero fee (PoP v1 is zero-fee).
///
/// Pure given the two HTTP responses the caller fetched through [`MintHttp`];
/// kept here (not on the transport) because it is ceremony logic, not I/O.
async fn resolve_output_keyset<H: MintHttp + ?Sized>(
    http: &H,
    mint_url: &MintUrl,
    input_keyset_id: Id,
) -> Result<(Id, Keys, Vec<u64>), MintClientError> {
    let keysets: Vec<KeySetInfo> = http.get_keysets(mint_url).await?.keysets;

    let input_unit = keysets
        .iter()
        .find(|k| k.id == input_keyset_id)
        .map(|k| k.unit.clone())
        .ok_or_else(|| {
            MintClientError::RejectedSwap(format!("input keyset {input_keyset_id} unknown at mint"))
        })?;

    let active_keyset = keysets
        .active()
        .find(|k| k.unit == input_unit)
        .ok_or_else(|| {
            MintClientError::RejectedSwap(format!(
                "no active keyset at mint for unit {input_unit:?}"
            ))
        })?
        .clone();

    if active_keyset.input_fee_ppk != 0 {
        return Err(MintClientError::RejectedSwap(format!(
            "active keyset {} has non-zero input_fee_ppk; PoP v1 requires zero fee",
            active_keyset.id
        )));
    }

    let active_keyset_full = http.get_keyset_keys(mint_url, active_keyset.id).await?;

    // `Keys::keys()` returns `&BTreeMap<Amount, _>` — already sorted ascending
    // by `Amount`, so its keys are the canonical denomination list the mint
    // can sign.
    let signing_amounts: Vec<u64> = active_keyset_full
        .keys
        .keys()
        .keys()
        .map(|a| u64::from(*a))
        .collect();

    Ok((active_keyset.id, active_keyset_full.keys, signing_amounts))
}

/// The shared NUT-03 swap-to-redeem ceremony.
///
/// Given a concrete [`MintHttp`] transport, the mint, and the input
/// `proofs`, this:
///
/// 1. resolves the active output keyset for the inputs' unit,
/// 2. blinds fresh outputs (`PreMintSecrets::random`) summing to the input
///    total (PoP v1 is zero-fee),
/// 3. POSTs the [`SwapRequest`], and
/// 4. unblinds the returned [`SwapResponse`] signatures via
///    [`construct_proofs`] into spendable [`Proofs`] under fresh,
///    verifier-owned secrets.
///
/// All four steps are `cashu`-pure; only the two GETs and the POST cross the
/// [`MintHttp`] seam, so native and wasm callers share this entire body. The
/// blinding RNG (`PreMintSecrets::random`) is why the `wasm` feature must
/// select a js `getrandom` backend.
pub async fn swap_to_redeem<H: MintHttp + ?Sized>(
    http: &H,
    mint_url: &MintUrl,
    proofs: Proofs,
) -> Result<Proofs, MintClientError> {
    if proofs.is_empty() {
        // Defensive: the validator short-circuits on TokenEmpty before ever
        // reaching swap, and a zero-input swap is malformed at the mint
        // anyway. Surface as RejectedSwap rather than make a wasted call.
        return Err(MintClientError::RejectedSwap(
            "cannot swap empty proof set".to_string(),
        ));
    }

    // All inputs share a unit (the validator verified that against the
    // requirement upstream); resolve the active output keyset from the first
    // input's keyset id.
    let input_keyset_id = proofs[0].keyset_id;
    let (active_keyset_id, active_keys, signing_amounts) =
        resolve_output_keyset(http, mint_url, input_keyset_id).await?;

    // Outputs must sum to the input total (PoP v1 is zero-fee).
    let total = proofs
        .total_amount()
        .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    // FeeAndAmounts drives the power-of-two split; the amounts list must come
    // from the keyset's signing denominations so we only request outputs the
    // mint can sign.
    let fee_and_amounts: FeeAndAmounts = (0u64, signing_amounts).into();

    // Generate blinded outputs against the active keyset id with fresh
    // verifier secrets.
    let pre_mint = PreMintSecrets::random(
        active_keyset_id,
        total,
        &SplitTarget::None,
        &fee_and_amounts,
    )
    .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    let swap_request = SwapRequest::new(proofs, pre_mint.blinded_messages());

    let response = http.post_swap(mint_url, swap_request).await?;

    // Unblind: combine the mint's signatures with our blinding factors and
    // secrets to produce spendable proofs.
    let new_proofs = construct_proofs(
        response.signatures,
        pre_mint.rs(),
        pre_mint.secrets(),
        &active_keys,
    )
    .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    Ok(new_proofs)
}
