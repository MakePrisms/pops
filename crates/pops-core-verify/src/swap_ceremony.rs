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
use cashu::nuts::nut00::{BlindSignature, PreMintSecrets};
use cashu::nuts::nut01::Keys;
use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeySetInfosMethods, KeysetResponse};
use cashu::nuts::nut03::{SwapRequest, SwapResponse};
use cashu::nuts::nut12;
use cashu::nuts::ProofsMethods;
use cashu::{MintUrl, Proofs};

use crate::mint_client::MintClientError;

/// STRICTLY verify every swap-output blind signature's NUT-12 DLEQ proof
/// against the active keyset's signing key, BEFORE the outputs are unblinded
/// into redeemable proofs.
///
/// This is the money-safety gate: `cashu::dhke::construct_proofs` silently
/// accepts blind signatures whose `dleq` is `None`, so without this check a
/// malicious or buggy mint could return UNSIGNED (or wrong-key) blind
/// signatures and the verifier would treat the resulting proofs as redeemed
/// bearer value — and the gateway would serve the gated resource against them.
///
/// Mirrors the wallet-side `pop::mint_client::verify_blind_signatures` check
/// pattern (same `BlindSignature::verify_dleq(key, B_)` call, same `amount_key`
/// lookup) with ONE deliberate difference: a redeemed-VALUE path MUST NOT
/// tolerate a missing DLEQ. Where that wallet helper treats
/// [`nut12::Error::MissingDleqProof`] as acceptable (an optional offline
/// check), here a missing proof is a HARD REJECT — the mint failed to prove it
/// signed these outputs at all.
///
/// Pairs each returned signature with its originating blinded message by
/// position: `construct_proofs` consumes `response.signatures` and
/// `pre_mint.secrets()` in lockstep, so the same positional zip is the correct
/// `B_` for each signature. A signature/secret count mismatch (the mint
/// returned the wrong number of outputs) is itself a reject.
///
/// On any failure returns [`MintClientError::SwapOutputDleqInvalid`] (NOT
/// `RejectedSwap`): the cross-slice contract distinguishes a mint that omitted
/// or forged the output DLEQ from an ordinary swap refusal.
fn verify_swap_output_dleq(
    signatures: &[BlindSignature],
    pre_mint: &PreMintSecrets,
    keys: &Keys,
) -> Result<(), MintClientError> {
    // A count mismatch means we cannot pair every signature with the blinded
    // message it must verify against — reject rather than silently verify a
    // prefix and unblind an unverified tail.
    if signatures.len() != pre_mint.secrets.len() {
        return Err(MintClientError::SwapOutputDleqInvalid(format!(
            "swap returned {} blind signatures but {} were requested",
            signatures.len(),
            pre_mint.secrets.len()
        )));
    }

    for (sig, premint) in signatures.iter().zip(pre_mint.secrets.iter()) {
        // The advertised signing key for this output's amount. Its absence
        // means the mint signed an amount it never published a key for — a
        // reject, not a tolerated case.
        let key = keys.amount_key(sig.amount).ok_or_else(|| {
            MintClientError::SwapOutputDleqInvalid(format!(
                "active keyset has no key for swap-output amount {}",
                sig.amount
            ))
        })?;

        // STRICT: present-but-invalid AND missing both reject here. This is the
        // single line that diverges from the wallet's lenient check.
        sig.verify_dleq(key, premint.blinded_message.blinded_secret)
            .map_err(|e| match e {
                nut12::Error::MissingDleqProof => MintClientError::SwapOutputDleqInvalid(
                    "mint omitted the DLEQ proof on a swap-output blind signature \
                     (cannot prove the outputs were signed with the advertised key)"
                        .to_string(),
                ),
                other => MintClientError::SwapOutputDleqInvalid(other.to_string()),
            })?;
    }

    Ok(())
}

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
/// 3. POSTs the [`SwapRequest`],
/// 4. STRICTLY DLEQ-verifies every returned blind signature against the active
///    keyset key ([`verify_swap_output_dleq`]) — rejecting a missing OR invalid
///    proof — so a malicious/buggy mint cannot get unsigned outputs treated as
///    redeemed value, and
/// 5. unblinds the verified [`SwapResponse`] signatures via
///    [`construct_proofs`] into spendable [`Proofs`] under fresh,
///    verifier-owned secrets.
///
/// All five steps are `cashu`-pure; only the two GETs and the POST cross the
/// [`MintHttp`] seam, so native and wasm callers share this entire body. The
/// blinding RNG (`PreMintSecrets::random`) is why the `wasm` feature must
/// select a js `getrandom` backend.
///
/// MONEY-SAFETY INVARIANT: step 4 runs BEFORE step 5, so this function never
/// returns proofs whose swap-output DLEQ was not verified. A DLEQ failure
/// surfaces as [`MintClientError::SwapOutputDleqInvalid`].
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

    // The swap POST is the point of no return: once the inputs are submitted, a
    // transport failure (5xx / read-timeout) leaves the outcome INDETERMINATE —
    // the mint may have consumed the inputs even though we never read a
    // response. Re-tag a determinate `Unreachable` from THIS call as
    // `UnreachableIndeterminate` so the validator surfaces
    // `indeterminate: true`. The pre-POST GETs above keep plain `Unreachable`
    // (no inputs submitted yet → a retry is authoritative). `RejectedSwap` /
    // `SwapOutputDleqInvalid` are definitive mint answers and pass through.
    let response = http
        .post_swap(mint_url, swap_request)
        .await
        .map_err(|e| match e {
            MintClientError::Unreachable(msg) => MintClientError::UnreachableIndeterminate(msg),
            other => other,
        })?;

    // MONEY-SAFETY GATE (must precede construct_proofs): STRICTLY DLEQ-verify
    // every returned blind signature against the active keyset key. A missing
    // OR invalid proof is rejected — `construct_proofs` would otherwise
    // silently accept `dleq: None` and we would treat unsigned outputs as
    // redeemed bearer value. See `verify_swap_output_dleq`.
    verify_swap_output_dleq(&response.signatures, &pre_mint, &active_keys)?;

    // Unblind: combine the mint's (now DLEQ-verified) signatures with our
    // blinding factors and secrets to produce spendable proofs.
    let new_proofs = construct_proofs(
        response.signatures,
        pre_mint.rs(),
        pre_mint.secrets(),
        &active_keys,
    )
    .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    Ok(new_proofs)
}

#[cfg(test)]
mod tests {
    //! Money-safety tests for the swap-output DLEQ gate.
    //!
    //! These drive [`swap_to_redeem`] over a hand-rolled mock [`MintHttp`] that
    //! signs the ceremony's blinded outputs as a real mint would, then attaches
    //! one of three DLEQ behaviours: VALID (happy path), MISSING (`dleq: None`),
    //! or PRESENT-BUT-INVALID (DLEQ computed against the wrong key). The
    //! invariant under test: NO redeemed proofs are ever produced unless every
    //! swap-output blind signature carried a DLEQ that verifies against the
    //! mint's advertised key.

    use std::str::FromStr;

    use cashu::dhke::{hash_to_curve, sign_message};
    use cashu::nuts::nut00::{BlindSignature, Proof};
    use cashu::nuts::nut01::Keys;
    use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeysetResponse};
    use cashu::nuts::nut03::{SwapRequest, SwapResponse};
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, PublicKey, SecretKey};

    use super::{swap_to_redeem, MintHttp};
    use crate::mint_client::MintClientError;

    /// How the mock mint should attach (or not) a DLEQ to each blind signature.
    #[derive(Clone, Copy)]
    enum DleqMode {
        /// Real NUT-12 DLEQ bound to the correct signing key (happy path).
        Valid,
        /// No DLEQ at all (`dleq: None`) — the core bug: `construct_proofs`
        /// tolerates this, so the gate MUST reject it.
        Missing,
        /// A DLEQ that is present but computed against the WRONG key, so it
        /// fails verification against the keyset's advertised key.
        InvalidWrongKey,
        /// The mint signs and DLEQ-proves correctly for every output EXCEPT it
        /// drops the DLEQ on exactly one (the last) — a single unsigned output
        /// smuggled into an otherwise-valid batch must still reject the whole.
        ValidButOneMissing,
    }

    /// Deterministic per-amount mint secret keys for the test keyset. Distinct
    /// 32-byte scalars; any valid secp256k1 scalars work.
    fn mint_secret_for_amount(amount: u64) -> SecretKey {
        // Encode the amount into the low bytes of an otherwise-fixed scalar so
        // each denomination has its own key (and none is the zero scalar).
        let mut bytes = [0u8; 32];
        bytes[0] = 0x11;
        bytes[31] = amount as u8;
        bytes[30] = (amount >> 8) as u8;
        SecretKey::from_slice(&bytes).expect("non-zero scalar is a valid secret key")
    }

    /// The denominations the test keyset can sign (powers of two up to 8 — the
    /// ceremony splits the input total across these).
    fn signing_amounts() -> Vec<u64> {
        vec![1, 2, 4, 8]
    }

    /// A mock mint: one keyset (acting as both the input keyset and the active
    /// output keyset) over [`signing_amounts`], signing the ceremony's blinded
    /// outputs with the matching per-amount secret key and attaching a DLEQ per
    /// the configured [`DleqMode`].
    struct MockMint {
        unit: CurrencyUnit,
        mode: DleqMode,
    }

    impl MockMint {
        fn new(mode: DleqMode) -> Self {
            Self {
                unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
                mode,
            }
        }

        /// The mint secret key for `amount` (panics if `amount` is not a signing
        /// denomination — the ceremony only ever requests signing amounts).
        fn secret_key(&self, amount: Amount) -> SecretKey {
            assert!(
                signing_amounts().contains(&u64::from(amount)),
                "mock asked to sign non-denomination amount {amount}"
            );
            mint_secret_for_amount(u64::from(amount))
        }

        /// The public [`Keys`] map this mint advertises (NUT-01).
        fn public_keys(&self) -> Keys {
            let map = signing_amounts()
                .into_iter()
                .map(|a| {
                    let pk: PublicKey = mint_secret_for_amount(a).public_key();
                    (Amount::from(a), pk)
                })
                .collect();
            Keys::new(map)
        }

        /// The keyset id, derived from the advertised keys (V0 id).
        fn keyset_id(&self) -> Id {
            Id::v1_from_keys(&self.public_keys())
        }
    }

    #[async_trait::async_trait]
    impl MintHttp for MockMint {
        async fn get_keysets(
            &self,
            _mint_url: &MintUrl,
        ) -> Result<KeysetResponse, MintClientError> {
            Ok(KeysetResponse {
                keysets: vec![KeySetInfo {
                    id: self.keyset_id(),
                    unit: self.unit.clone(),
                    active: true,
                    input_fee_ppk: 0,
                    final_expiry: None,
                }],
            })
        }

        async fn get_keyset_keys(
            &self,
            _mint_url: &MintUrl,
            keyset_id: Id,
        ) -> Result<KeySet, MintClientError> {
            assert_eq!(keyset_id, self.keyset_id(), "unexpected keyset requested");
            Ok(KeySet {
                id: self.keyset_id(),
                unit: self.unit.clone(),
                active: Some(true),
                keys: self.public_keys(),
                input_fee_ppk: 0,
                final_expiry: None,
            })
        }

        async fn post_swap(
            &self,
            _mint_url: &MintUrl,
            request: SwapRequest,
        ) -> Result<SwapResponse, MintClientError> {
            let id = self.keyset_id();
            let outputs = request.outputs();
            let last = outputs.len().saturating_sub(1);

            let mut signatures = Vec::with_capacity(outputs.len());
            for (i, bm) in outputs.iter().enumerate() {
                let k = self.secret_key(bm.amount);
                // Correct blind signature C_ = k * B_ in every mode, so the
                // ONLY thing under test is the DLEQ (not the unblinding).
                let c = sign_message(&k, &bm.blinded_secret).expect("mock sign_message");

                let attach_valid_dleq = |c: PublicKey, k: &SecretKey| -> BlindSignature {
                    BlindSignature::new(bm.amount, c, id, &bm.blinded_secret, k.clone())
                        .expect("mock DLEQ generation")
                };

                let sig = match self.mode {
                    DleqMode::Valid => attach_valid_dleq(c, &k),
                    DleqMode::Missing => BlindSignature {
                        amount: bm.amount,
                        keyset_id: id,
                        c,
                        dleq: None,
                    },
                    DleqMode::InvalidWrongKey => {
                        // Correct C_, but the DLEQ is proved against a DIFFERENT
                        // key, so it fails verification against the real key.
                        let wrong = mint_secret_for_amount(u64::from(bm.amount) + 1000);
                        BlindSignature::new(bm.amount, c, id, &bm.blinded_secret, wrong)
                            .expect("mock (wrong-key) DLEQ generation")
                    }
                    DleqMode::ValidButOneMissing => {
                        if i == last {
                            BlindSignature {
                                amount: bm.amount,
                                keyset_id: id,
                                c,
                                dleq: None,
                            }
                        } else {
                            attach_valid_dleq(c, &k)
                        }
                    }
                };
                signatures.push(sig);
            }
            Ok(SwapResponse::new(signatures))
        }
    }

    fn mint_url() -> MintUrl {
        MintUrl::from_str("https://mint.example.com").expect("valid mint url")
    }

    /// One input proof carrying the mock mint's keyset id. The C point is
    /// deterministic-but-arbitrary — the mock never verifies inputs, it only
    /// reads the keyset id off `proofs[0]`.
    fn input_proof(amount: u64, index: u8, keyset_id: Id) -> Proof {
        let mut preimage = [0u8; 33];
        preimage[0] = 2;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
    }

    /// Inputs totalling 10 (8 + 2) against the mock's keyset.
    fn inputs_for(mint: &MockMint) -> Proofs {
        let id = mint.keyset_id();
        vec![input_proof(8, 0, id), input_proof(2, 1, id)]
    }

    #[tokio::test]
    async fn swap_valid_dleq_happy_path_redeems() {
        let mint = MockMint::new(DleqMode::Valid);
        let proofs = inputs_for(&mint);

        let redeemed = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect("valid-DLEQ swap must redeem");

        // Produced spendable proofs summing to the input total.
        let total: u64 = redeemed.iter().map(|p| u64::from(p.amount)).sum();
        assert_eq!(
            total, 10,
            "redeemed value must equal the swapped input total"
        );
        assert!(!redeemed.is_empty(), "happy path must yield proofs");
    }

    #[tokio::test]
    async fn swap_missing_dleq_rejects_and_yields_no_proofs() {
        // THE BUG: mint returns blind signatures with `dleq: None`. The gate
        // must REJECT (a redeemed-value path does NOT tolerate a missing DLEQ),
        // producing no proofs.
        let mint = MockMint::new(DleqMode::Missing);
        let proofs = inputs_for(&mint);

        let err = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect_err("missing swap-output DLEQ MUST be rejected");

        match err {
            MintClientError::SwapOutputDleqInvalid(msg) => {
                assert!(
                    msg.contains("omitted"),
                    "missing-DLEQ rejection should name the omission, got: {msg}"
                );
            }
            other => panic!("expected SwapOutputDleqInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn swap_invalid_dleq_rejects_and_yields_no_proofs() {
        // Present-but-invalid: DLEQ proved against the wrong key. Must reject.
        let mint = MockMint::new(DleqMode::InvalidWrongKey);
        let proofs = inputs_for(&mint);

        let err = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect_err("present-but-invalid swap-output DLEQ MUST be rejected");

        assert!(
            matches!(err, MintClientError::SwapOutputDleqInvalid(_)),
            "expected SwapOutputDleqInvalid, got {err:?}"
        );
    }

    /// A mock that drives the ceremony's keyset GETs successfully but lets a
    /// chosen call fail with a transport `Unreachable`, to prove the ceremony
    /// re-tags ONLY a `post_swap` transport failure as indeterminate.
    struct TransportFailMint {
        inner: MockMint,
        fail_on_post_swap: bool,
        fail_on_keysets: bool,
    }

    #[async_trait::async_trait]
    impl MintHttp for TransportFailMint {
        async fn get_keysets(
            &self,
            mint_url: &MintUrl,
        ) -> Result<KeysetResponse, MintClientError> {
            if self.fail_on_keysets {
                return Err(MintClientError::Unreachable("keysets down".into()));
            }
            self.inner.get_keysets(mint_url).await
        }

        async fn get_keyset_keys(
            &self,
            mint_url: &MintUrl,
            keyset_id: Id,
        ) -> Result<KeySet, MintClientError> {
            self.inner.get_keyset_keys(mint_url, keyset_id).await
        }

        async fn post_swap(
            &self,
            mint_url: &MintUrl,
            request: SwapRequest,
        ) -> Result<SwapResponse, MintClientError> {
            if self.fail_on_post_swap {
                return Err(MintClientError::Unreachable("swap POST timed out".into()));
            }
            self.inner.post_swap(mint_url, request).await
        }
    }

    #[tokio::test]
    async fn swap_post_transport_failure_is_retagged_indeterminate() {
        // A transport `Unreachable` from the swap POST itself must surface as
        // `UnreachableIndeterminate` — the inputs were submitted, so the
        // outcome is unknown.
        let inner = MockMint::new(DleqMode::Valid);
        let proofs = inputs_for(&inner);
        let mint = TransportFailMint {
            inner,
            fail_on_post_swap: true,
            fail_on_keysets: false,
        };

        let err = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect_err("a swap-POST transport failure must error");
        assert!(
            matches!(err, MintClientError::UnreachableIndeterminate(_)),
            "a post_swap transport failure must be re-tagged indeterminate, got {err:?}"
        );
    }

    #[tokio::test]
    async fn swap_pre_post_keysets_failure_stays_determinate() {
        // A transport `Unreachable` from a PRE-POST keysets GET (no inputs
        // submitted yet) must stay the plain determinate `Unreachable` — NOT
        // re-tagged indeterminate.
        let inner = MockMint::new(DleqMode::Valid);
        let proofs = inputs_for(&inner);
        let mint = TransportFailMint {
            inner,
            fail_on_post_swap: false,
            fail_on_keysets: true,
        };

        let err = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect_err("a pre-POST keysets failure must error");
        assert!(
            matches!(err, MintClientError::Unreachable(_)),
            "a pre-POST transport failure must stay determinate, got {err:?}"
        );
    }

    #[tokio::test]
    async fn swap_one_missing_dleq_in_batch_rejects_whole() {
        // A valid batch with a SINGLE unsigned output smuggled in must still
        // reject the entire swap (no partial redemption).
        let mint = MockMint::new(DleqMode::ValidButOneMissing);
        let proofs = inputs_for(&mint);

        let err = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect_err("one missing DLEQ in the batch MUST reject the whole swap");

        assert!(
            matches!(err, MintClientError::SwapOutputDleqInvalid(_)),
            "expected SwapOutputDleqInvalid, got {err:?}"
        );
    }
}
