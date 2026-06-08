//! Shared NUT-03 swap ceremony — the crypto, lifted out of any one transport so
//! native (`cdk`) and wasm (injected `fetch`) clients share it.
//!
//! The ceremony is `cashu`-pure (it never touches an HTTP type); the ONLY thing
//! that differs between native and wasm is the transport — the three raw mint
//! HTTP calls — so [`MintHttp`] is that seam, and [`swap_to_redeem`] holds ALL
//! the crypto. Each transport implements only the three `MintHttp` methods and
//! delegates its [`MintClient::swap`][crate::mint_client::MintClient::swap] here.

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

/// THE money-safety gate: STRICTLY verify every swap-output blind signature's
/// NUT-12 DLEQ against the active keyset's signing key BEFORE the outputs are
/// unblinded. `cashu::dhke::construct_proofs` silently accepts a `dleq: None`
/// signature, so without this a malicious/buggy mint could return UNSIGNED (or
/// wrong-key) outputs and the verifier would treat the resulting proofs as
/// redeemed bearer value — and the gateway would serve the resource against them.
///
/// STRICT, not lenient: a redeemed-VALUE path MUST NOT tolerate a missing DLEQ.
/// A [`nut12::Error::MissingDleqProof`] is a HARD REJECT here (an offline wallet
/// check may treat it as acceptable; this path cannot).
///
/// Pairs each signature with its blinded message by position — `construct_proofs`
/// consumes signatures and secrets in lockstep, so the same positional zip is
/// the correct `B_`. A count mismatch is itself a reject.
///
/// Any failure returns [`MintClientError::SwapOutputDleqInvalid`] (NOT
/// `RejectedSwap`): the contract distinguishes an omitted/forged output DLEQ
/// from an ordinary swap refusal.
fn verify_swap_output_dleq(
    signatures: &[BlindSignature],
    pre_mint: &PreMintSecrets,
    keys: &Keys,
) -> Result<(), MintClientError> {
    // A count mismatch ⇒ we cannot pair every signature with its blinded message;
    // reject rather than verify a prefix and unblind an unverified tail.
    if signatures.len() != pre_mint.secrets.len() {
        return Err(MintClientError::SwapOutputDleqInvalid(format!(
            "swap returned {} blind signatures but {} were requested",
            signatures.len(),
            pre_mint.secrets.len()
        )));
    }

    for (sig, pre_mint_secret) in signatures.iter().zip(pre_mint.secrets.iter()) {
        // No advertised key for this amount ⇒ the mint signed an amount it never
        // published a key for — reject.
        let key = keys.amount_key(sig.amount).ok_or_else(|| {
            MintClientError::SwapOutputDleqInvalid(format!(
                "active keyset has no key for swap-output amount {}",
                sig.amount
            ))
        })?;

        // STRICT: both present-but-invalid AND missing reject here.
        sig.verify_dleq(key, pre_mint_secret.blinded_message.blinded_secret)
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

/// The raw mint HTTP the swap ceremony needs (three calls only: NUT-02 keyset
/// list, one keyset's NUT-01 keys, NUT-03 swap), abstracted so the crypto stays
/// transport-agnostic. Implementors return `cashu` wire types and map transport
/// failures onto the coarse [`MintClientError`] split; [`swap_to_redeem`] owns
/// everything else. `?Send` on wasm32, `Send + Sync` on native.
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

/// Resolve the active output keyset for the unit on the input keyset id,
/// returning its id, signing [`Keys`] (to unblind the swap), and ascending
/// denomination list. The input keyset may have rotated; outputs are ALWAYS
/// requested against the currently-active keyset for the same unit. Errors if
/// the input keyset is unknown, no active keyset exists, or it charges a
/// non-zero fee (PoP v1 is zero-fee).
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

    // `Keys::keys()` is a `BTreeMap`, already sorted ascending by `Amount`, so
    // its keys are the canonical denomination list the mint can sign.
    let signing_amounts: Vec<u64> = active_keyset_full
        .keys
        .keys()
        .keys()
        .map(|a| u64::from(*a))
        .collect();

    Ok((active_keyset.id, active_keyset_full.keys, signing_amounts))
}

/// The shared NUT-03 swap-to-redeem ceremony: resolve the active output keyset,
/// blind fresh outputs summing to the input total (PoP v1 is zero-fee), POST the
/// swap, DLEQ-verify the returned signatures, then unblind into spendable
/// [`Proofs`] under fresh verifier secrets. Only the two GETs and the POST cross
/// the [`MintHttp`] seam, so native and wasm share this body. The blinding RNG is
/// why the `wasm` feature must select a js `getrandom` backend.
///
/// MONEY-SAFETY INVARIANT: the DLEQ verification (`verify_swap_output_dleq`)
/// runs BEFORE the unblind, so this never returns proofs whose swap-output DLEQ
/// was not verified. A DLEQ failure surfaces as
/// [`MintClientError::SwapOutputDleqInvalid`].
pub async fn swap_to_redeem<H: MintHttp + ?Sized>(
    http: &H,
    mint_url: &MintUrl,
    proofs: Proofs,
) -> Result<Proofs, MintClientError> {
    if proofs.is_empty() {
        // Defensive: the validator already short-circuits on TokenEmpty; surface
        // as RejectedSwap rather than make a wasted call.
        return Err(MintClientError::RejectedSwap(
            "cannot swap empty proof set".to_string(),
        ));
    }

    // All inputs share a unit (validated upstream); resolve the active output
    // keyset from the first input's keyset id.
    let input_keyset_id = proofs[0].keyset_id;
    let (active_keyset_id, active_keys, signing_amounts) =
        resolve_output_keyset(http, mint_url, input_keyset_id).await?;

    // Outputs must sum to the input total (PoP v1 is zero-fee).
    let total = proofs
        .total_amount()
        .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    // The amounts list must be the keyset's signing denominations so we only
    // request outputs the mint can sign.
    let fee_and_amounts: FeeAndAmounts = (0u64, signing_amounts).into();

    let pre_mint = PreMintSecrets::random(
        active_keyset_id,
        total,
        &SplitTarget::None,
        &fee_and_amounts,
    )
    .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    let swap_request = SwapRequest::new(proofs, pre_mint.blinded_messages());

    // The swap POST is the point of no return: once inputs are submitted, a
    // transport failure leaves the outcome INDETERMINATE (the mint may have
    // consumed them though we never read a response), so re-tag a determinate
    // `Unreachable` from THIS call as `UnreachableIndeterminate`. The pre-POST
    // GETs keep plain `Unreachable` (no inputs submitted → retry is
    // authoritative); `RejectedSwap` / `SwapOutputDleqInvalid` are definitive.
    let response = http
        .post_swap(mint_url, swap_request)
        .await
        .map_err(|e| match e {
            MintClientError::Unreachable(msg) => MintClientError::UnreachableIndeterminate(msg),
            other => other,
        })?;

    // MONEY-SAFETY GATE — must precede construct_proofs (see
    // `verify_swap_output_dleq`): without it, a `dleq: None` signature would be
    // silently unblinded and treated as redeemed bearer value.
    verify_swap_output_dleq(&response.signatures, &pre_mint, &active_keys)?;

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
    //! Money-safety tests for the swap-output DLEQ gate. A mock [`MintHttp`] signs
    //! the blinded outputs as a real mint would, then attaches VALID, MISSING, or
    //! PRESENT-BUT-INVALID DLEQ. Invariant under test: NO redeemed proofs unless
    //! every swap-output signature carried a DLEQ that verifies against the
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
        /// No DLEQ at all (`dleq: None`): `construct_proofs` tolerates this, so
        /// the gate MUST reject it.
        Missing,
        /// A DLEQ that is present but computed against the WRONG key, so it
        /// fails verification against the keyset's advertised key.
        InvalidWrongKey,
        /// The mint signs and DLEQ-proves correctly for every output EXCEPT it
        /// drops the DLEQ on exactly one (the last) — a single unsigned output
        /// smuggled into an otherwise-valid batch must still reject the whole.
        ValidButOneMissing,
    }

    /// Deterministic per-amount mint secret key: the amount goes into the low
    /// bytes of a fixed scalar so each denomination has its own (non-zero) key.
    fn mint_secret_for_amount(amount: u64) -> SecretKey {
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

    /// A mock mint with one keyset (both input and active output) that signs the
    /// ceremony's blinded outputs and attaches a DLEQ per the [`DleqMode`].
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
            for (i, blinded_message) in outputs.iter().enumerate() {
                let k = self.secret_key(blinded_message.amount);
                // Correct blind signature C_ = k * B_ in every mode, so the
                // ONLY thing under test is the DLEQ (not the unblinding).
                let c =
                    sign_message(&k, &blinded_message.blinded_secret).expect("mock sign_message");

                let attach_valid_dleq = |c: PublicKey, k: &SecretKey| -> BlindSignature {
                    BlindSignature::new(
                        blinded_message.amount,
                        c,
                        id,
                        &blinded_message.blinded_secret,
                        k.clone(),
                    )
                    .expect("mock DLEQ generation")
                };

                let sig = match self.mode {
                    DleqMode::Valid => attach_valid_dleq(c, &k),
                    DleqMode::Missing => BlindSignature {
                        amount: blinded_message.amount,
                        keyset_id: id,
                        c,
                        dleq: None,
                    },
                    DleqMode::InvalidWrongKey => {
                        // Correct C_, but the DLEQ is proved against a DIFFERENT
                        // key, so it fails verification against the real key.
                        let wrong =
                            mint_secret_for_amount(u64::from(blinded_message.amount) + 1000);
                        BlindSignature::new(
                            blinded_message.amount,
                            c,
                            id,
                            &blinded_message.blinded_secret,
                            wrong,
                        )
                        .expect("mock (wrong-key) DLEQ generation")
                    }
                    DleqMode::ValidButOneMissing => {
                        if i == last {
                            BlindSignature {
                                amount: blinded_message.amount,
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

    /// One input proof carrying the mock's keyset id. The C point is arbitrary —
    /// the mock never verifies inputs, it only reads `proofs[0].keyset_id`.
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

        let total: u64 = redeemed.iter().map(|p| u64::from(p.amount)).sum();
        assert_eq!(
            total, 10,
            "redeemed value must equal the swapped input total"
        );
        assert!(!redeemed.is_empty(), "happy path must yield proofs");
    }

    #[tokio::test]
    async fn swap_missing_dleq_rejects_and_yields_no_proofs() {
        // `dleq: None` signatures. A redeemed-value path does NOT tolerate a
        // missing DLEQ, so the gate must REJECT with no proofs.
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

    /// A mock that fails a chosen call with `Unreachable`, to prove the ceremony
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
        // post_swap `Unreachable` → `UnreachableIndeterminate`: inputs were
        // submitted, so the outcome is unknown.
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
        // Pre-POST keysets `Unreachable` (no inputs submitted) stays plain
        // determinate — NOT re-tagged indeterminate.
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
