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

use crate::mint_client::{MintClientError, SwapOutcome};

/// STRICTLY verify every swap-output blind signature's NUT-12 DLEQ against the
/// active keyset's signing key. `cashu::dhke::construct_proofs` silently
/// accepts a `dleq: None` signature, so this is the ONLY place the mint is held
/// to proving it signed the outputs with its advertised key.
///
/// The verdict is a FLAG, not a gate (`draft-cashu-charge-01` verification
/// step 9 + §security-dleq): by the time these signatures exist the swap
/// SUCCEEDED — the presented inputs are consumed and cannot be restored — so a
/// failure here is a mint-trust incident the caller reports (WARN + the
/// [`SwapOutcome::dleq_ok`] flag), never a payment failure. Failing the request
/// instead would both destroy the redeemed value (outputs discarded, inputs
/// spent) and 402 a client whose payment settled, violating the spec's
/// consume-once rule.
///
/// STRICT in what it checks: a [`nut12::Error::MissingDleqProof`] fails the
/// verdict exactly like a wrong-key proof (an offline wallet check may tolerate
/// a missing DLEQ; a redeemed-value verdict cannot call one "ok").
///
/// Pairs each signature with its blinded message by position — `construct_proofs`
/// consumes signatures and secrets in lockstep, so the same positional zip is
/// the correct `B_`. A count mismatch fails the verdict (no pairing exists
/// under which the unpaired tail could have been verified).
///
/// `Err` carries the human-readable failure detail for the operator log.
fn verify_swap_output_dleq(
    signatures: &[BlindSignature],
    pre_mint: &PreMintSecrets,
    keys: &Keys,
) -> Result<(), String> {
    // A count mismatch ⇒ we cannot pair every signature with its blinded
    // message, so no signature can be called verified.
    if signatures.len() != pre_mint.secrets.len() {
        return Err(format!(
            "swap returned {} blind signatures but {} were requested",
            signatures.len(),
            pre_mint.secrets.len()
        ));
    }

    for (sig, pre_mint_secret) in signatures.iter().zip(pre_mint.secrets.iter()) {
        // No advertised key for this amount ⇒ the mint signed an amount it never
        // published a key for — nothing to verify the DLEQ against.
        let key = keys.amount_key(sig.amount).ok_or_else(|| {
            format!(
                "active keyset has no key for swap-output amount {}",
                sig.amount
            )
        })?;

        // STRICT: both present-but-invalid AND missing fail the verdict.
        sig.verify_dleq(key, pre_mint_secret.blinded_message.blinded_secret)
            .map_err(|e| match e {
                nut12::Error::MissingDleqProof => {
                    "mint omitted the DLEQ proof on a swap-output blind signature \
                     (cannot prove the outputs were signed with the advertised key)"
                        .to_string()
                }
                other => other.to_string(),
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
        // A policy reject, raised BEFORE any swap is submitted (the token is
        // not consumed) — typed so it never surfaces as a double-spend.
        return Err(MintClientError::FeeTooHigh {
            keyset_id: active_keyset.id.to_string(),
            input_fee_ppk: active_keyset.input_fee_ppk,
        });
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
/// MONEY-SAFETY INVARIANT: the swap-output DLEQ verification
/// (`verify_swap_output_dleq`) ALWAYS runs, and its verdict is returned as
/// [`SwapOutcome::dleq_ok`]. A failed verdict does NOT fail the ceremony
/// (`draft-cashu-charge-01` §security-dleq: a mint-trust incident, not a
/// payment failure — the inputs were consumed by the successful swap, so
/// erroring here would destroy the redeemed value AND fail a settled payment).
/// It is logged at WARN naming the mint so the operator can alert and
/// quarantine.
pub async fn swap_to_redeem<H: MintHttp + ?Sized>(
    http: &H,
    mint_url: &MintUrl,
    proofs: Proofs,
) -> Result<SwapOutcome, MintClientError> {
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
    // authoritative); `RejectedSwap` is definitive.
    let response = http
        .post_swap(mint_url, swap_request)
        .await
        .map_err(|e| match e {
            MintClientError::Unreachable(msg) => MintClientError::UnreachableIndeterminate(msg),
            other => other,
        })?;

    // The swap has SUCCEEDED: the inputs are spent. Verify the returned
    // signatures' DLEQ and record the verdict (see `verify_swap_output_dleq` —
    // a flag per §security-dleq, never an error), then unblind regardless: the
    // outputs are the only artifact of the consumed value.
    let dleq_ok = match verify_swap_output_dleq(&response.signatures, &pre_mint, &active_keys) {
        Ok(()) => true,
        Err(detail) => {
            tracing::warn!(
                mint_url = %mint_url,
                detail = %detail,
                "swap-output DLEQ missing or invalid — mint-trust incident \
                 (draft-cashu-charge-01 §security-dleq): payment is settled and \
                 the resource will be served; alert the operator and quarantine \
                 this mint pending investigation"
            );
            false
        }
    };

    let new_proofs = construct_proofs(
        response.signatures,
        pre_mint.rs(),
        pre_mint.secrets(),
        &active_keys,
    )
    .map_err(|e| MintClientError::RejectedSwap(e.to_string()))?;

    Ok(SwapOutcome {
        proofs: new_proofs,
        dleq_ok,
    })
}

#[cfg(test)]
mod tests {
    //! Money-safety tests for the swap-output DLEQ verdict. A mock [`MintHttp`]
    //! signs the blinded outputs as a real mint would, then attaches VALID,
    //! MISSING, or PRESENT-BUT-INVALID DLEQ. Invariants under test
    //! (`draft-cashu-charge-01` step 9 + §security-dleq): the redeemed value is
    //! returned in EVERY DLEQ mode (the swap consumed the inputs; discarding
    //! outputs would destroy value), `dleq_ok` is `true` iff every signature's
    //! DLEQ verified, and a failed verdict WARNs naming the mint.

    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

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
        /// `input_fee_ppk` the keyset advertises (0 = the fee-free profile).
        fee_ppk: u64,
    }

    impl MockMint {
        fn new(mode: DleqMode) -> Self {
            Self {
                unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
                mode,
                fee_ppk: 0,
            }
        }

        /// As [`Self::new`] but the keyset advertises a non-zero fee.
        fn with_fee(mode: DleqMode, fee_ppk: u64) -> Self {
            Self {
                fee_ppk,
                ..Self::new(mode)
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
                    input_fee_ppk: self.fee_ppk,
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

    /// A minimal subscriber capturing WARN-and-above events as formatted
    /// strings (field=value pairs), so a test can assert the operator-facing
    /// log without pulling in a subscriber crate.
    struct WarnCapture {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::WARN
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
    async fn swap_valid_dleq_happy_path_redeems_with_flag_true() {
        let mint = MockMint::new(DleqMode::Valid);
        let proofs = inputs_for(&mint);

        let outcome = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect("valid-DLEQ swap must redeem");

        let total: u64 = outcome.proofs.iter().map(|p| u64::from(p.amount)).sum();
        assert_eq!(
            total, 10,
            "redeemed value must equal the swapped input total"
        );
        assert!(!outcome.proofs.is_empty(), "happy path must yield proofs");
        assert!(
            outcome.dleq_ok,
            "every signature carried a valid DLEQ, so the verdict is ok"
        );
    }

    #[tokio::test]
    async fn swap_missing_dleq_serves_value_with_flag_false_and_warns() {
        // `dleq: None` signatures. Step 9: "a failed or missing DLEQ proof
        // after a successful swap is a mint-trust incident, not a payment
        // failure" — the value is still redeemed (the swap consumed the
        // inputs), the verdict flag is false, and the operator is warned with
        // the mint named.
        let events = Arc::new(Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(WarnCapture {
            events: events.clone(),
        });

        let captured = |events: &Arc<Mutex<Vec<String>>>| {
            events
                .lock()
                .expect("capture lock")
                .iter()
                .any(|w| w.contains("mint.example.com") && w.contains("omitted"))
        };

        // tracing caches per-callsite interest GLOBALLY: a parallel test's
        // cold hit on this same warn! callsite can race this thread's
        // dispatcher registration and cache `never`. Rebuilding the cache and
        // retrying bounds that race out without weakening the assertion — a
        // genuinely missing WARN fails every attempt.
        for _ in 0..5 {
            tracing::callsite::rebuild_interest_cache();

            let mint = MockMint::new(DleqMode::Missing);
            let proofs = inputs_for(&mint);
            let outcome = swap_to_redeem(&mint, &mint_url(), proofs)
                .await
                .expect("missing swap-output DLEQ must NOT fail the redemption");

            let total: u64 = outcome.proofs.iter().map(|p| u64::from(p.amount)).sum();
            assert_eq!(total, 10, "the consumed inputs' value must be redeemed");
            assert!(!outcome.dleq_ok, "missing DLEQ ⇒ verdict false");

            if captured(&events) {
                break;
            }
        }

        let warns = events.lock().expect("capture lock");
        assert!(
            warns
                .iter()
                .any(|w| w.contains("mint.example.com") && w.contains("omitted")),
            "a WARN naming the mint and the omission must fire, got: {warns:?}"
        );
    }

    #[tokio::test]
    async fn swap_invalid_dleq_serves_value_with_flag_false() {
        // Present-but-invalid: DLEQ proved against the wrong key. Same
        // serve-and-flag outcome as missing.
        let mint = MockMint::new(DleqMode::InvalidWrongKey);
        let proofs = inputs_for(&mint);

        let outcome = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect("invalid swap-output DLEQ must NOT fail the redemption");

        let total: u64 = outcome.proofs.iter().map(|p| u64::from(p.amount)).sum();
        assert_eq!(total, 10, "the consumed inputs' value must be redeemed");
        assert!(!outcome.dleq_ok, "wrong-key DLEQ ⇒ verdict false");
    }

    #[tokio::test]
    async fn fee_bearing_keyset_rejects_as_fee_too_high_before_swap() {
        // A non-zero `input_fee_ppk` on the active keyset is a POLICY reject:
        // its own typed error (never RejectedSwap → never read as a
        // double-spend), raised before any swap is submitted.
        let mint = MockMint::with_fee(DleqMode::Valid, 100);
        let proofs = inputs_for(&mint);

        let err = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect_err("a fee-bearing keyset must be rejected");
        match err {
            MintClientError::FeeTooHigh {
                keyset_id,
                input_fee_ppk,
            } => {
                assert_eq!(input_fee_ppk, 100, "carries the published fee");
                assert!(!keyset_id.is_empty(), "names the offending keyset");
            }
            other => panic!("expected FeeTooHigh, got {other:?}"),
        }
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
    async fn swap_one_missing_dleq_in_batch_flags_whole_outcome() {
        // A valid batch with a SINGLE unsigned output smuggled in: the verdict
        // covers the WHOLE batch (one unproven signature ⇒ dleq_ok false), but
        // the redemption still completes — no partial anything.
        let mint = MockMint::new(DleqMode::ValidButOneMissing);
        let proofs = inputs_for(&mint);

        let outcome = swap_to_redeem(&mint, &mint_url(), proofs)
            .await
            .expect("a partially-unproven batch must still redeem");

        let total: u64 = outcome.proofs.iter().map(|p| u64::from(p.amount)).sum();
        assert_eq!(total, 10, "the consumed inputs' value must be redeemed");
        assert!(
            !outcome.dleq_ok,
            "one missing DLEQ in the batch must flag the whole outcome"
        );
    }
}
