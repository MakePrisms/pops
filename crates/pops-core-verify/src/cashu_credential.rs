//! Swap-at-mint validator for cashu charge credentials.
//!
//! A successful swap at the issuing mint is the proof of unspentness *and* of
//! `final_expiry` not having passed — there is no separate check for either.
//! The charge is transfer-on-use: the verifier swaps the whole token and keeps
//! the value.
//!
//! Structural checks (unit, mint, amount) run BEFORE the swap so an
//! obviously-bad token — or a flood of them — never reaches the mint.
//!
//! [`ChargeValidator`] is the cashu-typed engine; [`CashuCredential`] wraps it
//! to expose the ecash-agnostic [`Redeemer`]
//! seam (converting to `String`/`u64` and the [`charge`](crate::charge) contract).

use std::str::FromStr;

use cashu::nuts::nut00::ProofsMethods;
use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
use crate::charge::{ChargeError, DleqLocation, RedeemedProofs};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::challenge::{decode_token, CashuRequirement};
use crate::redeemer::{ChargeRequirement, Redeemer, Redeemed};
use crate::error::Error as ChallengeError;
use crate::mint_client::{MintClient, MintClientError};

/// Result of a successful charge validation.
#[derive(Debug, Clone)]
pub struct ValidatedCharge {
    /// Proofs the verifier now controls: the mint signed these against blinded
    /// outputs the swap generated, so they are under verifier secrets.
    pub new_proofs: Proofs,
    /// Mint that signed both the original and the new proofs.
    pub mint_url: MintUrl,
    /// Currency unit of the swapped value.
    pub unit: CurrencyUnit,
    /// Total amount of the swapped proofs.
    pub amount: Amount,
}

/// Errors a [`ChargeValidator`] can return. The pre-swap arms (`UnitMismatch`,
/// `MintNotAllowed`, `AmountMismatch`, `TokenEmpty`, `LockedToken`,
/// `MultiMintOrUnit`, `TooManyProofs`) are raised BEFORE the swap is ever
/// attempted; the rest are raised at/after it. [`CashuCredential`] maps these
/// onto [`crate::charge::ChargeError`].
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Token unit does not match the requirement's unit.
    #[error("token unit {got:?} does not match requirement unit {expected:?}")]
    UnitMismatch {
        /// Unit the verifier advertised.
        expected: CurrencyUnit,
        /// Unit found on the token.
        got: CurrencyUnit,
    },

    /// A proof carries a NUT-10 spending-condition secret (P2PK / HTLC). This
    /// intent is BEARER-only; a locked proof is rejected before the swap, which
    /// the bearer ceremony could not satisfy anyway.
    #[error("token carries a NUT-10 spending condition (locked); bearer proofs only")]
    LockedToken,

    /// Proofs reference more than one keyset id. Rejected before the swap so the
    /// ceremony's `proofs[0]` output-keyset assumption holds: a cashu keyset is
    /// mint-AND-unit-specific, so a single shared id is what guarantees a single
    /// mint and unit across the whole set.
    #[error("token references multiple keysets/units (must be a single keyset)")]
    MultiMintOrUnit,

    /// More proofs than the configured cap — a pre-swap DoS guard.
    #[error("too many proofs: {got} exceeds max {max}")]
    TooManyProofs {
        /// Proof count the token carried.
        got: usize,
        /// Configured per-token maximum.
        max: usize,
    },

    /// Token was issued by a mint not in the requirement's allowlist.
    #[error("token mint {got} is not in the requirement's allowed mints: {allowed:?}")]
    MintNotAllowed {
        /// Mint the token names.
        got: MintUrl,
        /// Mints the verifier allowed.
        allowed: Vec<MintUrl>,
    },

    /// Total proof amount is not EXACTLY the requirement. The charge is
    /// exact-amount: the verifier makes no change, so an over-funded token is
    /// rejected just like an under-funded one (the holder splits locally,
    /// non-custodially, before presenting).
    #[error("token amount {got} does not equal required {required}")]
    AmountMismatch {
        /// Amount required.
        required: Amount,
        /// Total presented.
        got: Amount,
    },

    /// Mint accepted the call but rejected the proofs (expired, double-spent,
    /// bad signature, keyset rotated, etc.).
    #[error("mint rejected swap: {0}")]
    MintRejectedSwap(String),

    /// Swap-output blind signatures whose NUT-12 DLEQ is missing or invalid:
    /// unsigned / wrong-key outputs that MUST NOT be redeemed. Kept distinct
    /// from [`Self::MintRejectedSwap`] so it maps to `DleqInvalid`, not a
    /// double-spend — collapsing the two would hide the mint-trust signal.
    #[error("swap-output DLEQ verification failed: {0}")]
    SwapOutputDleqInvalid(String),

    /// DETERMINATE unreachable: a pre-swap GET or a connect failure that never
    /// submitted the inputs. The token was NOT consumed; retry is authoritative.
    #[error("mint unreachable: {0}")]
    MintUnreachable(String),

    /// The swap POST failed AFTER submitting inputs, so the outcome is
    /// INDETERMINATE — the mint may already have consumed them. Maps to the
    /// contract's `indeterminate: true` so the operator checkstates rather than
    /// assuming the token is still good.
    #[error("mint unreachable (indeterminate swap outcome): {0}")]
    MintUnreachableIndeterminate(String),

    /// Token carried zero proofs.
    #[error("token contains no proofs")]
    TokenEmpty,

    /// Token internals (proof extraction, summation, mint-url parse) failed.
    #[error("malformed token: {0}")]
    MalformedToken(String),
}

/// Validates charge tokens against a [`CashuRequirement`] by calling the
/// issuing mint's swap endpoint. Holds no per-request state; construct once and
/// reuse.
///
/// `max_proofs` is an optional pre-swap DoS guard ([`ValidationError::TooManyProofs`]);
/// `None` imposes no cap.
#[derive(Debug)]
pub struct ChargeValidator<M: MintClient> {
    mint_client: M,
    max_proofs: Option<usize>,
}

impl<M: MintClient> ChargeValidator<M> {
    /// Construct with NO proof-count cap.
    pub fn new(mint_client: M) -> Self {
        Self {
            mint_client,
            max_proofs: None,
        }
    }

    /// Construct with a per-token `max_proofs` cap (pre-swap DoS guard).
    pub fn with_max_proofs(mint_client: M, max_proofs: usize) -> Self {
        Self {
            mint_client,
            max_proofs: Some(max_proofs),
        }
    }

    /// Borrow the underlying mint client.
    pub fn mint_client(&self) -> &M {
        &self.mint_client
    }

    /// The network-free structural checks plus proof extraction, returning the
    /// swap inputs (mint, unit, proofs). Run as a prelude so an obviously-bad
    /// token never reaches the swap endpoint.
    async fn check_and_extract(
        &self,
        token: &Token,
        requirement: &CashuRequirement,
    ) -> Result<(MintUrl, CurrencyUnit, Proofs), ValidationError> {
        // `Token::unit()` is `Option` because V3 makes the unit optional on the
        // wire; a missing unit is a mismatch — the verifier always advertises one.
        let token_unit = token
            .unit()
            .ok_or_else(|| ValidationError::UnitMismatch {
                expected: requirement.unit.clone(),
                got: CurrencyUnit::Custom(String::new()),
            })?;
        if token_unit != requirement.unit {
            return Err(ValidationError::UnitMismatch {
                expected: requirement.unit.clone(),
                got: token_unit,
            });
        }

        // Empty `requirement.mints` means "any mint" (see `CashuRequirement`).
        let token_mint = token
            .mint_url()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
        if !requirement.mints.is_empty() && !requirement.mints.contains(&token_mint) {
            return Err(ValidationError::MintNotAllowed {
                got: token_mint,
                allowed: requirement.mints.clone(),
            });
        }

        // `token_secrets()` reads raw per-proof secrets across V3/V4 WITHOUT a
        // keyset-resolution network call, so the DoS + locked checks below
        // short-circuit before we even fetch keysets, let alone swap.
        let secrets = token.token_secrets();

        if let Some(max) = self.max_proofs {
            if secrets.len() > max {
                return Err(ValidationError::TooManyProofs {
                    got: secrets.len(),
                    max,
                });
            }
        }

        // A plain 32-byte hex secret does NOT parse as NUT-10, so this fires
        // only on a genuinely locked (P2PK/HTLC) proof — which the bearer
        // ceremony could not spend.
        if secrets
            .iter()
            .any(|s| cashu::nuts::nut10::Secret::try_from(*s).is_ok())
        {
            return Err(ValidationError::LockedToken);
        }

        // V0 keyset IDs round-trip locally, but V1 short IDs are a 7-byte prefix
        // on the wire and need the full 32-byte ID from `/v1/keysets` to expand,
        // so fetch keysets before extracting proofs. Surfacing unreachable here
        // (before swap) means we never swap when we cannot even read the inputs.
        let keysets = self
            .mint_client
            .keysets(&token_mint)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                // `keysets()` submits no inputs and does no DLEQ work, so these
                // two arms are unreachable here; map defensively (determinate
                // unreachable / swap-rejection) to keep the match total.
                MintClientError::UnreachableIndeterminate(msg) => {
                    ValidationError::MintUnreachable(msg)
                }
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
                MintClientError::SwapOutputDleqInvalid(msg) => {
                    ValidationError::MintRejectedSwap(msg)
                }
            })?;

        // Resolves V1 short IDs against the list (V0 do not consult it). A V1 ID
        // with no matching keyset surfaces as MalformedToken.
        let proofs = token
            .proofs(&keysets)
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        if proofs.is_empty() {
            return Err(ValidationError::TokenEmpty);
        }

        // See `MultiMintOrUnit`: a single shared keyset id is what makes the
        // ceremony's `proofs[0]` output-keyset resolution sound for the set.
        let first_keyset = proofs[0].keyset_id;
        if proofs.iter().any(|p| p.keyset_id != first_keyset) {
            return Err(ValidationError::MultiMintOrUnit);
        }

        // Exact-amount (see `AmountMismatch`). Summed directly rather than via
        // `Token::value()` so an off-amount token short-circuits before swap.
        let token_amount = proofs
            .total_amount()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
        if token_amount != requirement.amount {
            return Err(ValidationError::AmountMismatch {
                required: requirement.amount,
                got: token_amount,
            });
        }

        Ok((token_mint, token_unit, proofs))
    }

    /// Run the full validation pipeline: structural prelude, then (only if it
    /// passes) the mint swap, which redeems the WHOLE token to the verifier.
    pub async fn validate(
        &self,
        token: &Token,
        requirement: &CashuRequirement,
    ) -> Result<ValidatedCharge, ValidationError> {
        let (token_mint, token_unit, proofs) =
            self.check_and_extract(token, requirement).await?;

        // A successful swap atomically proves both unspentness (nullifier check)
        // and unexpired credential (`final_expiry` check).
        let new_proofs = self
            .mint_client
            .swap(&token_mint, proofs)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                MintClientError::UnreachableIndeterminate(msg) => {
                    ValidationError::MintUnreachableIndeterminate(msg)
                }
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
                // Money-safety: a bad swap-output DLEQ is its own outcome, NEVER
                // collapsed into MintRejectedSwap (which would 402 as a
                // DoubleSpend and hide the mint-trust signal).
                MintClientError::SwapOutputDleqInvalid(msg) => {
                    ValidationError::SwapOutputDleqInvalid(msg)
                }
            })?;

        let new_amount = new_proofs
            .total_amount()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        Ok(ValidatedCharge {
            new_proofs,
            mint_url: token_mint,
            unit: token_unit,
            amount: new_amount,
        })
    }
}

/// Convert a cashu-typed [`CashuRequirement`] into the decoupled
/// [`ChargeRequirement`] the [`Redeemer`] seam speaks. For callers (the
/// middleware) that hold the cashu-typed requirement but drive a generic
/// `Redeemer`.
pub fn charge_requirement_from_cashu(req: &CashuRequirement) -> ChargeRequirement {
    ChargeRequirement {
        amount: u64::from(req.amount),
        unit: req.unit.to_string(),
        mints: req.mints.iter().map(|m| m.to_string()).collect(),
        payment_id: req.payment_id.clone(),
        description: req.description.clone(),
        single_use: req.single_use,
    }
}

/// Build the cashu-typed [`CashuRequirement`] from the decoupled one. A bad
/// requirement is server-side config, so a parse failure maps to
/// [`ChargeError::MalformedRequest`] (a 400, NOT a 402 — the credential was
/// never the problem).
fn cashu_requirement_from_charge(req: &ChargeRequirement) -> Result<CashuRequirement, ChargeError> {
    let unit = CurrencyUnit::from_str(&req.unit).map_err(|e| {
        ChargeError::MalformedRequest(format!("requirement unit {:?}: {e}", req.unit))
    })?;
    let mut mints = Vec::with_capacity(req.mints.len());
    for m in &req.mints {
        let parsed = MintUrl::from_str(m)
            .map_err(|e| ChargeError::MalformedRequest(format!("requirement mint {m:?}: {e}")))?;
        mints.push(parsed);
    }
    Ok(CashuRequirement {
        unit,
        mints,
        amount: Amount::from(req.amount),
        payment_id: req.payment_id.clone(),
        description: req.description.clone(),
        single_use: req.single_use,
    })
}

/// SHA-256 of the EXACT presented credential string, lowercase hex. The receipt
/// `reference` (`RedeemedProofs.token_hash`): a stable, shareable settlement id
/// that exposes no secret.
fn token_hash_hex(presented: &str) -> String {
    let digest = Sha256::digest(presented.as_bytes());
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        s.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble<16"));
        s.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble<16"));
    }
    s
}

/// Map a cashu-typed [`ValidationError`] onto the cross-slice [`ChargeError`].
/// `mint_url` supplies the transport context the cashu arm does not carry. The
/// two money-safety arms (DoubleSpend, DLEQ) are noted inline.
fn map_validation_error(e: ValidationError, mint_url: &str) -> ChargeError {
    match e {
        ValidationError::MintUnreachable(detail) => ChargeError::MintUnreachable {
            mint_url: mint_url.to_string(),
            transport_detail: detail,
            indeterminate: false,
        },
        ValidationError::MintUnreachableIndeterminate(detail) => ChargeError::MintUnreachable {
            mint_url: mint_url.to_string(),
            transport_detail: detail,
            indeterminate: true,
        },
        ValidationError::LockedToken => ChargeError::LockedToken,
        ValidationError::MultiMintOrUnit => ChargeError::MultiMintOrUnit,
        ValidationError::TooManyProofs { got, max } => ChargeError::TooManyProofs { got, max },
        ValidationError::AmountMismatch { required, got } => ChargeError::AmountMismatch {
            required: u64::from(required),
            presented: u64::from(got),
            amount: u64::from(required),
            expected_swap_fee: 0,
        },
        ValidationError::UnitMismatch { expected, got } => ChargeError::WrongUnit {
            expected: expected.to_string(),
            got: got.to_string(),
        },
        ValidationError::MintNotAllowed { got, allowed } => ChargeError::MintNotAllowed {
            got: got.to_string(),
            allowed: allowed.iter().map(|m| m.to_string()).collect(),
        },
        ValidationError::TokenEmpty => {
            ChargeError::MalformedCredential("token contains no proofs".to_string())
        }
        ValidationError::MalformedToken(msg) => {
            ChargeError::MalformedCredential(format!("malformed token: {msg}"))
        }
        // Both swap-rejections (expired credential OR double-spent proof)
        // currently surface as DoubleSpend=402. Splitting out an Expired arm
        // needs the mint's NUT-03 error-body parse, which is not yet done.
        ValidationError::MintRejectedSwap(_) => ChargeError::DoubleSpend,
        // Money-safety: a missing/invalid swap-output DLEQ is verification-
        // failed at the SwapOutput location — a 402 (gateway serves nothing),
        // distinct from a double-spend so the operator sees the mint-trust
        // signal. NEVER serve the resource on this path.
        ValidationError::SwapOutputDleqInvalid(_) => ChargeError::DleqInvalid {
            location: DleqLocation::SwapOutput,
        },
    }
}

/// The ecash-agnostic [`Redeemer`] implementation for Cashu: wraps a
/// [`ChargeValidator`] and produces the cross-slice [`RedeemedProofs`].
/// `token_hash` and `fresh_proofs` are computed HERE because both need data only
/// the core holds (the raw presented string / the swap-returned proofs).
#[derive(Debug)]
pub struct CashuCredential<M: MintClient> {
    validator: ChargeValidator<M>,
}

impl<M: MintClient> CashuCredential<M> {
    /// Construct with NO proof-count cap.
    pub fn new(mint_client: M) -> Self {
        Self {
            validator: ChargeValidator::new(mint_client),
        }
    }

    /// Construct with a per-token `max_proofs` cap (pre-swap DoS guard).
    pub fn with_max_proofs(mint_client: M, max_proofs: usize) -> Self {
        Self {
            validator: ChargeValidator::with_max_proofs(mint_client, max_proofs),
        }
    }

    /// Construct from an already-built [`ChargeValidator`].
    pub fn from_validator(validator: ChargeValidator<M>) -> Self {
        Self { validator }
    }

    /// Borrow the underlying validator.
    pub fn validator(&self) -> &ChargeValidator<M> {
        &self.validator
    }
}

// `?Send` on wasm32 to match the `Redeemer` trait + `MintClient` seam.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<M: MintClient> Redeemer for CashuCredential<M> {
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError> {
        // Any decode failure (bad prefix, bad base64/CBOR, cashuA-not-cashuB) is
        // a malformed credential — a 402 about the credential, not about value.
        let token = decode_token(presented).map_err(|e| match e {
            ChallengeError::InvalidHeader(m) => {
                ChargeError::MalformedCredential(format!("invalid token: {m}"))
            }
            ChallengeError::DecodeFailed(m) => {
                ChargeError::MalformedCredential(format!("failed to decode token: {m}"))
            }
            ChallengeError::EncodeFailed(m) => ChargeError::MalformedCredential(m),
        })?;

        // Extracted up front: supplies the transport context for a
        // `MintUnreachable` and is the mint_url the fresh proofs re-tokenize
        // under. A token that cannot name its mint is malformed.
        let token_mint = token.mint_url().map_err(|e| {
            ChargeError::MalformedCredential(format!("token mint_url: {e}"))
        })?;

        let cashu_req = cashu_requirement_from_charge(req)?;

        let validated = self
            .validator
            .validate(&token, &cashu_req)
            .await
            .map_err(|e| map_validation_error(e, &token_mint.to_string()))?;

        // Re-serialize to a canonical cashuB string (`fresh_proofs` carries no
        // `cashu::Proofs`).
        let fresh_proofs = Token::new(
            validated.mint_url.clone(),
            validated.new_proofs.clone(),
            None,
            validated.unit.clone(),
        )
        .to_string();

        // The mint's active keyset for the unit, which may differ from the input
        // keyset.
        let active_keyset_id = validated
            .new_proofs
            .first()
            .map(|p| p.keyset_id.to_string())
            .unwrap_or_default();

        let amount = u64::from(validated.amount);
        let unit = validated.unit.to_string();

        let proofs = RedeemedProofs {
            fresh_proofs,
            amount,
            unit: unit.clone(),
            active_keyset_id,
            token_hash: token_hash_hex(presented),
        };

        Ok(Redeemed {
            unit,
            amount,
            proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use cashu::dhke::hash_to_curve;
    use cashu::nuts::nut02::{Id, KeySetInfo};
    use cashu::nuts::Proof;
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};

    use super::{ChargeValidator, ValidatedCharge, ValidationError};
    use crate::challenge::CashuRequirement;
    use crate::mint_client::{MintClient, MintClientError};

    /// Canned outcome for the mock [`MintClient::swap`] call.
    enum SwapResponse {
        /// Echo the incoming proofs back, so tests can assert amount
        /// preservation without constructing fresh proofs.
        Echo,
        Unreachable,
        UnreachableIndeterminate,
        RejectedSwap,
        DleqInvalid,
    }

    /// Canned outcome for the mock [`MintClient::keysets`] call.
    enum KeysetsResponse {
        Ok(Vec<KeySetInfo>),
        Unreachable,
    }

    /// Mock [`MintClient`]. The `*_calls` counters let tests assert whether each
    /// endpoint was contacted — structural failures must short-circuit before
    /// any network call.
    struct MockMintClient {
        swap_response: SwapResponse,
        keysets_response: KeysetsResponse,
        swap_calls: Arc<AtomicUsize>,
        keysets_calls: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct MockCounters {
        swap: Arc<AtomicUsize>,
        keysets: Arc<AtomicUsize>,
    }

    impl MockMintClient {
        fn new(
            swap_response: SwapResponse,
            keysets_response: KeysetsResponse,
        ) -> (Self, MockCounters) {
            let swap_calls = Arc::new(AtomicUsize::new(0));
            let keysets_calls = Arc::new(AtomicUsize::new(0));
            let counters = MockCounters {
                swap: swap_calls.clone(),
                keysets: keysets_calls.clone(),
            };
            (
                Self {
                    swap_response,
                    keysets_response,
                    swap_calls,
                    keysets_calls,
                },
                counters,
            )
        }

        /// Mock with an empty keyset list (sufficient for V0-format tokens).
        fn with_swap(swap_response: SwapResponse) -> (Self, MockCounters) {
            Self::new(swap_response, KeysetsResponse::Ok(Vec::new()))
        }
    }

    #[async_trait]
    impl MintClient for MockMintClient {
        async fn keysets(
            &self,
            _mint_url: &MintUrl,
        ) -> Result<Vec<KeySetInfo>, MintClientError> {
            self.keysets_calls.fetch_add(1, Ordering::SeqCst);
            match &self.keysets_response {
                KeysetsResponse::Ok(infos) => Ok(infos.clone()),
                KeysetsResponse::Unreachable => {
                    Err(MintClientError::Unreachable("mock keysets unreachable".into()))
                }
            }
        }

        async fn swap(
            &self,
            _mint_url: &MintUrl,
            proofs: Proofs,
        ) -> Result<Proofs, MintClientError> {
            self.swap_calls.fetch_add(1, Ordering::SeqCst);
            match self.swap_response {
                SwapResponse::Echo => Ok(proofs),
                SwapResponse::Unreachable => {
                    Err(MintClientError::Unreachable("mock unreachable".into()))
                }
                SwapResponse::UnreachableIndeterminate => Err(
                    MintClientError::UnreachableIndeterminate("mock indeterminate".into()),
                ),
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
                SwapResponse::DleqInvalid => Err(MintClientError::SwapOutputDleqInvalid(
                    "mock swap-output DLEQ invalid".into(),
                )),
            }
        }
    }

    fn pop_unit() -> CurrencyUnit {
        CurrencyUnit::Custom("pop_1700000000".to_string())
    }

    fn mint_a() -> MintUrl {
        MintUrl::from_str("https://mint-a.example.com").expect("valid mint url")
    }

    fn mint_b() -> MintUrl {
        MintUrl::from_str("https://mint-b.example.com").expect("valid mint url")
    }

    /// Build a `Proof` with a deterministic-but-unique C point (the `index`
    /// byte keeps `Token` from flagging duplicates). Uses a V0 keyset id, which
    /// `Token::proofs(&[])` round-trips without needing KeySetInfo.
    fn make_proof(amount: u64, index: u8) -> Proof {
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        proof_with_keyset(amount, index, keyset_id)
    }

    /// As [`make_proof`] but with an explicit keyset id, so tests can mint
    /// V1-format proofs (`01` prefix, 32 bytes of id).
    fn proof_with_keyset(amount: u64, index: u8, keyset_id: Id) -> Proof {
        let mut preimage = [0u8; 33];
        preimage[0] = 1;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
    }

    /// A NUT-10 P2PK-LOCKED proof: its secret is a `["P2PK", …]` NUT-10 secret,
    /// not a plain 32-byte hex string, so the locked-token gate must reject it.
    fn p2pk_locked_proof(amount: u64, index: u8) -> Proof {
        use cashu::nuts::nut10::SpendingConditions;
        use cashu::nuts::SecretKey;

        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let pk = SecretKey::generate().public_key();
        let nut10_secret: Secret = SpendingConditions::new_p2pk(pk, None)
            .try_into()
            .expect("P2PK spending-condition serializes to a NUT-10 secret");
        let mut preimage = [0u8; 33];
        preimage[0] = 3;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, nut10_secret, c)
    }

    /// A representative V1 keyset id (`01` prefix + 32 bytes). The bytes are
    /// arbitrary: V1 short-id resolution only matches the 7-byte token prefix
    /// against the first 7 bytes of the full id.
    fn v1_keyset_id() -> Id {
        Id::from_str(
            "01aabbccddeeff001122334455667788\
              99aabbccddeeff00112233445566778899",
        )
        .expect("valid v1 keyset id")
    }

    fn keyset_info(id: Id, unit: CurrencyUnit) -> KeySetInfo {
        KeySetInfo {
            id,
            unit,
            active: true,
            input_fee_ppk: 0,
            final_expiry: None,
        }
    }

    fn make_token(mint: MintUrl, unit: CurrencyUnit, proofs: Proofs) -> Token {
        Token::new(mint, proofs, None, unit)
    }

    fn requirement(unit: CurrencyUnit, mints: Vec<MintUrl>, amount: u64) -> CashuRequirement {
        CashuRequirement {
            unit,
            mints,
            amount: Amount::from(amount),
            payment_id: None,
            description: None,
            single_use: true,
        }
    }

    #[tokio::test]
    async fn validate_happy_path() {
        let proofs = vec![make_proof(8, 0), make_proof(2, 1)];
        let token = make_token(mint_a(), pop_unit(), proofs);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let ValidatedCharge {
            new_proofs,
            mint_url,
            unit,
            amount,
        } = validator
            .validate(&token, &req)
            .await
            .expect("happy-path validation succeeds");

        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets endpoint must be called once"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap endpoint must be called once"
        );
        assert_eq!(mint_url, mint_a());
        assert_eq!(unit, pop_unit());
        assert_eq!(amount, Amount::from(10));
        assert_eq!(new_proofs.len(), 2);
    }

    #[tokio::test]
    async fn validate_rejects_unit_mismatch() {
        let token = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("unit mismatch must fail");
        assert!(
            matches!(err, ValidationError::UnitMismatch { .. }),
            "expected UnitMismatch, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on unit mismatch"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called on unit mismatch"
        );
    }

    #[tokio::test]
    async fn validate_rejects_disallowed_mint() {
        let token = make_token(mint_b(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("disallowed mint must fail");
        assert!(
            matches!(err, ValidationError::MintNotAllowed { .. }),
            "expected MintNotAllowed, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on mint-allowlist failure"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called on mint-allowlist failure"
        );
    }

    #[tokio::test]
    async fn validate_rejects_underfunded_amount() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(2, 0), make_proof(3, 1)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("underfunded amount must fail");
        assert!(
            matches!(err, ValidationError::AmountMismatch { .. }),
            "expected AmountMismatch, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on amount mismatch"
        );
    }

    #[tokio::test]
    async fn validate_rejects_overfunded_amount() {
        // Exact-amount: an over-funded token is rejected, NOT charged with change.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(16, 0), make_proof(4, 1)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("overfunded amount must fail (no verifier-side change)");
        assert!(
            matches!(err, ValidationError::AmountMismatch { .. }),
            "expected AmountMismatch, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on amount mismatch"
        );
    }

    #[tokio::test]
    async fn validate_accepts_exact_amount() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(8, 0), make_proof(2, 1)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let validated = validator
            .validate(&token, &req)
            .await
            .expect("exact amount must validate");
        assert_eq!(validated.amount, Amount::from(10));
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once on the exact-amount happy path"
        );
    }

    #[tokio::test]
    async fn validate_rejects_empty_token() {
        let token = make_token(mint_a(), pop_unit(), vec![]);
        let req = requirement(pop_unit(), vec![mint_a()], 1);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("empty token must fail");
        assert!(
            matches!(err, ValidationError::TokenEmpty),
            "expected TokenEmpty, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on empty token"
        );
    }

    #[tokio::test]
    async fn validate_propagates_mint_unreachable() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Unreachable);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("unreachable mint must fail");
        assert!(
            matches!(err, ValidationError::MintUnreachable(_)),
            "expected MintUnreachable, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once before unreachable surfaces"
        );
    }

    #[tokio::test]
    async fn validate_propagates_mint_rejected_swap() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::RejectedSwap);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("rejected swap must fail");
        assert!(
            matches!(err, ValidationError::MintRejectedSwap(_)),
            "expected MintRejectedSwap, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once before rejection surfaces"
        );
    }

    #[tokio::test]
    async fn validate_propagates_swap_output_dleq_invalid() {
        // Money-safety: a swap-output DLEQ failure must surface as its OWN arm,
        // never collapsed into MintRejectedSwap.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::DleqInvalid);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("swap-output DLEQ failure must fail validation");
        assert!(
            matches!(err, ValidationError::SwapOutputDleqInvalid(_)),
            "expected SwapOutputDleqInvalid (distinct from MintRejectedSwap), got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once before the DLEQ failure surfaces"
        );
    }

    #[tokio::test]
    async fn validate_happy_path_v1_keyset() {
        // A V1 token serializes its keyset id as a 7-byte short id on the wire;
        // decoding back needs the full `KeySetInfo` from keysets(). Round-trip
        // through encode/decode so the proofs lose their full id and force that
        // resolution.
        let v1_id = v1_keyset_id();
        let proofs = vec![
            proof_with_keyset(7, 0, v1_id),
            proof_with_keyset(3, 1, v1_id),
        ];
        let token_str = make_token(mint_a(), pop_unit(), proofs).to_string();
        let token = Token::from_str(&token_str).expect("v1 token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![keyset_info(v1_id, pop_unit())]),
        );
        let validator = ChargeValidator::new(mock);

        let ValidatedCharge { amount, .. } = validator
            .validate(&token, &req)
            .await
            .expect("v1 happy path validates");
        assert_eq!(amount, Amount::from(10));
        assert_eq!(counters.keysets.load(Ordering::SeqCst), 1);
        assert_eq!(counters.swap.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn validate_propagates_keysets_unreachable() {
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) =
            MockMintClient::new(SwapResponse::Echo, KeysetsResponse::Unreachable);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("keysets-unreachable must fail");
        assert!(
            matches!(err, ValidationError::MintUnreachable(_)),
            "expected MintUnreachable, got {err:?}"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets must be called once before unreachable surfaces"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when keysets() failed"
        );
    }

    #[tokio::test]
    async fn validate_rejects_v1_token_with_no_matching_keyset() {
        // Empty keysets list ⇒ the 7-byte short id cannot resolve, so extraction
        // fails as MalformedToken and no proofs exist to swap.
        let v1_id = v1_keyset_id();
        let proofs = vec![proof_with_keyset(10, 0, v1_id)];
        let token_str = make_token(mint_a(), pop_unit(), proofs).to_string();
        let token = Token::from_str(&token_str).expect("v1 token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) =
            MockMintClient::new(SwapResponse::Echo, KeysetsResponse::Ok(Vec::new()));
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("no-matching-keyset must fail");
        assert!(
            matches!(err, ValidationError::MalformedToken(_)),
            "expected MalformedToken, got {err:?}"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets must be called"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when no proofs can be extracted"
        );
    }

    #[tokio::test]
    async fn validate_rejects_locked_p2pk_proof_before_swap() {
        // Bearer-only: a locked proof is rejected before any network call.
        let token = make_token(mint_a(), pop_unit(), vec![p2pk_locked_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("a NUT-10 locked proof must be rejected");
        assert!(
            matches!(err, ValidationError::LockedToken),
            "expected LockedToken, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on a locked proof"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called on a locked proof (pre-network gate)"
        );
    }

    #[tokio::test]
    async fn validate_rejects_locked_proof_mixed_with_plain() {
        // The gate is `any`: even one locked proof rejects the whole token.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), p2pk_locked_proof(2, 1)],
        );
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("one locked proof must reject the whole token");
        assert!(
            matches!(err, ValidationError::LockedToken),
            "expected LockedToken, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when any proof is locked"
        );
    }

    #[tokio::test]
    async fn validate_rejects_mixed_keysets_before_swap() {
        // Two proofs on DIFFERENT keyset ids. The V1 keyset is resolvable (we
        // supply its KeySetInfo) so extraction succeeds and the homogeneity
        // check is what fires — not an extraction error.
        let v0 = make_proof(4, 0); // keyset 009a1f293253e41e
        let v1_id = v1_keyset_id();
        let v1 = proof_with_keyset(6, 1, v1_id);
        let token_str = make_token(mint_a(), pop_unit(), vec![v0, v1]).to_string();
        let token = Token::from_str(&token_str).expect("mixed-keyset token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![keyset_info(v1_id, pop_unit())]),
        );
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("a token mixing keysets must be rejected");
        assert!(
            matches!(err, ValidationError::MultiMintOrUnit),
            "expected MultiMintOrUnit, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on a mixed-keyset token"
        );
    }

    #[tokio::test]
    async fn validate_rejects_too_many_proofs_before_swap() {
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(2, 0), make_proof(4, 1), make_proof(4, 2)],
        );
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::with_max_proofs(mock, 2);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("over the proof cap must be rejected");
        match err {
            ValidationError::TooManyProofs { got, max } => {
                assert_eq!(got, 3, "reports the actual proof count");
                assert_eq!(max, 2, "reports the configured cap");
            }
            other => panic!("expected TooManyProofs, got {other:?}"),
        }
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when over the proof cap"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called when over the proof cap (pre-network gate)"
        );
    }

    #[tokio::test]
    async fn validate_at_proof_cap_boundary_passes() {
        // The guard is strictly `>`, not `>=`: a token exactly at the cap passes.
        let token = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), make_proof(2, 1)],
        );
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::with_max_proofs(mock, 2);

        validator
            .validate(&token, &req)
            .await
            .expect("a token exactly at the cap must validate");
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap runs for a token at (not over) the cap"
        );
    }

    #[tokio::test]
    async fn validate_swap_unreachable_is_determinate_at_validator() {
        // `Unreachable` from the swap seam is DETERMINATE: it maps to the plain
        // MintUnreachable arm, NOT the indeterminate one.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Unreachable);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("unreachable swap must fail");
        assert!(
            matches!(err, ValidationError::MintUnreachable(_)),
            "a determinate Unreachable must map to MintUnreachable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn validate_swap_unreachable_indeterminate_maps_through() {
        // A post-submit swap-POST failure must surface as the distinct
        // MintUnreachableIndeterminate arm.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::UnreachableIndeterminate);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("indeterminate swap outcome must fail");
        assert!(
            matches!(err, ValidationError::MintUnreachableIndeterminate(_)),
            "expected MintUnreachableIndeterminate, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap was attempted before the indeterminate outcome surfaced"
        );
    }

    // ---- Redeemer impl: ValidationError → ChargeError mapping + the
    //      RedeemedProofs shape -------------

    use super::CashuCredential;
    use crate::redeemer::{ChargeRequirement, Redeemer};
    use crate::charge::ChargeError;

    fn charge_req(unit: &str, mints: Vec<MintUrl>, amount: u64) -> ChargeRequirement {
        ChargeRequirement {
            amount,
            unit: unit.to_string(),
            mints: mints.iter().map(|m| m.to_string()).collect(),
            payment_id: None,
            description: None,
            single_use: true,
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_happy_produces_redeemed_proofs() {
        let presented = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(8, 0), make_proof(2, 1)],
        )
        .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let redeemed = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect("happy verify_and_redeem succeeds");

        assert_eq!(redeemed.amount, 10);
        assert_eq!(redeemed.unit, "pop_1700000000");
        assert_eq!(redeemed.proofs.amount, 10);
        assert_eq!(redeemed.proofs.unit, "pop_1700000000");

        let th = &redeemed.proofs.token_hash;
        assert_eq!(th.len(), 64, "token_hash must be 64 hex chars, got {th:?}");
        assert!(
            th.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "token_hash must be lowercase hex: {th}"
        );
        // Must be the SHA-256 of the EXACT presented string.
        assert_eq!(th, &super::token_hash_hex(&presented));

        assert!(
            redeemed.proofs.fresh_proofs.starts_with("cashuB"),
            "fresh_proofs must be a cashuB token, got: {}",
            &redeemed.proofs.fresh_proofs[..redeemed.proofs.fresh_proofs.len().min(8)]
        );
        let reparsed = Token::from_str(&redeemed.proofs.fresh_proofs)
            .expect("fresh_proofs re-parses as a cashu token");
        assert_eq!(
            reparsed.value().expect("token value"),
            Amount::from(10),
            "re-parsed fresh_proofs must total the redeemed amount"
        );

        assert!(
            !redeemed.proofs.active_keyset_id.is_empty(),
            "active_keyset_id must be populated"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_unit_mismatch_to_wrong_unit() {
        let presented = make_token(mint_a(), CurrencyUnit::Sat, vec![make_proof(10, 0)])
            .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("unit mismatch must map to WrongUnit");
        assert!(
            matches!(err, ChargeError::WrongUnit { .. }),
            "expected WrongUnit, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_amount_mismatch_with_zero_fee() {
        let presented = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(16, 0), make_proof(4, 1)],
        )
        .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("amount mismatch must map to AmountMismatch");
        match err {
            ChargeError::AmountMismatch {
                required,
                presented,
                amount,
                expected_swap_fee,
            } => {
                assert_eq!(required, 10);
                assert_eq!(presented, 20);
                assert_eq!(amount, 10);
                assert_eq!(expected_swap_fee, 0, "fee forced 0 in Step 1");
            }
            other => panic!("expected AmountMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_rejected_swap_to_double_spend() {
        // Any swap rejection collapses to DoubleSpend (see `map_validation_error`).
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)])
            .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::RejectedSwap);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("rejected swap must map to DoubleSpend");
        assert!(
            matches!(err, ChargeError::DoubleSpend),
            "expected DoubleSpend, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_swap_output_dleq_to_dleq_invalid_swap_output() {
        // Money-safety: a swap-output DLEQ failure maps to DleqInvalid{SwapOutput},
        // NOT DoubleSpend — the gateway serves nothing and no proofs are produced.
        use crate::charge::DleqLocation;
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::DleqInvalid);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("swap-output DLEQ failure must map to DleqInvalid");
        match err {
            ChargeError::DleqInvalid { location } => {
                assert_eq!(
                    location,
                    DleqLocation::SwapOutput,
                    "swap-output DLEQ failure must carry the SwapOutput location"
                );
            }
            other => panic!("expected DleqInvalid {{ SwapOutput }}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_unreachable_to_mint_unreachable() {
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)])
            .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Unreachable);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("unreachable mint must map to MintUnreachable");
        match err {
            ChargeError::MintUnreachable {
                mint_url,
                indeterminate,
                ..
            } => {
                assert!(!mint_url.is_empty(), "mint_url must be threaded through");
                assert!(!indeterminate, "Step 1 never sets indeterminate");
            }
            other => panic!("expected MintUnreachable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_rejects_malformed_credential() {
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);
        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem("not-a-token", &req)
            .await
            .expect_err("garbage credential must be rejected");
        assert!(
            matches!(err, ChargeError::MalformedCredential(_)),
            "expected MalformedCredential, got {err:?}"
        );
    }

    /// A real cashuA/TokenV3 string (cashu-0.16.0 test vector). The contract is
    /// cashuB/TokenV4 only, so `verify_and_redeem` must reject it as
    /// MalformedCredential — and never touch the mint.
    const VERIFY_CASHU_A_V3: &str = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ==";

    #[tokio::test]
    async fn verify_and_redeem_rejects_cashu_a_as_malformed() {
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);
        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(VERIFY_CASHU_A_V3, &req)
            .await
            .expect_err("cashuA must be rejected as malformed");
        assert!(
            matches!(err, ChargeError::MalformedCredential(_)),
            "expected MalformedCredential for cashuA, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_locked_token_to_locked_token() {
        let presented =
            make_token(mint_a(), pop_unit(), vec![p2pk_locked_proof(10, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("a locked proof must map to LockedToken");
        assert!(
            matches!(err, ChargeError::LockedToken),
            "expected LockedToken, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_too_many_proofs_to_too_many_proofs() {
        let presented = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(2, 0), make_proof(4, 1), make_proof(4, 2)],
        )
        .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::with_max_proofs(mock, 2);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("an over-cap token must map to TooManyProofs");
        match err {
            ChargeError::TooManyProofs { got, max } => {
                assert_eq!(got, 3);
                assert_eq!(max, 2);
            }
            other => panic!("expected TooManyProofs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_indeterminate_unreachable_to_indeterminate_true() {
        // indeterminate: true — still 503 at HTTP, but the operator must
        // checkstate before assuming the token is good.
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::UnreachableIndeterminate);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("indeterminate outcome must map to MintUnreachable");
        match err {
            ChargeError::MintUnreachable {
                indeterminate,
                mint_url,
                ..
            } => {
                assert!(
                    indeterminate,
                    "a post-submit swap failure must set indeterminate: true"
                );
                assert!(!mint_url.is_empty(), "mint_url must be threaded through");
            }
            other => panic!("expected MintUnreachable {{ indeterminate: true }}, got {other:?}"),
        }
    }
}
