//! Swap-at-mint validator for cashu charge credentials.
//!
//! Given a decoded [`Token`] from a holder retrying a 402-gated request and a
//! [`CashuRequirement`] the verifier originally advertised, [`ChargeValidator`]:
//!
//! 1. Confirms structural fit (unit, mint, amount) without touching the
//!    network.
//! 2. Calls the issuing mint's swap endpoint via [`MintClient`] — a
//!    successful swap is the proof of unspentness *and* of
//!    `final_expiry` not having passed.
//! 3. Returns a [`ValidatedCharge`] holding the new proofs the verifier
//!    received from the swap. The charge is transfer-on-use: the verifier
//!    keeps the value.
//!
//! Structural checks run first so an obviously-bad token never produces a
//! network round trip to the mint.
//!
//! [`ChargeValidator`] is the cashu-typed internal engine; the public
//! ecash-agnostic [`Credential`][crate::credential::Credential] impl
//! ([`CashuCredential`]) wraps it, converting at the boundary to
//! `String`/`u64` and to the [`pops_core_types`] contract.

use std::str::FromStr;

use cashu::nuts::nut00::ProofsMethods;
use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};
use pops_core_types::{ChargeError, RedeemedProofs};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::challenge::{decode_token, CashuRequirement};
use crate::credential::{ChargeRequirement, Credential, Redeemed};
use crate::error::Error as ChallengeError;
use crate::mint_client::{MintClient, MintClientError};

/// Result of a successful charge validation.
///
/// `new_proofs` are the proofs the verifier now controls (the mint signed
/// them against blinded outputs the swap call generated). `mint_url`,
/// `unit`, and `amount` echo the validated facts about the original token so
/// callers do not have to re-derive them.
#[derive(Debug, Clone)]
pub struct ValidatedCharge {
    /// Proofs returned by the mint's swap response, now under verifier
    /// secrets.
    pub new_proofs: Proofs,
    /// Mint that signed both the original and the new proofs.
    pub mint_url: MintUrl,
    /// Currency unit of the swapped value (matches the
    /// [`CashuRequirement`]).
    pub unit: CurrencyUnit,
    /// Total amount of the swapped proofs (sum of `new_proofs.amount`).
    pub amount: Amount,
}

/// Errors a [`ChargeValidator`] can return.
///
/// Variants split into two groups: structural (`UnitMismatch`,
/// `MintNotAllowed`, `AmountMismatch`, `TokenEmpty`) — raised before
/// any network call — and mint-mediated (`MintRejectedSwap`,
/// `MintUnreachable`) — raised after the swap attempt.
///
/// These are the cashu-typed internal arms; the public
/// [`CashuCredential`] maps them onto
/// [`pops_core_types::ChargeError`][pops_core_types::ChargeError].
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Token unit does not match the requirement's unit.
    #[error("token unit {got:?} does not match requirement unit {expected:?}")]
    UnitMismatch {
        /// Unit advertised by the verifier in the challenge.
        expected: CurrencyUnit,
        /// Unit found on the presented token.
        got: CurrencyUnit,
    },

    /// Token was issued by a mint not in the requirement's allowlist.
    #[error("token mint {got} is not in the requirement's allowed mints: {allowed:?}")]
    MintNotAllowed {
        /// Mint URL embedded in the token.
        got: MintUrl,
        /// Mints the verifier explicitly allowed.
        allowed: Vec<MintUrl>,
    },

    /// Token's total proof amount does not exactly equal the requirement.
    ///
    /// The charge is exact-amount (L402 / NUT-18 style): the holder must
    /// present a token worth precisely `requirement.amount`. The verifier
    /// makes no change — splitting an over-funded credential is the holder's
    /// job, done locally and non-custodially before presentation. Both an
    /// under- and an over-funded token are rejected with this error.
    #[error("token amount {got} does not equal required {required}")]
    AmountMismatch {
        /// Amount the verifier required in the challenge.
        required: Amount,
        /// Total of all proof amounts in the presented token.
        got: Amount,
    },

    /// Mint accepted the swap call but rejected the proofs (expired
    /// credential, double-spent proof, invalid signature, keyset rotated,
    /// etc.).
    #[error("mint rejected swap: {0}")]
    MintRejectedSwap(String),

    /// Mint could not be reached (DNS, TCP, TLS, timeout, etc.).
    #[error("mint unreachable: {0}")]
    MintUnreachable(String),

    /// Token carried zero proofs — nothing to validate or swap.
    #[error("token contains no proofs")]
    TokenEmpty,

    /// Token internals (proof extraction, value summation, mint-url
    /// parsing) failed before the swap could be attempted.
    #[error("malformed token: {0}")]
    MalformedToken(String),
}

/// Validates charge tokens against a [`CashuRequirement`] by calling the
/// issuing mint's swap endpoint.
///
/// Construct once with a configured [`MintClient`] and reuse for many
/// validations. The validator holds no per-request state.
#[derive(Debug)]
pub struct ChargeValidator<M: MintClient> {
    mint_client: M,
}

impl<M: MintClient> ChargeValidator<M> {
    /// Construct a validator backed by the supplied mint client.
    pub fn new(mint_client: M) -> Self {
        Self { mint_client }
    }

    /// Borrow the underlying mint client (used by the [`CashuCredential`]
    /// wrapper, which holds the validator).
    pub fn mint_client(&self) -> &M {
        &self.mint_client
    }

    /// Run the structural (network-free) checks plus proof extraction.
    ///
    /// Confirms unit, mint allowlist, non-emptiness, and exact amount,
    /// fetching keysets only to resolve V1 short keyset IDs. Returns the
    /// token's mint, its unit, and the extracted proofs — the inputs a
    /// swap needs. [`Self::validate`] runs this prelude so an
    /// obviously-bad token never reaches the swap endpoint.
    async fn check_and_extract(
        &self,
        token: &Token,
        requirement: &CashuRequirement,
    ) -> Result<(MintUrl, CurrencyUnit, Proofs), ValidationError> {
        // Structural: unit.
        //
        // `Token::unit()` returns `Option<CurrencyUnit>` because V3 tokens
        // make the unit optional on the wire. We treat a missing unit as a
        // mismatch — the verifier always advertises one.
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

        // Structural: mint allowlist.
        //
        // An empty `requirement.mints` means "any mint" — see
        // `CashuRequirement` docs. Otherwise the token's mint must be a
        // member.
        let token_mint = token
            .mint_url()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
        if !requirement.mints.is_empty() && !requirement.mints.contains(&token_mint) {
            return Err(ValidationError::MintNotAllowed {
                got: token_mint,
                allowed: requirement.mints.clone(),
            });
        }

        // Network: fetch keysets for V1 short-id resolution.
        //
        // V0 keyset IDs round-trip locally; V1 short IDs are a 7-byte
        // prefix on the wire and need a full 32-byte ID from the mint's
        // `/v1/keysets` response to expand. We fetch up front so the
        // proof-extraction step below works for both formats. If the
        // mint is unreachable, surface that before the swap call — no
        // point attempting swap when we can't even read the inputs.
        let keysets = self
            .mint_client
            .keysets(&token_mint)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
            })?;

        // Extract proofs against the fetched keyset list. Resolves V1
        // short IDs cleanly; V0 short IDs do not consult the list. If a
        // V1 ID has no matching keyset, this surfaces as MalformedToken
        // (the cashu crate returns `UnknownShortKeysetId`).
        let proofs = token
            .proofs(&keysets)
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        // Structural: non-empty.
        if proofs.is_empty() {
            return Err(ValidationError::TokenEmpty);
        }

        // Structural: amount must match EXACTLY.
        //
        // The charge is exact-amount: the holder presents a token worth
        // precisely `requirement.amount` and the verifier swaps the whole
        // thing. The verifier never makes change — an over-funded token is
        // rejected just like an under-funded one, and the holder is expected
        // to split locally (non-custodially) down to the exact amount before
        // presenting. We sum proof amounts directly (rather than
        // `Token::value()`) so the comparison happens before any network
        // call and an off-amount token short-circuits before swap.
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

    /// Run the full validation pipeline on `token` against `requirement`.
    ///
    /// Structural checks run first; the mint swap is only attempted if the
    /// token is structurally valid. This keeps obviously-bad tokens from
    /// producing network traffic.
    ///
    /// Swaps the *whole* presented token — the verifier keeps all of it.
    /// The charge is exact-amount, so the structural prelude already
    /// guaranteed the token is worth precisely `requirement.amount`; the
    /// verifier never returns change. Splitting an over-funded credential is
    /// the holder's responsibility, done locally before presentation.
    pub async fn validate(
        &self,
        token: &Token,
        requirement: &CashuRequirement,
    ) -> Result<ValidatedCharge, ValidationError> {
        let (token_mint, token_unit, proofs) =
            self.check_and_extract(token, requirement).await?;

        // Network: swap at the issuing mint.
        //
        // A successful swap proves both unspentness (nullifier check) and
        // unexpired credential (`final_expiry` check) atomically.
        let new_proofs = self
            .mint_client
            .swap(&token_mint, proofs)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
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
/// [`ChargeRequirement`] (`String`/`u64`) the [`Credential`] seam speaks.
/// Used by callers that already hold the cashu-typed requirement (the
/// middleware) and want to drive a generic `Credential`.
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

/// Build the cashu-typed [`CashuRequirement`] from the decoupled
/// [`ChargeRequirement`]. Fallible: the `unit` / `mints` strings must parse
/// into their cashu types. A bad requirement is server-side config, so a
/// parse failure maps to [`ChargeError::MalformedRequest`] (a 400 framework
/// status, NOT a 402 — the credential was never the problem).
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

/// SHA-256 of the EXACT presented credential string, lowercase hex. This is
/// the receipt `reference` (`RedeemedProofs.token_hash`) — a stable,
/// shareable settlement id that exposes no secret.
fn token_hash_hex(presented: &str) -> String {
    let digest = Sha256::digest(presented.as_bytes());
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // lower-hex, fixed 2 chars/byte.
        s.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble<16"));
        s.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble<16"));
    }
    s
}

/// Map a cashu-typed [`ValidationError`] onto the cross-slice
/// [`ChargeError`] contract. `mint_url` supplies the transport context the
/// cashu arm does not carry.
///
/// The mapping follows the build-plan §1.3 "currently fully emitted" set:
/// - `MintUnreachable` → `MintUnreachable { indeterminate: false }`
///   (pre-/at-swap transport failure; the durability-driven indeterminate
///   case is not split in Step 1).
/// - `AmountMismatch`  → `AmountMismatch { expected_swap_fee: 0 }`
///   (fee forced 0 today; `required == amount`).
/// - `UnitMismatch`    → `WrongUnit`.
/// - `MintNotAllowed`  → `MintNotAllowed`.
/// - `TokenEmpty` / `MalformedToken` → `MalformedCredential`.
/// - `MintRejectedSwap`→ `DoubleSpend` (SAFE interim — both swap-rejections
///   collapse to DoubleSpend=402 until the NUT-03 error-body parse for
///   `Expired` lands; that split is conformance backlog, NOT Step 1).
fn map_validation_error(e: ValidationError, mint_url: &str) -> ChargeError {
    match e {
        ValidationError::MintUnreachable(detail) => ChargeError::MintUnreachable {
            mint_url: mint_url.to_string(),
            transport_detail: detail,
            indeterminate: false,
        },
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
        // SAFE interim: both swap-rejections (expired credential OR
        // double-spent proof) collapse to DoubleSpend=402. The Expired split
        // needs the mint's NUT-03 error-body parse (conformance stream, G5).
        ValidationError::MintRejectedSwap(_) => ChargeError::DoubleSpend,
    }
}

/// The ecash-agnostic [`Credential`] implementation for Cashu.
///
/// Wraps a [`ChargeValidator`] (the cashu-typed engine) and exposes the
/// decoupled [`Credential`] seam: it converts the [`ChargeRequirement`] in,
/// runs verify+swap, maps [`ValidationError`] → [`ChargeError`], and produces
/// the cross-slice [`RedeemedProofs`] (computing `token_hash` from the
/// presented bytes and `fresh_proofs` from the swap response). `token_hash`
/// and `fresh_proofs` are computed HERE because both need data only the core
/// holds (the raw presented string / the swap-returned proofs).
#[derive(Debug)]
pub struct CashuCredential<M: MintClient> {
    validator: ChargeValidator<M>,
}

impl<M: MintClient> CashuCredential<M> {
    /// Construct from a configured [`MintClient`].
    pub fn new(mint_client: M) -> Self {
        Self {
            validator: ChargeValidator::new(mint_client),
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

// async_trait is `?Send` on wasm32 to match the `Credential` trait + the
// `MintClient` seam this composes over.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<M: MintClient> Credential for CashuCredential<M> {
    async fn verify_and_redeem(
        &self,
        presented: &str,
        req: &ChargeRequirement,
    ) -> Result<Redeemed, ChargeError> {
        // Decode the presented credential. Any decode failure (bad prefix,
        // bad base64/CBOR, cashuA-not-cashuB) is a malformed credential.
        let token = decode_token(presented).map_err(|e| match e {
            ChallengeError::InvalidHeader(m) => {
                ChargeError::MalformedCredential(format!("invalid token: {m}"))
            }
            ChallengeError::DecodeFailed(m) => {
                ChargeError::MalformedCredential(format!("failed to decode token: {m}"))
            }
            ChallengeError::EncodeFailed(m) => ChargeError::MalformedCredential(m),
        })?;

        // Extract the token's mint up front: it supplies the transport
        // context for a `MintUnreachable` and is the mint_url the fresh
        // proofs are re-tokenized under. A token that cannot name its mint
        // is malformed.
        let token_mint = token.mint_url().map_err(|e| {
            ChargeError::MalformedCredential(format!("token mint_url: {e}"))
        })?;

        // Convert the decoupled requirement into the cashu-typed one the
        // engine needs (fallible: server-config parse).
        let cashu_req = cashu_requirement_from_charge(req)?;

        // Run verify + swap-to-redeem; map the cashu-typed error onto the
        // cross-slice contract.
        let validated = self
            .validator
            .validate(&token, &cashu_req)
            .await
            .map_err(|e| map_validation_error(e, &token_mint.to_string()))?;

        // Serialize the swap-returned proofs to a canonical cashuB token
        // string (the cross-slice `fresh_proofs` carries no `cashu::Proofs`).
        let fresh_proofs = Token::new(
            validated.mint_url.clone(),
            validated.new_proofs.clone(),
            None,
            validated.unit.clone(),
        )
        .to_string();

        // The keyset the FRESH proofs are signed under (the mint's active
        // keyset for the unit, which may differ from the input keyset).
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
        /// Echo the incoming proofs back as the "new" proofs. Lets tests
        /// assert amount preservation without constructing fresh proofs.
        Echo,
        /// Return [`MintClientError::Unreachable`] with a fixed message.
        Unreachable,
        /// Return [`MintClientError::RejectedSwap`] with a fixed message.
        RejectedSwap,
    }

    /// Canned outcome for the mock [`MintClient::keysets`] call.
    enum KeysetsResponse {
        /// Return the supplied list of [`KeySetInfo`]s.
        Ok(Vec<KeySetInfo>),
        /// Return [`MintClientError::Unreachable`] with a fixed message.
        Unreachable,
    }

    /// Mock [`MintClient`] used in validator unit tests.
    ///
    /// `swap_response` and `keysets_response` are the canned outcomes for
    /// each trait method. `swap_calls` and `keysets_calls` let tests
    /// assert whether and how often each endpoint was actually contacted
    /// (structural failures must short-circuit before any network call).
    struct MockMintClient {
        swap_response: SwapResponse,
        keysets_response: KeysetsResponse,
        swap_calls: Arc<AtomicUsize>,
        keysets_calls: Arc<AtomicUsize>,
    }

    /// Call counters returned by [`MockMintClient::new`] so tests can
    /// observe behaviour without holding a reference to the mock itself.
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

        /// Convenience: build a mock that returns the default empty
        /// keyset list (sufficient for V0-format tokens) and the supplied
        /// swap response.
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
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
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

    /// Build a `Proof` with a deterministic-but-unique C point. The
    /// `index` byte differentiates proofs so `Token` does not flag them as
    /// duplicates.
    fn make_proof(amount: u64, index: u8) -> Proof {
        // V0 keyset id (`00` prefix); `Token::proofs(&[])` round-trips V0
        // short ids without needing KeySetInfo.
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        proof_with_keyset(amount, index, keyset_id)
    }

    /// As [`make_proof`] but parameterised by keyset id so tests can mint
    /// V1-format proofs (`01` prefix, 32 bytes of id).
    fn proof_with_keyset(amount: u64, index: u8, keyset_id: Id) -> Proof {
        let mut preimage = [0u8; 33];
        preimage[0] = 1;
        preimage[1] = index;
        let c = hash_to_curve(&preimage).expect("hash_to_curve");
        Proof::new(Amount::from(amount), keyset_id, Secret::generate(), c)
    }

    /// Build a representative V1 keyset id (`01` prefix + 32 bytes).
    /// The bytes are arbitrary — V1 short-id resolution only checks
    /// that the 7-byte token prefix matches the first 7 bytes of the
    /// full id, so any well-formed 32-byte id round-trips through the
    /// token codec.
    fn v1_keyset_id() -> Id {
        Id::from_str(
            "01aabbccddeeff001122334455667788\
              99aabbccddeeff00112233445566778899",
        )
        .expect("valid v1 keyset id")
    }

    /// Build a [`KeySetInfo`] for a V1 id that matches the proofs
    /// produced via [`proof_with_keyset`] with that same id.
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
        // Token issued by mint_b, requirement only allows mint_a.
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
        // Token totals 5, requirement asks for 10 — under the exact amount.
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
        // Token totals 20, requirement asks for exactly 10. The charge is
        // exact-amount: an over-funded token is rejected, NOT charged with
        // change. The holder must split down to 10 locally before
        // presenting.
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
        // Token totals exactly 10 == requirement: the happy exact-amount
        // path. (Reinforces the boundary the over/under tests bracket.)
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
        // This is the case where `final_expiry` has passed or a nullifier
        // collided (double-spend).
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
    async fn validate_happy_path_v1_keyset() {
        // Synthesize a V1-format token: proofs whose keyset id has the
        // `01` version byte. On the wire the token serializes the id as
        // a 7-byte short id; decoding back into proofs needs the matching
        // full 32-byte `KeySetInfo` from the mint's keysets endpoint.
        let v1_id = v1_keyset_id();
        let proofs = vec![
            proof_with_keyset(7, 0, v1_id),
            proof_with_keyset(3, 1, v1_id),
        ];
        // Round-trip the token through encode/decode so the proofs lose
        // their full id and force the validator to resolve via keysets().
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
        // V1 token but the mint returns an empty keysets list — the
        // 7-byte short id cannot be resolved into a full id, so proof
        // extraction surfaces as MalformedToken. Swap must not be
        // attempted: we cannot construct a swap request without proofs.
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

    // ---- Credential impl: ValidationError → ChargeError mapping + the
    //      RedeemedProofs shape (build-plan §1.3 new tests) -------------

    use super::CashuCredential;
    use crate::credential::{ChargeRequirement, Credential};
    use pops_core_types::ChargeError;

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
        // Echo swap, exact amount → Ok. Assert the RedeemedProofs shape:
        // token_hash is 64 lowercase-hex, fresh_proofs re-parses to a cashuB
        // token, amount matches, active_keyset_id is non-empty.
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

        // token_hash: 64 lowercase-hex chars (SHA-256).
        let th = &redeemed.proofs.token_hash;
        assert_eq!(th.len(), 64, "token_hash must be 64 hex chars, got {th:?}");
        assert!(
            th.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "token_hash must be lowercase hex: {th}"
        );
        // And it must be the SHA-256 of the EXACT presented string.
        assert_eq!(th, &super::token_hash_hex(&presented));

        // fresh_proofs: a cashuB string that re-parses to a Token.
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

        // active_keyset_id: non-empty hex of the fresh proofs' keyset.
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
        // Overfunded: present 20 against required 10 → AmountMismatch with
        // expected_swap_fee 0 and required == amount.
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
        // SAFE interim: any swap rejection collapses to DoubleSpend in Step 1.
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
    async fn verify_and_redeem_maps_unreachable_to_mint_unreachable() {
        // Transport failure → MintUnreachable { indeterminate: false } with
        // the token's mint threaded into mint_url.
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
        // A non-cashu string is a malformed credential (not a 402 reason
        // about value).
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
}
