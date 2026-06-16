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
use crate::charge::{ChargeError, RedeemedProofs};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::challenge::{decode_token, mint_url_has_userinfo, CashuRequirement};
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
    /// NUT-12 verdict on the swap-RETURNED blind signatures. `false` is a
    /// mint-trust incident (`draft-cashu-charge-00` §security-dleq), already
    /// WARN-logged by the swap ceremony — the charge itself SUCCEEDED and the
    /// resource is served; the flag rides along so hosts can alert/quarantine.
    pub dleq_ok: bool,
}

/// Errors a [`ChargeValidator`] can return. The pre-swap arms (`UnitMismatch`,
/// `ResolvedKeysetUnitMismatch`, `MintNotAllowed`, `PaymentInsufficient`,
/// `TokenEmpty`, `LockedToken`, `TooManyProofs`) are raised
/// BEFORE the swap is ever attempted; the rest are raised at/after it.
/// [`CashuCredential`] maps these onto [`crate::charge::ChargeError`].
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

    /// A RESOLVED keyset's unit differs from the requirement's (spec
    /// verification step 6): the token's declared unit is client-supplied data,
    /// the mint's published keyset is the authority. Raised BEFORE the swap, so
    /// a foreign-unit proof smuggled under a matching declared unit never
    /// reaches the mint.
    #[error(
        "resolved keyset {keyset_id} has unit {got:?}, requirement unit is {expected:?} \
         (the published keyset, not the token's declared unit, is authoritative)"
    )]
    ResolvedKeysetUnitMismatch {
        /// The offending keyset (full hex id).
        keyset_id: String,
        /// Unit the requirement demands.
        expected: CurrencyUnit,
        /// Unit the mint publishes for this keyset.
        got: CurrencyUnit,
    },

    /// A proof carries a NUT-10 spending-condition secret (P2PK / HTLC). The
    /// spec permits conditions only when the challenge advertised them; this
    /// implementation advertises none, so a condition is unsatisfiable and the
    /// swap would reject it. Rejected early as a fast-path (same
    /// verification-failed outcome, no mint round-trip).
    #[error("token carries a NUT-10 spending condition (locked); bearer proofs only")]
    LockedToken,

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

    /// Token's mint URL carries userinfo (`user@host`) — the spec's mint-trust
    /// § rejects it outright, before any membership comparison.
    #[error("token mint URL {url} carries userinfo (user@host), which is rejected outright")]
    MintUrlUserinfo {
        /// The offending mint URL.
        url: String,
    },

    /// A v2 short keyset id resolves to zero or multiple keysets in the mint's
    /// published list. Raised BEFORE proof extraction (cashu's own resolver
    /// silently takes the first prefix match, so ambiguity is checked here).
    #[error("unresolvable or ambiguous short keyset id {short_id} against the mint's published keysets")]
    ShortKeysetIdUnresolved {
        /// The short id as it appears on the wire (hex).
        short_id: String,
    },

    /// Total proof amount is LESS than the requirement (spec verification
    /// step 7: value must be at least `amount + expected_swap_fee`). The
    /// verifier makes no change; value ABOVE the requirement is accepted and
    /// retained, so only an under-funded token is rejected.
    #[error("token amount {got} is less than required {required}")]
    PaymentInsufficient {
        /// Amount required.
        required: Amount,
        /// Total presented.
        got: Amount,
    },

    /// Mint accepted the call but rejected the proofs WITHOUT typing the
    /// reason as already-spent or keyset-class (bad signature, unbalanced,
    /// etc.) — the definitive-rejection catch-all.
    #[error("mint rejected swap: {0}")]
    MintRejectedSwap(String),

    /// Mint rejected the swap because an input proof is ALREADY SPENT (the
    /// mint-typed double-spend, NUT code 11001).
    #[error("mint rejected swap: proof already spent: {0}")]
    AlreadySpent(String),

    /// Mint rejected the call with a keyset-class error: the keyset has
    /// retired or its `final_expiry` has passed (spec verification step 8 — a
    /// swap rejection, so `verification-failed`, with the cause named in the
    /// problem `detail`). The token was NOT consumed.
    #[error("mint rejected swap (keyset retired or final_expiry passed): {0}")]
    KeysetRetiredOrExpired(String),

    /// The keyset charges an `input_fee_ppk` the fee-free profile disallows —
    /// a policy reject raised before the swap (token NOT consumed), kept
    /// distinct from [`Self::MintRejectedSwap`] so it never reads as a
    /// double-spend.
    #[error(
        "fee-bearing keyset {keyset_id} disallowed: input_fee_ppk {input_fee_ppk} \
         exceeds the fee-free profile"
    )]
    FeeTooHigh {
        /// Keyset whose fee exceeded the profile (hex id).
        keyset_id: String,
        /// The disallowed `input_fee_ppk`.
        input_fee_ppk: u64,
    },

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
        // Spec mint-trust §: a userinfo-bearing mint URL is rejected outright,
        // before any membership comparison.
        if mint_url_has_userinfo(&token_mint.to_string()) {
            return Err(ValidationError::MintUrlUserinfo {
                url: token_mint.to_string(),
            });
        }
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

        // Fast-path, not a spec-mandated step: spec f3183d2 permits spending
        // conditions only when the challenge's payment request advertised them
        // (step 8 supplies the witness); this implementation advertises none, so
        // any condition is unsatisfiable here and the swap would reject it. A
        // plain 32-byte hex secret does NOT parse as NUT-10, so this fires only
        // on a genuinely locked (P2PK/HTLC) proof; rejecting it early yields the
        // same verification-failed the swap would, without the mint round-trip.
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
                // `keysets()` submits no inputs and does no DLEQ/fee work, so
                // the remaining arms are unreachable here; map defensively
                // (each onto its honest counterpart) to keep the match total.
                MintClientError::UnreachableIndeterminate(msg) => {
                    ValidationError::MintUnreachable(msg)
                }
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
                MintClientError::AlreadySpent(msg) => ValidationError::AlreadySpent(msg),
                MintClientError::KeysetRetiredOrExpired(msg) => {
                    ValidationError::KeysetRetiredOrExpired(msg)
                }
                MintClientError::FeeTooHigh {
                    keyset_id,
                    input_fee_ppk,
                } => ValidationError::FeeTooHigh {
                    keyset_id,
                    input_fee_ppk,
                },
            })?;

        // cashu 0.16's `Id::from_short_keyset_id` silently resolves a v2 short
        // id to the FIRST prefix match, so resolve locally first: zero matches
        // is unresolvable and more than one is ambiguous — both reject here,
        // pre-extraction. Only well-formed v2 prefixes (7–32 bytes) are
        // checked; anything else falls through to the extraction error below.
        for short in token_short_keyset_ids(token) {
            let bytes = short.to_bytes();
            let prefix = &bytes[1..];
            if bytes[0] != 0x01 || !(7..=32).contains(&prefix.len()) {
                continue;
            }
            let matches = keysets
                .iter()
                .filter(|k| k.id.to_bytes()[1..].starts_with(prefix))
                .count();
            if matches != 1 {
                return Err(ValidationError::ShortKeysetIdUnresolved {
                    short_id: short.to_string(),
                });
            }
        }

        // Resolves V1 short IDs against the list (V0 do not consult it).
        let proofs = token
            .proofs(&keysets)
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        if proofs.is_empty() {
            return Err(ValidationError::TokenEmpty);
        }

        // Spec verification step 6, BEFORE the step-7 value check and the swap:
        // EVERY resolved keyset's unit must equal the requirement's. The token's
        // declared unit (checked above) is client-supplied data; the mint's
        // published keyset is the authority — without this, a sat-keyset proof
        // under a token DECLARING the pop unit would reach the swap. Proofs may
        // span several keysets (a TokenV4 groups proofs by keyset id; change
        // accrued across a keyset rotation is exactly such a token), so check
        // each distinct keyset, not just the first. A keyset id absent from the
        // published list resolves nothing (no unit to assert); the swap rejects
        // unknown keysets.
        for proof in &proofs {
            if let Some(resolved) = keysets.iter().find(|k| k.id == proof.keyset_id) {
                if resolved.unit != requirement.unit {
                    return Err(ValidationError::ResolvedKeysetUnitMismatch {
                        keyset_id: proof.keyset_id.to_string(),
                        expected: requirement.unit.clone(),
                        got: resolved.unit.clone(),
                    });
                }
            }
        }

        // Value check (see `PaymentInsufficient`): at least the requirement
        // (the fee-free profile's `expected_swap_fee` is 0, so the requirement
        // is the bare amount). Summed directly rather than via `Token::value()`
        // so an under-funded token short-circuits before swap.
        let token_amount = proofs
            .total_amount()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
        if token_amount < requirement.amount {
            return Err(ValidationError::PaymentInsufficient {
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
        // and unexpired credential (`final_expiry` check). Its `dleq_ok` is the
        // swap-output NUT-12 verdict — a FLAG, never a failure (the ceremony
        // already WARN-logged a false one; see `ValidatedCharge::dleq_ok`).
        let outcome = self
            .mint_client
            .swap(&token_mint, proofs)
            .await
            .map_err(|e| match e {
                MintClientError::Unreachable(msg) => ValidationError::MintUnreachable(msg),
                MintClientError::UnreachableIndeterminate(msg) => {
                    ValidationError::MintUnreachableIndeterminate(msg)
                }
                MintClientError::RejectedSwap(msg) => ValidationError::MintRejectedSwap(msg),
                // The mint-typed already-spent rejection keeps the honest
                // double-spend detail.
                MintClientError::AlreadySpent(msg) => ValidationError::AlreadySpent(msg),
                // Spec step 8: a keyset-retirement/final_expiry rejection is a
                // swap rejection (verification-failed), kept in its own arm so
                // the cause can be named in the problem `detail`.
                MintClientError::KeysetRetiredOrExpired(msg) => {
                    ValidationError::KeysetRetiredOrExpired(msg)
                }
                // A fee-policy reject (raised pre-submit inside the ceremony)
                // keeps its own arm so it never reads as a double-spend.
                MintClientError::FeeTooHigh {
                    keyset_id,
                    input_fee_ppk,
                } => ValidationError::FeeTooHigh {
                    keyset_id,
                    input_fee_ppk,
                },
            })?;

        let new_amount = outcome
            .proofs
            .total_amount()
            .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;

        Ok(ValidatedCharge {
            new_proofs: outcome.proofs,
            mint_url: token_mint,
            unit: token_unit,
            amount: new_amount,
            dleq_ok: outcome.dleq_ok,
        })
    }
}

/// Every short keyset id the token references on the wire (V4 groups proofs
/// per keyset id; V3 carries one per proof) — the inputs to the local
/// resolution scan above.
fn token_short_keyset_ids(token: &Token) -> Vec<cashu::nuts::nut02::ShortKeysetId> {
    match token {
        Token::TokenV3(t) => t
            .token
            .iter()
            .flat_map(|t| t.proofs.iter().map(|p| p.keyset_id.clone()))
            .collect(),
        Token::TokenV4(t) => t.token.iter().map(|t| t.keyset_id.clone()).collect(),
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
        external_id: req.external_id.clone(),
        description: req.description.clone(),
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
        // Spec mint-trust §: userinfo is rejected outright; on the requirement
        // side it is server-side config, so a 400, not a 402.
        if mint_url_has_userinfo(m) {
            return Err(ChargeError::MalformedRequest(format!(
                "requirement mint {m:?} carries userinfo (user@host), which is rejected"
            )));
        }
        let parsed = MintUrl::from_str(m)
            .map_err(|e| ChargeError::MalformedRequest(format!("requirement mint {m:?}: {e}")))?;
        mints.push(parsed);
    }
    Ok(CashuRequirement {
        unit,
        mints,
        amount: Amount::from(req.amount),
        external_id: req.external_id.clone(),
        description: req.description.clone(),
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
/// money-safety DoubleSpend arm is noted inline.
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
        ValidationError::TooManyProofs { got, max } => ChargeError::TooManyProofs { got, max },
        ValidationError::PaymentInsufficient { required, got } => {
            ChargeError::PaymentInsufficient {
                required: u64::from(required),
                presented: u64::from(got),
                amount: u64::from(required),
                expected_swap_fee: 0,
            }
        }
        ValidationError::UnitMismatch { expected, got } => ChargeError::WrongUnit {
            expected: expected.to_string(),
            got: got.to_string(),
        },
        // Spec step 6: a resolved-keyset unit mismatch is the same
        // verification-failed condition as a declared-unit mismatch (the
        // keyset-id context stays in the validation-layer log).
        ValidationError::ResolvedKeysetUnitMismatch { expected, got, .. } => {
            ChargeError::WrongUnit {
                expected: expected.to_string(),
                got: got.to_string(),
            }
        }
        ValidationError::MintNotAllowed { got, allowed } => ChargeError::MintNotAllowed {
            got: got.to_string(),
            allowed: allowed.iter().map(|m| m.to_string()).collect(),
        },
        ValidationError::MintUrlUserinfo { url } => ChargeError::MintUrlUserinfo { url },
        ValidationError::ShortKeysetIdUnresolved { short_id } => {
            ChargeError::ShortKeysetIdUnresolved { short_id }
        }
        ValidationError::TokenEmpty => {
            ChargeError::MalformedCredential("token contains no proofs".to_string())
        }
        ValidationError::MalformedToken(msg) => {
            ChargeError::MalformedCredential(format!("malformed token: {msg}"))
        }
        // Spec step 8: a swap rejected for keyset retirement or passed
        // `final_expiry` (the mint's NUT keyset-error codes, classified by the
        // mint client) is verification-failed, like every other swap rejection.
        // The arm stays distinct from the already-spent (honest double-spend
        // detail) and neutral catch-all only so the cause is named in `detail`.
        ValidationError::KeysetRetiredOrExpired(_) => ChargeError::Expired,
        ValidationError::AlreadySpent(_) => ChargeError::DoubleSpend,
        ValidationError::MintRejectedSwap(detail) => ChargeError::SwapRejected(detail),
        ValidationError::FeeTooHigh {
            keyset_id,
            input_fee_ppk,
        } => ChargeError::FeeTooHigh {
            keyset_id,
            input_fee_ppk,
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
            dleq_ok: validated.dleq_ok,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use cashu::dhke::hash_to_curve;
    use cashu::nuts::nut02::{Id, KeySetInfo};
    use cashu::nuts::Proof;
    use cashu::secret::Secret;
    use cashu::{Amount, CurrencyUnit, MintUrl, Proofs, Token};

    use super::{ChargeValidator, ValidatedCharge, ValidationError};
    use crate::challenge::CashuRequirement;
    use crate::mint_client::{MintClient, MintClientError, SwapOutcome};

    /// Canned outcome for the mock [`MintClient::swap`] call.
    enum SwapResponse {
        /// Echo the incoming proofs back, so tests can assert amount
        /// preservation without constructing fresh proofs.
        Echo,
        Unreachable,
        UnreachableIndeterminate,
        RejectedSwap,
        /// The mint-typed already-spent rejection (NUT code 11001).
        AlreadySpent,
        /// The keyset-class rejection (retired / final_expiry passed) — the
        /// spec's payment-expired swap outcome.
        KeysetRetiredOrExpired,
        DleqInvalid,
        /// The ceremony's pre-submit fee-policy reject (fee-bearing keyset).
        FeeTooHigh,
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
        /// The proofs handed to the most recent `swap` call, so a test can
        /// assert the WHOLE presented set (every keyset) reaches the swap.
        swapped_proofs: Arc<Mutex<Proofs>>,
    }

    #[derive(Clone)]
    struct MockCounters {
        swap: Arc<AtomicUsize>,
        keysets: Arc<AtomicUsize>,
        swapped_proofs: Arc<Mutex<Proofs>>,
    }

    impl MockMintClient {
        fn new(
            swap_response: SwapResponse,
            keysets_response: KeysetsResponse,
        ) -> (Self, MockCounters) {
            let swap_calls = Arc::new(AtomicUsize::new(0));
            let keysets_calls = Arc::new(AtomicUsize::new(0));
            let swapped_proofs = Arc::new(Mutex::new(Vec::new()));
            let counters = MockCounters {
                swap: swap_calls.clone(),
                keysets: keysets_calls.clone(),
                swapped_proofs: swapped_proofs.clone(),
            };
            (
                Self {
                    swap_response,
                    keysets_response,
                    swap_calls,
                    keysets_calls,
                    swapped_proofs,
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
        ) -> Result<SwapOutcome, MintClientError> {
            self.swap_calls.fetch_add(1, Ordering::SeqCst);
            *self.swapped_proofs.lock().expect("swap capture lock") = proofs.clone();
            match self.swap_response {
                SwapResponse::Echo => Ok(SwapOutcome {
                    proofs,
                    dleq_ok: true,
                }),
                SwapResponse::Unreachable => {
                    Err(MintClientError::Unreachable("mock unreachable".into()))
                }
                SwapResponse::UnreachableIndeterminate => Err(
                    MintClientError::UnreachableIndeterminate("mock indeterminate".into()),
                ),
                SwapResponse::RejectedSwap => {
                    Err(MintClientError::RejectedSwap("mock rejected".into()))
                }
                SwapResponse::AlreadySpent => {
                    Err(MintClientError::AlreadySpent("mock already spent".into()))
                }
                SwapResponse::KeysetRetiredOrExpired => Err(
                    MintClientError::KeysetRetiredOrExpired("mock keyset retired".into()),
                ),
                // The ceremony's serve-and-flag contract: a DLEQ failure on the
                // swap-returned signatures still redeems (spec §security-dleq).
                SwapResponse::DleqInvalid => Ok(SwapOutcome {
                    proofs,
                    dleq_ok: false,
                }),
                SwapResponse::FeeTooHigh => Err(MintClientError::FeeTooHigh {
                    keyset_id: "009a1f293253e41e".into(),
                    input_fee_ppk: 100,
                }),
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
            external_id: None,
            description: None,
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
            dleq_ok,
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
        assert!(dleq_ok, "a clean swap reports a clean DLEQ verdict");
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
            matches!(err, ValidationError::PaymentInsufficient { .. }),
            "expected PaymentInsufficient, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on an insufficient token"
        );
    }

    #[tokio::test]
    async fn validate_accepts_overfunded_amount_and_retains_excess() {
        // Spec step 7: value ABOVE `amount + expected_swap_fee` is accepted and
        // retained — the whole 20 is swapped against a 10 requirement.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(16, 0), make_proof(4, 1)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let validated = validator
            .validate(&token, &req)
            .await
            .expect("an over-funded token must validate");
        assert_eq!(
            validated.amount,
            Amount::from(20),
            "the WHOLE presented value is redeemed (excess retained, no change)"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap runs once on the over-funded accept path"
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
    async fn validate_propagates_keyset_retired_swap_rejection_distinctly() {
        // Spec step 8: a swap rejected for keyset retirement / final_expiry
        // surfaces as its own arm, never collapsed into MintRejectedSwap.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) =
            MockMintClient::with_swap(SwapResponse::KeysetRetiredOrExpired);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("a keyset-class rejection must fail");
        assert!(
            matches!(err, ValidationError::KeysetRetiredOrExpired(_)),
            "expected KeysetRetiredOrExpired, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "swap must be called once before the rejection surfaces"
        );
    }

    #[tokio::test]
    async fn validate_succeeds_with_dleq_flag_false_on_swap_output_dleq_failure() {
        // Spec step 8: a failed or missing DLEQ proof on the swap-returned
        // signatures indicates a misbehaving mint, not a payment failure, and
        // the payment stands — validation SUCCEEDS, the redeemed value is kept,
        // and `dleq_ok` carries the verdict for the operator.
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::DleqInvalid);
        let validator = ChargeValidator::new(mock);

        let validated = validator
            .validate(&token, &req)
            .await
            .expect("a swap-output DLEQ failure must NOT fail validation");
        assert!(!validated.dleq_ok, "the verdict flag must carry the failure");
        assert_eq!(
            u64::from(validated.amount),
            10,
            "the consumed inputs' value must be redeemed"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "the swap ran once and succeeded"
        );
    }

    #[tokio::test]
    async fn validate_rejects_resolved_keyset_unit_mismatch_before_swap() {
        // Spec step 6: the published keyset is the unit authority. A token
        // DECLARING the required unit whose proofs sit on a keyset the mint
        // publishes under a DIFFERENT unit is rejected pre-swap — with ZERO
        // swap calls, so the foreign-unit proofs are never consumed.
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![keyset_info(keyset_id, CurrencyUnit::Sat)]),
        );
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("a sat-keyset proof under a pop-declared token must be rejected");
        match err {
            ValidationError::ResolvedKeysetUnitMismatch {
                keyset_id: id,
                expected,
                got,
            } => {
                assert_eq!(id, "009a1f293253e41e");
                assert_eq!(expected, pop_unit());
                assert_eq!(got, CurrencyUnit::Sat);
            }
            other => panic!("expected ResolvedKeysetUnitMismatch, got {other:?}"),
        }
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "step 6 must reject BEFORE the swap (zero swap calls)"
        );
    }

    #[tokio::test]
    async fn validate_accepts_resolved_keyset_with_matching_unit() {
        // The positive half of the step-7 assertion: a published keyset whose
        // unit equals the requirement's passes through to the swap.
        let keyset_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let token = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![keyset_info(keyset_id, pop_unit())]),
        );
        let validator = ChargeValidator::new(mock);

        validator
            .validate(&token, &req)
            .await
            .expect("a matching resolved-keyset unit must validate");
        assert_eq!(counters.swap.load(Ordering::SeqCst), 1, "swap proceeds");
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
        // Empty keysets list ⇒ the 7-byte short id resolves to nothing — the
        // dedicated ShortKeysetIdUnresolved verification failure (never the
        // malformed-credential family), and no proofs exist to swap.
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
            matches!(err, ValidationError::ShortKeysetIdUnresolved { .. }),
            "expected ShortKeysetIdUnresolved, got {err:?}"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            1,
            "keysets must be called"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called when the short id resolves nothing"
        );
    }

    #[tokio::test]
    async fn validate_rejects_ambiguous_short_keyset_id() {
        // TWO published keysets share the wire short id's 7-byte prefix —
        // cashu's own resolver would silently take the first; the validator
        // rejects the ambiguity instead, before any swap.
        let v1_id = v1_keyset_id();
        let sibling = Id::from_str(
            "01aabbccddeeff00ffeeddccbbaa99887766554433221100ffeeddccbbaa998877",
        )
        .expect("valid v1 keyset id sharing the 7-byte prefix");
        let proofs = vec![proof_with_keyset(10, 0, v1_id)];
        let token_str = make_token(mint_a(), pop_unit(), proofs).to_string();
        let token = Token::from_str(&token_str).expect("v1 token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![
                keyset_info(v1_id, pop_unit()),
                keyset_info(sibling, pop_unit()),
            ]),
        );
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("an ambiguous short id must fail");
        assert!(
            matches!(err, ValidationError::ShortKeysetIdUnresolved { .. }),
            "expected ShortKeysetIdUnresolved, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on an ambiguous short id"
        );
    }

    #[tokio::test]
    async fn validate_rejects_userinfo_mint_url_before_any_network_call() {
        // Spec mint-trust §: `user@host` in the token's mint URL is rejected
        // outright — even when the requirement would otherwise accept any mint.
        let userinfo_mint =
            MintUrl::from_str("https://user@mint-a.example.com").expect("parses with userinfo");
        let token = make_token(userinfo_mint, pop_unit(), vec![make_proof(10, 0)]);
        let req = requirement(pop_unit(), vec![], 10);

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("a userinfo mint URL must be rejected");
        assert!(
            matches!(err, ValidationError::MintUrlUserinfo { .. }),
            "expected MintUrlUserinfo, got {err:?}"
        );
        assert_eq!(
            counters.keysets.load(Ordering::SeqCst),
            0,
            "keysets must NOT be called for a userinfo mint URL"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called for a userinfo mint URL"
        );
    }

    #[tokio::test]
    async fn validate_rejects_locked_p2pk_proof_before_swap() {
        // Fast-path: this implementation advertises no condition, so a locked
        // proof is unsatisfiable and rejected before any network call.
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
    async fn validate_accepts_mixed_keysets_same_unit() {
        // A TokenV4 carries one mint and one unit (both token-scalar) but groups
        // proofs by keyset id, so proofs spanning several keysets of the same
        // unit are well-formed (e.g. change accrued across a keyset rotation).
        // Both keysets resolve to the requirement's unit, so structural
        // validation passes and the WHOLE set reaches the swap.
        let v0 = make_proof(4, 0); // keyset 009a1f293253e41e (V0)
        let v1_id = v1_keyset_id();
        let v1 = proof_with_keyset(6, 1, v1_id);
        let v0_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let token_str = make_token(mint_a(), pop_unit(), vec![v0, v1]).to_string();
        let token = Token::from_str(&token_str).expect("mixed-keyset token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![
                keyset_info(v0_id, pop_unit()),
                keyset_info(v1_id, pop_unit()),
            ]),
        );
        let validator = ChargeValidator::new(mock);

        let validated = validator
            .validate(&token, &req)
            .await
            .expect("a same-unit mixed-keyset token must validate");
        assert_eq!(
            u64::from(validated.amount),
            10,
            "the whole multi-keyset value (4 + 6) is redeemed"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            1,
            "the mixed-keyset set reaches the swap exactly once"
        );
    }

    #[tokio::test]
    async fn validate_rejects_mixed_keysets_when_one_resolves_to_a_foreign_unit() {
        // The step-6 check covers EVERY keyset, not just the first: a token
        // whose second keyset the mint publishes under a DIFFERENT unit is
        // rejected pre-swap, even though the first keyset matches.
        let v0_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let v1_id = v1_keyset_id();
        let v0 = make_proof(4, 0); // keyset 009a1f293253e41e (matches the unit)
        let v1 = proof_with_keyset(6, 1, v1_id); // foreign-unit keyset
        let token_str = make_token(mint_a(), pop_unit(), vec![v0, v1]).to_string();
        let token = Token::from_str(&token_str).expect("mixed-keyset token round-trips");

        let req = requirement(pop_unit(), vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![
                keyset_info(v0_id, pop_unit()),
                keyset_info(v1_id, CurrencyUnit::Sat),
            ]),
        );
        let validator = ChargeValidator::new(mock);

        let err = validator
            .validate(&token, &req)
            .await
            .expect_err("a foreign-unit keyset anywhere in the set must reject");
        match err {
            ValidationError::ResolvedKeysetUnitMismatch { keyset_id, got, .. } => {
                assert_eq!(keyset_id, v1_id.to_string(), "names the foreign keyset");
                assert_eq!(got, CurrencyUnit::Sat);
            }
            other => panic!("expected ResolvedKeysetUnitMismatch, got {other:?}"),
        }
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "a foreign-unit keyset must reject BEFORE the swap"
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
            external_id: None,
            description: None,
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
        assert!(
            redeemed.dleq_ok,
            "a clean swap-output DLEQ verdict rides the success"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_mixed_keysets_swaps_all_proofs() {
        // End-to-end through the Redeemer seam: a token whose proofs span two
        // keysets of the same unit redeems, and the swap receives the WHOLE set
        // (one NUT-03 request carrying every proof), not just the first keyset's.
        let v0_id = Id::from_str("009a1f293253e41e").expect("valid v0 keyset id");
        let v1_id = v1_keyset_id();
        let v0 = make_proof(7, 0); // keyset 009a1f293253e41e (V0)
        let v1 = proof_with_keyset(3, 1, v1_id);
        let presented = make_token(mint_a(), pop_unit(), vec![v0, v1]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, counters) = MockMintClient::new(
            SwapResponse::Echo,
            KeysetsResponse::Ok(vec![
                keyset_info(v0_id, pop_unit()),
                keyset_info(v1_id, pop_unit()),
            ]),
        );
        let cred = CashuCredential::new(mock);

        let redeemed = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect("a mixed-keyset token must redeem end-to-end");
        assert_eq!(redeemed.amount, 10, "the whole 7 + 3 multi-keyset value");

        let swapped = counters.swapped_proofs.lock().expect("swap capture lock");
        assert_eq!(
            swapped.len(),
            2,
            "both proofs (every keyset) must reach the one swap, got {}",
            swapped.len()
        );
        let mut swapped_keysets: Vec<String> =
            swapped.iter().map(|p| p.keyset_id.to_string()).collect();
        swapped_keysets.sort();
        let mut expected = vec![v0_id.to_string(), v1_id.to_string()];
        expected.sort();
        assert_eq!(
            swapped_keysets, expected,
            "the swap must carry proofs from BOTH keysets"
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
    async fn verify_and_redeem_maps_underfunded_to_payment_insufficient() {
        let presented =
            make_token(mint_a(), pop_unit(), vec![make_proof(8, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("an under-funded token must map to PaymentInsufficient");
        match err {
            ChargeError::PaymentInsufficient {
                required,
                presented,
                amount,
                expected_swap_fee,
            } => {
                assert_eq!(required, 10);
                assert_eq!(presented, 8);
                assert_eq!(amount, 10);
                assert_eq!(expected_swap_fee, 0, "fee-free profile: fee is 0");
            }
            other => panic!("expected PaymentInsufficient, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_accepts_overfunded_and_reports_full_value() {
        // Over-funded accept path through the Redeemer seam: the excess is
        // retained, so the redeemed amount is the FULL presented value.
        let presented = make_token(
            mint_a(),
            pop_unit(),
            vec![make_proof(16, 0), make_proof(4, 1)],
        )
        .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let redeemed = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect("an over-funded token must redeem");
        assert_eq!(redeemed.amount, 20, "full presented value redeemed");
        assert_eq!(redeemed.proofs.amount, 20);
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_untyped_rejection_to_neutral_swap_rejected() {
        // A swap rejection the mint did NOT type as already-spent maps to the
        // neutral SwapRejected — verification-failed (the spec's step-8
        // catch-all) with a detail that claims no double-spend.
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)])
            .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::RejectedSwap);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("rejected swap must map to SwapRejected");
        assert!(
            matches!(err, ChargeError::SwapRejected(_)),
            "expected SwapRejected, got {err:?}"
        );
        let detail = err.to_string();
        assert!(
            detail.contains("the mint rejected the swap"),
            "neutral detail expected, got: {detail}"
        );
        assert!(
            !detail.contains("double-spend"),
            "an untyped rejection must not claim a double-spend: {detail}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_already_spent_to_double_spend() {
        // The mint-typed already-spent rejection keeps the spent-specific
        // DoubleSpend detail.
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)])
            .to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::AlreadySpent);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("already-spent must map to DoubleSpend");
        assert!(
            matches!(err, ChargeError::DoubleSpend),
            "expected DoubleSpend, got {err:?}"
        );
        assert!(
            err.to_string().contains("double-spend"),
            "the spent-specific detail must survive: {err}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_unresolved_short_id_to_its_own_variant() {
        // An unresolvable v2 short keyset id is the dedicated
        // ShortKeysetIdUnresolved (slug verification-failed), never a
        // malformed credential.
        let v1_id = v1_keyset_id();
        let presented =
            make_token(mint_a(), pop_unit(), vec![proof_with_keyset(10, 0, v1_id)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) =
            MockMintClient::new(SwapResponse::Echo, KeysetsResponse::Ok(Vec::new()));
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("an unresolvable short id must fail");
        assert!(
            matches!(err, ChargeError::ShortKeysetIdUnresolved { .. }),
            "expected ShortKeysetIdUnresolved, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_rejects_userinfo_requirement_mint_as_malformed_request() {
        // Operator-config side of the mint-trust rule: a requirement mint with
        // userinfo is server-side config → MalformedRequest (400), never a 402.
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]).to_string();
        let req = ChargeRequirement {
            amount: 10,
            unit: "pop_1700000000".to_string(),
            mints: vec!["https://user@mint-a.example.com".to_string()],
            external_id: None,
            description: None,
        };

        let (mock, counters) = MockMintClient::with_swap(SwapResponse::Echo);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("a userinfo requirement mint must fail");
        assert!(
            matches!(err, ChargeError::MalformedRequest(_)),
            "expected MalformedRequest, got {err:?}"
        );
        assert_eq!(
            counters.swap.load(Ordering::SeqCst),
            0,
            "swap must NOT be called on a misconfigured requirement"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_keyset_retired_rejection_to_expired() {
        // Spec step 8 + Keyset Rotation §: a swap rejected because the keyset
        // retired or its final_expiry passed maps to Expired, which is now a
        // verification-failed swap rejection (kept distinct only so the cause is
        // named in the problem detail).
        let presented =
            make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::KeysetRetiredOrExpired);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("a keyset-class rejection must map to Expired");
        assert!(
            matches!(err, ChargeError::Expired),
            "expected Expired (verification-failed), got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_redeem_maps_fee_reject_to_fee_too_high_not_double_spend() {
        // A fee-bearing keyset is a POLICY reject with an honest detail —
        // never collapsed into DoubleSpend.
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::FeeTooHigh);
        let cred = CashuCredential::new(mock);

        let err = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect_err("a fee-policy reject must map to FeeTooHigh");
        match err {
            ChargeError::FeeTooHigh {
                keyset_id,
                input_fee_ppk,
            } => {
                assert_eq!(keyset_id, "009a1f293253e41e");
                assert_eq!(input_fee_ppk, 100);
            }
            other => panic!("expected FeeTooHigh (not DoubleSpend), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_and_redeem_succeeds_with_dleq_flag_false_on_swap_output_dleq_failure() {
        // Spec step 8: a missing/invalid DLEQ on the swap-RETURNED signatures
        // is a mint-trust incident, NOT a payment failure — the redeem
        // SUCCEEDS, the value is kept, and `Redeemed` carries `dleq_ok: false`
        // for the operator surface.
        let presented = make_token(mint_a(), pop_unit(), vec![make_proof(10, 0)]).to_string();
        let req = charge_req("pop_1700000000", vec![mint_a()], 10);

        let (mock, _c) = MockMintClient::with_swap(SwapResponse::DleqInvalid);
        let cred = CashuCredential::new(mock);

        let redeemed = cred
            .verify_and_redeem(&presented, &req)
            .await
            .expect("a swap-output DLEQ failure must NOT fail the redeem");
        assert!(!redeemed.dleq_ok, "Redeemed must carry the false verdict");
        assert_eq!(redeemed.amount, 10, "the redeemed value is kept");
        assert!(
            redeemed.proofs.fresh_proofs.starts_with("cashuB"),
            "fresh proofs are still produced (the value was redeemed)"
        );
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
                assert!(
                    !indeterminate,
                    "a determinate connect failure never sets indeterminate"
                );
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

    /// The exact `payload.token` from the Night Bazaar `spawn` credential that
    /// the old multi-keyset guard rejected (one mint, one unit, proofs across
    /// two keysets). A live regression fixture, asserted decode-only (no mint).
    const BAZAAR_SPAWN_TOKEN: &str = "cashuBo2FteBtodHRwOi8vMTAwLjk2LjI1MS4xMTE6MjgzMzhhdW5wb3BfMTc4MTcxMzE1NmF0gqJhaUgBTdAqoYOS0mFwgaNhYQhhc3hANDQ4ZWUxMThlNWIzYjkxZDg5NmU4NWE3ZTEyZGI1MzJjN2QxNmRlYTE3MGMxZjFjOTIwY2Y5YmUzODUyMmYwZWFjWCEDICQ3pOMHpi9D_S7SZS4gGwOn5zeGVbjODUtChTPBDVeiYWlIARIH4yx54AFhcIGjYWECYXN4QGJkYWRmNzE5Yjc1NTJhNzFiMTJjMGRmNzliMjU4OGM3NGQxMzE1YjlhMmMyZDRlMThiYzM4MjJhNjRmYTA2OWRhY1ghA_TL14f_mM70kPXEA8HvjkEP8MOqacqKGXyCRcJDd0kV";

    #[test]
    fn bazaar_spawn_token_is_one_mint_one_unit_across_two_keysets() {
        // The bazaar incident: pops 402'd this credential as malformed for
        // "multiple mints or units". A TokenV4's mint and unit are token-scalar,
        // and the `t` array groups proofs by keyset, so the token is well-formed
        // multi-keyset ecash (change across a keyset rotation). Decode-only, so
        // it regresses the structural verdict without reaching a mint.
        let token = Token::from_str(BAZAAR_SPAWN_TOKEN).expect("the fixture decodes as a TokenV4");

        assert!(
            matches!(token, Token::TokenV4(_)),
            "the fixture is a cashuB/TokenV4 token"
        );
        assert_eq!(
            token.mint_url().expect("one scalar mint").to_string(),
            "http://100.96.251.111:28338",
            "exactly one mint (token-scalar)"
        );
        assert_eq!(
            token.unit().expect("one scalar unit"),
            CurrencyUnit::Custom("pop_1781713156".to_string()),
            "exactly one unit (token-scalar)"
        );

        let Token::TokenV4(v4) = &token else {
            unreachable!("asserted TokenV4 above")
        };
        let mut keysets: Vec<String> = v4
            .token
            .iter()
            .map(|group| group.keyset_id.to_string())
            .collect();
        keysets.sort();
        assert_eq!(
            keysets.len(),
            2,
            "the token groups its proofs across two keysets"
        );
        assert!(
            keysets[0].starts_with("01") && keysets[1].starts_with("01"),
            "both are v1 short keyset ids, got {keysets:?}"
        );
        assert_ne!(keysets[0], keysets[1], "the two keysets are distinct");
        // One proof per keyset group: the multiplicity is across keysets.
        assert_eq!(
            token.token_secrets().len(),
            2,
            "two proofs total, one per keyset"
        );
    }
}
