//! Cross-slice charge contract: [`ChargeError`], [`DleqLocation`], and
//! [`RedeemedProofs`] — the single committed shape the funder slice, the verify
//! crate, and its SDK consumer all map off.
//!
//! CASHU-FREE: every field is plain data; `RedeemedProofs.fresh_proofs` is a
//! serialized `cashuB…` token string (NOT `cashu::Proofs`), keeping this crate
//! WASM-lean and cashu/cdk-free. The verify impl converts at its boundary.
//!
//! TYPE ONLY: the per-variant status/problem-type/retryability docs ARE the
//! contract the SDK maps off, but the SDK owns emission — no `to_status()` etc.
//! lives here.

/// Error returned by `Credential::verify_and_redeem`. The per-variant docs are
/// AUTHORITATIVE on each variant's status; this banner gives the invariant.
///
/// Variants encode THREE NON-COLLAPSING concerns the HTTP envelope must keep
/// distinct:
///   (A) TRANSPORT          -> 503, token NOT consumed, RETRYABLE same token
///   (B) VERIFICATION       -> 402 + fresh challenge, terminal for THIS token
///   (C) MALFORMED          -> 400 (request frame) OR 402 (credential), per variant
///
/// Net envelope mapping: `MintUnreachable` -> 503, `MalformedRequest` -> 400,
/// EVERY other variant (verification + malformed-credential) -> 402.
///
/// THE load-bearing invariant: a mint-unreachable / timeout MUST NEVER collapse
/// into a 402 — a 402 says "your payment was wrong, re-pay"; a 503 says "we
/// couldn't check, keep your token and retry". Collapsing them burns a valid
/// token on a transient blip, so `MintUnreachable` is a SEPARATE top-level
/// variant, never folded into a 402 sub-reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChargeError {
    // ─────────────────────────────────────────────────────────────────────
    // (A) TRANSPORT — 503, retryable, token NOT consumed. ONE variant only.
    // ─────────────────────────────────────────────────────────────────────
    /// Mint unreachable (DNS/TCP/TLS/timeout), OR a swap outcome unresolved after
    /// a 5xx/timeout. The token is NOT consumed; the caller MAY retry the SAME
    /// token.
    ///
    /// HTTP 503 · problem-type `mint-unavailable` · RETRYABLE · SHOULD carry
    /// `Retry-After`. (spec §Errors `mint-unavailable`, §Durability)
    ///
    /// NOTE: the contract names this field `source`, but `thiserror` reserves
    /// `source` for the error-chain link (must `impl Error`), so a plain `String`
    /// named `source` will not compile — renamed to `transport_detail`. The
    /// `Display` output is byte-identical to the contract's.
    #[error("mint unavailable at {mint_url}: {transport_detail}")]
    MintUnreachable {
        /// Mint endpoint that could not be reached, for envelope log / alert.
        mint_url: String,
        /// Underlying transport detail (a `String` to stay cashu/reqwest-free).
        transport_detail: String,
        /// True iff an INDETERMINATE swap outcome (5xx/timeout AFTER submit) vs a
        /// pre-swap connect failure. Both are 503+retry, but indeterminate means
        /// the operator MUST NOT assume the token is still good without a
        /// checkstate (spec §Durability). Never affects status.
        indeterminate: bool,
    },

    // ── (B) VERIFICATION — 402 + fresh re-challenge, terminal for THIS token.
    //    Sub-reasons are distinct variants so the envelope picks the precise
    //    problem-type. ──
    /// Presented value does not equal `amount + expected_swap_fee` (over- OR
    /// under-funded; the server makes no change).
    ///
    /// HTTP 402 · problem-type `payment-insufficient` · terminal.
    /// (spec step 12, §Fees)
    #[error("amount mismatch: presented {presented}, required {required} (= amount {amount} + swap_fee {expected_swap_fee})")]
    AmountMismatch {
        /// `amount + expected_swap_fee` the server requires.
        required: u64,
        /// Total value the presented token carried.
        presented: u64,
        /// The bare requested `amount` (net the server receives).
        amount: u64,
        /// Server-recomputed swap fee (0 for fee-free keysets, e.g. pop_<ts>);
        /// `required = amount + expected_swap_fee`. (spec §Fees)
        expected_swap_fee: u64,
    },

    /// Token's unit does not equal the challenge `currency`.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 8)
    #[error("wrong unit: expected {expected}, got {got}")]
    WrongUnit {
        /// Unit the challenge advertised.
        expected: String,
        /// Unit found on the token.
        got: String,
    },

    /// Token's mint is not in the challenge's accepted set. A reachable-but-
    /// disallowed mint is `verification-failed`, NOT a policy 403 (spec §Errors).
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 9)
    #[error("mint not allowed: {got} not in {allowed:?}")]
    MintNotAllowed {
        /// Mint the token named (URL or NUT-01 key str).
        got: String,
        /// The accepted mint set.
        allowed: Vec<String>,
    },

    /// Token's proofs reference more than one mint or unit.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 3)
    #[error("token references multiple mints or units")]
    MultiMintOrUnit,

    /// A proof carries a NUT-10 (P2PK/HTLC) spending-condition secret. This
    /// intent is BEARER-only; a locked proof is a verification failure (402 not
    /// 400), rejected BEFORE the swap.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 10)
    #[error("token carries a NUT-10 spending condition (locked); bearer proofs only")]
    LockedToken,

    /// A present DLEQ proof (NUT-12) is INVALID — on a presented input proof, or
    /// (security-critical) on a blind signature the swap RETURNED. ABSENCE of an
    /// input-proof DLEQ is NOT this error; a mint that OMITS output DLEQ IS.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal.
    /// (spec steps 13-14, §DLEQ Verification)
    #[error("DLEQ verification failed ({location})")]
    DleqInvalid {
        /// Disambiguates the lenient input case (present-but-invalid) from the
        /// strict swap-output case (invalid OR omitted — a mint-trust signal,
        /// not a client error).
        location: DleqLocation,
    },

    /// A proof's short (v1) keyset id does NOT resolve, or resolves ambiguously,
    /// against the mint's published keysets.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 11)
    #[error("unresolvable or ambiguous short keyset id: {short_id}")]
    ShortKeysetIdUnresolved {
        /// The unresolvable short id, hex.
        short_id: String,
    },

    /// Swap rejected because a proof was already spent (double-spend / replay).
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 14)
    #[error("double-spend: a proof in the token is already spent")]
    DoubleSpend,

    /// Swap rejected because the keyset RETIRED or its `final_expiry` (NUT-02)
    /// passed — a DISTINCT outcome from double-spend (the spec mandates a
    /// separate `payment-expired`). For pop_<ts> this is where the CLTV
    /// time-lock surfaces, enforced by the MINT at swap, never by the verifier.
    ///
    /// HTTP 402 · problem-type `payment-expired` · terminal. (spec step 14)
    #[error("payment expired: keyset retired or final_expiry passed")]
    Expired,

    /// The echoed `challenge.expires` is in the PAST — the framework challenge
    /// clock, caught BEFORE any swap. Distinct from `Expired` (mint-side keyset
    /// /`final_expiry`).
    ///
    /// HTTP 402 · problem-type `payment-expired` · terminal. (spec step 7)
    #[error("challenge expired (echoed `expires` is in the past)")]
    ChallengeExpired,

    /// The echoed `credential.challenge` is not a faithful echo: `id`-HMAC fails,
    /// no stored challenge matches, or a field/`digest` was tampered. A token
    /// replayed against a DIFFERENT challenge lands here.
    ///
    /// HTTP 402 · problem-type `invalid-challenge` · terminal.
    /// (spec steps 4-6, §Challenge Binding)
    #[error("invalid challenge: echo does not match an issued challenge")]
    InvalidChallenge,

    // ── (C) MALFORMED — not a well-formed payment attempt. Status SPLITS: a
    //    malformed *request* frame is 400, a malformed *credential* is 402
    //    `malformed-credential` (a bad credential is still a re-makeable attempt).
    // ──
    /// The credential could not be decoded/parsed: bad base64url, bad JSON, a
    /// required field absent/wrong-typed, `cashu_token` not a Cashu token, OR a
    /// `cashuA…` (TokenV3) — this intent is cashuB/TokenV4 only, so REJECT cashuA.
    ///
    /// HTTP 402 · problem-type `malformed-credential` (NOT the framework 400 —
    /// see the (C) split). (spec §Errors `malformed-credential`)
    #[error("malformed credential: {0}")]
    MalformedCredential(String),

    /// The credential names an unsupported method, or the request bore more than
    /// one `Authorization: Payment` credential.
    ///
    /// HTTP 400 · framework status (NOT a 402 problem-type). (spec §Errors para 2)
    #[error("unsupported method or malformed request: {0}")]
    MalformedRequest(String),

    /// Token carries more proofs than the configured maximum (DoS guard). SHOULD
    /// be rejected before the swap.
    ///
    /// HTTP 402 · problem-type `malformed-credential` · terminal. (spec step 2,
    /// §Denial of Service)
    #[error("too many proofs: {got} exceeds max {max}")]
    TooManyProofs {
        /// Proof count the token carried.
        got: usize,
        /// Configured per-token maximum.
        max: usize,
    },
}

/// Where a DLEQ check failed — payload of `ChargeError::DleqInvalid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DleqLocation {
    /// On a presented INPUT proof (present-but-invalid). Lenient elsewhere:
    /// ABSENCE of input DLEQ never produces an error.
    InputProof,
    /// On a blind signature the SWAP RETURNED — invalid OR omitted by the mint
    /// (security-critical; a malicious mint reporting unsigned outputs).
    SwapOutput,
}

impl std::fmt::Display for DleqLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DleqLocation::InputProof => "input proof",
            DleqLocation::SwapOutput => "swap output",
        };
        f.write_str(s)
    }
}

/// The value the operator holds after a successful verify+redeem, plus what the
/// SDK needs to emit a Payment-Receipt.
///
/// SECURITY: MUST NOT be logged whole or placed in a shared receipt —
/// `fresh_proofs` are spendable bearer secrets. The receipt uses `token_hash`
/// (a SHA-256 of the presented token), never the proofs or the token string.
/// (spec §Receipt `reference`, §Privacy)
#[derive(Debug, Clone)]
pub struct RedeemedProofs {
    /// Fresh proofs the operator now controls, blinded against the unit's ACTIVE
    /// keyset. A serialized `cashuB…` string (NOT `cashu::Proofs`, to keep this
    /// crate WASM-lean); the operator/wallet re-parses to spend.
    pub fresh_proofs: String,
    /// Net value received = the requested `amount` exactly (the mint deducted
    /// the swap fee). The caller asserts `amount == challenge.amount` to confirm
    /// settlement.
    pub amount: u64,
    /// Unit of the redeemed value (echoes the challenge `currency`).
    pub unit: String,
    /// Keyset id (hex) the FRESH proofs are signed under — the mint's ACTIVE
    /// keyset, which MAY differ from the input proofs' keyset. For spending
    /// without re-fetching keysets, and for audit. (spec §Settlement)
    pub active_keyset_id: String,
    /// SHA-256 (lowercase hex) of the EXACT presented `cashu_token` (NOT a
    /// re-encoding) — the receipt `reference`: a stable, shareable settlement id
    /// that exposes no secret. (spec §Receipt `reference`)
    pub token_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dleq_location_display() {
        assert_eq!(DleqLocation::InputProof.to_string(), "input proof");
        assert_eq!(DleqLocation::SwapOutput.to_string(), "swap output");
    }

    #[test]
    fn dleq_invalid_display_interpolates_location() {
        let err = ChargeError::DleqInvalid {
            location: DleqLocation::SwapOutput,
        };
        assert_eq!(err.to_string(), "DLEQ verification failed (swap output)");
    }

    #[test]
    fn amount_mismatch_display() {
        let err = ChargeError::AmountMismatch {
            required: 1100,
            presented: 1000,
            amount: 1000,
            expected_swap_fee: 100,
        };
        assert_eq!(
            err.to_string(),
            "amount mismatch: presented 1000, required 1100 (= amount 1000 + swap_fee 100)"
        );
    }

    #[test]
    fn mint_unreachable_constructs_and_displays() {
        let err = ChargeError::MintUnreachable {
            mint_url: "https://m".into(),
            transport_detail: "timeout".into(),
            indeterminate: true,
        };
        assert_eq!(err.to_string(), "mint unavailable at https://m: timeout");
        if let ChargeError::MintUnreachable { indeterminate, .. } = err {
            assert!(indeterminate);
        } else {
            panic!("expected MintUnreachable");
        }
    }

    #[test]
    fn redeemed_proofs_constructs_with_all_fields() {
        let redeemed = RedeemedProofs {
            fresh_proofs: "cashuBfoo".into(),
            amount: 1000,
            unit: "pop_1782259200".into(),
            active_keyset_id: "0114c426".into(),
            token_hash: "abc123".into(),
        };
        assert_eq!(redeemed.amount, 1000);
        assert_eq!(redeemed.unit, "pop_1782259200");
        assert_eq!(redeemed.active_keyset_id, "0114c426");
        assert_eq!(redeemed.token_hash, "abc123");
        assert_eq!(redeemed.fresh_proofs, "cashuBfoo");
    }
}
