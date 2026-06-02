//! Cross-slice charge contract: [`ChargeError`], [`DleqLocation`], and
//! [`RedeemedProofs`].
//!
//! These are the verify/charge types `pops-core-types` exposes so the funder
//! slice (`pops-core-funder`) can compile against them without itself
//! producing them, and so the verify crate (`pops-core-verify`) and its SDK
//! consumer can map off a single committed shape.
//!
//! CASHU-FREE: every field is plain data (`String`/`u64`/`usize`/`bool`/
//! `Vec<String>`/[`DleqLocation`]). `RedeemedProofs.fresh_proofs` is a
//! serialized `cashuB…` token string and `.token_hash` is a hex digest — NOT
//! `cashu::Proofs` — so this crate stays WASM-lean and free of any cashu/cdk
//! dependency. The verify impl converts at its boundary.
//!
//! TYPE ONLY: the variant → HTTP-status → problem-type → retryability mapping
//! documented per variant is the contract the verifier SDK maps off; the SDK
//! owns emission. No `to_status()` / `problem_type()` / `is_retryable()` lives
//! here — this module defines the type, not the mapping.

/// Error returned by `Credential::verify_and_redeem` (pops-core-verify),
/// defined in pops-core-types as the cross-slice contract.
///
/// Top-level variants encode THREE NON-COLLAPSING concerns the HTTP envelope
/// must keep distinct (the load-bearing invariant):
///   (A) TRANSPORT failure          -> 503, token NOT consumed, RETRYABLE same token
///   (B) client-re-pay VERIFICATION -> 402 + fresh challenge, terminal for THIS token
///   (C) MALFORMED request/credential -> 400, framework status, NOT 402
///
/// A mint-unreachable / timeout MUST NEVER collapse into a 402: a 402 tells the
/// client "your payment was wrong, re-pay"; a 503 tells it "we couldn't check —
/// keep your token and retry". Collapsing them would burn a valid token on a
/// transient backend blip. `MintUnreachable` is therefore a SEPARATE top-level
/// variant, never folded into any 402 sub-reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChargeError {
    // ─────────────────────────────────────────────────────────────────────
    // (A) TRANSPORT — 503, retryable, token NOT consumed. ONE variant only.
    // ─────────────────────────────────────────────────────────────────────
    /// Mint could not be reached (DNS, TCP, TLS, connect/read timeout), OR a
    /// swap outcome could not be resolved after a 5xx/timeout per
    /// {{durability}} (checkstate could not settle whether inputs were spent).
    /// The token is NOT consumed; the caller MAY retry the SAME token.
    ///
    /// HTTP 503 · problem-type `mint-unavailable` · **RETRYABLE** ·
    /// SHOULD carry `Retry-After`. (spec §Errors `mint-unavailable`, §Durability)
    ///
    /// NOTE (deviation from the contract block): the contract names this field
    /// `source: String`, but `thiserror` reserves the field name `source` for
    /// the error-chain link (`std::error::Error::source()`) and requires it to
    /// `impl Error`; a plain `String` named `source` does not compile on
    /// `thiserror` 1.x or 2.x. The field is renamed to `transport_detail`
    /// (matching its doc comment) to keep it a plain display string. The
    /// rendered `Display` message is byte-identical to the contract's.
    #[error("mint unavailable at {mint_url}: {transport_detail}")]
    MintUnreachable {
        /// Mint endpoint that could not be reached / resolved. Lets the
        /// envelope log + the operator alert without parsing the message.
        mint_url: String,
        /// Underlying transport detail (boxed so the type is cashu/reqwest-free).
        transport_detail: String,
        /// True iff the failure is an INDETERMINATE swap outcome (5xx/timeout
        /// AFTER the swap was sent, checkstate unresolved) vs. a pre-swap
        /// connect failure. Both are 503+retry, but an indeterminate outcome
        /// means the operator MUST NOT assume the token is still good without
        /// a checkstate (spec §Durability) — surfaced so the envelope can pick
        /// the right `Retry-After` / operator log line. Never affects status.
        indeterminate: bool,
    },

    // ─────────────────────────────────────────────────────────────────────
    // (B) VERIFICATION — 402 + fresh re-challenge. Sub-reasons are DISTINCT
    //     variants so the envelope picks the precise problem-type. Terminal
    //     for THIS token (client must present a different/correct token).
    // ─────────────────────────────────────────────────────────────────────

    /// Presented value does not equal `amount + expected_swap_fee` (over- OR
    /// under-funded; the server makes no change). Carries both sides so the
    /// body can say exactly how far off.
    ///
    /// HTTP 402 · problem-type `payment-insufficient` · terminal.
    /// (spec step 12, §Fees, §Amount-and-Fee-Determinism)
    #[error("amount mismatch: presented {presented}, required {required} (= amount {amount} + swap_fee {expected_swap_fee})")]
    AmountMismatch {
        /// `amount + expected_swap_fee` the server requires.
        required: u64,
        /// Total value the presented token actually carried.
        presented: u64,
        /// The bare requested `amount` (net the server must receive).
        amount: u64,
        /// Server-recomputed swap fee over the presented proofs' keyset(s)
        /// (0 for fee-free keysets, e.g. pop_<ts> today). `required = amount
        /// + expected_swap_fee`. Carried so the body is self-explaining and the
        /// holder can see the fee component. (spec §Fees)
        expected_swap_fee: u64,
    },

    /// Token's unit does not equal the challenge `currency`.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 8)
    #[error("wrong unit: expected {expected}, got {got}")]
    WrongUnit {
        /// Unit the challenge advertised (the required `currency`).
        expected: String,
        /// Unit found on the presented token.
        got: String,
    },

    /// Token's mint is not a member of the challenge's accepted mint set.
    /// (A reachable-but-disallowed mint is `verification-failed`, NOT a policy
    /// 403 — spec §Errors final para.)
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 9)
    #[error("mint not allowed: {got} not in {allowed:?}")]
    MintNotAllowed {
        /// Mint identity the token named (URL or, preferably, NUT-01 key str).
        got: String,
        /// The server-chosen accepted mint set.
        allowed: Vec<String>,
    },

    /// Token's proofs reference MORE THAN ONE mint or MORE THAN ONE unit.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal. (spec step 3)
    #[error("token references multiple mints or units")]
    MultiMintOrUnit,

    /// A proof carries a NUT-10 well-known (P2PK / HTLC) spending-condition
    /// secret. This intent accepts plain-secret BEARER proofs only; a locked
    /// proof is rejected BEFORE the swap.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal.
    /// (spec step 10, §Spending-Condition-Locked Tokens — see §"Locked-token
    ///  status call" below for why 402 not 400.)
    #[error("token carries a NUT-10 spending condition (locked); bearer proofs only")]
    LockedToken,

    /// A present DLEQ proof (NUT-12) is INVALID — either on a presented input
    /// proof, or (security-critical) on a blind signature the swap RETURNED.
    /// Absence of an input-proof DLEQ is NOT this error (it must not reject);
    /// a mint that OMITS DLEQ on swap-returned sigs IS this error.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal.
    /// (spec steps 13-14, §DLEQ Verification)
    #[error("DLEQ verification failed ({location})")]
    DleqInvalid {
        /// Where the bad/missing DLEQ was found — disambiguates the lenient
        /// input case (present-but-invalid) from the strict swap-output case
        /// (invalid OR omitted). Both map to verification-failed; carried for
        /// the body + operator triage (a mint omitting output DLEQ is a
        /// mint-trust signal, not a client error).
        location: DleqLocation,
    },

    /// A proof's keyset id is a short (v1, 8-byte) id that does NOT resolve, or
    /// resolves AMBIGUOUSLY, against the mint's published keyset list.
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal.
    /// (spec step 11, §Short Keyset Identifiers)
    #[error("unresolvable or ambiguous short keyset id: {short_id}")]
    ShortKeysetIdUnresolved {
        /// The unresolvable short id, hex. Carried for the operator log.
        short_id: String,
    },

    /// Swap rejected because a proof was already spent (double-spend / replay
    /// of a token already redeemed).
    ///
    /// HTTP 402 · problem-type `verification-failed` · terminal.
    /// (spec step 14: "already spent ... is a verification-failed condition";
    ///  §Token Replay)
    #[error("double-spend: a proof in the token is already spent")]
    DoubleSpend,

    /// Swap rejected because the token's keyset has RETIRED or its
    /// `final_expiry` (NUT-02) has passed. THIS IS A DISTINCT outcome from
    /// double-spend (above): the spec mandates a separate `payment-expired`.
    /// For pop_<ts> credentials, `final_expiry` is where the CLTV time-lock
    /// surfaces — but the verifier never computes it; the mint enforces it at
    /// swap time.
    ///
    /// HTTP 402 · problem-type `payment-expired` · terminal.
    /// (spec step 14, §Keyset Rotation and Expiry)
    #[error("payment expired: keyset retired or final_expiry passed")]
    Expired,

    /// The echoed `challenge.expires` auth-param is in the PAST (the sole
    /// challenge-level expiry signal; a creqA has no expiry of its own).
    /// Distinct from `Expired` (which is mint-side keyset/`final_expiry`):
    /// this is the framework challenge clock, caught BEFORE any swap.
    ///
    /// HTTP 402 · problem-type `payment-expired` · terminal. (spec step 7)
    #[error("challenge expired (echoed `expires` is in the past)")]
    ChallengeExpired,

    /// The echoed `credential.challenge` is not a faithful echo of an issued
    /// challenge: `id`-HMAC fails (stateless), or no stored challenge matches
    /// (stored), or an echoed field / `digest` was tampered. Replay of a token
    /// against a DIFFERENT challenge lands here (stateless: may instead surface
    /// as `DoubleSpend` at swap).
    ///
    /// HTTP 402 · problem-type `invalid-challenge` · terminal.
    /// (spec steps 4-6, §Challenge Binding)
    #[error("invalid challenge: echo does not match an issued challenge")]
    InvalidChallenge,

    // ─────────────────────────────────────────────────────────────────────
    // (C) MALFORMED — 400, framework status (NOT 402). The request/credential
    //     is not a well-formed payment attempt at all.
    // ─────────────────────────────────────────────────────────────────────

    /// The credential token could not be decoded / parsed: bad base64url, the
    /// JSON did not parse, a required field (`challenge`, `payload`,
    /// `payload.cashu_token`) is absent or wrong-typed, `cashu_token` does not
    /// decode as a Cashu token, OR the token is a `cashuA...` (TokenV3)
    /// serialization (this intent is cashuB/TokenV4 only — REJECT cashuA).
    ///
    /// HTTP 402 · problem-type `malformed-credential`. (spec §Errors
    /// `malformed-credential` — note: the spec scopes THIS to 402, see
    /// §"Status-code nuance" below.)
    #[error("malformed credential: {0}")]
    MalformedCredential(String),

    /// The credential names an unsupported method, or the request bore more
    /// than one `Authorization: Payment` credential. This is the framework's
    /// `method-unsupported` / multi-credential case.
    ///
    /// HTTP 400 · framework status (NOT a 402 problem-type).
    /// (spec §Errors para 2; base httpauth-payment)
    #[error("unsupported method or malformed request: {0}")]
    MalformedRequest(String),

    /// Token carries MORE proofs than the server's configured maximum (DoS
    /// guard). SHOULD be rejected before the swap.
    ///
    /// HTTP 402 · problem-type `malformed-credential` (over-large token is a
    /// malformed credential per spec §DoS framing) · terminal.
    /// (spec step 2, §Denial of Service)
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

/// The value the operator now holds after a successful verify+redeem, plus
/// exactly what the SDK needs to emit a Payment-Receipt. Defined in
/// pops-core-types; returned inside `Redeemed` by `verify_and_redeem`.
///
/// SECURITY: this struct MUST NOT be logged whole and MUST NOT be placed in a
/// shared receipt — `fresh_proofs` are spendable bearer secrets. The receipt
/// uses `token_hash` (a SHA-256 of the PRESENTED token), never the proofs and
/// never the presented token string. (spec §Receipt `reference`, §Privacy)
#[derive(Debug, Clone)]
pub struct RedeemedProofs {
    // ── (a) confirm value received ──────────────────────────────────────
    /// The fresh proofs the operator now controls, blinded against the unit's
    /// ACTIVE keyset by the swap. Serialized as the canonical cashu token
    /// string (`cashuB…`) so pops-core-types carries NO `cashu::Proofs` in its
    /// public API (keeps it WASM-lean + funder-slice-independent). The verify
    /// crate produces it from the swap response; the operator/wallet re-parses
    /// to spend. (cashu Proofs ⇄ token string is the de/serialization seam.)
    pub fresh_proofs: String,
    /// Net value the operator received = the requested `amount` exactly (the
    /// mint deducted `swap_fee` from the inputs; outputs sum to `amount`).
    /// The caller asserts `amount == challenge.amount` to confirm settlement.
    pub amount: u64,
    /// Unit of the redeemed value (echoes the challenge `currency`).
    pub unit: String,
    /// Keyset id (hex) the FRESH proofs are signed under — the mint's ACTIVE
    /// keyset for the unit, which MAY differ from the input proofs' keyset
    /// (spec §Settlement). Carried so the operator can spend without re-fetching
    /// keysets, and for audit.
    pub active_keyset_id: String,

    // ── (b) emit a Payment-Receipt (spec §Receipt) ──────────────────────
    /// SHA-256, lowercase hex, of the EXACT `cashu_token` credential string as
    /// received from the client (NOT a re-encoding). This is the receipt
    /// `reference` — a stable, shareable settlement id that exposes no secret.
    /// Computed in core (it needs the presented bytes) so the SDK never has to
    /// re-hold the raw token. (spec §Receipt `reference`)
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
        // Field access confirms the struct shape (indeterminate is plain bool).
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
