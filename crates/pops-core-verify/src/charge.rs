//! The charge contract: [`ChargeError`], [`DleqLocation`], and [`RedeemedProofs`]
//! — the committed shape the verifier produces and its hosts (the gateway, the
//! wasm/serverless SDK) map off.
//!
//! Plain data only (`RedeemedProofs.fresh_proofs` is a serialized `cashuB…`
//! string, not `cashu::Proofs`), so it stays wasm-clean and is the canonical
//! at-rest / wire form the operator persists and re-spends.

/// Error returned by `Redeemer::verify_and_redeem`. Each variant's doc is
/// authoritative on its HTTP status; the SDK owns emission (no `to_status()`
/// here).
///
/// THE load-bearing invariant: a mint-unreachable / timeout MUST NEVER collapse
/// into a 402. A 402 means "your payment was wrong, re-pay"; a 503 means "we
/// couldn't check — keep your token and retry". Collapsing them burns a valid
/// token on a transient blip, so `MintUnreachable` is its own top-level variant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChargeError {
    // (A) TRANSPORT — 503, retryable, token NOT consumed.
    /// Mint unreachable (DNS/TCP/TLS/timeout), or a swap whose outcome is
    /// unresolved after a 5xx/timeout. Token NOT consumed; the caller MAY retry
    /// the same token.
    ///
    /// HTTP 503 · `mint-unavailable` · RETRYABLE · SHOULD carry `Retry-After`.
    #[error("mint unavailable at {mint_url}: {transport_detail}")]
    MintUnreachable {
        /// Mint endpoint that could not be reached.
        mint_url: String,
        /// Underlying transport detail (named `transport_detail`, not `source`,
        /// which `thiserror` reserves for the error-chain link).
        transport_detail: String,
        /// True iff the swap outcome is INDETERMINATE (5xx/timeout after submit)
        /// rather than a pre-swap connect failure: still 503+retry, but the
        /// operator must checkstate before assuming the token is still good.
        indeterminate: bool,
    },

    // (B) VERIFICATION — 402 + fresh re-challenge, terminal for this token.
    /// Presented value ≠ `amount + expected_swap_fee` (over- or under-funded; the
    /// server makes no change).
    ///
    /// HTTP 402 · `payment-insufficient` · terminal.
    #[error("amount mismatch: presented {presented}, required {required} (= amount {amount} + swap_fee {expected_swap_fee})")]
    AmountMismatch {
        /// `amount + expected_swap_fee` the server requires.
        required: u64,
        /// Total value the presented token carried.
        presented: u64,
        /// The bare requested `amount` (net the server receives).
        amount: u64,
        /// Server-recomputed swap fee; 0 for fee-free keysets (e.g. `pop_<ts>`).
        expected_swap_fee: u64,
    },

    /// Token's unit does not equal the challenge `currency`.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("wrong unit: expected {expected}, got {got}")]
    WrongUnit {
        /// Unit the challenge advertised.
        expected: String,
        /// Unit found on the token.
        got: String,
    },

    /// Token's mint is not in the challenge's accepted set. A disallowed mint is
    /// `verification-failed`, not a policy 403.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("mint not allowed: {got} not in {allowed:?}")]
    MintNotAllowed {
        /// Mint the token named (URL or NUT-01 key str).
        got: String,
        /// The accepted mint set.
        allowed: Vec<String>,
    },

    /// Token's proofs reference more than one mint or unit.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("token references multiple mints or units")]
    MultiMintOrUnit,

    /// A proof carries a NUT-10 (P2PK/HTLC) spending condition. This intent is
    /// BEARER-only, so a locked proof fails verification (rejected before swap).
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("token carries a NUT-10 spending condition (locked); bearer proofs only")]
    LockedToken,

    /// A DLEQ proof (NUT-12) is INVALID — on a presented input proof, or
    /// (security-critical) on a blind signature the swap RETURNED. Absence of an
    /// input-proof DLEQ is NOT this error; a mint that OMITS output DLEQ IS.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("DLEQ verification failed ({location})")]
    DleqInvalid {
        /// Distinguishes the lenient input case (present-but-invalid) from the
        /// strict swap-output case (invalid or omitted — a mint-trust signal).
        location: DleqLocation,
    },

    /// A proof's short (v1) keyset id does not resolve, or resolves ambiguously,
    /// against the mint's published keysets.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("unresolvable or ambiguous short keyset id: {short_id}")]
    ShortKeysetIdUnresolved {
        /// The unresolvable short id, hex.
        short_id: String,
    },

    /// Swap rejected because a proof was already spent (double-spend / replay).
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("double-spend: a proof in the token is already spent")]
    DoubleSpend,

    /// Swap rejected because the keyset retired or its `final_expiry` (NUT-02)
    /// passed — distinct from double-spend. For `pop_<ts>` this is where the CLTV
    /// time-lock surfaces (enforced by the mint at swap).
    ///
    /// HTTP 402 · `payment-expired` · terminal.
    #[error("payment expired: keyset retired or final_expiry passed")]
    Expired,

    /// The echoed `challenge.expires` is in the past — the framework challenge
    /// clock, caught BEFORE any swap. Distinct from `Expired` (mint-side keyset /
    /// `final_expiry`, caught AT swap).
    ///
    /// HTTP 402 · `payment-expired` · terminal.
    #[error("challenge expired (echoed `expires` is in the past)")]
    ChallengeExpired,

    /// The echoed `credential.challenge` is not a faithful echo (no stored
    /// challenge matches, or a field/`digest` was tampered). A token replayed
    /// against a different challenge lands here.
    ///
    /// HTTP 402 · `invalid-challenge` · terminal.
    #[error("invalid challenge: echo does not match an issued challenge")]
    InvalidChallenge,

    // (C) MALFORMED — 400 for a bad request frame, 402 for a bad credential.
    /// The credential could not be decoded/parsed: bad base64url or JSON, a
    /// required field absent/wrong-typed, `cashu_token` not a Cashu token, or a
    /// `cashuA…` (TokenV3 — this intent is cashuB/TokenV4 only).
    ///
    /// HTTP 402 · `malformed-credential` (a bad credential is 402, not 400 — it
    /// is still a re-makeable attempt).
    #[error("malformed credential: {0}")]
    MalformedCredential(String),

    /// The credential names an unsupported method, or the request bore more than
    /// one `Authorization: Payment` credential.
    ///
    /// HTTP 400 · framework status (not a well-formed payment attempt).
    #[error("unsupported method or malformed request: {0}")]
    MalformedRequest(String),

    /// Token carries more proofs than the configured maximum (DoS guard),
    /// rejected before the swap.
    ///
    /// HTTP 402 · `malformed-credential` · terminal.
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
/// `fresh_proofs` are spendable bearer secrets. The receipt uses `token_hash`,
/// never the proofs or the token string.
#[derive(Debug, Clone)]
pub struct RedeemedProofs {
    /// Fresh proofs the operator now controls, blinded against the unit's ACTIVE
    /// keyset — a serialized `cashuB…` string the operator/wallet re-parses to
    /// spend.
    pub fresh_proofs: String,
    /// Net value received = the requested `amount` exactly (the mint deducted the
    /// swap fee). The caller asserts `amount == challenge.amount` to confirm
    /// settlement.
    pub amount: u64,
    /// Unit of the redeemed value (echoes the challenge `currency`).
    pub unit: String,
    /// Keyset id (hex) the FRESH proofs are signed under — the mint's ACTIVE
    /// keyset, which MAY differ from the input proofs' keyset. For spending
    /// without re-fetching keysets, and for audit.
    pub active_keyset_id: String,
    /// SHA-256 (lowercase hex) of the EXACT presented `cashu_token` — the receipt
    /// `reference`: a stable, shareable settlement id that exposes no secret.
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
