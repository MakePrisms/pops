//! The charge contract: [`ChargeError`] and [`RedeemedProofs`] — the committed
//! shape the verifier produces and its hosts (the gateway, the wasm/serverless
//! SDK) map off.
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
    /// HTTP 503 · no problem type (`about:blank` body) · RETRYABLE · SHOULD
    /// carry `Retry-After`.
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
    /// Presented value < `amount + expected_swap_fee` (spec verification step 8).
    /// UNDER-funded only: value above the requirement is accepted and retained
    /// by the server (the spec's Errors § has no over-payment counterpart).
    ///
    /// HTTP 402 · `payment-insufficient` · terminal.
    #[error("payment insufficient: presented {presented}, required {required} (= amount {amount} + swap_fee {expected_swap_fee})")]
    PaymentInsufficient {
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

    /// The keyset charges a swap fee this server's fee-free profile disallows
    /// (`input_fee_ppk` over the supported maximum of 0). A policy-disallowed
    /// unit per the spec's Errors §, NOT a double-spend.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error(
        "fee-bearing keyset disallowed by server policy: keyset {keyset_id} charges \
         input_fee_ppk {input_fee_ppk} (this server's profile is fee-free)"
    )]
    FeeTooHigh {
        /// Keyset whose fee exceeded the profile (hex id).
        keyset_id: String,
        /// The disallowed `input_fee_ppk` the mint publishes for it.
        input_fee_ppk: u64,
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

    /// A blind signature the swap RETURNED failed NUT-12 DLEQ — invalid or
    /// omitted by the mint (a malicious mint reporting outputs it never validly
    /// signed, which the server then could not spend). Security-critical.
    ///
    /// HTTP 402 · `verification-failed` · terminal.
    #[error("swap-output DLEQ verification failed")]
    DleqInvalid,

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
    /// required field absent/wrong-typed, `payload.token` not a Cashu token, or
    /// a `cashuA…` (TokenV3 — this intent is cashuB/TokenV4 only).
    ///
    /// HTTP 402 · `malformed-credential` (a bad credential is 402, not 400 — it
    /// is still a re-makeable attempt).
    #[error("malformed credential: {0}")]
    MalformedCredential(String),

    /// The credential names a payment method this server does not support
    /// (anything ≠ `"cashu"`). Framework problem type `method-unsupported`.
    ///
    /// HTTP 400 · `method-unsupported` (the framework's status table; not a
    /// payment-verification failure, so no 402 re-challenge).
    #[error("unsupported payment method {method:?} (this server accepts \"cashu\")")]
    MethodUnsupported {
        /// The method string the credential carried.
        method: String,
    },

    /// The REQUEST frame is malformed — more than one `Authorization: Payment`
    /// credential, or a server-side requirement that cannot be parsed. Follows
    /// the framework's status handling (400), NOT a 402: there is no problem
    /// type registered for it, so the body's `type` is `about:blank`.
    ///
    /// HTTP 400 · no registered slug.
    #[error("malformed request: {0}")]
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
    /// Net value received: at least the requested `amount` (the mint deducted
    /// the swap fee; value presented above the requirement is retained, so this
    /// MAY exceed `challenge.amount`).
    pub amount: u64,
    /// Unit of the redeemed value (echoes the challenge `currency`).
    pub unit: String,
    /// Keyset id (hex) the FRESH proofs are signed under — the mint's ACTIVE
    /// keyset, which MAY differ from the input proofs' keyset. For spending
    /// without re-fetching keysets, and for audit.
    pub active_keyset_id: String,
    /// SHA-256 (lowercase hex) of the EXACT presented `payload.token` string —
    /// the receipt `reference`: a stable, shareable settlement id that exposes
    /// no secret.
    pub token_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dleq_invalid_displays() {
        let err = ChargeError::DleqInvalid;
        assert_eq!(err.to_string(), "swap-output DLEQ verification failed");
    }

    #[test]
    fn payment_insufficient_display() {
        let err = ChargeError::PaymentInsufficient {
            required: 1100,
            presented: 1000,
            amount: 1000,
            expected_swap_fee: 100,
        };
        assert_eq!(
            err.to_string(),
            "payment insufficient: presented 1000, required 1100 (= amount 1000 + swap_fee 100)"
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
