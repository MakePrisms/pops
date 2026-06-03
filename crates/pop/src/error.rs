//! The FROZEN output & error contract — typed errors + the JSON envelope.
//!
//! Every `pop` invocation emits **exactly one** top-level JSON object to stdout
//! (json is the default mode; `--human` switches to text). On failure the
//! object is the error envelope:
//!
//! ```json
//! { "schema_version": 1,
//!   "error": { "code": "<snake_case>", "retriable": <bool>,
//!              "message": "<human>", "details": { ... }? } }
//! ```
//!
//! `code` is a **closed, documented, additive-only** enum (see the variants of
//! [`PopError`]). `retriable` is true iff the failure is transient (safe to
//! retry as-is). `message` is HUMAN help only — agents MUST parse `code` +
//! `details`, never the prose. `details` is REQUIRED-populated for the codes the
//! contract marks (each carrying variant captures the data locally at error
//! time).
//!
//! The wallet's internal modules still propagate `Box<dyn std::error::Error>`
//! for plumbing. A site that wants a precise contract code constructs the
//! matching [`PopError`] variant and returns it (it boxes transparently because
//! [`PopError`] is an `std::error::Error`). At the top level, [`crate::run`]
//! downcasts the boxed error back to a [`PopError`]; anything that isn't one of
//! ours becomes [`PopError::Internal`] (`internal_error`) — an unmapped,
//! unexpected failure.

use serde_json::{json, Value};

/// The frozen top-level schema version stamped on EVERY json output (success
/// and failure).
pub const SCHEMA_VERSION: u64 = 1;

/// A typed `pop` error mapping 1:1 to a contract `code`. Each variant carries
/// exactly the `details` data the contract requires (locally available at error
/// time), so an agent repairs its call from structured fields, never prose.
///
/// The enum is **closed and additive-only**: never remove or rename a variant
/// or its `code` string; a new failure mode gets a new variant; a breaking
/// change bumps [`SCHEMA_VERSION`].
#[derive(Debug)]
pub enum PopError {
    // ---- needs_input (false) ----
    /// Spend exceeds available balance. (`insufficient_funds`)
    InsufficientFunds {
        /// Sats the operation needed.
        required_sats: u64,
        /// Sats actually available.
        available_sats: u64,
    },
    /// A deposit id was not found in the local ledger. (`deposit_not_found`)
    DepositNotFound {
        /// The id that wasn't found.
        deposit_id: String,
    },
    /// `--dest` (or another address) is for a different network than the wallet.
    /// (`network_mismatch`)
    NetworkMismatch {
        /// Network the wallet is pinned to.
        expected: String,
        /// Network the supplied value was for.
        got: String,
    },
    /// The mint credited a different amount than was quoted (PoP is exact-amount;
    /// the on-chain funds are safe in the CLTV address — recover them).
    /// (`amount_mismatch`)
    AmountMismatch {
        /// Sats the quote expected.
        expected_sats: u64,
        /// Sats the mint saw funded.
        funded_sats: u64,
    },
    /// The funding quote's window closed before funding credited; stop polling
    /// and re-quote. (`quote_expired`)
    QuoteExpired {
        /// The expired quote id.
        quote_id: String,
        /// Unix seconds the quote expired at.
        expired_at: u64,
    },
    /// A recovery UTXO is uneconomical to sweep (value <= fee). (`value_below_fee`)
    ValueBelowFee {
        /// UTXO value, sats.
        value_sats: u64,
        /// Computed fee, sats.
        fee_sats: u64,
    },
    /// A wallet is required but none is initialized at the wallet dir.
    /// (`wallet_not_initialized`)
    WalletNotInitialized {
        /// Human help (message-only code).
        message: String,
    },
    /// `init` refused because a wallet already exists. (`wallet_exists`)
    WalletExists {
        /// Human help (message-only code).
        message: String,
    },
    /// An imported BIP-39 mnemonic failed validation. NEVER echoes the mnemonic.
    /// (`invalid_mnemonic`)
    InvalidMnemonic {
        /// Human help (message-only; must not contain the phrase).
        message: String,
    },
    /// Generic input/validation failure. (`invalid_input`)
    InvalidInput {
        /// Human help (message-only code).
        message: String,
    },

    // ---- transient (true) ----
    /// The mint's HTTP endpoint was unreachable (network error). (`mint_unreachable`)
    MintUnreachable {
        /// The mint base URL.
        mint_url: String,
    },
    /// An esplora **GET/read** (tip-MTP, UTXO lookup, fee estimate) failed at the
    /// transport layer — the chain backend was unreachable (network error).
    /// MIRRORS [`PopError::MintUnreachable`] for the chain side. DISTINCT from
    /// [`PopError::BroadcastFailed`], which is the esplora **POST/broadcast** path;
    /// a non-network esplora error (e.g. a garbage response body) stays
    /// `internal_error`, not this. (`chain_unreachable`)
    ChainUnreachable {
        /// The esplora base URL that was unreachable.
        esplora_url: String,
        /// Which read failed: `"tip_mtp"`, `"utxo_fetch"`, or `"fee_estimate"`.
        operation: Option<String>,
    },
    /// Funding has not yet credited; keep polling. (`funding_pending`)
    FundingPending {
        /// The funding address.
        address: String,
        /// Unix seconds the quote/funding window expires at.
        expires_at: u64,
        /// Confirmations seen so far, if known.
        confs_seen: Option<u64>,
        /// Confirmations required, if known.
        confs_required: Option<u64>,
        /// On a NON-mainnet network, a machine-readable on-ramp hint for where to
        /// get test coins (signet/testnet faucet URL, or a regtest note).
        /// `None` on mainnet (real BTC has no faucet).
        faucet_hint: Option<String>,
    },
    /// The deposit's CLTV has not matured (MTP < ts_expiry); wait, then retry the
    /// same call. (`cltv_not_expired`)
    CltvNotExpired {
        /// Unix seconds the deposit matures at (its `ts_expiry`).
        matures_at: u64,
        /// The chain tip's median-time-past now.
        now: u64,
    },
    /// Broadcasting the recovery tx was rejected (often transient/mempool).
    /// (`broadcast_failed`)
    BroadcastFailed {
        /// The node's reject reason, if any.
        reject_reason: Option<String>,
        /// The tx id we tried to broadcast, if known.
        txid: Option<String>,
    },

    // ---- terminal (false) ----
    /// The mint returned an application-level error (non-2xx with a message).
    /// (`mint_error`)
    MintError {
        /// HTTP status code, if from an HTTP response.
        status: Option<u16>,
        /// The mint's error message / response body.
        mint_message: String,
    },
    /// The independently reconstructed funding address did not match the mint's
    /// quote address — a security stop, do NOT fund. (`address_mismatch`)
    AddressMismatch {
        /// The address we independently reconstructed (expected).
        expected: String,
        /// The address the mint returned (got).
        got: String,
    },
    /// An unexpected / unmapped internal failure. (`internal_error`)
    Internal {
        /// Human help (message-only code).
        message: String,
    },

    // ---- pay path (phase-2; defined now, used by `pay`) ----
    /// A URL the funder tried to pay did not answer with HTTP 402. (`not_402`)
    Not402 {
        /// The URL that was probed.
        url: String,
        /// The status actually returned.
        status_got: u16,
    },
    /// A 402-gated payment was rejected by the service. (`payment_rejected`)
    PaymentRejected {
        /// The amount the 402 required, if it told us.
        required_amount: Option<u64>,
        /// The unit the 402 named.
        unit: Option<String>,
        /// The service's reason, if any.
        reason: Option<String>,
    },

    // ---- pay path (the `pop pay` HTTP-402 client dance) ----
    /// The resource returned HTTP 402 but carried no parseable
    /// `WWW-Authenticate: Payment …` challenge (or its params were malformed),
    /// so there is nothing to satisfy. (`no_payment_challenge`)
    NoPaymentChallenge {
        /// The URL that was probed.
        url: String,
        /// Why the challenge could not be parsed (header absent / malformed).
        reason: String,
    },
    /// A 402 `Payment` challenge was present but could not be decoded into a
    /// concrete charge (bad request envelope or `creqA` payment request, or a
    /// charge missing its required amount). (`challenge_parse_failed`)
    ChallengeParseFailed {
        /// What specifically failed to decode.
        reason: String,
    },
    /// The held token's unit does not match the unit the charge requires; paying
    /// it would be wrong-currency. Send nothing. (`token_unit_mismatch`)
    TokenUnitMismatch {
        /// The unit the charge requires.
        required: String,
        /// The unit the held token carries.
        got: String,
    },
    /// The held token is from a mint the charge does not accept. Send nothing.
    /// (`token_mint_mismatch`)
    TokenMintMismatch {
        /// The mint URL the held token is from.
        token_mint: String,
        /// The set of mint URLs the charge accepts (empty ⟹ the charge named no
        /// mints, which this wallet treats as "must be explicit" and rejects).
        accepted_mints: Vec<String>,
    },
    /// The held token is worth less than the charge requires. Send nothing.
    /// (`insufficient_token_value`)
    InsufficientTokenValue {
        /// Sats the held token is worth.
        have: u64,
        /// Sats the charge requires.
        need: u64,
    },
    /// The charge's amount exceeds the caller's `--max-amount` safety cap; refuse
    /// so a malicious 402 cannot trick an agent into overspending. Send nothing.
    /// (`amount_exceeds_cap`)
    AmountExceedsCap {
        /// Sats the charge required.
        amount: u64,
        /// The `--max-amount` cap, in sats.
        cap: u64,
    },
    /// The NUT-03 swap-to-exact failed (mint rejected it, or the unblind/DLEQ
    /// check failed). The held token may be partially spent — surface the change
    /// if any was produced. (`swap_failed`)
    SwapFailed {
        /// The swap failure detail.
        reason: String,
    },
    /// INTERNAL money-safety gate: the constructed send set did not sum to
    /// EXACTLY the charge amount. This must never fire in practice — it means a
    /// split/selection bug, and the payment is aborted before anything is sent.
    /// (`exact_amount_assertion_failed`)
    ExactAmountAssertionFailed {
        /// The amount the send set was required to equal.
        required: u64,
        /// What the send set actually summed to.
        got: u64,
    },
    /// The gateway rejected the presented payment on retry (it answered 402
    /// again). Carries the gateway's response body and the change token (if the
    /// swap already produced one) so no value is silently lost.
    /// (`gateway_rejected_payment`)
    GatewayRejectedPayment {
        /// The HTTP status the retry returned (typically 402).
        status: u16,
        /// The gateway's response body verbatim (intelligible rejection reason).
        body: String,
        /// The change `cashuB` token, if a swap produced one before the retry —
        /// it is spendable and must not be lost.
        change_token: Option<String>,
    },
}

impl PopError {
    /// The stable, lower-snake_case contract `code` string for this error.
    pub fn code(&self) -> &'static str {
        match self {
            PopError::InsufficientFunds { .. } => "insufficient_funds",
            PopError::DepositNotFound { .. } => "deposit_not_found",
            PopError::NetworkMismatch { .. } => "network_mismatch",
            PopError::AmountMismatch { .. } => "amount_mismatch",
            PopError::QuoteExpired { .. } => "quote_expired",
            PopError::ValueBelowFee { .. } => "value_below_fee",
            PopError::WalletNotInitialized { .. } => "wallet_not_initialized",
            PopError::WalletExists { .. } => "wallet_exists",
            PopError::InvalidMnemonic { .. } => "invalid_mnemonic",
            PopError::InvalidInput { .. } => "invalid_input",
            PopError::MintUnreachable { .. } => "mint_unreachable",
            PopError::ChainUnreachable { .. } => "chain_unreachable",
            PopError::FundingPending { .. } => "funding_pending",
            PopError::CltvNotExpired { .. } => "cltv_not_expired",
            PopError::BroadcastFailed { .. } => "broadcast_failed",
            PopError::MintError { .. } => "mint_error",
            PopError::AddressMismatch { .. } => "address_mismatch",
            PopError::Internal { .. } => "internal_error",
            PopError::Not402 { .. } => "not_402",
            PopError::PaymentRejected { .. } => "payment_rejected",
            PopError::NoPaymentChallenge { .. } => "no_payment_challenge",
            PopError::ChallengeParseFailed { .. } => "challenge_parse_failed",
            PopError::TokenUnitMismatch { .. } => "token_unit_mismatch",
            PopError::TokenMintMismatch { .. } => "token_mint_mismatch",
            PopError::InsufficientTokenValue { .. } => "insufficient_token_value",
            PopError::AmountExceedsCap { .. } => "amount_exceeds_cap",
            PopError::SwapFailed { .. } => "swap_failed",
            PopError::ExactAmountAssertionFailed { .. } => "exact_amount_assertion_failed",
            PopError::GatewayRejectedPayment { .. } => "gateway_rejected_payment",
        }
    }

    /// Whether retrying the SAME call as-is is safe (true ⟺ the documented
    /// retry-class is `transient`). `needs_input` and `terminal` are both false.
    pub fn retriable(&self) -> bool {
        matches!(
            self,
            PopError::MintUnreachable { .. }
                | PopError::ChainUnreachable { .. }
                | PopError::FundingPending { .. }
                | PopError::CltvNotExpired { .. }
                | PopError::BroadcastFailed { .. }
        )
    }

    /// The structured `details` object for this error, or `None` for the
    /// message-only codes. Agents repair their call from these fields.
    pub fn details(&self) -> Option<Value> {
        match self {
            PopError::InsufficientFunds {
                required_sats,
                available_sats,
            } => Some(json!({
                "required_sats": required_sats,
                "available_sats": available_sats,
            })),
            PopError::DepositNotFound { deposit_id } => Some(json!({
                "deposit_id": deposit_id,
            })),
            PopError::NetworkMismatch { expected, got } => Some(json!({
                "expected": expected,
                "got": got,
            })),
            PopError::AmountMismatch {
                expected_sats,
                funded_sats,
            } => Some(json!({
                "expected_sats": expected_sats,
                "funded_sats": funded_sats,
            })),
            PopError::QuoteExpired {
                quote_id,
                expired_at,
            } => Some(json!({
                "quote_id": quote_id,
                "expired_at": expired_at,
            })),
            PopError::ValueBelowFee {
                value_sats,
                fee_sats,
            } => Some(json!({
                "value_sats": value_sats,
                "fee_sats": fee_sats,
            })),
            PopError::MintUnreachable { mint_url } => Some(json!({
                "mint_url": mint_url,
            })),
            PopError::ChainUnreachable {
                esplora_url,
                operation,
            } => {
                // esplora_url is REQUIRED-present; operation is emitted only if known.
                let mut o = json!({ "esplora_url": esplora_url });
                if let Some(op) = operation {
                    o["operation"] = json!(op);
                }
                Some(o)
            }
            PopError::FundingPending {
                address,
                expires_at,
                confs_seen,
                confs_required,
                faucet_hint,
            } => {
                let mut o = json!({
                    "address": address,
                    "expires_at": expires_at,
                });
                if let Some(c) = confs_seen {
                    o["confs_seen"] = json!(c);
                }
                if let Some(c) = confs_required {
                    o["confs_required"] = json!(c);
                }
                // Non-mainnet on-ramp hint (where to get test coins); absent on mainnet.
                if let Some(h) = faucet_hint {
                    o["faucet_hint"] = json!(h);
                }
                Some(o)
            }
            PopError::CltvNotExpired { matures_at, now } => Some(json!({
                "matures_at": matures_at,
                "now": now,
            })),
            PopError::BroadcastFailed {
                reject_reason,
                txid,
            } => {
                let mut o = json!({});
                if let Some(r) = reject_reason {
                    o["reject_reason"] = json!(r);
                }
                if let Some(t) = txid {
                    o["txid"] = json!(t);
                }
                // Both optional; emit `details` only if at least one is present.
                if o.as_object().is_some_and(|m| m.is_empty()) {
                    None
                } else {
                    Some(o)
                }
            }
            PopError::MintError {
                status,
                mint_message,
            } => {
                let mut o = json!({ "mint_message": mint_message });
                if let Some(s) = status {
                    o["status"] = json!(s);
                }
                Some(o)
            }
            PopError::AddressMismatch { expected, got } => Some(json!({
                "expected": expected,
                "got": got,
            })),
            PopError::Not402 { url, status_got } => Some(json!({
                "url": url,
                "status_got": status_got,
            })),
            PopError::PaymentRejected {
                required_amount,
                unit,
                reason,
            } => {
                let mut o = json!({});
                if let Some(a) = required_amount {
                    o["required_amount"] = json!(a);
                }
                if let Some(u) = unit {
                    o["unit"] = json!(u);
                }
                if let Some(r) = reason {
                    o["reason"] = json!(r);
                }
                if o.as_object().is_some_and(|m| m.is_empty()) {
                    None
                } else {
                    Some(o)
                }
            }
            PopError::NoPaymentChallenge { url, reason } => Some(json!({
                "url": url,
                "reason": reason,
            })),
            PopError::ChallengeParseFailed { reason } => Some(json!({
                "reason": reason,
            })),
            PopError::TokenUnitMismatch { required, got } => Some(json!({
                "required": required,
                "got": got,
            })),
            PopError::TokenMintMismatch {
                token_mint,
                accepted_mints,
            } => Some(json!({
                "token_mint": token_mint,
                "accepted_mints": accepted_mints,
            })),
            PopError::InsufficientTokenValue { have, need } => Some(json!({
                "have": have,
                "need": need,
            })),
            PopError::AmountExceedsCap { amount, cap } => Some(json!({
                "amount": amount,
                "cap": cap,
            })),
            PopError::SwapFailed { reason } => Some(json!({
                "reason": reason,
            })),
            PopError::ExactAmountAssertionFailed { required, got } => Some(json!({
                "required": required,
                "got": got,
            })),
            PopError::GatewayRejectedPayment {
                status,
                body,
                change_token,
            } => {
                let mut o = json!({
                    "status": status,
                    "body": body,
                });
                // Surface the change token so a partially-spent pop is never lost.
                if let Some(ct) = change_token {
                    o["change_token"] = json!(ct);
                }
                Some(o)
            }
            // Message-only codes carry no details object.
            PopError::WalletNotInitialized { .. }
            | PopError::WalletExists { .. }
            | PopError::InvalidMnemonic { .. }
            | PopError::InvalidInput { .. }
            | PopError::Internal { .. } => None,
        }
    }

    /// The human help message for this error (stderr in `--human` mode; the
    /// `message` field of the json envelope). Agents MUST NOT parse it.
    pub fn message(&self) -> String {
        match self {
            PopError::InsufficientFunds {
                required_sats,
                available_sats,
            } => format!(
                "insufficient funds: need {required_sats} sat but only {available_sats} sat available"
            ),
            PopError::DepositNotFound { deposit_id } => {
                format!("no deposit with id `{deposit_id}` in this wallet")
            }
            PopError::NetworkMismatch { expected, got } => {
                format!("address is for the wrong network: wallet is {expected}, address is {got}")
            }
            PopError::AmountMismatch {
                expected_sats,
                funded_sats,
            } => format!(
                "funded amount {funded_sats} sat does not match the quoted {expected_sats} sat \
                 (PoP is exact-amount; the on-chain funds are safe in the CLTV address — recover them)"
            ),
            PopError::QuoteExpired {
                quote_id,
                expired_at,
            } => format!(
                "quote {quote_id} expired at {expired_at} before funding credited; \
                 stop polling and re-quote (any funds sent are recoverable after the CLTV)"
            ),
            PopError::ValueBelowFee {
                value_sats,
                fee_sats,
            } => format!(
                "UTXO value ({value_sats} sat) is not greater than the fee ({fee_sats} sat); \
                 lower the fee or wait for the feerate to drop"
            ),
            PopError::WalletNotInitialized { message }
            | PopError::WalletExists { message }
            | PopError::InvalidMnemonic { message }
            | PopError::InvalidInput { message }
            | PopError::Internal { message } => message.clone(),
            PopError::MintUnreachable { mint_url } => {
                format!("mint at {mint_url} is unreachable (network error); retry")
            }
            PopError::ChainUnreachable {
                esplora_url,
                operation,
            } => match operation {
                Some(op) => {
                    format!("esplora at {esplora_url} is unreachable ({op}) (network error); retry")
                }
                None => format!("esplora at {esplora_url} is unreachable (network error); retry"),
            },
            PopError::FundingPending {
                address,
                expires_at,
                ..
            } => format!(
                "funding for {address} has not credited yet (quote expires at {expires_at}); keep polling"
            ),
            PopError::CltvNotExpired { matures_at, now } => format!(
                "deposit is not yet recoverable: chain MTP {now} < ts_expiry {matures_at}; wait until it matures"
            ),
            PopError::BroadcastFailed { reject_reason, .. } => match reject_reason {
                Some(r) => format!("broadcast rejected: {r}"),
                None => "broadcast failed".to_string(),
            },
            PopError::MintError {
                status,
                mint_message,
            } => match status {
                Some(s) => format!("mint returned an error (HTTP {s}): {mint_message}"),
                None => format!("mint returned an error: {mint_message}"),
            },
            PopError::AddressMismatch { expected, got } => format!(
                "ABORT: the mint's funding address does not match our independent reconstruction. \
                 expected {expected}, got {got}. The mint may be returning an address it can itself \
                 spend. Do NOT fund."
            ),
            PopError::Not402 { url, status_got } => {
                format!("{url} did not return HTTP 402 (got {status_got})")
            }
            PopError::PaymentRejected { reason, .. } => match reason {
                Some(r) => format!("payment rejected: {r}"),
                None => "payment rejected by the service".to_string(),
            },
            PopError::NoPaymentChallenge { url, reason } => format!(
                "{url} returned 402 but carried no usable `WWW-Authenticate: Payment` challenge: {reason}"
            ),
            PopError::ChallengeParseFailed { reason } => {
                format!("could not decode the 402 payment challenge into a charge: {reason}")
            }
            PopError::TokenUnitMismatch { required, got } => format!(
                "the held token's unit `{got}` does not match the charge's required unit `{required}`; \
                 not paying (wrong currency). Present a token in `{required}`."
            ),
            PopError::TokenMintMismatch {
                token_mint,
                accepted_mints,
            } => {
                if accepted_mints.is_empty() {
                    format!(
                        "the charge named no accepted mints, so this wallet cannot confirm the held \
                         token's mint ({token_mint}) is acceptable; not paying"
                    )
                } else {
                    format!(
                        "the held token is from {token_mint}, which is not in the charge's accepted \
                         mints {accepted_mints:?}; not paying"
                    )
                }
            }
            PopError::InsufficientTokenValue { have, need } => format!(
                "the held token is worth {have} sat but the charge requires {need} sat; \
                 present a token worth at least the charge"
            ),
            PopError::AmountExceedsCap { amount, cap } => format!(
                "the charge requires {amount} sat, which exceeds the --max-amount cap of {cap} sat; \
                 refusing to pay (raise --max-amount only if you trust this charge)"
            ),
            PopError::SwapFailed { reason } => {
                format!("the swap-to-exact-amount failed: {reason}")
            }
            PopError::ExactAmountAssertionFailed { required, got } => format!(
                "INTERNAL money-safety abort: the send set summed to {got} sat, not the required \
                 {required} sat; nothing was sent (this indicates a split bug — please report it)"
            ),
            PopError::GatewayRejectedPayment {
                status,
                body,
                change_token,
            } => {
                let ct = match change_token {
                    Some(_) => " (a change token was produced and is in `details.change_token` — keep it)",
                    None => "",
                };
                format!("the gateway rejected the payment (HTTP {status}): {body}{ct}")
            }
        }
    }

    /// The full failure envelope as a JSON value:
    /// `{ "schema_version", "error": { "code", "retriable", "message", "details"? } }`.
    pub fn to_envelope(&self) -> Value {
        let mut err = json!({
            "code": self.code(),
            "retriable": self.retriable(),
            "message": self.message(),
        });
        if let Some(d) = self.details() {
            err["details"] = d;
        }
        json!({
            "schema_version": SCHEMA_VERSION,
            "error": err,
        })
    }
}

impl std::fmt::Display for PopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for PopError {}

/// Convenience constructors for the message-only codes (keep call sites terse).
impl PopError {
    /// `invalid_input` from anything displayable.
    pub fn invalid_input(msg: impl std::fmt::Display) -> Self {
        PopError::InvalidInput {
            message: msg.to_string(),
        }
    }

    /// `internal_error` from anything displayable.
    pub fn internal(msg: impl std::fmt::Display) -> Self {
        PopError::Internal {
            message: msg.to_string(),
        }
    }

    /// `wallet_not_initialized` from anything displayable.
    pub fn wallet_not_initialized(msg: impl std::fmt::Display) -> Self {
        PopError::WalletNotInitialized {
            message: msg.to_string(),
        }
    }
}

/// Resolves an arbitrary boxed error into a typed [`PopError`]: if it already is
/// one, take it; otherwise wrap its `Display` as [`PopError::Internal`]
/// (`internal_error` — an unmapped, unexpected failure).
pub fn from_boxed(err: Box<dyn std::error::Error>) -> PopError {
    match err.downcast::<PopError>() {
        Ok(pe) => *pe,
        Err(other) => PopError::Internal {
            message: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant must produce a non-empty snake_case code and a message.
    #[test]
    fn codes_are_snake_case_and_messages_present() {
        let samples = sample_errors();
        for e in &samples {
            let code = e.code();
            assert!(!code.is_empty());
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "code `{code}` is not lower snake_case"
            );
            assert!(!e.message().is_empty(), "empty message for {code}");
        }
    }

    /// The envelope always carries schema_version + the error block, and the
    /// REQUIRED-details codes actually populate `details`.
    #[test]
    fn envelope_shape_and_required_details() {
        // A required-details code: cltv_not_expired.
        let e = PopError::CltvNotExpired {
            matures_at: 2000,
            now: 1000,
        };
        let env = e.to_envelope();
        assert_eq!(env["schema_version"], json!(SCHEMA_VERSION));
        assert_eq!(env["error"]["code"], json!("cltv_not_expired"));
        assert_eq!(env["error"]["retriable"], json!(true));
        assert_eq!(env["error"]["details"]["matures_at"], json!(2000));
        assert_eq!(env["error"]["details"]["now"], json!(1000));
        assert!(env["error"]["message"].is_string());

        // address_mismatch is terminal (not retriable) and has required details.
        let e = PopError::AddressMismatch {
            expected: "bc1pexpected".to_string(),
            got: "bc1pgot".to_string(),
        };
        let env = e.to_envelope();
        assert_eq!(env["error"]["code"], json!("address_mismatch"));
        assert_eq!(env["error"]["retriable"], json!(false));
        assert_eq!(env["error"]["details"]["expected"], json!("bc1pexpected"));
        assert_eq!(env["error"]["details"]["got"], json!("bc1pgot"));
    }

    /// `chain_unreachable` is transient (retriable) and carries required
    /// `esplora_url` details plus the optional `operation` when known. It mirrors
    /// `mint_unreachable` on the chain-read side.
    #[test]
    fn chain_unreachable_envelope_is_retriable_with_details() {
        let e = PopError::ChainUnreachable {
            esplora_url: "https://esplora.example".to_string(),
            operation: Some("tip_mtp".to_string()),
        };
        let env = e.to_envelope();
        assert_eq!(env["error"]["code"], json!("chain_unreachable"));
        assert_eq!(env["error"]["retriable"], json!(true));
        assert_eq!(
            env["error"]["details"]["esplora_url"],
            json!("https://esplora.example")
        );
        assert_eq!(env["error"]["details"]["operation"], json!("tip_mtp"));
        assert!(env["error"]["message"].is_string());

        // operation is optional: esplora_url is still always present.
        let e = PopError::ChainUnreachable {
            esplora_url: "https://esplora.example".to_string(),
            operation: None,
        };
        let d = e.details().unwrap();
        assert_eq!(d["esplora_url"], json!("https://esplora.example"));
        assert!(d.get("operation").is_none());
    }

    /// `funding_pending` carries the non-mainnet `faucet_hint` in its details when
    /// present (signet/testnet/regtest), and OMITS it on mainnet (None).
    #[test]
    fn funding_pending_carries_faucet_hint_when_present() {
        // Signet-style: faucet_hint present.
        let e = PopError::FundingPending {
            address: "tb1pexample".to_string(),
            expires_at: 1_788_000_000,
            confs_seen: None,
            confs_required: None,
            faucet_hint: Some("https://faucet.mutinynet.com".to_string()),
        };
        let env = e.to_envelope();
        assert_eq!(env["error"]["code"], json!("funding_pending"));
        assert_eq!(env["error"]["retriable"], json!(true));
        assert_eq!(
            env["error"]["details"]["faucet_hint"],
            json!("https://faucet.mutinynet.com")
        );
        // Required details still present.
        assert_eq!(env["error"]["details"]["address"], json!("tb1pexample"));
        assert_eq!(
            env["error"]["details"]["expires_at"],
            json!(1_788_000_000u64)
        );

        // Mainnet-style: no faucet_hint key.
        let e = PopError::FundingPending {
            address: "bc1pexample".to_string(),
            expires_at: 1_788_000_000,
            confs_seen: None,
            confs_required: None,
            faucet_hint: None,
        };
        let d = e.details().unwrap();
        assert!(
            d.get("faucet_hint").is_none(),
            "mainnet funding_pending must not carry a faucet_hint"
        );
    }

    /// Message-only codes carry no `details` key.
    #[test]
    fn message_only_codes_have_no_details() {
        let e = PopError::WalletNotInitialized {
            message: "no wallet".to_string(),
        };
        let env = e.to_envelope();
        assert!(env["error"].get("details").is_none());
        assert!(e.details().is_none());
    }

    /// A non-PopError boxed error resolves to internal_error.
    #[test]
    fn from_boxed_wraps_unknown_as_internal() {
        let boxed: Box<dyn std::error::Error> = "some plumbing failure".into();
        let pe = from_boxed(boxed);
        assert_eq!(pe.code(), "internal_error");
        assert_eq!(pe.message(), "some plumbing failure");
    }

    /// A PopError boxed and re-resolved keeps its identity.
    #[test]
    fn from_boxed_recovers_pop_error() {
        let boxed: Box<dyn std::error::Error> = PopError::DepositNotFound {
            deposit_id: "abc".to_string(),
        }
        .into();
        let pe = from_boxed(boxed);
        assert_eq!(pe.code(), "deposit_not_found");
        assert_eq!(pe.details().unwrap()["deposit_id"], json!("abc"));
    }

    fn sample_errors() -> Vec<PopError> {
        vec![
            PopError::InsufficientFunds {
                required_sats: 1,
                available_sats: 0,
            },
            PopError::DepositNotFound {
                deposit_id: "d".into(),
            },
            PopError::NetworkMismatch {
                expected: "mainnet".into(),
                got: "signet".into(),
            },
            PopError::AmountMismatch {
                expected_sats: 1,
                funded_sats: 2,
            },
            PopError::QuoteExpired {
                quote_id: "q".into(),
                expired_at: 1,
            },
            PopError::ValueBelowFee {
                value_sats: 1,
                fee_sats: 2,
            },
            PopError::WalletNotInitialized {
                message: "m".into(),
            },
            PopError::WalletExists {
                message: "m".into(),
            },
            PopError::InvalidMnemonic {
                message: "m".into(),
            },
            PopError::InvalidInput {
                message: "m".into(),
            },
            PopError::MintUnreachable {
                mint_url: "u".into(),
            },
            PopError::ChainUnreachable {
                esplora_url: "u".into(),
                operation: Some("tip_mtp".into()),
            },
            PopError::FundingPending {
                address: "a".into(),
                expires_at: 1,
                confs_seen: None,
                confs_required: None,
                faucet_hint: None,
            },
            PopError::CltvNotExpired {
                matures_at: 2,
                now: 1,
            },
            PopError::BroadcastFailed {
                reject_reason: Some("r".into()),
                txid: None,
            },
            PopError::MintError {
                status: Some(500),
                mint_message: "m".into(),
            },
            PopError::AddressMismatch {
                expected: "e".into(),
                got: "g".into(),
            },
            PopError::Internal {
                message: "m".into(),
            },
            PopError::Not402 {
                url: "u".into(),
                status_got: 200,
            },
            PopError::PaymentRejected {
                required_amount: Some(1),
                unit: Some("pop_1".into()),
                reason: None,
            },
            PopError::NoPaymentChallenge {
                url: "https://x".into(),
                reason: "no header".into(),
            },
            PopError::ChallengeParseFailed {
                reason: "bad creqA".into(),
            },
            PopError::TokenUnitMismatch {
                required: "pop_2".into(),
                got: "pop_1".into(),
            },
            PopError::TokenMintMismatch {
                token_mint: "https://m1".into(),
                accepted_mints: vec!["https://m2".into()],
            },
            PopError::InsufficientTokenValue { have: 1, need: 2 },
            PopError::AmountExceedsCap {
                amount: 100,
                cap: 50,
            },
            PopError::SwapFailed {
                reason: "rejected".into(),
            },
            PopError::ExactAmountAssertionFailed {
                required: 10,
                got: 9,
            },
            PopError::GatewayRejectedPayment {
                status: 402,
                body: "still owe".into(),
                change_token: Some("cashuBchange".into()),
            },
        ]
    }
}
