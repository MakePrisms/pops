//! The FROZEN output & error contract — typed errors + the JSON envelope.
//!
//! Every `pop` invocation emits exactly one top-level JSON object to stdout. On
//! failure it is the error envelope:
//!
//! ```json
//! { "schema_version": 1,
//!   "error": { "code": "<snake_case>", "retriable": <bool>,
//!              "message": "<human>", "details": { ... }? } }
//! ```
//!
//! Agents MUST parse `code` + `details`, never the prose `message`. `code` is a
//! closed, additive-only enum (see [`PopError`]); `retriable` is true iff the
//! failure is transient (safe to retry as-is).
//!
//! Internal modules propagate `Box<dyn Error>`; a site wanting a precise code
//! returns the matching [`PopError`] (it boxes transparently). At the top,
//! [`crate::run`] downcasts back — anything not ours becomes
//! [`PopError::Internal`].

use serde_json::{json, Value};

/// The frozen schema version stamped on EVERY json output (success and failure).
pub const SCHEMA_VERSION: u64 = 1;

/// A typed `pop` error mapping 1:1 to a contract `code`. Each variant carries
/// exactly the `details` the contract requires, so an agent repairs its call
/// from structured fields, never prose.
///
/// CLOSED and additive-only: never remove or rename a variant or its `code`
/// string; a new failure mode gets a new variant; a breaking change bumps
/// [`SCHEMA_VERSION`].
#[derive(Debug)]
pub enum PopError {
    // ---- needs_input (false) ----
    /// Spend exceeds available balance. (`insufficient_funds`)
    InsufficientFunds {
        /// Sats needed.
        required_sats: u64,
        /// Sats available.
        available_sats: u64,
    },
    /// A deposit id was not found in the local ledger. (`deposit_not_found`)
    DepositNotFound {
        /// The id that wasn't found.
        deposit_id: String,
    },
    /// An address is for a different network than the wallet. (`network_mismatch`)
    NetworkMismatch {
        /// Network the wallet is pinned to.
        expected: String,
        /// Network the value was for.
        got: String,
    },
    /// The mint credited a different amount than quoted. PoP is exact-amount; the
    /// on-chain funds are safe in the CLTV address — recover them. (`amount_mismatch`)
    AmountMismatch {
        /// Sats the quote expected.
        expected_sats: u64,
        /// Sats the mint saw funded.
        funded_sats: u64,
    },
    /// The funding quote's window closed before funding credited; re-quote.
    /// (`quote_expired`)
    QuoteExpired {
        /// The expired quote id.
        quote_id: String,
        /// Unix seconds it expired at.
        expired_at: u64,
    },
    /// A recovery UTXO is uneconomical to sweep (value <= fee). (`value_below_fee`)
    ValueBelowFee {
        /// UTXO value, sats.
        value_sats: u64,
        /// Computed fee, sats.
        fee_sats: u64,
    },
    /// An AUTO-ESTIMATED recovery fee would consume an unreasonable fraction of
    /// the UTXO (a hostile/misconfigured `/fee-estimates` endpoint, or a tiny
    /// UTXO in a high-fee market). Refused BEFORE broadcast so the BTC isn't
    /// burned to the miner; pass an explicit `--fee <sats>` to set the fee
    /// yourself, or `--no-broadcast` to inspect the tx first. (`fee_too_high`)
    FeeTooHigh {
        /// The resolved fee, sats.
        fee_sats: u64,
        /// The UTXO value, sats.
        value_sats: u64,
        /// The guard threshold: max fee as a percent of value.
        max_percent: u64,
    },
    /// A wallet is required but none is initialized. (`wallet_not_initialized`)
    WalletNotInitialized {
        /// Human help.
        message: String,
    },
    /// `init` refused because a wallet already exists. (`wallet_exists`)
    WalletExists {
        /// Human help.
        message: String,
    },
    /// An imported BIP-39 mnemonic failed validation. The `message` must NEVER
    /// echo the phrase. (`invalid_mnemonic`)
    InvalidMnemonic {
        /// Human help (must not contain the phrase).
        message: String,
    },
    /// Generic input/validation failure. (`invalid_input`)
    InvalidInput {
        /// Human help.
        message: String,
    },

    // ---- transient (true) ----
    /// The mint's HTTP endpoint was unreachable (network error). (`mint_unreachable`)
    MintUnreachable {
        /// The mint base URL.
        mint_url: String,
    },
    /// An esplora GET/read (tip-MTP, UTXO lookup, fee estimate) failed at the
    /// transport layer. Mirrors [`PopError::MintUnreachable`] for the chain side;
    /// DISTINCT from [`PopError::BroadcastFailed`] (the POST path). A non-network
    /// esplora error stays `internal_error`. (`chain_unreachable`)
    ChainUnreachable {
        /// The esplora base URL.
        esplora_url: String,
        /// `"tip_mtp"`, `"utxo_fetch"`, or `"fee_estimate"`.
        operation: Option<String>,
    },
    /// Funding has not yet credited; keep polling. (`funding_pending`)
    FundingPending {
        /// The funding address.
        address: String,
        /// Unix seconds the window expires at.
        expires_at: u64,
        /// Confirmations seen, if known.
        confs_seen: Option<u64>,
        /// Confirmations required, if known.
        confs_required: Option<u64>,
        /// On NON-mainnet, where to get test coins (faucet URL / regtest note).
        /// `None` on mainnet (real BTC has no faucet).
        faucet_hint: Option<String>,
    },
    /// The deposit's CLTV has not matured (MTP < ts_expiry); wait, then retry.
    /// (`cltv_not_expired`)
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
        /// The tx id, if known.
        txid: Option<String>,
    },

    // ---- terminal (false) ----
    /// The mint returned an application-level error (non-2xx). (`mint_error`)
    MintError {
        /// HTTP status, if from a response.
        status: Option<u16>,
        /// The mint's error message / body.
        mint_message: String,
    },
    /// The independently reconstructed funding address did not match the mint's
    /// quote address — a security stop, do NOT fund (the mint may be returning an
    /// address it can itself spend). (`address_mismatch`)
    AddressMismatch {
        /// The address we reconstructed.
        expected: String,
        /// The address the mint returned.
        got: String,
    },
    /// An unexpected / unmapped internal failure. (`internal_error`)
    Internal {
        /// Human help.
        message: String,
    },

    // ---- pay path ----
    /// A URL the funder tried to pay did not answer with HTTP 402. (`not_402`)
    Not402 {
        /// The URL probed.
        url: String,
        /// The status returned.
        status_got: u16,
    },
    /// A 402-gated payment was rejected by the service. (`payment_rejected`)
    PaymentRejected {
        /// The amount the 402 required, if told.
        required_amount: Option<u64>,
        /// The unit the 402 named.
        unit: Option<String>,
        /// The service's reason, if any.
        reason: Option<String>,
    },

    // ---- pay path (the `pop pay` HTTP-402 client dance) ----
    /// HTTP 402 with no parseable `WWW-Authenticate: Payment …` challenge, so
    /// there is nothing to satisfy. (`no_payment_challenge`)
    NoPaymentChallenge {
        /// The URL probed.
        url: String,
        /// Why the challenge could not be parsed.
        reason: String,
    },
    /// A 402 `Payment` challenge was present but could not be decoded into a
    /// concrete charge (bad envelope / `creqA`, or missing amount).
    /// (`challenge_parse_failed`)
    ChallengeParseFailed {
        /// What failed to decode.
        reason: String,
    },
    /// The held token's unit differs from the charge's; paying would be
    /// wrong-currency. Send nothing. (`token_unit_mismatch`)
    TokenUnitMismatch {
        /// The unit the charge requires.
        required: String,
        /// The unit the held token carries.
        got: String,
    },
    /// The held token is from a mint the charge does not accept. Send nothing.
    /// (`token_mint_mismatch`)
    TokenMintMismatch {
        /// The mint the held token is from.
        token_mint: String,
        /// Empty ⟹ the charge named no mints, which this wallet treats as
        /// "must be explicit" and rejects.
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
    /// The charge exceeds the caller's `--max-amount` cap; refuse so a malicious
    /// 402 cannot trick an agent into overspending. Send nothing.
    /// (`amount_exceeds_cap`)
    AmountExceedsCap {
        /// Sats the charge required.
        amount: u64,
        /// The `--max-amount` cap, sats.
        cap: u64,
    },
    /// The NUT-03 swap-to-exact failed (mint rejected it, or unblind/DLEQ failed).
    /// The held token may be partially spent — surface any change. (`swap_failed`)
    SwapFailed {
        /// The swap failure detail.
        reason: String,
    },
    /// INTERNAL money-safety gate: the send set did not sum to EXACTLY the charge.
    /// Must never fire (it means a split/selection bug); the payment is aborted
    /// before anything is sent. (`exact_amount_assertion_failed`)
    ExactAmountAssertionFailed {
        /// The amount the send set had to equal.
        required: u64,
        /// What it actually summed to.
        got: u64,
    },
    /// The gateway rejected the presented payment on retry. It did NOT redeem, so
    /// BOTH the send set (worth `amount`) AND any change are unspent ecash —
    /// carried so no value is silently lost. (`gateway_rejected_payment`)
    GatewayRejectedPayment {
        /// HTTP status the retry returned (typically 402).
        status: u16,
        /// The gateway's response body verbatim.
        body: String,
        /// Worth EXACTLY the charge; unredeemed, so valid ecash that MUST be
        /// recovered (the bigger half of the value).
        send_token: String,
        /// Change token, if a swap produced one — also unspent.
        change_token: Option<String>,
    },
    /// A freshly-minted proof set could not be encoded to its `cashuB` string.
    /// The swap had ALREADY spent the held inputs, so the value survives ONLY as
    /// these raw proofs, surfaced as JSON (wire `Proof` shape) for re-encoding.
    /// Must never happen (proof CBOR does not fail). (`token_encode_failed`)
    TokenEncodeFailed {
        /// What failed to encode (bucket + reason).
        reason: String,
        /// Worth EXACTLY the charge, or `None` if only the change failed to encode.
        send_proofs_json: Option<String>,
        /// The change proofs as JSON, if any.
        change_proofs_json: Option<String>,
    },
    /// The payment-retry HTTP call failed in transport AFTER the swap spent the
    /// held proofs. The retry never reached the gateway, so the send set (worth
    /// `amount`) and any change are unspent ecash that exist ONLY as these
    /// strings — losing them is permanent value loss. NOT retriable with the
    /// original `--token` (its inputs are spent); instead present `send_token` to
    /// the gateway directly. (`gateway_retry_failed`)
    GatewayRetryFailed {
        /// The transport-layer failure reason.
        reason: String,
        /// Worth EXACTLY the charge, unspent — MUST be recovered.
        send_token: String,
        /// Change token, if a swap produced one — also unspent.
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
            PopError::FeeTooHigh { .. } => "fee_too_high",
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
            PopError::GatewayRetryFailed { .. } => "gateway_retry_failed",
            PopError::TokenEncodeFailed { .. } => "token_encode_failed",
        }
    }

    /// True iff retrying the SAME call as-is is safe (the `transient` retry-class;
    /// `needs_input` and `terminal` are both false).
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
            PopError::FeeTooHigh {
                fee_sats,
                value_sats,
                max_percent,
            } => Some(json!({
                "fee_sats": fee_sats,
                "value_sats": value_sats,
                "max_percent": max_percent,
            })),
            PopError::MintUnreachable { mint_url } => Some(json!({
                "mint_url": mint_url,
            })),
            PopError::ChainUnreachable {
                esplora_url,
                operation,
            } => {
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
                send_token,
                change_token,
            } => {
                // Surface BOTH: unredeemed ⇒ send set AND any change are unspent.
                let mut o = json!({
                    "status": status,
                    "body": body,
                    "send_token": send_token,
                });
                if let Some(ct) = change_token {
                    o["change_token"] = json!(ct);
                }
                Some(o)
            }
            PopError::GatewayRetryFailed {
                reason,
                send_token,
                change_token,
            } => {
                // Surface BOTH: retry never reached the gateway post-swap.
                let mut o = json!({
                    "reason": reason,
                    "send_token": send_token,
                });
                if let Some(ct) = change_token {
                    o["change_token"] = json!(ct);
                }
                Some(o)
            }
            PopError::TokenEncodeFailed {
                reason,
                send_proofs_json,
                change_proofs_json,
            } => {
                // Raw proofs (parsed JSON when possible) so the ecash survives
                // the failed cashuB encode.
                let parse =
                    |s: &str| -> Value { serde_json::from_str(s).unwrap_or_else(|_| json!(s)) };
                let mut o = json!({ "reason": reason });
                if let Some(sp) = send_proofs_json {
                    o["send_proofs"] = parse(sp);
                }
                if let Some(cp) = change_proofs_json {
                    o["change_proofs"] = parse(cp);
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

    /// Human help (the envelope `message` field; stderr in `--human` mode).
    /// Agents MUST NOT parse it.
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
            PopError::FeeTooHigh {
                fee_sats,
                value_sats,
                max_percent,
            } => format!(
                "estimated fee {fee_sats} sat is >= {max_percent}% of the UTXO ({value_sats} sat); \
                 refusing to burn it to the miner. Re-run with an explicit --fee <sats> if this is \
                 intentional, --no-broadcast to inspect first, or wait for the feerate to drop"
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
                ..
            } => {
                let ct = match change_token {
                    Some(_) => " plus a change token",
                    None => "",
                };
                format!(
                    "the gateway rejected the payment (HTTP {status}): {body}. The gateway did \
                     NOT redeem, so the send token{ct} are unspent ecash — RECOVER them \
                     (json: `details.send_token`/`details.change_token`; human mode prints them below)"
                )
            }
            PopError::GatewayRetryFailed {
                reason,
                change_token,
                ..
            } => {
                let ct = match change_token {
                    Some(_) => " plus a change token",
                    None => "",
                };
                format!(
                    "the payment retry to the gateway failed after the swap already spent the \
                     held proofs ({reason}). The retry never reached the gateway, so the send \
                     token{ct} are unspent ecash — RECOVER them and present the send token to \
                     the gateway directly; do NOT retry with the original --token (it is spent) \
                     (json: `details.send_token`/`details.change_token`; human mode prints them below)"
                )
            }
            PopError::TokenEncodeFailed { reason, .. } => format!(
                "INTERNAL: the swap succeeded but a proof set could not be encoded to a cashuB \
                 token ({reason}); your input proofs are ALREADY spent. The raw proofs are in \
                 `details.send_proofs`/`details.change_proofs` (and printed below in human mode) \
                 — they are your ecash; re-encode them to recover the value. Please report this."
            ),
        }
    }

    /// The full failure envelope (see the module-level shape).
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

    /// Recovery tokens `(send_token, change_token)`, for the POST-swap `pay`
    /// errors only — the swap already spent the held inputs, so this ecash exists
    /// ONLY as these strings and MUST surface on every exit. `--human` mode reads
    /// them here because it does not print `details`.
    pub fn recovery_tokens(&self) -> Option<(&str, Option<&str>)> {
        match self {
            PopError::GatewayRejectedPayment {
                send_token,
                change_token,
                ..
            }
            | PopError::GatewayRetryFailed {
                send_token,
                change_token,
                ..
            } => Some((send_token, change_token.as_deref())),
            _ => None,
        }
    }

    /// Raw recovery proofs `(send_proofs_json, change_proofs_json)`, for
    /// [`PopError::TokenEncodeFailed`] only — the `cashuB` encode failed, so the
    /// ecash survives only as these. Read by `--human` mode (no `details` there).
    pub fn recovery_proofs_json(&self) -> Option<(Option<&str>, Option<&str>)> {
        match self {
            PopError::TokenEncodeFailed {
                send_proofs_json,
                change_proofs_json,
                ..
            } => Some((send_proofs_json.as_deref(), change_proofs_json.as_deref())),
            _ => None,
        }
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

/// Resolves a boxed error to a typed [`PopError`]: downcast if it is one, else
/// wrap its `Display` as [`PopError::Internal`].
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

        // address_mismatch is terminal (not retriable).
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

        // operation optional; esplora_url still always present.
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
        assert_eq!(env["error"]["details"]["address"], json!("tb1pexample"));
        assert_eq!(
            env["error"]["details"]["expires_at"],
            json!(1_788_000_000u64)
        );

        // Mainnet: no faucet_hint key.
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

    /// Post-swap `gateway_rejected_payment` is terminal and MUST carry BOTH
    /// tokens (details + `recovery_tokens()`) — both halves are unspent ecash and
    /// losing either is permanent value loss.
    #[test]
    fn gateway_rejected_payment_surfaces_both_tokens() {
        let e = PopError::GatewayRejectedPayment {
            status: 402,
            body: "still owe".to_string(),
            send_token: "cashuBsend".to_string(),
            change_token: Some("cashuBchange".to_string()),
        };
        let env = e.to_envelope();
        assert_eq!(env["error"]["code"], json!("gateway_rejected_payment"));
        assert_eq!(env["error"]["retriable"], json!(false));
        assert_eq!(env["error"]["details"]["send_token"], json!("cashuBsend"));
        assert_eq!(
            env["error"]["details"]["change_token"],
            json!("cashuBchange")
        );
        assert_eq!(
            e.recovery_tokens(),
            Some(("cashuBsend", Some("cashuBchange")))
        );

        // ZERO-CHANGE swap: the input was still spent, so the send token must
        // STILL be surfaced even with change_token None.
        let e = PopError::GatewayRejectedPayment {
            status: 402,
            body: "no".to_string(),
            send_token: "cashuBsend".to_string(),
            change_token: None,
        };
        assert_eq!(e.details().unwrap()["send_token"], json!("cashuBsend"));
        assert!(e.details().unwrap().get("change_token").is_none());
        assert_eq!(e.recovery_tokens(), Some(("cashuBsend", None)));
    }

    /// `gateway_retry_failed` is terminal (NOT retriable — the input proofs are
    /// already spent), carrying BOTH unspent tokens so a retry network error
    /// never loses the freshly-minted ecash.
    #[test]
    fn gateway_retry_failed_is_terminal_and_carries_both_tokens() {
        let e = PopError::GatewayRetryFailed {
            reason: "connection reset by peer".to_string(),
            send_token: "cashuBsend".to_string(),
            change_token: Some("cashuBchange".to_string()),
        };
        let env = e.to_envelope();
        assert_eq!(env["error"]["code"], json!("gateway_retry_failed"));
        // CRITICAL: NOT retriable — retrying with the spent --token would mask
        // the loss (the input proofs are gone).
        assert_eq!(env["error"]["retriable"], json!(false));
        assert_eq!(env["error"]["details"]["send_token"], json!("cashuBsend"));
        assert_eq!(
            env["error"]["details"]["change_token"],
            json!("cashuBchange")
        );
        assert_eq!(
            e.recovery_tokens(),
            Some(("cashuBsend", Some("cashuBchange")))
        );
    }

    /// `token_encode_failed` carries the raw proofs as parsed JSON (so the value
    /// survives the failed encode) and exposes them via `recovery_proofs_json()`.
    #[test]
    fn token_encode_failed_surfaces_raw_proofs() {
        let e = PopError::TokenEncodeFailed {
            reason: "send bucket: cbor write failed".to_string(),
            send_proofs_json: Some(r#"[{"amount":600}]"#.to_string()),
            change_proofs_json: Some(r#"[{"amount":400}]"#.to_string()),
        };
        let env = e.to_envelope();
        assert_eq!(env["error"]["code"], json!("token_encode_failed"));
        assert_eq!(env["error"]["retriable"], json!(false));
        // Surfaced as PARSED json, not a string blob.
        assert_eq!(
            env["error"]["details"]["send_proofs"][0]["amount"],
            json!(600)
        );
        assert_eq!(
            env["error"]["details"]["change_proofs"][0]["amount"],
            json!(400)
        );
        assert_eq!(
            e.recovery_proofs_json(),
            Some((Some(r#"[{"amount":600}]"#), Some(r#"[{"amount":400}]"#)))
        );
        // NOT a cashuB-token-bearing error (different human-mode path).
        assert!(e.recovery_tokens().is_none());
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
            PopError::FeeTooHigh {
                fee_sats: 90,
                value_sats: 100,
                max_percent: 50,
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
                send_token: "cashuBsend".into(),
                change_token: Some("cashuBchange".into()),
            },
            PopError::GatewayRetryFailed {
                reason: "connection reset".into(),
                send_token: "cashuBsend".into(),
                change_token: Some("cashuBchange".into()),
            },
            PopError::TokenEncodeFailed {
                reason: "send bucket: cbor".into(),
                send_proofs_json: Some("[]".into()),
                change_proofs_json: None,
            },
        ]
    }
}
