//! `pop pay <URL> --token <cashuB>` — the HTTP-402 client dance: fetch a
//! gateway-protected resource, satisfy its `402 Payment` challenge with a token
//! worth EXACTLY the charge, return the resource.
//!
//! ## Money-safety invariant (the whole point)
//!
//! PoP charges are EXACT-AMOUNT — the mint gives no change on redeem — so `pay`
//! must hand the gateway a token summing to EXACTLY `amount`, never more. The
//! wallet holds no ecash of its own; the token comes IN via `--token` and any
//! leftover goes OUT as a NEW change `cashuB` the user keeps.
//!
//! - **token == charge** → send the token's proofs as-is (fast path, no swap).
//! - **token  > charge** → swap-to-exact (NUT-03): spend the held proofs, request
//!   two output buckets (send == `amount`, change == `total - amount - fee`),
//!   unblind each separately.
//!
//! Before anything is sent, a HARD ASSERTION ([`assert_send_is_exact`]) checks
//! the send set == `amount`; a mismatch aborts with
//! [`PopError::ExactAmountAssertionFailed`] and sends NOTHING. `--max-amount`
//! refuses an over-cap charge so a malicious 402 cannot force overspending. Swap
//! is UNSIGNED NUT-03, so `pay` never loads the wallet seed.

use std::io::Read as _;
use std::path::Path;
use std::str::FromStr;

use cdk_common::amount::SplitTarget;
use cdk_common::mint_url::MintUrl;
use cdk_common::nuts::{CurrencyUnit, Id, KeySetInfo, Keys, PreMintSecrets, Proofs, Token};
use cdk_common::Amount as CdkAmount;
use clap::Parser;

use crate::error::PopError;
use crate::http402::{
    decode_charge_request, encode_payment_credentials, parse_payment_params, CashuPayload,
    EchoedChallenge, PaymentCredentials, PaymentParams,
};
use crate::mint_client::{self, proofs_to_json, proofs_value, token_to_string};
use crate::SCHEMA_VERSION;

/// Arguments for `pop pay`.
#[derive(Debug, Parser)]
pub struct PayArgs {
    /// The pops-gateway-protected resource URL to fetch (and pay if it 402s).
    #[arg(value_name = "URL")]
    pub url: String,

    /// The `cashuB` token to pay WITH. If omitted, the token is read from
    /// `--token-file`, else from stdin. The wallet holds no ecash of its own.
    #[arg(long, value_name = "cashuB")]
    pub token: Option<String>,

    /// Read the `cashuB` token from this file (alternative to `--token`/stdin).
    #[arg(long, value_name = "PATH", conflicts_with = "token")]
    pub token_file: Option<std::path::PathBuf>,

    /// HTTP method (v1 only really needs GET).
    #[arg(long, value_name = "METHOD", default_value = "GET")]
    pub method: String,

    /// Safety cap: refuse to pay if the charge exceeds this many sats. An agent
    /// must not be tricked by a malicious 402 into overspending.
    #[arg(long, value_name = "SATS")]
    pub max_amount: Option<u64>,
}

/// The concrete charge decoded from a 402's `creqA` payment request: the EXACT
/// amount, the unit, and the accepted mints.
#[derive(Debug, Clone)]
pub struct Charge {
    /// Exact sat amount the holder must present (REQUIRED on the wire).
    pub amount: u64,
    /// Unit the proofs must carry (e.g. `pop_<ts>`).
    pub unit: CurrencyUnit,
    /// Mints the gateway accepts (empty ⟹ the charge named none).
    pub mints: Vec<MintUrl>,
}

/// The exact-split plan for a swap: how many sats go to the send set vs change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Split {
    /// Sats in the send set — ALWAYS exactly the charge amount.
    pub send: u64,
    /// Sats in the change set (`total - amount - fee`).
    pub change: u64,
}

/// Runs `pop pay`.
///
/// `wallet_dir` is accepted for signature symmetry with the other commands but
/// is unused: `pay` reads no wallet state (no seed, no DB proofs) — the token
/// comes in via `--token`/stdin and change goes out in the JSON.
///
/// # Errors
///
/// Propagates the HTTP-402 dance errors (see the `pay`-path [`PopError`]
/// variants); on any validation or exactness failure it sends NOTHING.
pub async fn run(
    args: &PayArgs,
    _wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let http = reqwest::Client::new();

    // ---- 1. Initial request. ----
    let method = parse_method(&args.method)?;
    eprintln!("{} {} ...", args.method.to_uppercase(), args.url);
    let resp = http
        .request(method.clone(), &args.url)
        .send()
        .await
        .map_err(|e| {
            eprintln!("request to {} failed: {e}", args.url);
            PopError::MintUnreachable {
                mint_url: args.url.clone(),
            }
        })?;
    let status = resp.status();

    // ---- 2. Already satisfied → no payment needed. ----
    if status.is_success() {
        eprintln!(
            "{} returned {} — no payment needed.",
            args.url,
            status.as_u16()
        );
        let body = resp.text().await.unwrap_or_default();
        emit_unpaid(args, status.as_u16(), &body, json)?;
        return Ok(());
    }

    // ---- 3. Must be a 402 to proceed; anything else isn't a payment ask. ----
    if status.as_u16() != 402 {
        return Err(PopError::Not402 {
            url: args.url.clone(),
            status_got: status.as_u16(),
        }
        .into());
    }

    // ---- 3a. Parse the `WWW-Authenticate: Payment …` challenge. ----
    let www_auth = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let www_auth = www_auth.ok_or_else(|| PopError::NoPaymentChallenge {
        url: args.url.clone(),
        reason: "no WWW-Authenticate header on the 402 response".to_string(),
    })?;
    let params = parse_payment_params(&www_auth).map_err(|e| PopError::NoPaymentChallenge {
        url: args.url.clone(),
        reason: format!("WWW-Authenticate Payment params did not parse: {e}"),
    })?;

    // ---- 3b/3c. Decode the request object → creqA → the concrete charge. ----
    let charge = decode_charge_from_params(&params)?;
    eprintln!(
        "Charge: {} sat of {} (mints: {})",
        charge.amount,
        charge.unit,
        if charge.mints.is_empty() {
            "<none named>".to_string()
        } else {
            charge
                .mints
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    );

    // ---- 4a. Safety cap FIRST (before touching the token or the mint). ----
    if let Some(cap) = args.max_amount {
        if charge.amount > cap {
            return Err(PopError::AmountExceedsCap {
                amount: charge.amount,
                cap,
            }
            .into());
        }
    }

    // ---- 4b. Decode + validate the held token against the charge. ----
    let token_str = read_token(args)?;
    let token = Token::from_str(token_str.trim())
        .map_err(|e| PopError::invalid_input(format!("--token is not a valid cashu token: {e}")))?;
    let token_unit = token
        .unit()
        .ok_or_else(|| PopError::invalid_input("--token has no unit".to_string()))?;
    let token_mint = token
        .mint_url()
        .map_err(|e| PopError::invalid_input(format!("--token has no single mint url: {e}")))?;
    let token_total = token
        .value()
        .map_err(|e| PopError::invalid_input(format!("--token value is unreadable: {e}")))?
        .to_u64();
    validate_token(token_total, &token_unit, &token_mint, &charge)?;

    // ---- 5/6/7. Build the EXACT-amount send token (fast path or swap). ----
    let base = token_mint.to_string();
    let base = base.trim_end_matches('/');
    let keyset_infos = mint_client::fetch_keyset_infos(&http, base).await?;
    let token_proofs = token
        .proofs(&keyset_infos)
        .map_err(|e| PopError::invalid_input(format!("--token proofs are unreadable: {e}")))?;

    let ExactPaymentTokens {
        send_token,
        change_token,
    } = build_exact_payment(
        &http,
        base,
        &charge,
        token_proofs,
        token_total,
        &token_unit,
        &keyset_infos,
    )
    .await?;

    // POST-SWAP VALUE-RECOVERY INVARIANT: `build_exact_payment` may have SPENT
    // the held input proofs, after which the only surviving form of that ecash is
    // `send_token` (+ any `change_token`). So EVERY exit below — success
    // included — must surface BOTH. `finish_payment` builds its two error cases
    // token-bearing by construction; `ensure_post_swap_token_bearing` is the
    // catch-all converting ANY other stray error into a token-bearing one, so an
    // unforeseen failure can never silently drop the spent value. (On the fast
    // path `send_token == --token`, harmless to echo; doing it uniformly also
    // covers the ZERO-CHANGE swap where the input was spent but change is None —
    // hence recovery is NOT gated on `change_token.is_some()`.)
    finish_payment(
        &http,
        method,
        args,
        &params,
        &charge,
        base,
        &send_token,
        change_token.as_deref(),
        json,
    )
    .await
    .map_err(|e| ensure_post_swap_token_bearing(e, &send_token, change_token.as_deref()))
}

/// Builds the credentials, retries the SAME request with the exact-amount token,
/// and emits. Every non-success exit is token-bearing (see the POST-SWAP
/// invariant at the call site):
///
/// - retry transport error → [`PopError::GatewayRetryFailed`] (NOT retriable —
///   the inputs are spent, so retrying `--token` would mask the loss; recover by
///   presenting `send_token`).
/// - gateway non-2xx → [`PopError::GatewayRejectedPayment`] carrying both tokens.
/// - 2xx → [`emit_paid`].
#[allow(clippy::too_many_arguments)]
async fn finish_payment(
    http: &reqwest::Client,
    method: reqwest::Method,
    args: &PayArgs,
    params: &PaymentParams,
    charge: &Charge,
    base: &str,
    send_token: &str,
    change_token: Option<&str>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let creds = build_credentials(params, send_token);
    let blob = encode_payment_credentials(&creds);
    eprintln!(
        "Presenting payment ({} sat) and retrying ...",
        charge.amount
    );
    let retry = http
        .request(method, &args.url)
        .header(reqwest::header::AUTHORIZATION, format!("Payment {blob}"))
        .send()
        .await
        .map_err(|e| {
            eprintln!("payment retry to {} failed: {e}", args.url);
            // Retry never reached the gateway → the send proofs are UNSPENT ecash.
            // NOT retriable (the inputs are spent; don't reuse --token).
            PopError::GatewayRetryFailed {
                reason: e.to_string(),
                send_token: send_token.to_string(),
                change_token: change_token.map(str::to_string),
            }
        })?;
    let retry_status = retry.status();
    let retry_body = retry.text().await.unwrap_or_default();

    if retry_status.is_success() {
        emit_paid(
            args,
            retry_status.as_u16(),
            charge,
            base,
            change_token,
            &retry_body,
            json,
        )?;
        Ok(())
    } else {
        // Gateway rejected (did NOT redeem) → send set AND any change are unspent
        // ecash; surface BOTH.
        Err(PopError::GatewayRejectedPayment {
            status: retry_status.as_u16(),
            body: retry_body,
            send_token: send_token.to_string(),
            change_token: change_token.map(str::to_string),
        }
        .into())
    }
}

/// Belt-and-suspenders: guarantees a post-swap error is token-bearing. An error
/// already carrying recovery tokens/proofs passes through; any other (an
/// unforeseen failure after the swap spent the input) is wrapped into a
/// token-bearing [`PopError::GatewayRetryFailed`] so the spent value is never
/// silently dropped.
fn ensure_post_swap_token_bearing(
    err: Box<dyn std::error::Error>,
    send_token: &str,
    change_token: Option<&str>,
) -> Box<dyn std::error::Error> {
    let pe = crate::error::from_boxed(err);
    if pe.recovery_tokens().is_some() || pe.recovery_proofs_json().is_some() {
        return pe.into();
    }
    PopError::GatewayRetryFailed {
        reason: pe.message(),
        send_token: send_token.to_string(),
        change_token: change_token.map(str::to_string),
    }
    .into()
}

/// The two tokens produced by the exact-amount construction.
struct ExactPaymentTokens {
    /// The token worth EXACTLY the charge — this is what is presented.
    send_token: String,
    /// The leftover change token (`None` when the held token equalled the charge).
    change_token: Option<String>,
}

/// Builds the exact-amount send token (and any change) from the held proofs.
///
/// Fast path when `token_total == charge.amount` (send the held proofs as-is);
/// otherwise swap-to-exact. Either way the send set is asserted to equal the
/// charge before it is returned.
#[allow(clippy::too_many_arguments)]
async fn build_exact_payment(
    http: &reqwest::Client,
    base: &str,
    charge: &Charge,
    token_proofs: Proofs,
    token_total: u64,
    unit: &CurrencyUnit,
    keyset_infos: &[KeySetInfo],
) -> Result<ExactPaymentTokens, Box<dyn std::error::Error>> {
    let mint_url_typed = MintUrl::from_str(base)
        .map_err(|e| PopError::invalid_input(format!("mint url `{base}` is invalid: {e}")))?;

    // FAST PATH: the held token already equals the charge exactly.
    if token_total == charge.amount {
        let send_sum = proofs_value(&token_proofs);
        assert_send_is_exact(send_sum, charge.amount)?;
        // No swap ran, so the input is NOT yet spent — an encode failure here is
        // benign (the caller still holds `--token`); still avoid the `.to_string()`
        // panic by surfacing it with the proofs.
        let send_proofs_json = proofs_to_json(&token_proofs);
        let send_token = token_to_string(&Token::new(
            mint_url_typed,
            token_proofs,
            None,
            unit.clone(),
        ))
        .map_err(|reason| PopError::TokenEncodeFailed {
            reason: format!("fast-path send token: {reason}"),
            send_proofs_json: Some(send_proofs_json),
            change_proofs_json: None,
        })?;
        return Ok(ExactPaymentTokens {
            send_token,
            change_token: None,
        });
    }

    // SWAP-TO-EXACT: token_total is strictly > charge.amount here (>= validated,
    // == handled above).
    let active = mint_client::select_active_keyset(keyset_infos, unit)?;
    let keyset_id: Id = active.id;
    let input_fee_ppk = active.input_fee_ppk;

    // Any fee is absorbed by CHANGE so the SEND set stays EXACTLY `amount`
    // (inputs == outputs + fee).
    let fee = swap_fee_sats(input_fee_ppk, token_proofs.len());
    let split = plan_split(token_total, charge.amount, fee)?;

    let keys = mint_client::fetch_keys(http, base, &keyset_id).await?;

    // Two output buckets: send == amount, change == total-amount-fee.
    let send_premint = build_premint(keyset_id, split.send, &keys)?;
    let mut buckets = vec![send_premint];
    if split.change > 0 {
        buckets.push(build_premint(keyset_id, split.change, &keys)?);
    }

    let mut proof_sets = mint_client::swap(http, base, token_proofs, &buckets, &keys)
        .await
        .map_err(|e| PopError::SwapFailed {
            reason: e.to_string(),
        })?;

    // proof_sets is in bucket order: [send, change?].
    let send_proofs = proof_sets.remove(0);
    let change_proofs = if split.change > 0 {
        Some(proof_sets.remove(0))
    } else {
        None
    };

    // HARD ASSERTION: the send set must sum to EXACTLY the charge.
    let send_sum = proofs_value(&send_proofs);
    assert_send_is_exact(send_sum, charge.amount)?;

    // POST-SWAP: the inputs are SPENT, so the freshly-minted ecash exists only as
    // these proofs/strings. Pre-serialize both to raw JSON so a failed `cashuB`
    // encode still recovers the value as proofs — never a `.to_string()` panic
    // that vaporizes spent ecash.
    let send_proofs_json = proofs_to_json(&send_proofs);
    let change_proofs_json = change_proofs.as_ref().map(proofs_to_json);

    let send_token = token_to_string(&Token::new(
        mint_url_typed.clone(),
        send_proofs,
        None,
        unit.clone(),
    ))
    .map_err(|reason| PopError::TokenEncodeFailed {
        reason: format!("send bucket: {reason}"),
        send_proofs_json: Some(send_proofs_json.clone()),
        change_proofs_json: change_proofs_json.clone(),
    })?;

    let change_token = match change_proofs {
        Some(cp) => Some(
            token_to_string(&Token::new(mint_url_typed, cp, None, unit.clone())).map_err(
                |reason| PopError::TokenEncodeFailed {
                    reason: format!("change bucket: {reason}"),
                    // The send token DID encode — carry it plus the raw change
                    // proofs that failed.
                    send_proofs_json: Some(send_proofs_json.clone()),
                    change_proofs_json: change_proofs_json.clone(),
                },
            )?,
        ),
        None => None,
    };

    Ok(ExactPaymentTokens {
        send_token,
        change_token,
    })
}

/// Decodes the concrete [`Charge`] from parsed 402 params: read the
/// `draft-cashu-charge-01` request object, deriving amount/unit/mints from the
/// authoritative `methodDetails.paymentRequest` (the shared codec rejects a
/// creqA missing `a`/`u`/`m` or disagreeing with the top-level
/// `amount`/`currency`). A 0-sat charge is rejected before any spend (an exact
/// 0-sat charge is meaningless).
fn decode_charge_from_params(params: &PaymentParams) -> Result<Charge, Box<dyn std::error::Error>> {
    let decoded =
        decode_charge_request(&params.request).map_err(|e| PopError::ChallengeParseFailed {
            reason: format!("request object did not decode: {e}"),
        })?;
    let amount = decoded.amount.to_u64();
    if amount == 0 {
        return Err(PopError::ChallengeParseFailed {
            reason: "payment request amount is 0 (a 0-sat exact charge is meaningless)".to_string(),
        }
        .into());
    }
    Ok(Charge {
        amount,
        unit: decoded.unit,
        mints: decoded.mints,
    })
}


/// Validates the held token against the charge BEFORE any spend: matching unit,
/// an accepted mint, and enough value. Any mismatch → a structured error and
/// (at the call site) SEND NOTHING.
pub fn validate_token(
    token_total: u64,
    token_unit: &CurrencyUnit,
    token_mint: &MintUrl,
    charge: &Charge,
) -> Result<(), Box<dyn std::error::Error>> {
    if token_unit != &charge.unit {
        return Err(PopError::TokenUnitMismatch {
            required: charge.unit.to_string(),
            got: token_unit.to_string(),
        }
        .into());
    }
    // The charge MUST name its accepted mint(s); an empty set is rejected — we
    // won't silently pay an unconstrained charge from an arbitrary mint.
    if !charge.mints.iter().any(|m| m == token_mint) {
        return Err(PopError::TokenMintMismatch {
            token_mint: token_mint.to_string(),
            accepted_mints: charge.mints.iter().map(ToString::to_string).collect(),
        }
        .into());
    }
    if token_total < charge.amount {
        return Err(PopError::InsufficientTokenValue {
            have: token_total,
            need: charge.amount,
        }
        .into());
    }
    Ok(())
}

/// The per-swap input fee in sats: `ceil(n_inputs * input_fee_ppk / 1000)`
/// (NUT-02 fee model). For 0-fee pop keysets this is 0.
pub fn swap_fee_sats(input_fee_ppk: u64, n_inputs: usize) -> u64 {
    let total_ppk = input_fee_ppk.saturating_mul(n_inputs as u64);
    total_ppk.div_ceil(1000)
}

/// Plans the exact split: send == amount, change == total - amount - fee.
///
/// Errors if `total < amount + fee` (the token cannot cover the charge once the
/// swap fee is taken) — surfaced as [`PopError::InsufficientTokenValue`] with
/// the fee folded into `need` so the caller sees the true requirement.
pub fn plan_split(total: u64, amount: u64, fee: u64) -> Result<Split, Box<dyn std::error::Error>> {
    let need = amount
        .checked_add(fee)
        .ok_or_else(|| PopError::internal("amount + fee overflowed u64"))?;
    if total < need {
        return Err(PopError::InsufficientTokenValue { have: total, need }.into());
    }
    Ok(Split {
        send: amount,
        change: total - need,
    })
}

/// The money-safety gate: the send set MUST sum to EXACTLY the charge amount.
///
/// Returns [`PopError::ExactAmountAssertionFailed`] (sends nothing) on any
/// deviation. This must never fire in practice — it guards against a split or
/// unblind bug ever letting a non-exact set reach the gateway.
pub fn assert_send_is_exact(send_sum: u64, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    if send_sum != amount {
        return Err(PopError::ExactAmountAssertionFailed {
            required: amount,
            got: send_sum,
        }
        .into());
    }
    Ok(())
}

/// Builds a [`PreMintSecrets`] for `amount` on `keyset_id` (least-proofs
/// power-of-2 split, no swap fee folded into the OUTPUT split — outputs are
/// 0-fee; the input fee is handled by the change bucket).
fn build_premint(
    keyset_id: Id,
    amount: u64,
    keys: &Keys,
) -> Result<PreMintSecrets, Box<dyn std::error::Error>> {
    let amounts: Vec<u64> = keys.keys().keys().map(|a| a.to_u64()).collect();
    let fee_and_amounts = (0u64, amounts).into();
    PreMintSecrets::random(
        keyset_id,
        CdkAmount::from(amount),
        &SplitTarget::None,
        &fee_and_amounts,
    )
    .map_err(|e| format!("failed to build premint secrets for {amount} sat: {e}").into())
}

/// Builds the `Authorization: Payment` credentials: a VERBATIM echo of the
/// parsed challenge params, plus the exact-amount token as the cashu payload. The
/// 402 carries no `digest`/`opaque`/`expires` (binding is server-deferred), so
/// those echo fields and the optional `source` are `None`.
pub fn build_credentials(params: &PaymentParams, token: &str) -> PaymentCredentials {
    PaymentCredentials {
        challenge: EchoedChallenge {
            id: params.id.clone(),
            realm: params.realm.clone(),
            method: params.method.clone(),
            intent: params.intent.clone(),
            request: params.request.clone(),
            digest: None,
            opaque: None,
            expires: None,
        },
        payload: CashuPayload {
            token: token.to_string(),
        },
        source: None,
    }
}

/// Reads the `cashuB` token from `--token`, else `--token-file`, else stdin.
fn read_token(args: &PayArgs) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(t) = &args.token {
        return Ok(t.clone());
    }
    if let Some(path) = &args.token_file {
        return std::fs::read_to_string(path).map_err(|e| {
            PopError::invalid_input(format!(
                "failed to read --token-file {}: {e}",
                path.display()
            ))
            .into()
        });
    }
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| PopError::invalid_input(format!("failed to read token from stdin: {e}")))?;
    if buf.trim().is_empty() {
        return Err(PopError::invalid_input(
            "no token supplied: pass --token <cashuB>, --token-file <path>, or pipe it on stdin",
        )
        .into());
    }
    Ok(buf)
}

/// Parses the `--method` string into a reqwest `Method`.
fn parse_method(m: &str) -> Result<reqwest::Method, Box<dyn std::error::Error>> {
    reqwest::Method::from_bytes(m.to_uppercase().as_bytes())
        .map_err(|e| PopError::invalid_input(format!("invalid --method `{m}`: {e}")).into())
}

/// Emits the success-without-payment JSON (`paid:false`) on a 2xx first hit.
fn emit_unpaid(
    args: &PayArgs,
    status: u16,
    body: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        let out = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "paid": false,
            "status": status,
            "url": args.url,
            "body": body,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{status} (no payment needed)\n{body}");
    }
    Ok(())
}

/// Emits the paid-success JSON after a satisfied retry.
#[allow(clippy::too_many_arguments)]
fn emit_paid(
    args: &PayArgs,
    status: u16,
    charge: &Charge,
    mint: &str,
    change_token: Option<&str>,
    body: &str,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        let out = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "paid": true,
            "status": status,
            "url": args.url,
            "amount": charge.amount,
            "unit": charge.unit.to_string(),
            "mint": mint,
            "change_token": change_token,
            "body": body,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "PAID {} sat of {} to {}",
            charge.amount, charge.unit, args.url
        );
        if let Some(ct) = change_token {
            println!("\nChange token (NOT stored — save it):\n{ct}");
        }
        println!("\n---- resource ----\n{body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http402::encode_payment_credentials;
    use pops_core_verify::challenge::{encode_charge_request, CashuRequirement};
    use pops_core_verify::envelope::parse_payment_authorization;

    fn pop_unit() -> CurrencyUnit {
        CurrencyUnit::Custom("pop_1782668279".to_string())
    }

    fn mint_a() -> MintUrl {
        MintUrl::from_str("https://mint.example").unwrap()
    }

    fn charge(amount: u64) -> Charge {
        Charge {
            amount,
            unit: pop_unit(),
            mints: vec![mint_a()],
        }
    }

    // ---- exact-split math ------------------------------------------------

    #[test]
    fn plan_split_zero_fee_change_is_total_minus_amount() {
        let s = plan_split(1000, 600, 0).unwrap();
        assert_eq!(s.send, 600);
        assert_eq!(s.change, 400);
        assert_eq!(s.send + s.change, 1000);
    }

    #[test]
    fn plan_split_exact_token_has_zero_change() {
        let s = plan_split(600, 600, 0).unwrap();
        assert_eq!(s.send, 600);
        assert_eq!(s.change, 0);
    }

    #[test]
    fn plan_split_fee_is_absorbed_by_change_send_stays_exact() {
        // The fee comes out of CHANGE; the SEND set stays exactly `amount`.
        let s = plan_split(1000, 600, 3).unwrap();
        assert_eq!(s.send, 600, "send must stay EXACTLY the charge");
        assert_eq!(s.change, 397);
        assert_eq!(s.send + s.change + 3, 1000, "inputs == outputs + fee");
    }

    #[test]
    fn plan_split_insufficient_after_fee_errors() {
        // Covers amount but not amount+fee.
        let err = plan_split(600, 600, 1).unwrap_err();
        let pe = crate::error::from_boxed(err);
        assert_eq!(pe.code(), "insufficient_token_value");
        let d = pe.details().unwrap();
        assert_eq!(d["have"], serde_json::json!(600));
        assert_eq!(d["need"], serde_json::json!(601));
    }

    #[test]
    fn swap_fee_sats_zero_keyset_is_free() {
        assert_eq!(swap_fee_sats(0, 5), 0);
    }

    #[test]
    fn swap_fee_sats_rounds_up() {
        assert_eq!(swap_fee_sats(100, 3), 1); // 300 ppk -> ceil = 1
        assert_eq!(swap_fee_sats(100, 10), 1); // 1000 ppk -> 1
        assert_eq!(swap_fee_sats(100, 11), 2); // 1100 ppk -> ceil = 2
    }

    // ---- the hard assertion fires on a bad split -------------------------

    #[test]
    fn assert_send_is_exact_passes_on_match() {
        assert!(assert_send_is_exact(600, 600).is_ok());
    }

    #[test]
    fn assert_send_is_exact_fires_when_over() {
        let err = assert_send_is_exact(601, 600).unwrap_err();
        let pe = crate::error::from_boxed(err);
        assert_eq!(pe.code(), "exact_amount_assertion_failed");
        let d = pe.details().unwrap();
        assert_eq!(d["required"], serde_json::json!(600));
        assert_eq!(d["got"], serde_json::json!(601));
    }

    #[test]
    fn assert_send_is_exact_fires_when_under() {
        let err = assert_send_is_exact(599, 600).unwrap_err();
        assert_eq!(
            crate::error::from_boxed(err).code(),
            "exact_amount_assertion_failed"
        );
    }

    // ---- unit / mint / value validations ---------------------------------

    #[test]
    fn validate_token_ok_when_unit_mint_value_match() {
        assert!(validate_token(1000, &pop_unit(), &mint_a(), &charge(600)).is_ok());
        assert!(validate_token(600, &pop_unit(), &mint_a(), &charge(600)).is_ok()); // exact
    }

    #[test]
    fn validate_token_rejects_unit_mismatch() {
        let other = CurrencyUnit::Custom("pop_9999999999".to_string());
        let err = validate_token(1000, &other, &mint_a(), &charge(600)).unwrap_err();
        assert_eq!(crate::error::from_boxed(err).code(), "token_unit_mismatch");
    }

    #[test]
    fn validate_token_rejects_mint_mismatch() {
        let other_mint = MintUrl::from_str("https://other.example").unwrap();
        let err = validate_token(1000, &pop_unit(), &other_mint, &charge(600)).unwrap_err();
        assert_eq!(crate::error::from_boxed(err).code(), "token_mint_mismatch");
    }

    #[test]
    fn validate_token_rejects_when_charge_names_no_mints() {
        // An empty accepted-mints set is rejected (no unconstrained pay).
        let c = Charge {
            amount: 600,
            unit: pop_unit(),
            mints: vec![],
        };
        let err = validate_token(1000, &pop_unit(), &mint_a(), &c).unwrap_err();
        assert_eq!(crate::error::from_boxed(err).code(), "token_mint_mismatch");
    }

    #[test]
    fn validate_token_rejects_insufficient_value() {
        let err = validate_token(599, &pop_unit(), &mint_a(), &charge(600)).unwrap_err();
        let pe = crate::error::from_boxed(err);
        assert_eq!(pe.code(), "insufficient_token_value");
        let d = pe.details().unwrap();
        assert_eq!(d["have"], serde_json::json!(599));
        assert_eq!(d["need"], serde_json::json!(600));
    }

    // ---- request-object decode (the client's 402 parse surface) ----------

    /// Build the parsed `PaymentParams` for a charge of `amount`, as the client
    /// sees them off a 402 carrying the spec request object.
    fn params_for_charge(amount: u64) -> PaymentParams {
        let req = CashuRequirement {
            unit: pop_unit(),
            mints: vec![mint_a()],
            amount: cdk_common::Amount::from(amount),
            payment_id: Some("ch-1".to_string()),
            description: None,
            single_use: true,
        };
        let request = encode_charge_request(&req).expect("requirement encodes");
        let header = format!(
            r#"Payment id="ch-1", realm="pops", method="cashu", intent="charge", request="{request}""#
        );
        parse_payment_params(&header).expect("parses params")
    }

    #[test]
    fn decode_charge_from_params_reads_amount_unit_mints() {
        let c = decode_charge_from_params(&params_for_charge(777)).unwrap();
        assert_eq!(c.amount, 777);
        assert_eq!(c.unit, pop_unit());
        assert_eq!(c.mints, vec![mint_a()]);
    }

    #[test]
    fn decode_charge_from_params_rejects_legacy_request_shape() {
        // The pre-spec wire carried `methodDetails.request` + `methodDetails.mints`;
        // the client parses ONLY the `paymentRequest` shape.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let legacy = URL_SAFE_NO_PAD.encode(
            br#"{"amount":"777","currency":"pop_1782668279","methodDetails":{"mints":["https://mint.example"],"request":"creqAx"}}"#,
        );
        let params = PaymentParams {
            id: "ch-1".into(),
            realm: "pops".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: legacy,
        };
        let err = decode_charge_from_params(&params).expect_err("legacy shape must not parse");
        assert_eq!(
            crate::error::from_boxed(err).code(),
            "challenge_parse_failed"
        );
    }

    #[test]
    fn decode_charge_from_params_rejects_zero_amount() {
        // A 0-sat exact charge is meaningless and must be rejected before any spend.
        let err = decode_charge_from_params(&params_for_charge(0)).unwrap_err();
        assert_eq!(
            crate::error::from_boxed(err).code(),
            "challenge_parse_failed"
        );
    }

    // ---- envelope round-trip: 402 header -> params -> request object -> credentials -

    #[test]
    fn full_envelope_roundtrip_402_to_credentials() {
        // Server: build the spec request object → WWW-Authenticate header.
        let req = CashuRequirement {
            unit: pop_unit(),
            mints: vec![mint_a()],
            amount: cdk_common::Amount::from(1234),
            payment_id: Some("ch-42".to_string()),
            description: None,
            single_use: true,
        };
        let request = encode_charge_request(&req).expect("requirement encodes");
        let header = format!(
            r#"Payment id="ch-42", realm="pops", method="cashu", intent="charge", request="{request}""#
        );

        // Client: parse params back out.
        let params = parse_payment_params(&header).expect("parses params");
        assert_eq!(params.id, "ch-42");
        assert_eq!(params.method, "cashu");

        let charge = decode_charge_from_params(&params).expect("charge decodes");
        assert_eq!(charge.amount, 1234);
        assert_eq!(charge.unit, pop_unit());
        assert_eq!(charge.mints, vec![mint_a()]);

        let creds = build_credentials(&params, "cashuBexampletoken");
        assert_eq!(creds.challenge.id, "ch-42");
        assert_eq!(creds.challenge.realm, "pops");
        assert_eq!(creds.challenge.method, "cashu");
        assert_eq!(creds.challenge.intent, "charge");
        assert_eq!(creds.challenge.request, request, "request echoed verbatim");
        assert_eq!(creds.payload.token, "cashuBexampletoken");

        // Parse the blob as the GATEWAY would (proves the wire round-trips
        // through the real verifier codec).
        let blob = encode_payment_credentials(&creds);
        let auth = format!("Payment {blob}");
        let parsed = parse_payment_authorization(&auth).expect("gateway parses our credentials");
        assert_eq!(parsed.challenge.id, "ch-42");
        assert_eq!(parsed.payload.token, "cashuBexampletoken");
    }
}
