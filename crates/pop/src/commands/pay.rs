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

    /// Dry run: report what pay WOULD do against this URL without spending
    /// anything. The initial request IS sent (the challenge can only be obtained
    /// that way); only the payment is withheld. Token is optional under
    /// --dry-run (stdin is NOT read when no --token/--token-file is given, so
    /// the command never hangs waiting on a pipe). Exit 0 whenever the report
    /// is produced, even if would_pay is false.
    #[arg(long)]
    pub dry_run: bool,
}

/// Facts about a supplied token, extracted before any spend.
#[derive(Debug, Clone)]
pub struct TokenFacts {
    /// Total value of the token in the charge's unit.
    pub total: u64,
    /// The token's currency unit.
    pub unit: CurrencyUnit,
    /// The mint the token is from.
    pub mint: MintUrl,
}

/// A single refusal entry in the dry-run report: an existing [`PopError`] code
/// plus its structured details, surfaced as a report field rather than an error.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunRefusal {
    /// The existing contract code string (e.g. `"challenge_expired"`).
    pub code: String,
    /// The structured details matching the error variant's `details()` shape.
    pub details: serde_json::Value,
}

/// The dry-run plan for a swap.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunPlan {
    /// `"fast"` when token_total == amount (no swap needed), else `"swap"`.
    pub path: &'static str,
    /// Sats to send (always == charge amount).
    pub send: u64,
    /// Swap fee in sats (0 on the fast path).
    pub fee: u64,
    /// Change sats (token_total - amount - fee).
    pub change: u64,
}

/// The token-check section of the dry-run report (present when a token was supplied).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunTokenCheck {
    /// Always true when this struct is present (a token was supplied).
    pub supplied: bool,
    /// True iff the token's unit matches the charge.
    pub unit_ok: bool,
    /// True iff the token's mint is accepted by the charge.
    pub mint_ok: bool,
    /// True iff token_total >= amount (or amount + fee for swap).
    pub value_ok: bool,
    /// The token's total value.
    pub token_total: u64,
    /// The planned split, or null if any earlier check failed.
    pub plan: Option<DryRunPlan>,
}

/// The full dry-run report emitted when `--dry-run` is passed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunReport {
    /// Always 1. Required on every output envelope.
    pub schema_version: u64,
    /// Always true for dry-run outputs.
    pub dry_run: bool,
    /// Always false: the dry-run never pays (contract Behavior step 2).
    pub paid: bool,
    /// HTTP status of the initial response.
    pub status: u16,
    /// The URL that was probed.
    pub url: String,
    /// The decoded charge (only present on a 402).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge: Option<DryRunCharge>,
    /// True iff the challenge is fresh (present on a 402); null on a 2xx (no
    /// challenge to check).
    pub challenge_fresh: Option<bool>,
    /// True iff the charge is within --max-amount; null when --max-amount was
    /// not given (or when there is no 402 challenge).
    pub cap_ok: Option<bool>,
    /// Token validation result; null when no token was supplied.
    pub token_check: Option<DryRunTokenCheck>,
    /// True iff all checks passed and a real pay would succeed.
    pub would_pay: bool,
    /// Structured refusals that would prevent payment (non-fatal under dry-run).
    pub refusals: Vec<DryRunRefusal>,
    /// Response body (only for the 2xx case).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Charge fields surfaced in the dry-run report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DryRunCharge {
    /// Exact sat amount required.
    pub amount: u64,
    /// Unit required.
    pub unit: String,
    /// Mints accepted.
    pub mints: Vec<String>,
    /// The challenge's `expires` field verbatim, if present.
    pub expires: Option<String>,
    /// The challenge's `description`, if present.
    pub description: Option<String>,
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
        if args.dry_run {
            // Dry-run on a 2xx: resource is not payment-gated; report that and exit 0.
            // Contract Behavior step 2: include `paid: false` in the emitted shape.
            let report = DryRunReport {
                schema_version: crate::SCHEMA_VERSION,
                dry_run: true,
                paid: false,
                status: status.as_u16(),
                url: args.url.clone(),
                charge: None,
                challenge_fresh: None,
                cap_ok: None,
                token_check: None,
                would_pay: false,
                refusals: vec![],
                body: Some(body),
            };
            emit_dry_run_report(&report, json)?;
        } else {
            emit_unpaid(args, status.as_u16(), &body, json)?;
        }
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

    // ---- DRY-RUN BRANCH: decode the charge, then report what WOULD happen. ----
    // The dry-run path decodes the charge (needed for the report), then exits
    // before read_token, before any mint call that spends value. It cannot reach
    // build_exact_payment or mint_client::swap. Freshness is folded into the
    // report by evaluate_dry_run rather than returned as an error.
    if args.dry_run {
        let charge = decode_charge_from_params(&params)?;
        return run_dry_run(args, &http, &params, &charge, json).await;
    }

    // ---- PAYING PATH (dry_run == false only below this point) ----

    // A credential MUST NOT be submitted against an expired challenge
    // (framework `expires`), so check freshness FIRST — before the charge is
    // even decoded, and long before any token is read or swapped. An expired
    // challenge returns challenge_expired (exit 3); an expired+malformed
    // challenge still returns challenge_expired, matching main behavior.
    if let Some(e) = expired_challenge_error(&params, &args.url) {
        return Err(e.into());
    }

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
    let token_str = read_token_opt(args, false)?.expect("non-dry-run always returns Some");
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

/// Executes the dry-run path: report what pay WOULD do, send nothing, spend
/// nothing. Exits via emit_dry_run_report (exit 0 on success).
async fn run_dry_run(
    args: &PayArgs,
    http: &reqwest::Client,
    params: &PaymentParams,
    charge: &Charge,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the token if supplied (optional under dry-run; stdin is SKIPPED when
    // neither --token nor --token-file is given).
    let token_str_opt = read_token_opt(args, true)?;

    // Extract token facts if a token was supplied.
    let token_facts_owned: Option<TokenFacts> = match token_str_opt.as_deref() {
        Some(s) => {
            // Parse the token — a malformed token is a real error even under
            // dry-run (the caller supplied garbage).
            let token = Token::from_str(s.trim()).map_err(|e| {
                PopError::invalid_input(format!("--token is not a valid cashu token: {e}"))
            })?;
            let unit = token
                .unit()
                .ok_or_else(|| PopError::invalid_input("--token has no unit".to_string()))?;
            let mint = token.mint_url().map_err(|e| {
                PopError::invalid_input(format!("--token has no single mint url: {e}"))
            })?;
            let total = token
                .value()
                .map_err(|e| PopError::invalid_input(format!("--token value is unreadable: {e}")))?
                .to_u64();
            Some(TokenFacts { total, unit, mint })
        }
        None => None,
    };
    let token_facts = token_facts_owned.as_ref();

    // Determine fee. Contract step 6: fetch keysets ONLY when the token passed
    // unit+mint checks AND token_total > charge.amount (the swap-plan case). An
    // undervalued or mismatched token must produce its report refusal without
    // requiring mint reachability. A mint read failure is a real error (a
    // "would_pay: true" computed from a guessed fee is worse than an honest
    // transient error); the fallback unwrap_or(1) is NOT used.
    let fee_sats: u64 = if let Some(tf) = token_facts {
        let unit_ok = tf.unit == charge.unit;
        let mint_ok = charge.mints.iter().any(|m| m == &tf.mint);
        if unit_ok && mint_ok && tf.total > charge.amount {
            // Swap path: fetch keysets to compute the exact fee.
            let base = tf.mint.to_string();
            let base_trimmed = base.trim_end_matches('/');
            let keyset_infos = mint_client::fetch_keyset_infos(http, base_trimmed).await?;
            let active = mint_client::select_active_keyset(&keyset_infos, &tf.unit)?;
            // Re-parse the token to get the actual proof count for the fee.
            // A proofs() failure here means the token is malformed — same
            // invalid_input error the paying path would produce.
            let token = Token::from_str(
                token_str_opt
                    .as_deref()
                    .expect("token_facts is Some iff token_str_opt is Some"),
            )
            .map_err(|e| {
                PopError::invalid_input(format!("--token is not a valid cashu token: {e}"))
            })?;
            let n_inputs = token
                .proofs(&keyset_infos)
                .map_err(|e| {
                    PopError::invalid_input(format!("--token proofs are unreadable: {e}"))
                })?
                .len();
            swap_fee_sats(active.input_fee_ppk, n_inputs)
        } else if tf.total == charge.amount {
            // Fast path: no swap, fee is 0, no mint call needed.
            0u64
        } else {
            // Unit/mint mismatch or undervalued token: no mint call needed; the
            // refusal will be reported by evaluate_dry_run without a fee.
            0u64
        }
    } else {
        // No token supplied: no mint call needed.
        0u64
    };

    let report = evaluate_dry_run(
        &args.url,
        charge,
        params,
        args.max_amount,
        token_facts,
        fee_sats,
    );
    emit_dry_run_report(&report, json)?;
    Ok(())
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
        // Non-2xx after the token was sent. A 4xx is a determinate rejection
        // (did NOT redeem → both tokens unspent); a 5xx can follow a
        // SUCCESSFUL swap (persist/upstream failure after settlement), so the
        // send token's state is unknown. The error's message branches on the
        // status; both tokens are surfaced either way.
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

    // POST-SWAP: the inputs are SPENT, so the freshly-minted ecash exists only as
    // these proofs/strings. Pre-serialize both to raw JSON BEFORE the assertion so
    // a failed assertion can carry them — never silent value loss.
    let send_proofs_json = proofs_to_json(&send_proofs);
    let change_proofs_json = change_proofs.as_ref().map(proofs_to_json);

    // HARD ASSERTION: the send set must sum to EXACTLY the charge.
    // POST-SWAP: inputs are already spent, so a failure here MUST carry the
    // minted proofs or the value is silently lost. Pre-serialize first (above).
    let send_sum = proofs_value(&send_proofs);
    if send_sum != charge.amount {
        return Err(PopError::TokenEncodeFailed {
            reason: format!(
                "POST-SWAP exact-amount assertion failed: send set summed to {send_sum}, \
                 not the required {} (inputs already spent; raw proofs preserved)",
                charge.amount
            ),
            send_proofs_json: Some(send_proofs_json.clone()),
            change_proofs_json: change_proofs_json.clone(),
        }
        .into());
    }

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

/// The expired-challenge refusal, when the 402's `expires` forbids paying it:
/// a challenge whose RFC 3339 `expires` is in the past (or unparseable, which
/// equally fails to establish freshness) MUST NOT have a credential submitted
/// against it — the server would only answer `payment-expired` after the
/// client did the work. A challenge without `expires` carries no expiry
/// signal and proceeds.
pub fn expired_challenge_error(params: &PaymentParams, url: &str) -> Option<PopError> {
    let expires = params.expires.as_deref()?;
    let is_past = match chrono::DateTime::parse_from_rfc3339(expires) {
        Ok(ts) => ts.with_timezone(&chrono::Utc) <= chrono::Utc::now(),
        Err(_) => true,
    };
    is_past.then(|| PopError::ChallengeExpired {
        url: url.to_string(),
        expires: expires.to_string(),
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

/// Evaluates a dry-run report from pure inputs (no network calls, no side
/// effects). Refusal evaluation converts pay-path errors into report entries
/// rather than process errors, so the dry-run answers "what would happen" in
/// one shot. `fee_sats` is 0 on the fast path (token_total == amount) or when
/// no token is supplied; the caller returns a real Err for any keyset fetch
/// failure before invoking this.
///
/// This function is pure and unit-testable.
pub fn evaluate_dry_run(
    url: &str,
    charge: &Charge,
    params: &PaymentParams,
    cap: Option<u64>,
    token_facts: Option<&TokenFacts>,
    fee_sats: u64,
) -> DryRunReport {
    let mut refusals: Vec<DryRunRefusal> = Vec::new();
    let mut would_pay = true;

    // Check challenge freshness (already done before this is called via
    // expired_challenge_error; here we record it as a report field).
    let challenge_fresh = match expired_challenge_error(params, url) {
        Some(e) => {
            would_pay = false;
            let d = e.details().unwrap_or(serde_json::json!({}));
            refusals.push(DryRunRefusal {
                code: e.code().to_string(),
                details: d,
            });
            false
        }
        None => true,
    };

    // Cap check.
    let cap_ok: Option<bool> = cap.map(|c| {
        if charge.amount > c {
            would_pay = false;
            let e = PopError::AmountExceedsCap {
                amount: charge.amount,
                cap: c,
            };
            refusals.push(DryRunRefusal {
                code: e.code().to_string(),
                details: e.details().unwrap_or(serde_json::json!({})),
            });
            false
        } else {
            true
        }
    });

    // Token check.
    let token_check = token_facts.map(|tf| {
        let unit_ok = tf.unit == charge.unit;
        let mint_ok = charge.mints.iter().any(|m| m == &tf.mint);
        let value_ok_basic = tf.total >= charge.amount;

        if !unit_ok {
            would_pay = false;
            let e = PopError::TokenUnitMismatch {
                required: charge.unit.to_string(),
                got: tf.unit.to_string(),
            };
            refusals.push(DryRunRefusal {
                code: e.code().to_string(),
                details: e.details().unwrap_or(serde_json::json!({})),
            });
        }
        if !mint_ok {
            would_pay = false;
            let e = PopError::TokenMintMismatch {
                token_mint: tf.mint.to_string(),
                accepted_mints: charge.mints.iter().map(ToString::to_string).collect(),
            };
            refusals.push(DryRunRefusal {
                code: e.code().to_string(),
                details: e.details().unwrap_or(serde_json::json!({})),
            });
        }

        // Plan the split (only when unit+mint are ok).
        let plan = if unit_ok && mint_ok {
            if tf.total == charge.amount {
                // Fast path: no swap needed.
                if value_ok_basic {
                    Some(DryRunPlan {
                        path: "fast",
                        send: charge.amount,
                        fee: 0,
                        change: 0,
                    })
                } else {
                    None
                }
            } else {
                // Swap path: check value covers amount + fee.
                match plan_split(tf.total, charge.amount, fee_sats) {
                    Ok(split) => Some(DryRunPlan {
                        path: "swap",
                        send: split.send,
                        fee: fee_sats,
                        change: split.change,
                    }),
                    Err(e) => {
                        would_pay = false;
                        let pe = crate::error::from_boxed(e);
                        refusals.push(DryRunRefusal {
                            code: pe.code().to_string(),
                            details: pe.details().unwrap_or(serde_json::json!({})),
                        });
                        None
                    }
                }
            }
        } else {
            None
        };

        // value_ok: true iff the token would cover the charge (+ fee if swap).
        let value_ok = plan.is_some()
            || (unit_ok
                && mint_ok
                && tf.total >= charge.amount
                && (tf.total == charge.amount
                    || tf.total >= charge.amount.saturating_add(fee_sats)));

        if unit_ok && mint_ok && !value_ok && plan.is_none() {
            // Only add a refusal if we haven't already added one above.
            let already_refused = refusals
                .iter()
                .any(|r| r.code == "insufficient_token_value");
            if !already_refused {
                would_pay = false;
                let e = PopError::InsufficientTokenValue {
                    have: tf.total,
                    need: charge.amount.saturating_add(fee_sats),
                };
                refusals.push(DryRunRefusal {
                    code: e.code().to_string(),
                    details: e.details().unwrap_or(serde_json::json!({})),
                });
            }
        }

        DryRunTokenCheck {
            supplied: true,
            unit_ok,
            mint_ok,
            value_ok,
            token_total: tf.total,
            plan,
        }
    });

    // No token supplied: would_pay = false (absence is not a refusal).
    if token_check.is_none() {
        would_pay = false;
    }

    DryRunReport {
        schema_version: crate::SCHEMA_VERSION,
        dry_run: true,
        paid: false,
        status: 402,
        url: url.to_string(),
        charge: Some(DryRunCharge {
            amount: charge.amount,
            unit: charge.unit.to_string(),
            mints: charge.mints.iter().map(ToString::to_string).collect(),
            expires: params.expires.clone(),
            description: params.description.clone(),
        }),
        challenge_fresh: Some(challenge_fresh),
        cap_ok,
        token_check,
        would_pay,
        refusals,
        body: None,
    }
}

/// Emits a dry-run report to stdout (JSON) or stdout (human).
fn emit_dry_run_report(
    report: &DryRunReport,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        // Human-readable rendering to STDOUT (a successful diagnosis, exit 0).
        println!("DRY RUN: {}", report.url);
        println!("  status: {}", report.status);
        if let Some(charge) = &report.charge {
            println!(
                "  charge: {} sat of {} (mints: {})",
                charge.amount,
                charge.unit,
                if charge.mints.is_empty() {
                    "<none>".to_string()
                } else {
                    charge.mints.join(", ")
                }
            );
            if let Some(exp) = &charge.expires {
                println!("  expires: {exp}");
            }
        }
        if let Some(fresh) = report.challenge_fresh {
            println!("  challenge fresh: {fresh}");
        }
        if let Some(cap_ok) = report.cap_ok {
            println!("  cap ok: {cap_ok}");
        }
        if let Some(tc) = &report.token_check {
            println!("  token_total: {}", tc.token_total);
            println!("  unit ok: {}", tc.unit_ok);
            println!("  mint ok: {}", tc.mint_ok);
            println!("  value ok: {}", tc.value_ok);
            if let Some(plan) = &tc.plan {
                println!(
                    "  plan: {} path, send {}, fee {}, change {}",
                    plan.path, plan.send, plan.fee, plan.change
                );
            }
        } else {
            println!("  token: not supplied");
        }
        if !report.refusals.is_empty() {
            println!("  refusals:");
            for r in &report.refusals {
                println!("    {}: {}", r.code, r.details);
            }
        }
        println!(
            "  WOULD PAY: {}",
            if report.would_pay { "yes" } else { "no" }
        );
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

/// Builds the `Authorization: Payment` credentials: a VERBATIM echo of EVERY
/// parsed challenge param — required and optional alike — plus the
/// exact-amount token as the cashu payload. The server's stateless binding
/// recomputes its id-HMAC over the echo, so a dropped or altered param
/// (`expires` included) makes the credential `invalid-challenge`; an optional
/// the 402 did not carry stays absent. `source` is `None` (bearer tokens carry
/// no payer identity).
pub fn build_credentials(params: &PaymentParams, token: &str) -> PaymentCredentials {
    PaymentCredentials {
        challenge: EchoedChallenge {
            id: params.id.clone(),
            realm: params.realm.clone(),
            method: params.method.clone(),
            intent: params.intent.clone(),
            request: params.request.clone(),
            digest: params.digest.clone(),
            opaque: params.opaque.clone(),
            expires: params.expires.clone(),
            description: params.description.clone(),
        },
        payload: CashuPayload {
            token: token.to_string(),
        },
        source: None,
    }
}

/// Reads the `cashuB` token from `--token`, else `--token-file`, else stdin.
///
/// When `dry_run == true` and neither `--token` nor `--token-file` is given,
/// returns `Ok(None)` WITHOUT touching stdin (a dry-run must never hang an
/// agent waiting on a pipe). When `dry_run == false`, behavior is byte-identical
/// to the paying path: precedence token, then token-file, then stdin; the same
/// `invalid_input` errors for unreadable file, stdin read failure, and empty
/// stdin. A present-but-unreadable `--token-file` is always a real error.
pub fn read_token_opt(
    args: &PayArgs,
    dry_run: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(t) = &args.token {
        return Ok(Some(t.clone()));
    }
    if let Some(path) = &args.token_file {
        return std::fs::read_to_string(path).map(Some).map_err(|e| {
            PopError::invalid_input(format!(
                "failed to read --token-file {}: {e}",
                path.display()
            ))
            .into()
        });
    }
    // Neither --token nor --token-file was given.
    if dry_run {
        // Skip stdin: a dry-run must never hang an agent waiting on a pipe.
        return Ok(None);
    }
    // Paying path: read from stdin (byte-identical to prior behavior).
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
    Ok(Some(buf))
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
        assert!(validate_token(600, &pop_unit(), &mint_a(), &charge(600)).is_ok());
        // exact
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

    // ---- the expired-challenge refusal (no credential against a past expires) -

    /// Params carrying the supplied `expires` (other fields don't matter to
    /// the freshness check).
    fn params_with_expires(expires: Option<&str>) -> PaymentParams {
        PaymentParams {
            id: "ch-1".into(),
            realm: "pops".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "cmVxdWVzdA".into(),
            expires: expires.map(str::to_string),
            digest: None,
            opaque: None,
            description: None,
        }
    }

    #[test]
    fn expired_challenge_is_refused_before_any_spend() {
        let err = expired_challenge_error(
            &params_with_expires(Some("2020-01-01T00:00:00Z")),
            "https://app.example/r",
        )
        .expect("a past expires must refuse");
        assert_eq!(err.code(), "challenge_expired");
        let d = err.details().expect("details required");
        assert_eq!(d["url"], serde_json::json!("https://app.example/r"));
        assert_eq!(d["expires"], serde_json::json!("2020-01-01T00:00:00Z"));
        assert!(
            !err.retriable(),
            "re-fetch the challenge, don't retry as-is"
        );
    }

    #[test]
    fn fresh_challenge_passes_the_expiry_check() {
        assert!(
            expired_challenge_error(
                &params_with_expires(Some("2999-01-01T00:00:00Z")),
                "https://app.example/r",
            )
            .is_none(),
            "a future expires must proceed"
        );
    }

    #[test]
    fn challenge_without_expires_passes_the_expiry_check() {
        assert!(
            expired_challenge_error(&params_with_expires(None), "https://app.example/r").is_none(),
            "no expires ⇒ no expiry signal to refuse on"
        );
    }

    #[test]
    fn unparseable_expires_is_refused_like_a_past_one() {
        let err = expired_challenge_error(
            &params_with_expires(Some("not-a-timestamp")),
            "https://app.example/r",
        )
        .expect("freshness cannot be established ⇒ refuse");
        assert_eq!(err.code(), "challenge_expired");
        assert_eq!(
            err.details().expect("details")["expires"],
            serde_json::json!("not-a-timestamp"),
            "the verbatim value is surfaced for diagnosis"
        );
    }

    // ---- request-object decode (the client's 402 parse surface) ----------

    /// Build the parsed `PaymentParams` for a charge of `amount`, as the client
    /// sees them off a 402 carrying the spec request object.
    fn params_for_charge(amount: u64) -> PaymentParams {
        let req = CashuRequirement {
            unit: pop_unit(),
            mints: vec![mint_a()],
            amount: cdk_common::Amount::from(amount),
            external_id: Some("ch-1".to_string()),
            description: None,
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
            expires: None,
            digest: None,
            opaque: None,
            description: None,
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
            external_id: Some("ch-42".to_string()),
            description: None,
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

    #[test]
    fn build_credentials_echoes_every_issued_optional_param_verbatim() {
        // A stateless-binding server recomputes its id-HMAC over the echo, so
        // the client MUST return every issued param byte-for-byte — expires
        // above all (a dropped expires makes the credential invalid-challenge).
        let header = r#"Payment id="hmacid", realm="pops", method="cashu", intent="charge", request="cmVxdWVzdA", expires="2026-03-15T12:05:00Z", digest="sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", opaque="b3BhcXVl", description="weather report""#;
        let params = parse_payment_params(header).expect("parses params");
        let creds = build_credentials(&params, "cashuBtok");
        assert_eq!(
            creds.challenge.expires.as_deref(),
            Some("2026-03-15T12:05:00Z")
        );
        assert_eq!(
            creds.challenge.digest.as_deref(),
            Some("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
        );
        assert_eq!(creds.challenge.opaque.as_deref(), Some("b3BhcXVl"));
        assert_eq!(
            creds.challenge.description.as_deref(),
            Some("weather report")
        );

        // And an optional the 402 did NOT carry stays absent (an invented one
        // would equally break the byte-exact echo).
        let bare = r#"Payment id="hmacid", realm="pops", method="cashu", intent="charge", request="cmVxdWVzdA""#;
        let creds = build_credentials(&parse_payment_params(bare).expect("parses"), "cashuBtok");
        assert_eq!(creds.challenge.expires, None);
        assert_eq!(creds.challenge.digest, None);
        assert_eq!(creds.challenge.opaque, None);
        assert_eq!(creds.challenge.description, None);
    }

    // ---- Part 2: dry-run report builder ----------------------------------

    fn tf(total: u64) -> TokenFacts {
        TokenFacts {
            total,
            unit: pop_unit(),
            mint: mint_a(),
        }
    }

    /// No token supplied: would_pay false, token_check null, no refusals.
    #[test]
    fn dry_run_no_token_would_pay_false_no_refusals() {
        let params = params_for_charge(600);
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, None, None, 0);
        assert!(!report.would_pay);
        assert!(report.token_check.is_none());
        assert!(
            report.refusals.is_empty(),
            "absence of token is not a refusal"
        );
        assert_eq!(report.schema_version, crate::SCHEMA_VERSION);
        assert!(report.dry_run);
        assert_eq!(report.status, 402);
    }

    /// Fast path (token == amount): plan shows fast, fee 0, change 0.
    #[test]
    fn dry_run_fast_path_plan() {
        let params = params_for_charge(600);
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(600)), 0);
        assert!(report.would_pay, "exact match should would_pay");
        let tc = report.token_check.unwrap();
        let plan = tc.plan.unwrap();
        assert_eq!(plan.path, "fast");
        assert_eq!(plan.send, 600);
        assert_eq!(plan.fee, 0);
        assert_eq!(plan.change, 0);
        assert!(report.refusals.is_empty());
    }

    /// Swap path (token > amount): plan shows swap, correct send/fee/change.
    #[test]
    fn dry_run_swap_path_plan() {
        let params = params_for_charge(600);
        let c = charge(600);
        // fee = 3, total = 1000 => change = 1000 - 600 - 3 = 397
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(1000)), 3);
        assert!(report.would_pay);
        let tc = report.token_check.unwrap();
        let plan = tc.plan.unwrap();
        assert_eq!(plan.path, "swap");
        assert_eq!(plan.send, 600);
        assert_eq!(plan.fee, 3);
        assert_eq!(plan.change, 397);
        assert!(report.refusals.is_empty());
    }

    /// Expired challenge becomes a refusal (not an error); would_pay false.
    #[test]
    fn dry_run_expired_challenge_is_refusal() {
        let params = params_with_expires(Some("2020-01-01T00:00:00Z"));
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(600)), 0);
        assert!(!report.would_pay);
        assert_eq!(report.challenge_fresh, Some(false));
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == "challenge_expired"),
            "expected challenge_expired refusal"
        );
    }

    /// Cap exceeded becomes a refusal; would_pay false.
    #[test]
    fn dry_run_cap_exceeded_is_refusal() {
        let params = params_for_charge(600);
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, Some(500), Some(&tf(600)), 0);
        assert!(!report.would_pay);
        assert_eq!(report.cap_ok, Some(false));
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == "amount_exceeds_cap"),
            "expected amount_exceeds_cap refusal"
        );
    }

    /// Unit mismatch becomes a refusal.
    #[test]
    fn dry_run_unit_mismatch_is_refusal() {
        let params = params_for_charge(600);
        let c = charge(600);
        let bad_tf = TokenFacts {
            total: 1000,
            unit: CurrencyUnit::Custom("pop_9999999999".to_string()),
            mint: mint_a(),
        };
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&bad_tf), 0);
        assert!(!report.would_pay);
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == "token_unit_mismatch"),
            "expected token_unit_mismatch refusal"
        );
        let tc = report.token_check.unwrap();
        assert!(!tc.unit_ok);
    }

    /// Mint mismatch becomes a refusal.
    #[test]
    fn dry_run_mint_mismatch_is_refusal() {
        let params = params_for_charge(600);
        let c = charge(600);
        let bad_tf = TokenFacts {
            total: 1000,
            unit: pop_unit(),
            mint: MintUrl::from_str("https://other.example").unwrap(),
        };
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&bad_tf), 0);
        assert!(!report.would_pay);
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == "token_mint_mismatch"),
            "expected token_mint_mismatch refusal"
        );
        let tc = report.token_check.unwrap();
        assert!(!tc.mint_ok);
    }

    /// Insufficient value (after fee) becomes a refusal.
    #[test]
    fn dry_run_insufficient_value_is_refusal() {
        let params = params_for_charge(600);
        let c = charge(600);
        // Token has 601 sats (> amount, so swap path), but fee=3 means
        // need 600 + 3 = 603, and 601 < 603 => insufficient.
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(601)), 3);
        assert!(!report.would_pay);
        assert!(
            report
                .refusals
                .iter()
                .any(|r| r.code == "insufficient_token_value"),
            "expected insufficient_token_value refusal"
        );
    }

    /// Refusal details match the corresponding PopError::details() shape.
    #[test]
    fn dry_run_refusal_details_match_pop_error_details() {
        // Cap exceeded: details should match PopError::AmountExceedsCap{}.details().
        let params = params_for_charge(600);
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, Some(500), Some(&tf(600)), 0);
        let refusal = report
            .refusals
            .iter()
            .find(|r| r.code == "amount_exceeds_cap")
            .unwrap();
        let expected = PopError::AmountExceedsCap {
            amount: 600,
            cap: 500,
        }
        .details()
        .unwrap();
        assert_eq!(
            refusal.details, expected,
            "refusal details must match PopError::details()"
        );

        // Token unit mismatch.
        let bad_tf = TokenFacts {
            total: 1000,
            unit: CurrencyUnit::Custom("pop_9999".to_string()),
            mint: mint_a(),
        };
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&bad_tf), 0);
        let refusal = report
            .refusals
            .iter()
            .find(|r| r.code == "token_unit_mismatch")
            .unwrap();
        let expected = PopError::TokenUnitMismatch {
            required: pop_unit().to_string(),
            got: "pop_9999".to_string(),
        }
        .details()
        .unwrap();
        assert_eq!(
            refusal.details, expected,
            "unit mismatch details must match"
        );
    }

    // ---- F1: 2xx dry-run emits paid:false (contract Behavior step 2) --------

    /// The 2xx dry-run report struct has `paid: false` present and serialises it.
    #[test]
    fn dry_run_2xx_report_includes_paid_false() {
        // Build the 2xx report shape exactly as run() does.
        let report = DryRunReport {
            schema_version: crate::SCHEMA_VERSION,
            dry_run: true,
            paid: false,
            status: 200,
            url: "https://app/r".to_string(),
            charge: None,
            challenge_fresh: None,
            cap_ok: None,
            token_check: None,
            would_pay: false,
            refusals: vec![],
            body: Some("ok".to_string()),
        };
        assert!(!report.paid, "paid must be false in dry-run 2xx");
        // Serialise and verify the key is present in JSON output.
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["paid"],
            serde_json::json!(false),
            "paid: false must appear in the serialised shape"
        );
        assert_eq!(json["dry_run"], serde_json::json!(true));
        assert_eq!(json["status"], serde_json::json!(200));
    }

    // ---- F1: 402 dry-run report also has paid:false -------------------------

    /// The 402 dry-run report from evaluate_dry_run carries paid: false.
    #[test]
    fn dry_run_402_report_includes_paid_false() {
        let params = params_for_charge(600);
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(600)), 0);
        assert!(!report.paid, "paid must be false in dry-run 402 report");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["paid"],
            serde_json::json!(false),
            "paid: false must appear in the serialised 402 dry-run shape"
        );
    }

    // ---- F4: undervalued token gets refusal without mint call ---------------

    /// An undervalued token (total < amount) gets insufficient_token_value refusal
    /// without any keyset/mint fetch (the caller supplies fee=0 for this case).
    #[test]
    fn dry_run_undervalued_token_is_refusal_no_mint_needed() {
        let params = params_for_charge(600);
        let c = charge(600);
        // Token has 500 sats, charge is 600: undervalued, fast-path (total < amount).
        // evaluate_dry_run must produce the refusal with fee_sats=0 (no mint needed).
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(500)), 0);
        assert!(!report.would_pay);
        let refusal = report
            .refusals
            .iter()
            .find(|r| r.code == "insufficient_token_value")
            .expect("undervalued token must produce insufficient_token_value refusal");
        // Details must match PopError::InsufficientTokenValue directly.
        let expected = PopError::InsufficientTokenValue {
            have: 500,
            need: 600,
        }
        .details()
        .unwrap();
        assert_eq!(
            refusal.details, expected,
            "refusal details must match PopError::InsufficientTokenValue details"
        );
        let tc = report.token_check.unwrap();
        assert!(!tc.value_ok, "value_ok must be false for undervalued token");
    }

    /// cap_ok is null when --max-amount was not given.
    #[test]
    fn dry_run_cap_ok_null_when_no_max_amount() {
        let params = params_for_charge(600);
        let c = charge(600);
        let report = evaluate_dry_run("https://app/r", &c, &params, None, Some(&tf(600)), 0);
        assert_eq!(
            report.cap_ok, None,
            "cap_ok must be null when no --max-amount"
        );
    }

    /// read_token_opt: dry_run + no flags returns Ok(None).
    #[test]
    fn read_token_opt_dry_run_no_flags_returns_none() {
        let args = PayArgs {
            url: "https://app/r".to_string(),
            token: None,
            token_file: None,
            method: "GET".to_string(),
            max_amount: None,
            dry_run: true,
        };
        let result = read_token_opt(&args, true).unwrap();
        assert!(
            result.is_none(),
            "dry_run with no token flags must return None"
        );
    }

    /// read_token_opt: dry_run + --token returns Some.
    #[test]
    fn read_token_opt_dry_run_with_token_flag_returns_some() {
        let args = PayArgs {
            url: "https://app/r".to_string(),
            token: Some("cashuBfoo".to_string()),
            token_file: None,
            method: "GET".to_string(),
            max_amount: None,
            dry_run: true,
        };
        let result = read_token_opt(&args, true).unwrap();
        assert_eq!(result, Some("cashuBfoo".to_string()));
    }

    /// read_token_opt: dry_run + unreadable --token-file returns invalid_input Err.
    #[test]
    fn read_token_opt_dry_run_unreadable_token_file_is_error() {
        let args = PayArgs {
            url: "https://app/r".to_string(),
            token: None,
            token_file: Some(std::path::PathBuf::from("/nonexistent/file.token")),
            method: "GET".to_string(),
            max_amount: None,
            dry_run: true,
        };
        let err = read_token_opt(&args, true).unwrap_err();
        assert_eq!(
            crate::error::from_boxed(err).code(),
            "invalid_input",
            "unreadable token-file must be invalid_input even under dry-run"
        );
    }

    // ---- Part 3: post-swap assertion value-loss fix ----------------------

    /// A TokenEncodeFailed built with the post-swap-assertion reason carries
    /// both proof JSONs and maps to exit 6 (value at risk).
    #[test]
    fn post_swap_assertion_failure_is_token_bearing_and_exit_6() {
        let e = PopError::TokenEncodeFailed {
            reason: "POST-SWAP exact-amount assertion failed: send set summed to 601, \
                     not the required 600 (inputs already spent; raw proofs preserved)"
                .to_string(),
            send_proofs_json: Some(r#"[{"amount":600}]"#.to_string()),
            change_proofs_json: Some(r#"[{"amount":400}]"#.to_string()),
        };
        // Must be token-bearing (carries proofs).
        assert!(
            e.recovery_proofs_json().is_some(),
            "post-swap assertion failure must be token-bearing"
        );
        // Must map to exit 6.
        assert_eq!(
            e.exit_code(),
            6,
            "token-bearing errors must be exit 6 (VALUE AT RISK)"
        );
        // Details must carry both proof sets.
        let d = e.details().unwrap();
        assert!(
            d.get("send_proofs").is_some(),
            "send_proofs must be in details"
        );
        assert!(
            d.get("change_proofs").is_some(),
            "change_proofs must be in details"
        );
    }

    /// The FAST-PATH assertion (inputs NOT spent) still fires as
    /// exact_amount_assertion_failed (exit 5, NOT token-bearing).
    #[test]
    fn fast_path_assertion_stays_exact_amount_assertion_failed_exit_5() {
        let err = assert_send_is_exact(601, 600).unwrap_err();
        let pe = crate::error::from_boxed(err);
        assert_eq!(pe.code(), "exact_amount_assertion_failed");
        // Not token-bearing.
        assert!(pe.recovery_tokens().is_none());
        assert!(pe.recovery_proofs_json().is_none());
        // Exit 5.
        assert_eq!(pe.exit_code(), 5);
    }
}
