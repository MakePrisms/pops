//! wasm-bindgen surface for `pops-core-verify` (feature `wasm`).
//!
//! Two layers cross the JS boundary here:
//!
//! 1. The **envelope codec** the TS client / extension needs — pure `serde` +
//!    `base64` + JCS, secp-free (`parse_payment_params`, `decode_request_object`,
//!    `encode_request_object`, `parse_payment_credential`,
//!    `build_payment_credential`). String-in, string-out; errors thrown as JS
//!    strings.
//!
//! 2. The **full `verify_and_redeem`**: decode + structural checks +
//!    the NUT-03 swap, with HTTP performed by the injected-`fetch`
//!    [`WasmMintClient`][crate::wasm_mint_client::WasmMintClient]. It is async
//!    (returns a `Promise`) and resolves to a structured JS object on success
//!    or REJECTS with a structured `{ ok:false, code, message }` so the JS
//!    route can map the [`ChargeError`] discriminant to an HTTP status
//!    (402 / 503 / 400).

use crate::charge::ChargeError;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::cashu_credential::CashuCredential;
use crate::redeemer::{ChargeRequirement, Redeemer};
use crate::envelope::{
    decode_request_object as core_decode_request_object, encode_payment_credentials,
    encode_request_object as core_encode_request_object, parse_payment_authorization,
    parse_payment_params as core_parse_payment_params, PaymentCredentials, RequestObject,
    PAYMENT_SCHEME,
};
use crate::wasm_mint_client::WasmMintClient;

/// Map any `Display` error to a JS exception value (a string).
fn js_err<E: core::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Parse a `WWW-Authenticate: Payment …` header (the 402 challenge the
/// client receives) into a JSON object `{id, realm, method, intent,
/// request}`. The `request` stays the raw base64url request object — decode
/// it with [`decode_request_object`].
#[wasm_bindgen]
pub fn parse_payment_params(www_authenticate: &str) -> Result<String, JsValue> {
    let params = core_parse_payment_params(www_authenticate).map_err(js_err)?;
    serde_json::to_string(&params).map_err(js_err)
}

/// Decode the base64url-nopad `request` auth-param into the JSON
/// `draft-cashu-charge-01` request object (`{amount, currency, description?,
/// externalId?, methodDetails:{request, mints}}`).
#[wasm_bindgen]
pub fn decode_request_object(b64: &str) -> Result<String, JsValue> {
    let object = core_decode_request_object(b64).map_err(js_err)?;
    serde_json::to_string(&object).map_err(js_err)
}

/// Encode a JSON `draft-cashu-charge-01` request object as the base64url-nopad
/// JCS-canonical `request="…"` auth-param value.
#[wasm_bindgen]
pub fn encode_request_object(request_object_json: &str) -> Result<String, JsValue> {
    let object: RequestObject = serde_json::from_str(request_object_json).map_err(js_err)?;
    Ok(core_encode_request_object(&object))
}

/// Parse an `Authorization: Payment <blob>` header (or a bare base64url
/// credentials blob) into a JSON [`PaymentCredentials`] object. Validates
/// the method is `cashu`.
#[wasm_bindgen]
pub fn parse_payment_credential(authorization: &str) -> Result<String, JsValue> {
    // Accept both the full `Payment <blob>` header and a bare blob.
    let trimmed = authorization.trim();
    let header_owned;
    let header = if trimmed
        .split_once(|c: char| c.is_ascii_whitespace())
        .map(|(s, _)| s.eq_ignore_ascii_case(PAYMENT_SCHEME))
        .unwrap_or(false)
    {
        trimmed
    } else {
        header_owned = format!("{PAYMENT_SCHEME} {trimmed}");
        &header_owned
    };
    let creds = parse_payment_authorization(header).map_err(js_err)?;
    serde_json::to_string(&creds).map_err(js_err)
}

/// Build the base64url-nopad credentials blob from a JSON
/// [`PaymentCredentials`] object (the inverse of
/// [`parse_payment_credential`]). Returns the bare blob — the caller
/// prepends `Payment ` to form the header value.
#[wasm_bindgen]
pub fn build_payment_credential(credentials_json: &str) -> Result<String, JsValue> {
    let creds: PaymentCredentials = serde_json::from_str(credentials_json).map_err(js_err)?;
    Ok(encode_payment_credentials(&creds))
}

/// Stable, machine-readable discriminant for a [`ChargeError`], carried as the
/// `code` field of the rejection object so the JS route can pick an HTTP status
/// without parsing prose. Values mirror the `draft-cashu-charge-01` problem-types:
/// transport → 503, verification → 402, malformed → 400/402.
fn charge_error_code(e: &ChargeError) -> &'static str {
    match e {
        ChargeError::MintUnreachable { .. } => "mint-unreachable",
        ChargeError::AmountMismatch { .. } => "amount-mismatch",
        ChargeError::WrongUnit { .. } => "wrong-unit",
        ChargeError::MintNotAllowed { .. } => "mint-not-allowed",
        ChargeError::MultiMintOrUnit => "multi-mint-or-unit",
        ChargeError::LockedToken => "locked-token",
        ChargeError::DleqInvalid => "dleq-invalid",
        ChargeError::ShortKeysetIdUnresolved { .. } => "short-keyset-id-unresolved",
        ChargeError::DoubleSpend => "double-spend",
        ChargeError::Expired => "expired",
        ChargeError::ChallengeExpired => "challenge-expired",
        ChargeError::InvalidChallenge => "invalid-challenge",
        ChargeError::MalformedCredential(_) => "malformed-credential",
        ChargeError::MalformedRequest(_) => "malformed-request",
        ChargeError::TooManyProofs { .. } => "too-many-proofs",
    }
}

/// Build the structured rejection value `{ ok:false, code, message }` for a
/// [`ChargeError`]. `code` is the stable discriminant; `message` is the
/// human-readable `Display`.
fn charge_error_to_js(e: &ChargeError) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&obj, &"ok".into(), &JsValue::FALSE);
    let _ = js_sys::Reflect::set(&obj, &"code".into(), &JsValue::from_str(charge_error_code(e)));
    let _ = js_sys::Reflect::set(&obj, &"message".into(), &JsValue::from_str(&e.to_string()));
    obj.into()
}

/// Full verify + redeem over an injected `fetch`.
///
/// `presented_token` is the holder's `cashuB…` token string; `requirement_json` is the
/// JSON form of a [`ChargeRequirement`] (`{ amount, unit, mints, payment_id,
/// description, single_use }`). Constructs a
/// [`CashuCredential<WasmMintClient>`] and runs the same decode → structural
/// checks → NUT-03 swap pipeline the native path runs, with all HTTP issued
/// via `globalThis.fetch` against the token's mint.
///
/// Returns a `Promise` that RESOLVES to
/// `{ ok:true, fresh_proofs, amount, unit, active_keyset_id, token_hash }` on
/// success, or REJECTS with `{ ok:false, code, message }` carrying the
/// [`ChargeError`] discriminant so the JS route maps 402 / 503 / 400.
///
/// A malformed `requirement_json` (server-side config error, never the holder's fault)
/// rejects with `code = "malformed-request"`.
#[wasm_bindgen]
pub fn verify_and_redeem(presented_token: &str, requirement_json: &str) -> js_sys::Promise {
    let presented_token = presented_token.to_string();
    let requirement_json = requirement_json.to_string();

    future_to_promise(async move {
        // Parse the requirement JSON. A bad requirement is server config, not a
        // payment failure → surface as MalformedRequest (the route maps it off
        // `code`, distinctly from a MalformedCredential).
        let requirement: ChargeRequirement = match serde_json::from_str(&requirement_json) {
            Ok(r) => r,
            Err(e) => {
                let err = ChargeError::MalformedRequest(format!("requirement json: {e}"));
                return Err(charge_error_to_js(&err));
            }
        };

        let cred = CashuCredential::new(WasmMintClient::new());

        match cred.verify_and_redeem(&presented_token, &requirement).await {
            Ok(redeemed) => {
                let obj = js_sys::Object::new();
                let set = |k: &str, v: &JsValue| {
                    let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(k), v);
                };
                set("ok", &JsValue::TRUE);
                set("fresh_proofs", &JsValue::from_str(&redeemed.proofs.fresh_proofs));
                // amount is u64; JS numbers are f64 — pop amounts are small, so
                // an f64 round-trips exactly. Pass as f64.
                set("amount", &JsValue::from_f64(redeemed.amount as f64));
                set("unit", &JsValue::from_str(&redeemed.unit));
                set(
                    "active_keyset_id",
                    &JsValue::from_str(&redeemed.proofs.active_keyset_id),
                );
                set("token_hash", &JsValue::from_str(&redeemed.proofs.token_hash));
                Ok(obj.into())
            }
            Err(e) => Err(charge_error_to_js(&e)),
        }
    })
}
