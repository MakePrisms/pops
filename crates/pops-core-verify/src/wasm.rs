//! wasm-bindgen surface for `pops-core-verify` (feature `wasm`).
//!
//! STEP 1 scope: the **envelope codec** the TS client / extension needs —
//! pure `serde` + `base64`, secp-free, guaranteed-wasm. None of these touch
//! `cashu`, so the wasm build stays lean and cannot pull the heavy crypto.
//!
//! All exports speak JSON strings at the boundary (no `serde-wasm-bindgen`
//! dependency): inputs/outputs that carry structure are JSON, errors are
//! thrown as JS strings.
//!
//! The full `verify_and_redeem` (decode + structural checks + the NUT-03
//! swap over an injected `fetch`) is **Step 2's** de-risk — the export is
//! present here as a STUB so Step 2 only fills the body.

use wasm_bindgen::prelude::*;

use crate::envelope::{
    decode_request_envelope as core_decode_request_envelope, encode_payment_credentials,
    encode_request_envelope as core_encode_request_envelope, parse_payment_authorization,
    parse_payment_params as core_parse_payment_params, PaymentCredentials, PAYMENT_SCHEME,
};

/// Map any `Display` error to a JS exception value (a string).
fn js_err<E: core::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Parse a `WWW-Authenticate: Payment …` header (the 402 challenge the
/// client receives) into a JSON object `{id, realm, method, intent,
/// request}`. The `request` stays the raw base64url envelope — unwrap it
/// with [`decode_request_envelope`].
#[wasm_bindgen]
pub fn parse_payment_params(www_authenticate: &str) -> Result<String, JsValue> {
    let params = core_parse_payment_params(www_authenticate).map_err(js_err)?;
    serde_json::to_string(&params).map_err(js_err)
}

/// Unwrap the base64url-nopad `request` envelope and return the inner
/// `creqA…` payment-request string.
#[wasm_bindgen]
pub fn decode_request_envelope(b64: &str) -> Result<String, JsValue> {
    core_decode_request_envelope(b64).map_err(js_err)
}

/// Wrap a `creqA…` string in the `request` envelope and base64url-nopad
/// encode it (what goes inside `request="…"` of `WWW-Authenticate:
/// Payment`). Infallible.
#[wasm_bindgen]
pub fn encode_request_envelope(creq_a: &str) -> String {
    core_encode_request_envelope(creq_a)
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

/// STEP 2 STUB. The full verify+redeem (structural checks + the NUT-03 swap
/// over an injected `fetch`) lands in Step 2; in Step 1 this export exists
/// only so the Step-2 body can drop in without changing the surface. Calling
/// it always errors.
#[wasm_bindgen]
pub fn verify_and_redeem(_presented: &str, _req_json: &str) -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "verify_and_redeem is not implemented in Step 1 (envelope-only wasm surface); \
         the full swap-over-fetch path lands in Step 2",
    ))
}
