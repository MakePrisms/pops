//! Cashu-free codec for the `Payment` auth-scheme: the request envelope
//! (`WWW-Authenticate` side) and the credentials envelope (`Authorization`
//! side).
//!
//! This module is the WASM-targetable layer — it touches no `cashu` types,
//! only `serde` + `base64`. It folds together the former `auth_header`
//! (credentials parsing) and the wrap/unwrap half of the former `challenge`
//! (the `request` envelope around a `creqA…` string).
//!
//! ## Credentials envelope (`Authorization: Payment <credentials>`)
//!
//! The retry credentials are a single opaque token: `auth-scheme` =
//! `Payment` followed by a base64url-nopad-encoded JSON object:
//!
//! ```json
//! {
//!   "challenge": {
//!     "id":      "<echo of WWW-Authenticate id>",
//!     "realm":   "<echo of realm>",
//!     "method":  "<echo of method, e.g. \"cashu\">",
//!     "intent":  "<echo of intent, e.g. \"charge\">",
//!     "request": "<echo of request param>"
//!   },
//!   "payload": { "cashu_token": "cashuB..." }
//! }
//! ```
//!
//! Required fields are honoured; optional fields (`source`, `description`,
//! `opaque`, `digest`, `expires`) are tolerated on the wire but ignored.
//!
//! ## Request envelope (`WWW-Authenticate: Payment … request="…"`)
//!
//! The `request` auth-param is a base64url-nopad-encoded JSON blob wrapping
//! the `creqA…` payment-request under a single `cashu_request` field.
//! [`encode_request_envelope`] does the wrap; [`decode_request_envelope`]
//! unwraps it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::Error;

/// HTTP auth-scheme for the Payment Authentication envelope. Matched
/// case-insensitively.
pub const PAYMENT_SCHEME: &str = "Payment";

/// Required value for the `method` field on the echoed challenge. The
/// wire value is lowercase ASCII, so this comparison is case-sensitive.
pub const CASHU_METHOD: &str = "cashu";

/// Echo of the `WWW-Authenticate` auth-params the client round-trips
/// from the 402.
///
/// All required fields are deserialized; optional fields
/// (`description`, `opaque`, `digest`, `expires`) are accepted but not
/// surfaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoedChallenge {
    /// Echo of the server-issued challenge id.
    pub id: String,
    /// Echo of the protection-space realm.
    pub realm: String,
    /// Echo of the payment method (we require `"cashu"`).
    pub method: String,
    /// Echo of the payment intent (we emit `"charge"`).
    pub intent: String,
    /// Echo of the base64url-encoded method-specific request blob.
    pub request: String,
}

/// Cashu-method `payload`: the data needed to complete the challenge.
///
/// For cashu this is the `cashuB…` token the holder mints from the issuer.
/// The token's structural validation (prefix, base64, CBOR, proof shape) is
/// the validator's job; this struct just carries the string out of the JSON
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuPayload {
    /// The `cashuB…` token string. Forwarded as-is to
    /// [`crate::challenge::decode_token`].
    pub cashu_token: String,
}

/// Full credentials object.
///
/// `challenge` and `payload` are required; `source` and any other extra
/// fields are tolerated and ignored, so a `source` a client sends
/// round-trips silently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredentials {
    /// Echo of the WWW-Authenticate auth-params.
    pub challenge: EchoedChallenge,
    /// Method-specific payload (cashu = `{ "cashu_token": "..." }`).
    pub payload: CashuPayload,
}

/// Why an `Authorization: Payment <blob>` header failed to parse.
///
/// Every variant maps to a 402 re-challenge in the middleware; they are
/// distinct enums only to make the response body intelligible to the
/// client.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthParseError {
    /// First whitespace-separated token is not `Payment`.
    #[error("auth scheme is not 'Payment'")]
    UnknownScheme,

    /// `Payment` scheme present but no credentials blob follows.
    #[error("Payment header missing credentials blob")]
    MissingCredentials,

    /// Credentials blob is not valid base64url-nopad.
    #[error("Payment credentials are not valid base64url-nopad: {0}")]
    Base64Decode(String),

    /// Base64-decoded bytes are not valid UTF-8 (so cannot be JSON).
    #[error("Payment credentials are not valid UTF-8: {0}")]
    Utf8Decode(String),

    /// JSON does not parse, or required fields are missing/of the wrong
    /// shape.
    #[error("Payment credentials JSON is malformed: {0}")]
    JsonParse(String),

    /// `challenge.method` is present but is not `"cashu"`.
    #[error("Payment method must be 'cashu', got {0:?}")]
    WrongMethod(String),
}

/// Parse an `Authorization: Payment <base64url-nopad-blob>` header and
/// return the structured credentials.
///
/// On success the caller still needs to:
/// 1. Validate that `credentials.challenge.method == "cashu"` —
///    `WrongMethod` is surfaced here for any other value.
/// 2. Decode `credentials.payload.cashu_token` via
///    [`crate::challenge::decode_token`].
pub fn parse_payment_authorization(
    header_value: &str,
) -> Result<PaymentCredentials, AuthParseError> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(AuthParseError::UnknownScheme);
    }

    // Split scheme off the first whitespace run; at least one space
    // separates scheme from credentials.
    let (scheme, rest) = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((s, r)) => (s, r.trim()),
        None => (trimmed, ""),
    };

    if !scheme.eq_ignore_ascii_case(PAYMENT_SCHEME) {
        return Err(AuthParseError::UnknownScheme);
    }

    if rest.is_empty() {
        return Err(AuthParseError::MissingCredentials);
    }

    // The credentials blob is base64url without padding. Anything else
    // (including a legacy key=value param form) trips up the base64
    // decoder and is rejected.
    let bytes = URL_SAFE_NO_PAD
        .decode(rest)
        .map_err(|e| AuthParseError::Base64Decode(e.to_string()))?;

    let json = std::str::from_utf8(&bytes)
        .map_err(|e| AuthParseError::Utf8Decode(e.to_string()))?;

    let credentials: PaymentCredentials = serde_json::from_str(json)
        .map_err(|e| AuthParseError::JsonParse(e.to_string()))?;

    if credentials.challenge.method != CASHU_METHOD {
        return Err(AuthParseError::WrongMethod(
            credentials.challenge.method.clone(),
        ));
    }

    Ok(credentials)
}

/// Helper for tests + downstream consumers: build a credentials blob
/// (the inverse of [`parse_payment_authorization`]).
///
/// Returns the bare base64url-nopad string — the caller is responsible
/// for prepending `Payment ` to form the full header value.
pub fn encode_payment_credentials(credentials: &PaymentCredentials) -> String {
    // `serde_json::to_string` cannot fail on these owned-String fields,
    // but we surface a panic via `expect` rather than introduce a
    // result-typed signature for a path that has no recoverable error.
    let json = serde_json::to_string(credentials).expect("PaymentCredentials always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// The `WWW-Authenticate: Payment …` auth-params a client receives on a 402,
/// parsed out for the holder. The inverse of the server's header build.
///
/// Cashu-free: the `request` field stays the raw base64url envelope string
/// (the client unwraps it via [`decode_request_envelope`] to get the `creqA`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentParams {
    /// Server-issued challenge id.
    pub id: String,
    /// Protection-space realm.
    pub realm: String,
    /// Payment method (e.g. `"cashu"`).
    pub method: String,
    /// Payment intent (e.g. `"charge"`).
    pub intent: String,
    /// The base64url-nopad request envelope (wraps the `creqA…`).
    pub request: String,
}

/// Parse a `WWW-Authenticate: Payment id="…", realm="…", method="…",
/// intent="…", request="…"` header into its [`PaymentParams`].
///
/// Tolerant of the `Payment ` scheme prefix being present or absent, of
/// surrounding whitespace, and of extra/reordered params (only the five
/// known fields are surfaced). Values are quoted-string auth-params. Returns
/// [`AuthParseError::JsonParse`] with a descriptive message if a required
/// field is missing or the value is unquoted/garbled.
pub fn parse_payment_params(header_value: &str) -> Result<PaymentParams, AuthParseError> {
    let trimmed = header_value.trim();

    // Drop an optional leading `Payment` scheme token.
    let params_str = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case(PAYMENT_SCHEME) => rest.trim(),
        // No scheme prefix (or the first token is itself a param) — treat the
        // whole string as the param list.
        _ => trimmed,
    };

    let mut id = None;
    let mut realm = None;
    let mut method = None;
    let mut intent = None;
    let mut request = None;

    // Split on commas; each piece is `key="value"`. Commas never appear in
    // our values (base64url-nopad + identifiers), so a naive split is safe.
    for piece in params_str.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let Some((key, val_raw)) = piece.split_once('=') else {
            continue;
        };
        let key = key.trim();
        // Strip surrounding double-quotes from the value.
        let val = val_raw.trim().trim_matches('"');
        match key {
            "id" => id = Some(val.to_string()),
            "realm" => realm = Some(val.to_string()),
            "method" => method = Some(val.to_string()),
            "intent" => intent = Some(val.to_string()),
            "request" => request = Some(val.to_string()),
            _ => {}
        }
    }

    let missing = |name: &str| {
        AuthParseError::JsonParse(format!("WWW-Authenticate Payment missing `{name}`"))
    };

    Ok(PaymentParams {
        id: id.ok_or_else(|| missing("id"))?,
        realm: realm.ok_or_else(|| missing("realm"))?,
        method: method.ok_or_else(|| missing("method"))?,
        intent: intent.ok_or_else(|| missing("intent"))?,
        request: request.ok_or_else(|| missing("request"))?,
    })
}

/// JSON envelope carried inside the `WWW-Authenticate` `request`
/// auth-param: a base64url-nopad-encoded object holding the `creqA…`
/// payment-request under a single `cashu_request` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestEnvelope {
    cashu_request: String,
}

/// Wrap a `creqA…` string in the `request` envelope and
/// base64url-nopad-encode it.
///
/// The returned string is what goes inside the `request="…"` auth-param
/// of `WWW-Authenticate: Payment`. Cannot fail.
pub fn encode_request_envelope(creq_a: &str) -> String {
    let envelope = RequestEnvelope {
        cashu_request: creq_a.to_string(),
    };
    let json = serde_json::to_string(&envelope)
        .expect("RequestEnvelope always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Unwrap the base64url-nopad-encoded `request` envelope and return the
/// inner `cashu_request` string (a `creqA…` payment-request).
///
/// Returns an error if the envelope cannot be base64-decoded, is not
/// valid UTF-8/JSON, or lacks the `cashu_request` field.
pub fn decode_request_envelope(b64: &str) -> Result<String, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| Error::DecodeFailed(format!("request envelope base64: {e}")))?;
    let envelope: RequestEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| Error::DecodeFailed(format!("request envelope json: {e}")))?;
    Ok(envelope.cashu_request)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- credentials envelope (was auth_header) ----------------------

    fn make_credentials(method: &str, token: &str) -> PaymentCredentials {
        PaymentCredentials {
            challenge: EchoedChallenge {
                id: "challenge-1".into(),
                realm: "pops-core-verify".into(),
                method: method.into(),
                intent: "charge".into(),
                request: "ZHVtbXkK".into(),
            },
            payload: CashuPayload {
                cashu_token: token.into(),
            },
        }
    }

    fn header_for(creds: &PaymentCredentials) -> String {
        format!("Payment {}", encode_payment_credentials(creds))
    }

    #[test]
    fn happy_path_decodes_credentials() {
        let creds = make_credentials("cashu", "cashuBabc");
        let header = header_for(&creds);
        let parsed = parse_payment_authorization(&header).expect("parses");
        assert_eq!(parsed.challenge.id, "challenge-1");
        assert_eq!(parsed.challenge.realm, "pops-core-verify");
        assert_eq!(parsed.challenge.method, "cashu");
        assert_eq!(parsed.challenge.intent, "charge");
        assert_eq!(parsed.payload.cashu_token, "cashuBabc");
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        for scheme in &["Payment", "PAYMENT", "payment", "pAyMeNt"] {
            let header = format!("{scheme} {blob}");
            parse_payment_authorization(&header).expect("scheme is case-insensitive");
        }
    }

    #[test]
    fn missing_scheme_returns_unknown_scheme() {
        assert_eq!(
            parse_payment_authorization("").unwrap_err(),
            AuthParseError::UnknownScheme,
        );
        assert_eq!(
            parse_payment_authorization("   ").unwrap_err(),
            AuthParseError::UnknownScheme,
        );
    }

    #[test]
    fn bearer_scheme_returns_unknown_scheme() {
        assert_eq!(
            parse_payment_authorization("Bearer abc123").unwrap_err(),
            AuthParseError::UnknownScheme,
        );
    }

    #[test]
    fn payment_with_no_blob_returns_missing_credentials() {
        assert_eq!(
            parse_payment_authorization("Payment").unwrap_err(),
            AuthParseError::MissingCredentials,
        );
        assert_eq!(
            parse_payment_authorization("Payment  ").unwrap_err(),
            AuthParseError::MissingCredentials,
        );
    }

    #[test]
    fn legacy_key_value_param_form_is_not_accepted() {
        let err = parse_payment_authorization(
            r#"Payment method="cashu", token="cashuBabc""#,
        )
        .expect_err("param form must be rejected");
        assert!(
            matches!(err, AuthParseError::Base64Decode(_)),
            "expected Base64Decode, got {err:?}"
        );
    }

    #[test]
    fn malformed_base64_returns_base64_decode() {
        let err = parse_payment_authorization("Payment !!!notbase64!!!")
            .expect_err("garbage base64");
        assert!(
            matches!(err, AuthParseError::Base64Decode(_)),
            "expected Base64Decode, got {err:?}"
        );
    }

    #[test]
    fn valid_base64_not_utf8_returns_utf8_decode() {
        let blob = URL_SAFE_NO_PAD.encode([0xffu8, 0xfe, 0xfd]);
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("non-utf8 payload");
        assert!(
            matches!(err, AuthParseError::Utf8Decode(_)),
            "expected Utf8Decode, got {err:?}"
        );
    }

    #[test]
    fn valid_base64_not_json_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(b"not a json object");
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("not json");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn json_missing_challenge_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(br#"{"payload":{"cashu_token":"x"}}"#);
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no challenge");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn json_missing_payload_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"}}"#,
        );
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no payload");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn payload_missing_cashu_token_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"},"payload":{}}"#,
        );
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no cashu_token");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn wrong_method_returns_wrong_method() {
        let creds = make_credentials("tempo", "abc");
        let header = header_for(&creds);
        assert_eq!(
            parse_payment_authorization(&header).unwrap_err(),
            AuthParseError::WrongMethod("tempo".into()),
        );
    }

    #[test]
    fn extra_unknown_fields_are_ignored() {
        let json = serde_json::json!({
            "challenge": {
                "id": "x",
                "realm": "pops-core-verify",
                "method": "cashu",
                "intent": "charge",
                "request": "r",
                "description": "ignored",
                "opaque": "ignored",
                "expires": "2030-01-01T00:00:00Z"
            },
            "source": "did:example:123",
            "payload": {
                "cashu_token": "cashuBxyz",
                "extra": "ignored"
            }
        });
        let blob = URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        let header = format!("Payment {blob}");
        let parsed = parse_payment_authorization(&header).expect("optional fields ok");
        assert_eq!(parsed.payload.cashu_token, "cashuBxyz");
    }

    #[test]
    fn extra_whitespace_around_blob_is_trimmed() {
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        let header = format!("  Payment   {blob}   ");
        parse_payment_authorization(&header).expect("extra whitespace tolerated");
    }

    // ---- request envelope (was challenge wrap/unwrap) ----------------

    #[test]
    fn request_envelope_roundtrips() {
        let creq = "creqAsomepayload";
        let envelope = encode_request_envelope(creq);
        let unwrapped = decode_request_envelope(&envelope)
            .expect("request envelope round-trips");
        assert_eq!(unwrapped, creq);
    }

    #[test]
    fn request_envelope_is_base64url_nopad() {
        let envelope = encode_request_envelope("creqAdummy");
        // base64url-nopad alphabet excludes '+', '/', '='. Confirm none
        // of those leak through.
        for c in envelope.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "envelope contains non-base64url char {c:?}: {envelope}"
            );
        }
    }

    #[test]
    fn decode_request_envelope_rejects_bad_base64() {
        let err = decode_request_envelope("!!!notbase64!!!")
            .expect_err("bad base64");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    #[test]
    fn decode_request_envelope_rejects_missing_field() {
        // Valid base64 + valid JSON, but no `cashu_request`.
        let bad = URL_SAFE_NO_PAD.encode(br#"{"other":"x"}"#);
        let err = decode_request_envelope(&bad)
            .expect_err("missing cashu_request");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    // ---- WWW-Authenticate param parsing ------------------------------

    #[test]
    fn parse_payment_params_extracts_all_five_fields() {
        let creq_envelope = encode_request_envelope("creqAsomepayload");
        let header = format!(
            r#"Payment id="ch-1", realm="pops-core-verify", method="cashu", intent="charge", request="{creq_envelope}""#
        );
        let params = parse_payment_params(&header).expect("parses Payment params");
        assert_eq!(params.id, "ch-1");
        assert_eq!(params.realm, "pops-core-verify");
        assert_eq!(params.method, "cashu");
        assert_eq!(params.intent, "charge");
        assert_eq!(params.request, creq_envelope);
        // And the request unwraps back to the creqA.
        assert_eq!(
            decode_request_envelope(&params.request).expect("unwrap"),
            "creqAsomepayload"
        );
    }

    #[test]
    fn parse_payment_params_tolerates_missing_scheme_prefix() {
        let header = r#"id="x", realm="r", method="cashu", intent="charge", request="env""#;
        let params = parse_payment_params(header).expect("parses without Payment prefix");
        assert_eq!(params.id, "x");
        assert_eq!(params.request, "env");
    }

    #[test]
    fn parse_payment_params_rejects_missing_required_field() {
        // No `request` param.
        let header = r#"Payment id="x", realm="r", method="cashu", intent="charge""#;
        let err = parse_payment_params(header).expect_err("missing request must fail");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }
}
