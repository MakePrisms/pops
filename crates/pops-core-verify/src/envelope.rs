//! Cashu-free codec for the `Payment` auth-scheme (the WASM-targetable layer:
//! `serde` + `base64`, no `cashu` types).
//!
//! Credentials envelope (`Authorization: Payment <blob>`): `Payment` + a
//! base64url-nopad JSON object:
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
//! Optional fields (`source`, `description`, `opaque`, `digest`, `expires`) are
//! tolerated on the wire but ignored.
//!
//! Request envelope (`request="…"`): a base64url-nopad JSON blob wrapping the
//! `creqA…` under a single `cashu_request` field.

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

/// Echo of the `WWW-Authenticate` auth-params the client round-trips from the
/// 402. Optional fields (`description`, `opaque`, `digest`, `expires`) are
/// accepted but not surfaced.
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
    /// Echo of the method-specific request blob.
    pub request: String,
}

/// Cashu-method `payload`. This struct just carries the token string out of the
/// JSON; its structural validation is the validator's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuPayload {
    /// The `cashuB…` token, forwarded as-is to [`crate::challenge::decode_token`].
    pub cashu_token: String,
}

/// Full credentials object. Extra fields (`source`, etc.) are tolerated and
/// ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredentials {
    /// Echo of the WWW-Authenticate auth-params.
    pub challenge: EchoedChallenge,
    /// Method-specific payload (cashu = `{ "cashu_token": "..." }`).
    pub payload: CashuPayload,
}

/// Why an `Authorization: Payment <blob>` header failed to parse. Every variant
/// is a 402 re-challenge in the middleware; distinct only to make the body
/// intelligible.
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

    /// Base64-decoded bytes are not valid UTF-8.
    #[error("Payment credentials are not valid UTF-8: {0}")]
    Utf8Decode(String),

    /// JSON does not parse, or a required field is missing/wrong-shaped.
    #[error("Payment credentials JSON is malformed: {0}")]
    JsonParse(String),

    /// `challenge.method` is present but is not `"cashu"`.
    #[error("Payment method must be 'cashu', got {0:?}")]
    WrongMethod(String),
}

/// Parse an `Authorization: Payment <base64url-nopad-blob>` header into the
/// structured credentials. `WrongMethod` is surfaced here for a non-`cashu`
/// method; the caller still decodes `payload.cashu_token` via
/// [`crate::challenge::decode_token`].
pub fn parse_payment_authorization(
    header_value: &str,
) -> Result<PaymentCredentials, AuthParseError> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(AuthParseError::UnknownScheme);
    }

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

    // base64url-nopad only; a legacy key=value param form trips the decoder.
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

/// Build a credentials blob (inverse of [`parse_payment_authorization`]),
/// returning the bare base64url-nopad string — the caller prepends `Payment `.
pub fn encode_payment_credentials(credentials: &PaymentCredentials) -> String {
    // Serialization of owned-String fields cannot fail; `expect` rather than a
    // result-typed signature for a non-recoverable path.
    let json = serde_json::to_string(credentials).expect("PaymentCredentials always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// The `WWW-Authenticate: Payment …` auth-params a client receives on a 402.
/// Cashu-free: `request` stays the raw base64url envelope (the client unwraps it
/// via [`decode_request_envelope`]).
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

/// Strip exactly ONE matched pair of surrounding double-quotes, or `None` (a
/// reject) if not a well-formed quoted-string: unquoted (`x`), one quote
/// (`"x`/`x"`), a lone `"`, or an interior `"` (`""x""`). Our values are
/// base64url/identifiers and never contain a quote, so an interior one is garbled.
fn strip_quoted(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    // A lone `"` would let `strip_suffix` consume the SAME quote twice; require ≥ 2 bytes.
    if s.len() < 2 {
        return None;
    }
    if inner.contains('"') {
        return None;
    }
    Some(inner)
}

/// Parse a `WWW-Authenticate: Payment` header into its [`PaymentParams`].
/// Tolerant of the scheme prefix, whitespace, and extra/reordered params. Values
/// MUST be RFC 7235 quoted-strings — an unquoted or unbalanced value is rejected
/// (NOT leniently stripped, which could mis-bind the echoed value); a missing or
/// garbled field returns [`AuthParseError::JsonParse`].
pub fn parse_payment_params(header_value: &str) -> Result<PaymentParams, AuthParseError> {
    let trimmed = header_value.trim();

    // Drop an optional leading `Payment` scheme token.
    let params_str = match trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case(PAYMENT_SCHEME) => rest.trim(),
        _ => trimmed,
    };

    let mut id = None;
    let mut realm = None;
    let mut method = None;
    let mut intent = None;
    let mut request = None;

    // Commas never appear in our values, so a naive split is safe.
    for piece in params_str.split(',') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let Some((key, val_raw)) = piece.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !matches!(key, "id" | "realm" | "method" | "intent" | "request") {
            continue;
        }
        // Strict quoted-string (see `strip_quoted` / the fn doc).
        let val = match strip_quoted(val_raw.trim()) {
            Some(v) => v,
            None => {
                return Err(AuthParseError::JsonParse(format!(
                    "WWW-Authenticate Payment `{key}` value must be a double-quoted string"
                )))
            }
        };
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

/// The JSON object inside the `request` auth-param, holding the `creqA…` under a
/// single `cashu_request` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestEnvelope {
    cashu_request: String,
}

/// Wrap a `creqA…` in the `request` envelope, base64url-nopad-encoded. The result
/// goes inside `request="…"`. Cannot fail.
pub fn encode_request_envelope(creq_a: &str) -> String {
    let envelope = RequestEnvelope {
        cashu_request: creq_a.to_string(),
    };
    let json = serde_json::to_string(&envelope)
        .expect("RequestEnvelope always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Unwrap the `request` envelope, returning the inner `cashu_request` (`creqA…`).
/// Errors on bad base64 / JSON or a missing `cashu_request`.
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
        // base64url-nopad excludes '+', '/', '='.
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
        let header = r#"Payment id="x", realm="r", method="cashu", intent="charge""#; // no request
        let err = parse_payment_params(header).expect_err("missing request must fail");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn parse_payment_params_rejects_unquoted_value() {
        // `id=x` must reject, not leniently accept `x` the way trim_matches would.
        let header = r#"Payment id=x, realm="r", method="cashu", intent="charge", request="e""#;
        let err = parse_payment_params(header).expect_err("unquoted id must fail");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn parse_payment_params_rejects_unbalanced_trailing_quote() {
        let header = r#"Payment id="x, realm="r", method="cashu", intent="charge", request="e""#;
        let err =
            parse_payment_params(header).expect_err("missing-trailing-quote id must fail");
        assert!(matches!(err, AuthParseError::JsonParse(_)), "got {err:?}");
    }

    #[test]
    fn parse_payment_params_rejects_unbalanced_leading_quote() {
        let header = r#"Payment id=x", realm="r", method="cashu", intent="charge", request="e""#;
        let err = parse_payment_params(header).expect_err("missing-leading-quote id must fail");
        assert!(matches!(err, AuthParseError::JsonParse(_)), "got {err:?}");
    }

    #[test]
    fn parse_payment_params_rejects_doubled_quotes() {
        // `id=""x""` — an interior quote is garbled; the strict strip rejects it.
        let header =
            r#"Payment id=""x"", realm="r", method="cashu", intent="charge", request="e""#;
        let err = parse_payment_params(header).expect_err("doubled-quote id must fail");
        assert!(matches!(err, AuthParseError::JsonParse(_)), "got {err:?}");
    }

    #[test]
    fn parse_payment_params_accepts_empty_quoted_value() {
        // `realm=""` is a well-formed quoted-string (strips to ``), distinct from
        // an unquoted/unbalanced value.
        let header =
            r#"Payment id="x", realm="", method="cashu", intent="charge", request="e""#;
        let params = parse_payment_params(header).expect("empty quoted realm is valid");
        assert_eq!(params.realm, "");
        assert_eq!(params.id, "x");
    }

    #[test]
    fn strip_quoted_unit() {
        assert_eq!(strip_quoted(r#""abc""#), Some("abc"));
        assert_eq!(strip_quoted(r#""""#), Some("")); // empty quoted string
        assert_eq!(strip_quoted("abc"), None); // unquoted
        assert_eq!(strip_quoted(r#""abc"#), None); // missing trailing
        assert_eq!(strip_quoted(r#"abc""#), None); // missing leading
        assert_eq!(strip_quoted(r#"""#), None); // lone quote
        assert_eq!(strip_quoted(""), None); // empty
        assert_eq!(strip_quoted(r#""a"b""#), None); // interior quote
    }
}
