//! Cashu-free codec for the `Payment` auth-scheme (the WASM-targetable layer:
//! `serde` + `base64` + JCS, no `cashu` types).
//!
//! Credentials envelope (`Authorization: Payment <blob>`): `Payment` + a
//! base64url-nopad encoding of the JCS-canonical (RFC 8785) bytes of:
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
//! The credential blob is JCS-canonical (`draft-cashu-charge-01` §Encoding); the
//! inner `request` echo and `cashu_token` strings are opaque (not
//! re-canonicalized). The echoed `challenge` carries optional `digest`/`opaque`/
//! `expires` (present iff the 402 carried them) and an optional top-level
//! `source`; the parser tolerates these and any further unknown fields.
//!
//! Request object (`request="…"`): a base64url-nopad encoding of the JCS-canonical
//! bytes of the `draft-cashu-charge-01` request schema —
//! `{ amount, currency, description?, externalId?, methodDetails: { request, mints } }`
//! — where `methodDetails.request` is the opaque `creqA…` and `methodDetails.mints`
//! is the non-empty superset of the creqA's accepted mints.

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
/// 402 (`draft-cashu-charge-01` steps 4-6). The client echoes `digest`, `opaque`,
/// and `expires` iff the 402 carried them; each is `None` (and absent on the
/// JCS-canonical wire) otherwise. Any further unknown field is tolerated.
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
    /// Echo of the optional challenge digest, present iff the 402 carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Echo of the optional server opaque, present iff the 402 carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
    /// Echo of the optional challenge expiry (RFC 3339), present iff the 402
    /// carried it. The verifier rejects an echo whose `expires` is in the past
    /// (`draft-cashu-charge-01` step 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// Cashu-method `payload`. This struct just carries the token string out of the
/// JSON; its structural validation is the validator's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuPayload {
    /// The `cashuB…` token, forwarded as-is to [`crate::challenge::decode_token`].
    pub cashu_token: String,
}

/// Full credentials object (`draft-cashu-charge-01` §Credential). The top-level
/// `source` is optional (tolerated, MUST NOT be required); any further unknown
/// field is tolerated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredentials {
    /// Echo of the WWW-Authenticate auth-params.
    pub challenge: EchoedChallenge,
    /// Method-specific payload (cashu = `{ "cashu_token": "..." }`).
    pub payload: CashuPayload,
    /// Optional client-supplied source identifier; absent on the wire when
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
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
/// The bytes are JCS-canonical (`draft-cashu-charge-01` §Encoding).
pub fn encode_payment_credentials(credentials: &PaymentCredentials) -> String {
    // Serialization of owned-String fields cannot fail; `expect` rather than a
    // result-typed signature for a non-recoverable path.
    let json =
        serde_jcs::to_string(credentials).expect("PaymentCredentials always serializes");
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

/// Cashu method-details of the request object (`draft-cashu-charge-01` §Request
/// Schema): the opaque `creqA…` and the non-empty superset of the creqA's
/// accepted mints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodDetails {
    /// The opaque `creqA…` payment-request string.
    pub request: String,
    /// Mints the verifier accepts — a non-empty superset of the creqA's mints.
    pub mints: Vec<String>,
}

/// The `request` auth-param object (`draft-cashu-charge-01` §Request Schema).
/// `amount` is the canonical decimal string and `currency` is the unit; the
/// cashu specifics live under `methodDetails`. Carried base64url-nopad over its
/// JCS-canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestObject {
    /// Exact amount required, as a decimal string.
    pub amount: String,
    /// Currency unit the proofs must carry (`pop_<unix_ts>` for PoP).
    pub currency: String,
    /// Optional human-readable description; absent on the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional external correlation id; absent on the wire when `None`.
    #[serde(default, rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Cashu method-specific details (the creqA + accepted mints).
    #[serde(rename = "methodDetails")]
    pub method_details: MethodDetails,
}

/// Encode a [`RequestObject`] as the `request="…"` auth-param: base64url-nopad
/// over its JCS-canonical bytes (`draft-cashu-charge-01` §Encoding). Cannot fail
/// (the owned-`String` fields always serialize).
pub fn encode_request_object(object: &RequestObject) -> String {
    let json = serde_jcs::to_string(object).expect("RequestObject always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Decode the `request="…"` auth-param into a [`RequestObject`]. Errors on bad
/// base64 / JSON or a missing/wrong-shaped field (the cashu-semantic
/// mints-superset check is the caller's, via the cashu-coupled
/// [`crate::challenge`] layer).
pub fn decode_request_object(b64: &str) -> Result<RequestObject, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| Error::DecodeFailed(format!("request object base64: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::DecodeFailed(format!("request object json: {e}")))
}

/// The JSON object inside the `pops-gateway` binary's `request` auth-param,
/// holding the `creqA…` under a single `cashu_request` field. The gateway
/// (`gateway.rs`) is a SEPARATE call-site that has not yet been folded onto the
/// spec [`RequestObject`] codec (`draft-cashu-charge-01` conformance is the
/// library path — `middleware.rs` — for now); this flat codec serves it until
/// that de-dup lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestEnvelope {
    cashu_request: String,
}

/// Wrap a `creqA…` in the gateway's flat `request` envelope, base64url-nopad-
/// encoded. Cannot fail. (The spec request codec is [`encode_request_object`].)
pub fn encode_request_envelope(creq_a: &str) -> String {
    let envelope = RequestEnvelope {
        cashu_request: creq_a.to_string(),
    };
    let json = serde_json::to_string(&envelope)
        .expect("RequestEnvelope always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Unwrap the gateway's flat `request` envelope, returning the inner
/// `cashu_request` (`creqA…`). Errors on bad base64 / JSON or a missing
/// `cashu_request`. (The spec request codec is [`decode_request_object`].)
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
                digest: None,
                opaque: None,
                expires: None,
            },
            payload: CashuPayload {
                cashu_token: token.into(),
            },
            source: None,
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

    // ---- spec request object (draft-cashu-charge-01 §Request Schema) ---------

    fn sample_request_object() -> RequestObject {
        RequestObject {
            amount: "100".into(),
            currency: "pop_1782668279".into(),
            description: Some("read access".into()),
            external_id: Some("inv-7".into()),
            method_details: MethodDetails {
                request: "creqAsomepayload".into(),
                mints: vec!["https://mint.example".into()],
            },
        }
    }

    #[test]
    fn request_object_roundtrips() {
        let obj = sample_request_object();
        let encoded = encode_request_object(&obj);
        let decoded = decode_request_object(&encoded).expect("request object round-trips");
        assert_eq!(decoded, obj);
    }

    #[test]
    fn request_object_is_base64url_nopad() {
        let encoded = encode_request_object(&sample_request_object());
        for c in encoded.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "request object contains non-base64url char {c:?}: {encoded}"
            );
        }
    }

    #[test]
    fn request_object_bytes_are_jcs_canonical() {
        // JCS sorts object keys lexicographically; the decoded base64 is exactly
        // those canonical bytes, key-sorted at both levels (amount < currency <
        // description < externalId < methodDetails; request < mints).
        let encoded = encode_request_object(&sample_request_object());
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            json,
            r#"{"amount":"100","currency":"pop_1782668279","description":"read access","externalId":"inv-7","methodDetails":{"mints":["https://mint.example"],"request":"creqAsomepayload"}}"#
        );
    }

    #[test]
    fn request_object_omits_absent_optionals_on_wire() {
        let obj = RequestObject {
            amount: "1".into(),
            currency: "pop_1700000000".into(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                request: "creqAx".into(),
                mints: vec!["https://m.example".into()],
            },
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(encode_request_object(&obj))
            .expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            json,
            r#"{"amount":"1","currency":"pop_1700000000","methodDetails":{"mints":["https://m.example"],"request":"creqAx"}}"#
        );
    }

    #[test]
    fn decode_request_object_rejects_missing_method_details() {
        let bad = URL_SAFE_NO_PAD.encode(br#"{"amount":"1","currency":"pop_1"}"#);
        let err = decode_request_object(&bad).expect_err("missing methodDetails");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    #[test]
    fn decode_request_object_rejects_bad_base64() {
        let err = decode_request_object("!!!notbase64!!!").expect_err("bad base64");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    // ---- credential blob: JCS + optional echo fields -------------------------

    #[test]
    fn credential_blob_bytes_are_jcs_canonical() {
        // The credential blob is JCS-canonical (challenge < payload < source;
        // within challenge: id < intent < method < realm < request, plus the
        // optional digest/opaque/expires when present).
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        let bytes = URL_SAFE_NO_PAD.decode(&blob).expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            json,
            r#"{"challenge":{"id":"challenge-1","intent":"charge","method":"cashu","realm":"pops-core-verify","request":"ZHVtbXkK"},"payload":{"cashu_token":"cashuBabc"}}"#
        );
    }

    #[test]
    fn credential_echo_carries_optional_fields_when_present() {
        let creds = PaymentCredentials {
            challenge: EchoedChallenge {
                id: "id".into(),
                realm: "r".into(),
                method: "cashu".into(),
                intent: "charge".into(),
                request: "req".into(),
                digest: Some("d".into()),
                opaque: Some("o".into()),
                expires: Some("2999-01-01T00:00:00Z".into()),
            },
            payload: CashuPayload {
                cashu_token: "cashuBz".into(),
            },
            source: Some("did:example:1".into()),
        };
        let header = format!("Payment {}", encode_payment_credentials(&creds));
        let parsed = parse_payment_authorization(&header).expect("optional echo round-trips");
        assert_eq!(parsed.challenge.digest.as_deref(), Some("d"));
        assert_eq!(parsed.challenge.opaque.as_deref(), Some("o"));
        assert_eq!(
            parsed.challenge.expires.as_deref(),
            Some("2999-01-01T00:00:00Z")
        );
        assert_eq!(parsed.source.as_deref(), Some("did:example:1"));
    }
}
