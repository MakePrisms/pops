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
//!   "payload": { "token": "cashuB..." }
//! }
//! ```
//!
//! The credential blob is JCS-canonical (RFC 8785); the inner `request` echo and
//! `token` strings are opaque (not re-canonicalized). The echoed
//! `challenge` carries optional `digest`/`opaque`/`expires` (present iff the 402
//! carried them) and an optional top-level `source`; the parser tolerates these
//! and any further unknown fields.
//!
//! Request object (`request="…"`): a base64url-nopad encoding of the JCS-canonical
//! bytes of the `draft-cashu-charge-00` request schema —
//! `{ amount, currency, description?, externalId?, methodDetails: { paymentRequest } }`
//! — where `methodDetails.paymentRequest` is the opaque `creqA…`, the
//! authoritative source of all payment parameters (amount, unit, accepted mints).

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
/// 402. The client echoes `digest`, `opaque`, and `expires` iff the 402 carried
/// them; each is `None` (and absent on the JCS-canonical wire) otherwise. Any
/// further unknown field is tolerated.
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
    /// carried it. The verifier rejects an echo whose `expires` is in the past.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Echo of the optional human-readable description, present iff the 402
    /// carried it. Display-only: the framework excludes it from the challenge
    /// binding, so it is echoed but never authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Cashu-method `payload`. This struct just carries the token string out of the
/// JSON; its structural validation is the validator's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuPayload {
    /// The `cashuB…` token (the spec's `payload.token`), forwarded as-is to
    /// [`crate::challenge::decode_token`].
    pub token: String,
}

/// Full `draft-cashu-charge-00` credentials object. The top-level `source` is
/// optional (tolerated, MUST NOT be required); any further unknown field is
/// tolerated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredentials {
    /// Echo of the WWW-Authenticate auth-params.
    pub challenge: EchoedChallenge,
    /// Method-specific payload (cashu = `{ "token": "..." }`).
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
/// method; the caller still decodes `payload.token` via
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
/// The bytes are JCS-canonical (RFC 8785).
pub fn encode_payment_credentials(credentials: &PaymentCredentials) -> String {
    // Serialization of owned-String fields cannot fail; `expect` rather than a
    // result-typed signature for a non-recoverable path.
    let json =
        serde_jcs::to_string(credentials).expect("PaymentCredentials always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// The `WWW-Authenticate: Payment …` auth-params a client receives on a 402.
/// Cashu-free: `request` stays the raw base64url request object (the client
/// decodes it via [`decode_request_object`] or the cashu-coupled
/// [`crate::challenge::decode_charge_request`]). The optional params
/// (`expires`/`digest`/`opaque`/`description`) are captured when present
/// because a client MUST echo each issued param unchanged in its credential
/// (spec Credential Schema + Challenge Binding).
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
    /// Optional RFC 3339 challenge expiry, present iff the 402 carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Optional request-body digest, present iff the 402 carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Optional server correlation opaque, present iff the 402 carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
    /// Optional human-readable description, present iff the 402 carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    let mut expires = None;
    let mut digest = None;
    let mut opaque = None;
    let mut description = None;

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
        if !matches!(
            key,
            "id" | "realm"
                | "method"
                | "intent"
                | "request"
                | "expires"
                | "digest"
                | "opaque"
                | "description"
        ) {
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
            "expires" => expires = Some(val.to_string()),
            "digest" => digest = Some(val.to_string()),
            "opaque" => opaque = Some(val.to_string()),
            "description" => description = Some(val.to_string()),
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
        expires,
        digest,
        opaque,
        description,
    })
}

/// Cashu method-details of the `draft-cashu-charge-00` request object. Exactly
/// ONE field: the opaque payment request, the authoritative source of all
/// payment parameters (amount, unit, accepted mints, spending-condition kind,
/// single-use flag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodDetails {
    /// The opaque Cashu payment-request string (`creqA…`).
    #[serde(rename = "paymentRequest")]
    pub payment_request: String,
}

/// The `draft-cashu-charge-00` `request` auth-param object. `amount` is the
/// canonical decimal string and `currency` is the unit; the cashu specifics live
/// under `methodDetails`. Carried base64url-nopad over its JCS-canonical bytes.
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
    /// Cashu method-specific details (the authoritative `paymentRequest`).
    #[serde(rename = "methodDetails")]
    pub method_details: MethodDetails,
}

/// Encode a [`RequestObject`] as the `request="…"` auth-param: base64url-nopad
/// over its JCS-canonical (RFC 8785) bytes. Cannot fail (the owned-`String`
/// fields always serialize).
pub fn encode_request_object(object: &RequestObject) -> String {
    let json = serde_jcs::to_string(object).expect("RequestObject always serializes");
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Decode the `request="…"` auth-param into a [`RequestObject`]. Errors on bad
/// base64 / JSON or a missing/wrong-shaped field. The base64url MUST be
/// unpadded — a padded value is malformed under the framework's grammar
/// (the artifacts INSIDE the JSON, `creqA…`/`cashuB…`, carry their own
/// padding-tolerant encodings). The cashu-semantic checks (creqA `a`/`u`/`m`
/// presence + consistency) are the caller's, via the cashu-coupled
/// [`crate::challenge`] layer.
pub fn decode_request_object(b64: &str) -> Result<RequestObject, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|e| Error::DecodeFailed(format!("request object base64: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::DecodeFailed(format!("request object json: {e}")))
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
                description: None,
            },
            payload: CashuPayload {
                token: token.into(),
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
        assert_eq!(parsed.payload.token, "cashuBabc");
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
        let blob = URL_SAFE_NO_PAD.encode(br#"{"payload":{"token":"x"}}"#);
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
    fn payload_missing_token_returns_json_parse() {
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"},"payload":{}}"#,
        );
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header).expect_err("no token");
        assert!(
            matches!(err, AuthParseError::JsonParse(_)),
            "expected JsonParse, got {err:?}"
        );
    }

    #[test]
    fn payload_with_only_legacy_cashu_token_field_returns_json_parse() {
        // The spec names the payload field `token`; the pre-spec `cashu_token`
        // spelling no longer satisfies the required field.
        let blob = URL_SAFE_NO_PAD.encode(
            br#"{"challenge":{"id":"a","realm":"b","method":"cashu","intent":"charge","request":"r"},"payload":{"cashu_token":"cashuBabc"}}"#,
        );
        let header = format!("Payment {blob}");
        let err = parse_payment_authorization(&header)
            .expect_err("legacy cashu_token field must not satisfy payload.token");
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
                "token": "cashuBxyz",
                "extra": "ignored"
            }
        });
        let blob = URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        let header = format!("Payment {blob}");
        let parsed = parse_payment_authorization(&header).expect("optional fields ok");
        assert_eq!(parsed.payload.token, "cashuBxyz");
    }

    #[test]
    fn extra_whitespace_around_blob_is_trimmed() {
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        let header = format!("  Payment   {blob}   ");
        parse_payment_authorization(&header).expect("extra whitespace tolerated");
    }

    #[test]
    fn parse_payment_params_extracts_all_five_fields() {
        let request_object = encode_request_object(&sample_request_object());
        let header = format!(
            r#"Payment id="ch-1", realm="pops-core-verify", method="cashu", intent="charge", request="{request_object}""#
        );
        let params = parse_payment_params(&header).expect("parses Payment params");
        assert_eq!(params.id, "ch-1");
        assert_eq!(params.realm, "pops-core-verify");
        assert_eq!(params.method, "cashu");
        assert_eq!(params.intent, "charge");
        assert_eq!(params.request, request_object);
        // And the request decodes back to the spec request object.
        let decoded = decode_request_object(&params.request).expect("decodes");
        assert_eq!(decoded, sample_request_object());
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

    // ---- draft-cashu-charge-00 request object --------------------------------

    fn sample_request_object() -> RequestObject {
        RequestObject {
            amount: "100".into(),
            currency: "pop_1782668279".into(),
            description: Some("read access".into()),
            external_id: Some("inv-7".into()),
            method_details: MethodDetails {
                payment_request: "creqAsomepayload".into(),
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
        // Expected bytes hand-derived from the spec (Request Schema + Method
        // Details + Encoding): JCS sorts keys lexicographically (amount <
        // currency < description < externalId < methodDetails) and
        // methodDetails carries exactly ONE field, `paymentRequest`.
        let encoded = encode_request_object(&sample_request_object());
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            json,
            r#"{"amount":"100","currency":"pop_1782668279","description":"read access","externalId":"inv-7","methodDetails":{"paymentRequest":"creqAsomepayload"}}"#
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
                payment_request: "creqAx".into(),
            },
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(encode_request_object(&obj))
            .expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            json,
            r#"{"amount":"1","currency":"pop_1700000000","methodDetails":{"paymentRequest":"creqAx"}}"#
        );
    }

    #[test]
    fn request_object_never_carries_a_mints_field() {
        // The deleted `methodDetails.mints` must not reappear on the wire; the
        // mint set lives only inside the creqA.
        let encoded = encode_request_object(&sample_request_object());
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert!(
            !json.contains("\"mints\""),
            "emitted request object must not carry methodDetails.mints: {json}"
        );
    }

    #[test]
    fn decode_request_object_rejects_missing_method_details() {
        let bad = URL_SAFE_NO_PAD.encode(br#"{"amount":"1","currency":"pop_1"}"#);
        let err = decode_request_object(&bad).expect_err("missing methodDetails");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    #[test]
    fn decode_request_object_rejects_legacy_request_field_name() {
        // The pre-spec wire named the creqA `methodDetails.request` (with a
        // sibling `mints`); only `paymentRequest` parses now.
        let bad = URL_SAFE_NO_PAD.encode(
            br#"{"amount":"1","currency":"pop_1","methodDetails":{"mints":["https://m.example"],"request":"creqAx"}}"#,
        );
        let err = decode_request_object(&bad).expect_err("legacy field names must not parse");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    #[test]
    fn decode_request_object_rejects_bad_base64() {
        let err = decode_request_object("!!!notbase64!!!").expect_err("bad base64");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    #[test]
    fn decode_request_object_rejects_padded_base64() {
        // Header values are base64url WITHOUT padding (spec Encoding §); a padded
        // value is malformed under the framework's grammar. Pick a description
        // length whose unpadded encoding is not a 4-multiple, so CANONICAL `=`
        // padding exists to append (the reject is then about padding, not length).
        let (unpadded, pad) = (0..4usize)
            .map(|n| {
                let mut obj = sample_request_object();
                obj.description = Some("x".repeat(n));
                let enc = encode_request_object(&obj);
                let pad = (4 - enc.len() % 4) % 4;
                (enc, pad)
            })
            .find(|(_, pad)| *pad > 0)
            .expect("some description length yields a non-4-multiple encoding");
        decode_request_object(&unpadded).expect("unpadded form decodes");
        let padded = format!("{unpadded}{}", "=".repeat(pad));
        let err = decode_request_object(&padded).expect_err("padded request object must reject");
        assert!(matches!(err, Error::DecodeFailed(_)));
    }

    // ---- credential blob: JCS + optional echo fields -------------------------

    #[test]
    fn credential_blob_bytes_are_jcs_canonical() {
        // The credential blob is JCS-canonical (challenge < payload < source;
        // within challenge: id < intent < method < realm < request, plus the
        // optional digest/opaque/expires when present). The payload field is
        // the spec's `token` (Credential Schema).
        let creds = make_credentials("cashu", "cashuBabc");
        let blob = encode_payment_credentials(&creds);
        let bytes = URL_SAFE_NO_PAD.decode(&blob).expect("decodes");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert_eq!(
            json,
            r#"{"challenge":{"id":"challenge-1","intent":"charge","method":"cashu","realm":"pops-core-verify","request":"ZHVtbXkK"},"payload":{"token":"cashuBabc"}}"#
        );
    }

    #[test]
    fn padded_credential_blob_is_rejected() {
        // The Authorization blob is a header value: base64url WITHOUT padding
        // (spec Encoding §). Canonical `=` padding makes it malformed.
        let (unpadded, pad) = (0..4usize)
            .map(|n| {
                let creds = make_credentials("cashu", &format!("cashuB{}", "a".repeat(n)));
                let blob = encode_payment_credentials(&creds);
                let pad = (4 - blob.len() % 4) % 4;
                (blob, pad)
            })
            .find(|(_, pad)| *pad > 0)
            .expect("some token length yields a non-4-multiple blob");
        parse_payment_authorization(&format!("Payment {unpadded}"))
            .expect("unpadded blob parses");
        let err = parse_payment_authorization(&format!("Payment {unpadded}{}", "=".repeat(pad)))
            .expect_err("padded credential blob must reject");
        assert!(
            matches!(err, AuthParseError::Base64Decode(_)),
            "expected Base64Decode, got {err:?}"
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
                description: Some("a memo".into()),
            },
            payload: CashuPayload {
                token: "cashuBz".into(),
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
        assert_eq!(parsed.challenge.description.as_deref(), Some("a memo"));
        assert_eq!(parsed.source.as_deref(), Some("did:example:1"));
    }

    #[test]
    fn parse_payment_params_captures_optional_params() {
        // A client MUST echo every issued param, so the parser captures the
        // optionals (expires/digest/opaque/description) when present.
        let header = r#"Payment id="x", realm="r", method="cashu", intent="charge", request="e", expires="2026-03-15T12:05:00Z", digest="sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", opaque="b3BhcXVl", description="weather report""#;
        let params = parse_payment_params(header).expect("parses with optionals");
        assert_eq!(params.expires.as_deref(), Some("2026-03-15T12:05:00Z"));
        assert_eq!(
            params.digest.as_deref(),
            Some("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")
        );
        assert_eq!(params.opaque.as_deref(), Some("b3BhcXVl"));
        assert_eq!(params.description.as_deref(), Some("weather report"));
    }

    #[test]
    fn parse_payment_params_leaves_absent_optionals_none() {
        let header = r#"Payment id="x", realm="r", method="cashu", intent="charge", request="e""#;
        let params = parse_payment_params(header).expect("parses without optionals");
        assert_eq!(params.expires, None);
        assert_eq!(params.digest, None);
        assert_eq!(params.opaque, None);
        assert_eq!(params.description, None);
    }
}
