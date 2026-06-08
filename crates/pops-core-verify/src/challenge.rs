//! The cashu-coupled `creqA` layer (the cashu-free envelopes live in
//! [`crate::envelope`]). [`encode_challenge`] serializes a [`CashuRequirement`]
//! into the opaque `creqA…`; [`encode_charge_request`] wraps it in the
//! `draft-cashu-charge-01` request object the 402's `request` auth-param carries,
//! and [`decode_charge_request`] reads that object back (enforcing the
//! mints-superset over the inner creqA); [`decode_token`] parses the `cashuB…`
//! token the client returns on retry.
//!
//! Transports are left empty (the challenge is in-band) and `nut10` is `None` (a
//! bearer charge has no spend lock). This module does NOT enforce the `pop_<ts>`
//! unit prefix — it round-trips whatever the caller supplies.

use cashu::nuts::nut18::PaymentRequest;
use cashu::nuts::CurrencyUnit;
use cashu::{Amount, MintUrl, Token};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::envelope::{
    decode_request_object, encode_request_object, MethodDetails, RequestObject,
};
use crate::error::Error;

/// What the verifier requires from a holder (cashu-typed). `single_use` is
/// forwarded as-is — enforcing replay is the verifier's job, not this module's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuRequirement {
    /// Currency unit the proofs must carry (`pop_<unix_ts>` for PoP).
    pub unit: CurrencyUnit,
    /// Mints the verifier accepts. Empty means "any mint".
    pub mints: Vec<MintUrl>,
    /// Exact amount of proofs required.
    pub amount: Amount,
    /// Optional payment correlation id.
    pub payment_id: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Whether the challenge is one-shot.
    pub single_use: bool,
}

impl CashuRequirement {
    /// Construct the underlying `PaymentRequest` with no transports (the
    /// challenge is in-band) and no spending conditions (bearer charge).
    fn to_payment_request(&self) -> PaymentRequest {
        PaymentRequest {
            payment_id: self.payment_id.clone(),
            amount: Some(self.amount),
            unit: Some(self.unit.clone()),
            single_use: Some(self.single_use),
            mints: self.mints.clone(),
            description: self.description.clone(),
            transports: vec![],
            nut10: None,
        }
    }
}

/// Encode a [`CashuRequirement`] into the `creqA...` string that becomes
/// `methodDetails.request` inside the `request` auth-param on a 402 response.
///
/// Cannot fail: the CBOR + base64url encoding of these fields is
/// infallible.
pub fn encode_challenge(req: &CashuRequirement) -> String {
    req.to_payment_request().to_string()
}

/// The decoded `draft-cashu-charge-01` request object: the spec amount/unit/mints
/// (the authoritative source) plus the opaque `creqA…` they were issued with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedChargeRequest {
    /// Exact amount required.
    pub amount: Amount,
    /// Currency unit the proofs must carry.
    pub unit: CurrencyUnit,
    /// Mints the verifier accepts (a non-empty superset of the creqA's mints).
    pub mints: Vec<MintUrl>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Optional external correlation id.
    pub external_id: Option<String>,
    /// The opaque `creqA…` carried under `methodDetails.request`.
    pub creq_a: String,
}

/// Build the `draft-cashu-charge-01` request object for the 402's `request`
/// auth-param: the spec amount/currency/description plus `methodDetails`
/// (`{ request: creqA, mints }`). `methodDetails.mints` is the requirement's
/// accepted set, which IS the creqA's set, so the spec's mints-superset holds by
/// construction. Returns the base64url-nopad JCS string (`encode_request_object`).
pub fn encode_charge_request(req: &CashuRequirement) -> String {
    let object = RequestObject {
        amount: u64::from(req.amount).to_string(),
        currency: req.unit.to_string(),
        description: req.description.clone(),
        external_id: req.payment_id.clone(),
        method_details: MethodDetails {
            request: encode_challenge(req),
            mints: req.mints.iter().map(|m| m.to_string()).collect(),
        },
    };
    encode_request_object(&object)
}

/// Decode the 402's `request` auth-param into a [`DecodedChargeRequest`].
///
/// Reads the authoritative amount/currency/mints, then enforces the
/// `draft-cashu-charge-01` rule against the inner `creqA`: `methodDetails.mints`
/// MUST be a NON-EMPTY superset of the creqA's mints. A missing/short superset,
/// an unparseable creqA, or a non-decimal `amount` is a [`Error::DecodeFailed`].
pub fn decode_charge_request(b64: &str) -> Result<DecodedChargeRequest, Error> {
    let object = decode_request_object(b64)?;

    let amount_u64: u64 = object.amount.parse().map_err(|e| {
        Error::DecodeFailed(format!("request amount {:?} is not a decimal: {e}", object.amount))
    })?;
    let unit = CurrencyUnit::from_str(&object.currency)
        .map_err(|e| Error::DecodeFailed(format!("request currency {:?}: {e}", object.currency)))?;

    let mut mints = Vec::with_capacity(object.method_details.mints.len());
    for m in &object.method_details.mints {
        mints.push(
            MintUrl::from_str(m)
                .map_err(|e| Error::DecodeFailed(format!("methodDetails mint {m:?}: {e}")))?,
        );
    }

    // The inner creqA is the ground truth for the accepted mints; methodDetails
    // MUST be a non-empty superset of it.
    let creq = PaymentRequest::from_str(&object.method_details.request)
        .map_err(|e| Error::DecodeFailed(format!("methodDetails.request creqA: {e}")))?;
    if mints.is_empty() {
        return Err(Error::DecodeFailed(
            "methodDetails.mints is empty (spec requires a non-empty superset of the creqA mints)"
                .to_string(),
        ));
    }
    for cm in &creq.mints {
        if !mints.contains(cm) {
            return Err(Error::DecodeFailed(format!(
                "methodDetails.mints is not a superset of the creqA mints (missing {cm})"
            )));
        }
    }

    Ok(DecodedChargeRequest {
        amount: Amount::from(amount_u64),
        unit,
        mints,
        description: object.description,
        external_id: object.external_id,
        creq_a: object.method_details.request,
    })
}

/// Decode the `cashuB…` token the client returns on retry.
///
/// CONTRACT: cashuB / TokenV4 ONLY. A `cashuA…` (TokenV3) is REJECTED at the
/// prefix (`InvalidHeader`) even though well-formed — V3 makes the unit optional
/// and lacks the V4 keyset framing the swap relies on. Gating before the parse
/// keeps any V3 token from reaching the validator. `DecodeFailed` is for a
/// malformed cashuB payload.
pub fn decode_token(token_str: &str) -> Result<Token, Error> {
    let trimmed = token_str.trim();
    if trimmed.starts_with("cashuA") {
        // A valid TokenV3, but out of contract — reject so the caller's body
        // names the cashuB-only rule rather than failing later on a missing unit.
        return Err(Error::InvalidHeader(
            "cashuA (TokenV3) is not accepted; this intent is cashuB/TokenV4 only".to_string(),
        ));
    }
    if !trimmed.starts_with("cashuB") {
        return Err(Error::InvalidHeader(format!(
            "expected cashuB prefix, got {:?}",
            trimmed.chars().take(8).collect::<String>()
        )));
    }
    Token::from_str(trimmed).map_err(|e| Error::DecodeFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{decode_request_envelope, encode_request_envelope};

    fn sample_requirement() -> CashuRequirement {
        CashuRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![
                MintUrl::from_str("https://mint1.example.com").expect("valid mint url"),
                MintUrl::from_str("https://mint2.example.com").expect("valid mint url"),
            ],
            amount: Amount::from(42),
            payment_id: Some("pop-test-id".to_string()),
            description: Some("test challenge".to_string()),
            single_use: true,
        }
    }

    #[test]
    fn encode_challenge_has_creqa_prefix() {
        let req = sample_requirement();
        let encoded = encode_challenge(&req);
        assert!(
            encoded.starts_with("creqA"),
            "expected creqA prefix, got {}",
            &encoded[..encoded.len().min(16)]
        );
    }

    #[test]
    fn encode_challenge_roundtrips_through_payment_request() {
        let req = sample_requirement();
        let encoded = encode_challenge(&req);

        let parsed = PaymentRequest::from_str(&encoded).expect("decodes as PaymentRequest");

        assert_eq!(parsed.payment_id, req.payment_id);
        assert_eq!(parsed.amount, Some(req.amount));
        assert_eq!(parsed.unit, Some(req.unit.clone()));
        assert_eq!(parsed.single_use, Some(req.single_use));
        assert_eq!(parsed.mints, req.mints);
        assert_eq!(parsed.description, req.description);
        assert!(
            parsed.transports.is_empty(),
            "in-band challenge: transports must be empty"
        );
        assert!(parsed.nut10.is_none(), "bearer charge: nut10 must be None");
    }

    #[test]
    fn encode_challenge_preserves_pop_custom_unit() {
        // The `pop_<ts>` custom unit must survive the CBOR round-trip unchanged.
        let req = CashuRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![],
            amount: Amount::from(1),
            payment_id: None,
            description: None,
            single_use: false,
        };
        let parsed = PaymentRequest::from_str(&encode_challenge(&req)).unwrap();
        assert_eq!(
            parsed.unit,
            Some(CurrencyUnit::Custom("pop_1700000000".to_string()))
        );
    }

    /// A real `cashuB` test vector (cashu-0.16.0).
    const VALID_CASHU_B: &str = "cashuBpGF0gaJhaUgArSaMTR9YJmFwgaNhYQFhc3hAOWE2ZGJiODQ3YmQyMzJiYTc2ZGIwZGYxOTcyMTZiMjlkM2I4Y2MxNDU1M2NkMjc4MjdmYzFjYzk0MmZlZGI0ZWFjWCEDhhhUP_trhpXfStS6vN6So0qWvc2X3O4NfM-Y1HISZ5JhZGlUaGFuayB5b3VhbXVodHRwOi8vbG9jYWxob3N0OjMzMzhhdWNzYXQ=";

    #[test]
    fn decode_token_accepts_valid_cashub() {
        let token = decode_token(VALID_CASHU_B).expect("decodes valid cashuB token");
        let reencoded = token.to_string();
        assert!(
            reencoded.starts_with("cashuB"),
            "expected cashuB roundtrip, got {}",
            &reencoded[..reencoded.len().min(8)]
        );
    }

    #[test]
    fn decode_token_trims_whitespace() {
        let padded = format!("  {VALID_CASHU_B}\n");
        decode_token(&padded).expect("trimmed whitespace decodes");
    }

    #[test]
    fn decode_token_rejects_unknown_prefix() {
        let err = decode_token("notatoken").expect_err("should reject unknown prefix");
        assert!(
            matches!(err, Error::InvalidHeader(_)),
            "expected InvalidHeader, got {err:?}"
        );
    }

    /// A real, well-formed `cashuA` (TokenV3) vector (cashu-0.16.0) — out of
    /// contract, so `decode_token` must reject it at the prefix.
    const VALID_CASHU_A_V3: &str = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRhNTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFhZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3JldCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJmNjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1dfV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91IHZlcnkgbXVjaC4ifQ==";

    #[test]
    fn decode_token_rejects_cashu_a_v3() {
        // cashuA must reject at the prefix as InvalidHeader (not DecodeFailed).
        let err = decode_token(VALID_CASHU_A_V3).expect_err("cashuA must be rejected");
        match err {
            Error::InvalidHeader(msg) => {
                assert!(
                    msg.to_ascii_lowercase().contains("cashua")
                        || msg.contains("TokenV3")
                        || msg.contains("cashuB"),
                    "rejection should name the cashuB-only rule, got: {msg}"
                );
            }
            other => panic!("expected InvalidHeader for cashuA, got {other:?}"),
        }
    }

    #[test]
    fn decode_token_rejects_cashu_a_even_with_whitespace() {
        // The prefix gate runs after trim.
        let padded = format!("  {VALID_CASHU_A_V3}\n");
        let err = decode_token(&padded).expect_err("padded cashuA must be rejected");
        assert!(matches!(err, Error::InvalidHeader(_)), "got {err:?}");
    }

    #[test]
    fn decode_token_rejects_empty_input() {
        let err = decode_token("").expect_err("should reject empty input");
        assert!(matches!(err, Error::InvalidHeader(_)));
    }

    #[test]
    fn decode_token_rejects_malformed_cashub_payload() {
        // Valid prefix, garbage payload → DecodeFailed, not InvalidHeader.
        let err = decode_token("cashuB!!!notbase64!!!")
            .expect_err("malformed payload should fail to decode");
        assert!(
            matches!(err, Error::DecodeFailed(_)),
            "expected DecodeFailed, got {err:?}"
        );
    }

    #[test]
    fn creqa_request_envelope_roundtrips() {
        // creqA → request-envelope → creqA.
        let req = sample_requirement();
        let creq = encode_challenge(&req);
        let envelope = encode_request_envelope(&creq);
        let unwrapped = decode_request_envelope(&envelope)
            .expect("request envelope round-trips");
        assert_eq!(unwrapped, creq);
        assert!(unwrapped.starts_with("creqA"));
    }

    #[test]
    fn charge_request_roundtrips_through_request_object() {
        // requirement → spec request object → decoded amount/unit/mints + creqA.
        let req = sample_requirement();
        let encoded = encode_charge_request(&req);
        let decoded = decode_charge_request(&encoded).expect("charge request round-trips");
        assert_eq!(decoded.amount, req.amount);
        assert_eq!(decoded.unit, req.unit);
        assert_eq!(decoded.mints, req.mints);
        assert_eq!(decoded.description, req.description);
        assert_eq!(decoded.external_id, req.payment_id);
        assert!(decoded.creq_a.starts_with("creqA"));
    }

    #[test]
    fn decode_charge_request_rejects_mints_subset() {
        // methodDetails.mints MUST be a superset of the creqA's mints. Hand-build
        // an object whose creqA names two mints but methodDetails names only one.
        let req = sample_requirement(); // creqA carries mint1 + mint2
        let creq = encode_challenge(&req);
        let object = RequestObject {
            amount: u64::from(req.amount).to_string(),
            currency: req.unit.to_string(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                request: creq,
                mints: vec!["https://mint1.example.com".into()], // missing mint2
            },
        };
        let err = decode_charge_request(&encode_request_object(&object))
            .expect_err("a mints-subset must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_empty_mints() {
        // A requirement with no mints yields an empty methodDetails.mints, which
        // the spec forbids (must be a non-empty superset).
        let req = CashuRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![],
            amount: Amount::from(5),
            payment_id: None,
            description: None,
            single_use: false,
        };
        let encoded = encode_charge_request(&req);
        let err = decode_charge_request(&encoded).expect_err("empty mints must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }
}
