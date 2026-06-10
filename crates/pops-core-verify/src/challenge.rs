//! The cashu-coupled `creqA` layer (the cashu-free envelopes live in
//! [`crate::envelope`]). [`encode_challenge`] serializes a [`CashuRequirement`]
//! into the opaque `creqA…`; [`encode_charge_request`] wraps it in the
//! `draft-cashu-charge-01` request object the 402's `request` auth-param carries
//! (`methodDetails.paymentRequest`, the authoritative artifact), and
//! [`decode_charge_request`] reads that object back, enforcing the spec's
//! creqA requirements (`a`/`u`/non-empty-`m` present, top-level
//! `amount`/`currency` matching them, empty transports, single-use true, no
//! `nut10`); [`decode_token`] parses the `cashuB…` token the client returns on
//! retry.
//!
//! The emitted creqA carries `single_use: true` and no payment id (`i`); its
//! transports are empty (the challenge is in-band) and `nut10` is `None` (a
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

/// What the verifier requires from a holder (cashu-typed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuRequirement {
    /// Currency unit the proofs must carry (`pop_<unix_ts>` for PoP).
    pub unit: CurrencyUnit,
    /// Mints the verifier accepts. Empty means "any mint" at the validator and
    /// on the bare-creqA `X-Cashu` transport; a `Payment` charge challenge
    /// cannot be emitted from an empty set ([`encode_charge_request`] requires
    /// a non-empty `m`).
    pub mints: Vec<MintUrl>,
    /// Exact amount of proofs required.
    pub amount: Amount,
    /// Optional merchant reference echoed as the request object's top-level
    /// `externalId` and in the receipt. It is NOT the creqA payment id (`i`),
    /// which the charge method omits.
    pub external_id: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
}

impl CashuRequirement {
    /// Construct the underlying `PaymentRequest` with no transports (the
    /// challenge is in-band) and no spending conditions (bearer charge).
    fn to_payment_request(&self) -> PaymentRequest {
        PaymentRequest {
            // The challenge `id` identifies the payment, so the creqA carries no
            // `i`; under stateless binding `id` is over the request bytes, which
            // no embedded value can equal.
            payment_id: None,
            amount: Some(self.amount),
            unit: Some(self.unit.clone()),
            // A challenge identifies one payment.
            single_use: Some(true),
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

/// The decoded `draft-cashu-charge-01` request object: the payment parameters
/// derived from the authoritative `methodDetails.paymentRequest` (already
/// checked against the top-level `amount`/`currency`), plus the opaque `creqA…`
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedChargeRequest {
    /// Exact amount required (the creqA's `a`, equal to the top-level `amount`).
    pub amount: Amount,
    /// Currency unit the proofs must carry (the creqA's `u`, equal to the
    /// top-level `currency`).
    pub unit: CurrencyUnit,
    /// Mints the verifier accepts: the creqA's `m`, always non-empty.
    pub mints: Vec<MintUrl>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Optional external correlation id.
    pub external_id: Option<String>,
    /// The opaque `creqA…` carried under `methodDetails.paymentRequest`.
    pub creq_a: String,
}

/// Build the `draft-cashu-charge-01` request object for the 402's `request`
/// auth-param: the spec amount/currency/description plus
/// `methodDetails.paymentRequest` (the creqA, carrying the same amount/unit and
/// the accepted mint set). Returns the base64url-nopad JCS string
/// (`encode_request_object`).
///
/// The spec REQUIRES the emitted creqA to carry `a`, `u`, and a NON-EMPTY `m`;
/// `a`/`u` always exist on a [`CashuRequirement`], so the one emit-side failure
/// is a requirement naming no mints — [`Error::EncodeFailed`].
pub fn encode_charge_request(req: &CashuRequirement) -> Result<String, Error> {
    if req.mints.is_empty() {
        return Err(Error::EncodeFailed(
            "requirement names no mints; the charge challenge requires a non-empty \
             mint set (`m`) in its payment request"
                .to_string(),
        ));
    }
    let object = RequestObject {
        amount: u64::from(req.amount).to_string(),
        currency: req.unit.to_string(),
        description: req.description.clone(),
        external_id: req.external_id.clone(),
        method_details: MethodDetails {
            payment_request: encode_challenge(req),
        },
    };
    Ok(encode_request_object(&object))
}

/// Decode the 402's `request` auth-param into a [`DecodedChargeRequest`],
/// enforcing the `draft-cashu-charge-01` rules on the embedded payment request
/// (the authoritative artifact):
///
/// - the creqA MUST carry `a` (amount), `u` (unit), and a NON-EMPTY `m` (mints);
/// - the top-level `amount`/`currency` MUST equal the creqA's `a`/`u`
///   (amounts compared as integers);
/// - the creqA's transport set MUST be empty (the credential is in-band);
/// - the creqA's single-use flag MUST be true (a challenge identifies one
///   payment);
/// - the creqA MUST carry no `nut10` spending condition (bearer-only profile —
///   rejecting here is what lets a future locked profile degrade closed).
///
/// Any violation, an unparseable creqA, or a non-decimal `amount` is a
/// [`Error::DecodeFailed`].
pub fn decode_charge_request(b64: &str) -> Result<DecodedChargeRequest, Error> {
    let object = decode_request_object(b64)?;

    let amount_u64: u64 = object.amount.parse().map_err(|e| {
        Error::DecodeFailed(format!("request amount {:?} is not a decimal: {e}", object.amount))
    })?;
    let unit = CurrencyUnit::from_str(&object.currency)
        .map_err(|e| Error::DecodeFailed(format!("request currency {:?}: {e}", object.currency)))?;

    let creq = PaymentRequest::from_str(&object.method_details.payment_request)
        .map_err(|e| Error::DecodeFailed(format!("methodDetails.paymentRequest creqA: {e}")))?;

    let creq_amount = creq.amount.ok_or_else(|| {
        Error::DecodeFailed("payment request omits `a` (amount); the charge method requires it".to_string())
    })?;
    let creq_unit = creq.unit.clone().ok_or_else(|| {
        Error::DecodeFailed("payment request omits `u` (unit); the charge method requires it".to_string())
    })?;
    if creq.mints.is_empty() {
        return Err(Error::DecodeFailed(
            "payment request omits `m` (mints); the charge method requires a non-empty mint set"
                .to_string(),
        ));
    }

    if u64::from(creq_amount) != amount_u64 {
        return Err(Error::DecodeFailed(format!(
            "request `amount` ({amount_u64}) does not equal the payment request's `a` ({})",
            u64::from(creq_amount)
        )));
    }
    if creq_unit != unit {
        return Err(Error::DecodeFailed(format!(
            "request `currency` ({unit}) does not equal the payment request's `u` ({creq_unit})"
        )));
    }

    if !creq.transports.is_empty() {
        return Err(Error::DecodeFailed(
            "payment request names a transport; the charge credential is in-band \
             (the transport set must be empty)"
                .to_string(),
        ));
    }
    if creq.single_use != Some(true) {
        return Err(Error::DecodeFailed(
            "payment request single-use flag is not true; a charge challenge \
             identifies one payment"
                .to_string(),
        ));
    }
    if creq.nut10.is_some() {
        return Err(Error::DecodeFailed(
            "payment request carries a nut10 spending condition; this bearer-only \
             profile requires it absent"
                .to_string(),
        ));
    }

    Ok(DecodedChargeRequest {
        amount: Amount::from(amount_u64),
        unit,
        mints: creq.mints,
        description: object.description,
        external_id: object.external_id,
        creq_a: object.method_details.payment_request,
    })
}

/// Whether a mint URL carries RFC 3986 userinfo (`user@host`): an `@` inside
/// the authority component (between the scheme's `://` and the first `/`, `?`,
/// or `#`). The spec's mint-trust § rejects such a URL outright — token-side as
/// a verification failure, operator-side as a config error.
pub fn mint_url_has_userinfo(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme[..end].contains('@')
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

    fn sample_requirement() -> CashuRequirement {
        CashuRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![
                MintUrl::from_str("https://mint1.example.com").expect("valid mint url"),
                MintUrl::from_str("https://mint2.example.com").expect("valid mint url"),
            ],
            amount: Amount::from(42),
            external_id: Some("inv-7".to_string()),
            description: Some("test challenge".to_string()),
        }
    }

    #[test]
    fn mint_url_userinfo_detection_is_scoped_to_the_authority() {
        for url in [
            "https://user@mint.example.com",
            "https://user:pw@mint.example.com:3338/path",
            "http://a@b",
        ] {
            assert!(mint_url_has_userinfo(url), "{url} carries userinfo");
        }
        for url in [
            "https://mint.example.com",
            "https://mint.example.com:3338/path",
            // `@` outside the authority is NOT userinfo.
            "https://mint.example.com/path@segment",
            "https://mint.example.com/?q=a@b",
        ] {
            assert!(!mint_url_has_userinfo(url), "{url} carries no userinfo");
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

        assert_eq!(parsed.payment_id, None, "creqA omits the payment id `i`");
        assert_eq!(parsed.amount, Some(req.amount));
        assert_eq!(parsed.unit, Some(req.unit.clone()));
        assert_eq!(parsed.single_use, Some(true), "single-use is pinned true");
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
            external_id: None,
            description: None,
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
    fn charge_request_roundtrips_through_request_object() {
        // requirement → spec request object → decoded amount/unit/mints + creqA.
        let req = sample_requirement();
        let encoded = encode_charge_request(&req).expect("encodes");
        let decoded = decode_charge_request(&encoded).expect("charge request round-trips");
        assert_eq!(decoded.amount, req.amount);
        assert_eq!(decoded.unit, req.unit);
        assert_eq!(decoded.mints, req.mints);
        assert_eq!(decoded.description, req.description);
        assert_eq!(decoded.external_id, req.external_id);
        assert!(decoded.creq_a.starts_with("creqA"));
    }

    /// Hand-build the request object around an arbitrary `PaymentRequest`, so
    /// each reject test controls exactly one creqA property. `amount`/`currency`
    /// default to the creqA's own values (overridable for the mismatch tests).
    fn object_for(creq: &PaymentRequest, amount: &str, currency: &str) -> String {
        encode_request_object(&RequestObject {
            amount: amount.to_string(),
            currency: currency.to_string(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                payment_request: creq.to_string(),
            },
        })
    }

    /// A fully spec-conformant `PaymentRequest` to mutate per test.
    fn conformant_creq() -> PaymentRequest {
        sample_requirement().to_payment_request()
    }

    #[test]
    fn encode_charge_request_rejects_empty_mints() {
        // Emit-side enforcement: the spec requires a non-empty `m`, so a
        // requirement naming no mints cannot become a challenge.
        let req = CashuRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![],
            amount: Amount::from(5),
            external_id: None,
            description: None,
        };
        let err = encode_charge_request(&req).expect_err("no-mints requirement must not encode");
        assert!(matches!(err, Error::EncodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_creqa_missing_amount() {
        let mut creq = conformant_creq();
        creq.amount = None;
        let err = decode_charge_request(&object_for(&creq, "42", "pop_1700000000"))
            .expect_err("creqA without `a` must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_creqa_missing_unit() {
        let mut creq = conformant_creq();
        creq.unit = None;
        let err = decode_charge_request(&object_for(&creq, "42", "pop_1700000000"))
            .expect_err("creqA without `u` must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_creqa_empty_mints() {
        let mut creq = conformant_creq();
        creq.mints = vec![];
        let err = decode_charge_request(&object_for(&creq, "42", "pop_1700000000"))
            .expect_err("creqA without a non-empty `m` must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_amount_disagreeing_with_creqa() {
        // Top-level `amount` and creqA `a` are compared as integers; any
        // disagreement is a tampered/inconsistent challenge.
        let creq = conformant_creq(); // a = 42
        let err = decode_charge_request(&object_for(&creq, "43", "pop_1700000000"))
            .expect_err("amount ≠ creqA `a` must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_currency_disagreeing_with_creqa() {
        let creq = conformant_creq(); // u = pop_1700000000
        let err = decode_charge_request(&object_for(&creq, "42", "sat"))
            .expect_err("currency ≠ creqA `u` must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_nonempty_transports() {
        use cashu::nuts::nut18::{Transport, TransportType};
        let mut creq = conformant_creq();
        creq.transports = vec![Transport {
            _type: TransportType::HttpPost,
            target: "https://elsewhere.example/pay".to_string(),
            tags: Vec::new(),
        }];
        let err = decode_charge_request(&object_for(&creq, "42", "pop_1700000000"))
            .expect_err("a creqA naming a transport must be rejected (in-band only)");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_rejects_non_single_use_challenge() {
        // Spec Method Details: a client MUST reject a challenge whose single-use
        // flag is not true, the same family as the amount/currency mismatch and
        // nut10 rejections.
        for flag in [None, Some(false)] {
            let mut creq = conformant_creq();
            creq.single_use = flag;
            let err = decode_charge_request(&object_for(&creq, "42", "pop_1700000000"))
                .expect_err("a non-single-use challenge must be rejected");
            assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
        }
    }

    #[test]
    fn decode_charge_request_rejects_nut10_locked_challenge() {
        // Bearer-only profile: a nut10-carrying challenge must be rejected by
        // the client, so a future locked profile degrades closed.
        use cashu::nuts::nut10::Kind;
        use cashu::nuts::nut18::Nut10SecretRequest;
        let mut creq = conformant_creq();
        creq.nut10 = Some(Nut10SecretRequest::new(
            Kind::P2PK,
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
            None::<Vec<Vec<String>>>,
        ));
        let err = decode_charge_request(&object_for(&creq, "42", "pop_1700000000"))
            .expect_err("a nut10-locked challenge must be rejected");
        assert!(matches!(err, Error::DecodeFailed(_)), "got {err:?}");
    }

    #[test]
    fn decode_charge_request_accepts_padded_creqa_inside_json() {
        // The creqA is an opaque string INSIDE the JSON; its own encoding allows
        // padding, so a padded creqA must be accepted (spec Encoding §) even
        // though the OUTER header value must be unpadded. Pick a description
        // length whose CBOR encodes with `=` padding so both forms are distinct.
        let (creq_padded, req) = (0..4usize)
            .map(|n| {
                let mut r = sample_requirement();
                r.description = Some("x".repeat(n));
                (r.to_payment_request().to_string(), r)
            })
            .find(|(s, _)| s.ends_with('='))
            .expect("some description length yields a padded creqA");
        let creq_unpadded = creq_padded.trim_end_matches('=').to_string();
        assert_ne!(creq_padded, creq_unpadded);
        for creq_str in [creq_padded, creq_unpadded] {
            let object = encode_request_object(&RequestObject {
                amount: u64::from(req.amount).to_string(),
                currency: req.unit.to_string(),
                description: None,
                external_id: None,
                method_details: MethodDetails {
                    payment_request: creq_str,
                },
            });
            let decoded =
                decode_charge_request(&object).expect("padded and unpadded creqA both decode");
            assert_eq!(decoded.amount, req.amount);
            assert_eq!(decoded.mints, req.mints);
        }
    }
}
