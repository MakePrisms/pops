//! Cashu-typed challenge encode + token decode helpers for the `Payment`
//! auth-scheme. This is the cashu-coupled `creqA` layer (the cashu-free
//! request/credentials envelopes live in [`crate::envelope`]). It compiles on
//! both native and wasm (cashu compiles to wasm), but is NOT re-exported on
//! the wasm-bindgen surface — only the envelope codec is (Step 1).
//!
//! [`CashuRequirement`] is the cashu-typed verifier-side description of what a
//! holder must present: a Cashu mint set, unit, amount and metadata.
//! [`encode_challenge`] serializes it into the `creqA...` string the server
//! carries inside the `request` auth-param on the 402 response.
//! [`decode_token`] parses the `cashuB...` token the client returns inside the
//! credentials payload on retry.
//!
//! Transports are left empty: the challenge travels in-band over HTTP, so
//! no separate Nostr/HTTPS transport hop is advertised. `nut10` is left
//! `None`: a bearer charge has no spend lock.
//!
//! [`CashuRequirement.unit`] is expected to be `CurrencyUnit::Custom("pop_<ts>")`
//! for PoP credentials, but this module does not enforce the prefix — it only
//! round-trips whatever unit the caller supplies. (The decoupled
//! `String`/`u64` [`ChargeRequirement`][crate::credential::ChargeRequirement]
//! is the ecash-agnostic seam; this `CashuRequirement` is its cashu-typed
//! sibling used only to build the `creqA`.)

use cashu::nuts::nut18::PaymentRequest;
use cashu::nuts::CurrencyUnit;
use cashu::{Amount, MintUrl, Token};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::error::Error;

/// What the verifier requires from a holder for a single charge challenge
/// (cashu-typed). Maps onto the underlying Cashu `PaymentRequest` fields the
/// verifier cares about. `single_use` is forwarded as-is; enforcing replay
/// semantics is the verifier's responsibility, not this module's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuRequirement {
    /// Currency unit the proofs must carry. For PoP this is
    /// `CurrencyUnit::Custom("pop_<unix_ts>")` where `<unix_ts>` is the
    /// CLTV expiry of the credential.
    pub unit: CurrencyUnit,
    /// Mints the verifier accepts. Empty means "any mint" — callers that
    /// want a closed set must populate this.
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

/// Encode a [`CashuRequirement`] into the `creqA...` string that becomes the
/// `cashu_request` field inside the `request` auth-param on a 402 response.
///
/// Cannot fail: the CBOR + base64url encoding of these fields is
/// infallible.
pub fn encode_challenge(req: &CashuRequirement) -> String {
    req.to_payment_request().to_string()
}

/// Decode the `cashuB.../cashuA...` token string the client returns in
/// the credentials payload on a retry.
///
/// Returns `InvalidHeader` when the value lacks a recognized cashu token
/// prefix, `DecodeFailed` when the payload itself is malformed.
pub fn decode_token(token_str: &str) -> Result<Token, Error> {
    let trimmed = token_str.trim();
    if !(trimmed.starts_with("cashuA") || trimmed.starts_with("cashuB")) {
        return Err(Error::InvalidHeader(format!(
            "expected cashuA/cashuB prefix, got {:?}",
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
        // The "pop_<ts>" custom unit must survive the CBOR round-trip
        // unchanged — the verifier later parses the timestamp out of it.
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

    /// `cashuB` test vector lifted from cashu-0.16.0
    /// `nuts::nut00::token::tests` so we exercise a real token without
    /// pulling in additional fixtures.
    const VALID_CASHU_B: &str = "cashuBpGF0gaJhaUgArSaMTR9YJmFwgaNhYQFhc3hAOWE2ZGJiODQ3YmQyMzJiYTc2ZGIwZGYxOTcyMTZiMjlkM2I4Y2MxNDU1M2NkMjc4MjdmYzFjYzk0MmZlZGI0ZWFjWCEDhhhUP_trhpXfStS6vN6So0qWvc2X3O4NfM-Y1HISZ5JhZGlUaGFuayB5b3VhbXVodHRwOi8vbG9jYWxob3N0OjMzMzhhdWNzYXQ=";

    #[test]
    fn decode_token_accepts_valid_cashub() {
        let token = decode_token(VALID_CASHU_B).expect("decodes valid cashuB token");
        // Sanity: re-encoding yields a cashuB string again.
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

    #[test]
    fn decode_token_rejects_empty_input() {
        let err = decode_token("").expect_err("should reject empty input");
        assert!(matches!(err, Error::InvalidHeader(_)));
    }

    #[test]
    fn decode_token_rejects_malformed_cashub_payload() {
        // Valid prefix, garbage payload — must surface as DecodeFailed,
        // not InvalidHeader.
        let err = decode_token("cashuB!!!notbase64!!!")
            .expect_err("malformed payload should fail to decode");
        assert!(
            matches!(err, Error::DecodeFailed(_)),
            "expected DecodeFailed, got {err:?}"
        );
    }

    #[test]
    fn creqa_request_envelope_roundtrips() {
        // The creqA → request-envelope → creqA path (the cashu-typed
        // requirement feeding the cashu-free envelope codec).
        let req = sample_requirement();
        let creq = encode_challenge(&req);
        let envelope = encode_request_envelope(&creq);
        let unwrapped = decode_request_envelope(&envelope)
            .expect("request envelope round-trips");
        assert_eq!(unwrapped, creq);
        assert!(unwrapped.starts_with("creqA"));
    }
}
