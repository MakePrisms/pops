//! Cashu-free codec for the NUT-24 `X-Cashu` HTTP transport (the
//! WASM-targetable layer, like [`crate::envelope`]: no `cashu` types, no
//! `serde`/`base64` envelope at all).
//!
//! NUT-24 is a bare-header transport: a single header name, `X-Cashu`, carries
//! both directions verbatim — no JSON wrapper, no auth-param echo. The challenge
//! is a `402` with `X-Cashu: <creqA…>` (the [`encode_challenge`] output as the
//! raw header value); the payment is a retry with `X-Cashu: <cashuB…>` (the
//! NUT-00 V4 token as the raw header value, handed to
//! [`crate::challenge::decode_token`]).
//!
//! This module is the inbound trim/outbound passthrough only; every structural
//! decision (token prefix, CBOR shape, unit/mint/amount) belongs to
//! [`crate::challenge`] and the [`Redeemer`][crate::redeemer::Redeemer].
//!
//! [`encode_challenge`]: crate::challenge::encode_challenge

use crate::challenge::{encode_challenge, CashuRequirement};
use crate::envelope::AuthParseError;

/// HTTP header carrying both the NUT-24 challenge (`creqA…`) and the payment
/// (`cashuB…`). Matched case-insensitively by `http::HeaderName` at the axum
/// layer; this constant is the canonical spelling for emission.
pub const X_CASHU: &str = "X-Cashu";

/// Build the `X-Cashu` challenge header value: the bare `creqA…` for `req`.
///
/// There is no inverse envelope — the header value IS the `creqA`, so this is
/// [`encode_challenge`] verbatim, named as
/// the one transport entry point for the `X-Cashu` wire.
pub fn xcashu_challenge_value(req: &CashuRequirement) -> String {
    encode_challenge(req)
}

/// Extract the presented `cashuB…` token string from an `X-Cashu` request
/// header value.
///
/// NUT-24 carries the token raw, so this only trims surrounding whitespace; the
/// prefix and structural validation are [`decode_token`][crate::challenge::decode_token]'s
/// job. An empty (or whitespace-only) value is the one failure this layer can
/// see — there is no token to forward — and maps to
/// [`AuthParseError::MissingCredentials`].
pub fn xcashu_token_from_header(header_value: &str) -> Result<String, AuthParseError> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return Err(AuthParseError::MissingCredentials);
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::CashuRequirement;
    use cashu::nuts::CurrencyUnit;
    use cashu::{Amount, MintUrl};
    use std::str::FromStr;

    fn sample_requirement() -> CashuRequirement {
        CashuRequirement {
            unit: CurrencyUnit::Custom("pop_1700000000".to_string()),
            mints: vec![MintUrl::from_str("https://mint-a.example.com").expect("valid mint url")],
            amount: Amount::from(10),
            external_id: None,
            description: None,
        }
    }

    #[test]
    fn challenge_value_is_a_bare_creqa() {
        let value = xcashu_challenge_value(&sample_requirement());
        assert!(
            value.starts_with("creqA"),
            "X-Cashu challenge value must be a bare creqA, got: {}",
            &value[..value.len().min(16)]
        );
    }

    #[test]
    fn challenge_value_equals_encode_challenge() {
        // The transport adds no wrapper: the value is encode_challenge verbatim.
        let req = sample_requirement();
        assert_eq!(xcashu_challenge_value(&req), encode_challenge(&req));
    }

    #[test]
    fn token_from_header_returns_the_bare_token() {
        let token = xcashu_token_from_header("cashuBabc").expect("non-empty value parses");
        assert_eq!(token, "cashuBabc");
    }

    #[test]
    fn token_from_header_trims_surrounding_whitespace() {
        let token = xcashu_token_from_header("  cashuBabc\n").expect("trimmed value parses");
        assert_eq!(token, "cashuBabc");
    }

    #[test]
    fn token_from_header_does_not_validate_prefix() {
        // Structural validation is decode_token's job; the codec forwards a
        // non-cashuB string unchanged so the prefix rule is enforced in one place.
        let token = xcashu_token_from_header("cashuAxyz").expect("forwarded unchanged");
        assert_eq!(token, "cashuAxyz");
    }

    #[test]
    fn empty_header_value_is_missing_credentials() {
        assert_eq!(
            xcashu_token_from_header("").unwrap_err(),
            AuthParseError::MissingCredentials
        );
    }

    #[test]
    fn whitespace_only_header_value_is_missing_credentials() {
        assert_eq!(
            xcashu_token_from_header("   \t  ").unwrap_err(),
            AuthParseError::MissingCredentials
        );
    }
}
