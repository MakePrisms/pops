//! The load-bearing `ChargeError` → HTTP status mapping, single-sourced.
//!
//! Both the axum [`middleware`](crate::middleware) and out-of-crate hosts (e.g.
//! `pops-gateway`) derive their HTTP status from this one function, so the
//! 503/400/402 trichotomy the charge contract pins cannot drift between them.
//! The response *body* still differs per host (RFC-9457 `problem+json` in the
//! middleware, a flat advisory JSON in the gateway) — only the status decision
//! is shared.

use http::StatusCode;
use crate::charge::ChargeError;

/// Map a [`ChargeError`] to its HTTP status per `draft-cashu-charge-01` §Errors.
///
/// THE load-bearing trichotomy (see the [`ChargeError`] banner): a transport
/// failure ([`ChargeError::MintUnreachable`]) is `503` — the token is NOT
/// consumed and the caller MAY retry it, so it MUST NEVER collapse into a `402`
/// ("your payment was wrong, re-pay"). A malformed *request frame*
/// ([`ChargeError::MalformedRequest`]) is `400`. EVERY other variant —
/// verification failures and a malformed *credential* — is `402` with a fresh
/// re-challenge.
pub fn charge_error_status(e: &ChargeError) -> StatusCode {
    match e {
        ChargeError::MintUnreachable { .. } => StatusCode::SERVICE_UNAVAILABLE,
        ChargeError::MalformedRequest(_) => StatusCode::BAD_REQUEST,
        // `#[non_exhaustive]`: an unmodelled future variant degrades to the
        // conservative 402 (verification-failed), never a 503/400.
        _ => StatusCode::PAYMENT_REQUIRED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_unreachable_is_503() {
        let e = ChargeError::MintUnreachable {
            mint_url: "https://m".into(),
            transport_detail: "timeout".into(),
            indeterminate: false,
        };
        assert_eq!(charge_error_status(&e), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn malformed_request_is_400() {
        let e = ChargeError::MalformedRequest("two credentials".into());
        assert_eq!(charge_error_status(&e), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn verification_and_malformed_credential_are_402() {
        for e in [
            ChargeError::WrongUnit {
                expected: "pop_500000000".into(),
                got: "sat".into(),
            },
            ChargeError::DoubleSpend,
            ChargeError::MalformedCredential("bad base64".into()),
            ChargeError::TooManyProofs { got: 100, max: 64 },
            ChargeError::AmountMismatch {
                required: 1,
                presented: 2,
                amount: 1,
                expected_swap_fee: 0,
            },
        ] {
            assert_eq!(
                charge_error_status(&e),
                StatusCode::PAYMENT_REQUIRED,
                "{e} must map to 402"
            );
        }
    }
}
