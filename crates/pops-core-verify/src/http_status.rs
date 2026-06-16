//! Native adapter lifting the single-sourced [`problem_mapping`] status into
//! `http::StatusCode`.
//!
//! The mapping itself (status + problem type + slug) lives in
//! [`crate::problem`], feature-independent, so every host — the axum
//! middlewares, `pops-gateway`, the wasm surface — derives from ONE table and
//! the 503/400/402 trichotomy cannot drift between them.

use crate::charge::ChargeError;
use crate::problem::problem_mapping;
use http::StatusCode;

/// Map a [`ChargeError`] to its HTTP status per `draft-cashu-charge-00` §Errors
/// — the [`problem_mapping`] status as a typed `StatusCode`.
///
/// THE load-bearing trichotomy (see the [`ChargeError`] banner): a transport
/// failure ([`ChargeError::MintUnreachable`]) is `503` — the token is NOT
/// consumed and the caller MAY retry it, so it MUST NEVER collapse into a `402`
/// ("your payment was wrong, re-pay"). A malformed *request frame*
/// ([`ChargeError::MalformedRequest`]) and an unsupported method
/// ([`ChargeError::MethodUnsupported`]) are `400`. EVERY other variant —
/// verification failures and a malformed *credential* — is `402` with a fresh
/// re-challenge.
pub fn charge_error_status(e: &ChargeError) -> StatusCode {
    StatusCode::from_u16(problem_mapping(e).status)
        .expect("problem_mapping emits only valid HTTP statuses")
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
    fn method_unsupported_is_400() {
        let e = ChargeError::MethodUnsupported {
            method: "tempo".into(),
        };
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
            ChargeError::PaymentInsufficient {
                required: 2,
                presented: 1,
                amount: 2,
                expected_swap_fee: 0,
            },
            ChargeError::FeeTooHigh {
                keyset_id: "009a1f293253e41e".into(),
                input_fee_ppk: 100,
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
