//! The single-sourced [`ChargeError`] → RFC-9457 problem mapping:
//! { absolute `type` URI, slug, HTTP status, title }.
//!
//! EVERY host emits its error wire from this one table — the axum
//! [`middleware`](crate::middleware), the NUT-24
//! [`middleware_xcashu`](crate::middleware_xcashu), `pops-gateway`, and the
//! wasm surface — so the spec mapping cannot drift between them. Statuses are
//! plain `u16` (no `http` dependency) so the table compiles on every feature
//! surface, wasm included; the native [`crate::http_status`] adapter lifts them
//! into `http::StatusCode`.
//!
//! URIs per `draft-cashu-charge-01` Errors § and the framework's problem
//! registry: the method defines NO problem types of its own — every 402 type
//! is a framework-registered `https://paymentauth.org/problems/<slug>`, and
//! mint unreachability carries no problem type at all (a plain 503 +
//! `Retry-After`, body `about:blank`). No relative URIs anywhere.

use serde::Serialize;

use crate::charge::ChargeError;

/// One row of the mapping: the spec problem type (or the RFC-9457 `about:blank`
/// fallback) plus the HTTP status a host MUST answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProblemMapping {
    /// The registered slug (`verification-failed`, `payment-insufficient`, …),
    /// or `None` where no problem type is registered (the `about:blank` rows).
    pub slug: Option<&'static str>,
    /// The ABSOLUTE `type` URI for the problem body.
    pub type_uri: &'static str,
    /// HTTP status the host answers with.
    pub status: u16,
    /// Short human-readable summary for the body's `title` member.
    pub title: &'static str,
}

/// The bare "resource requires payment, no attempt yet" challenge body — a
/// framework-registered type with no [`ChargeError`] (nothing failed).
pub const PAYMENT_REQUIRED: ProblemMapping = ProblemMapping {
    slug: Some("payment-required"),
    type_uri: "https://paymentauth.org/problems/payment-required",
    status: 402,
    title: "Payment Required",
};

/// Map a [`ChargeError`] onto its spec problem type + status.
///
/// THE load-bearing trichotomy: a transport failure
/// ([`ChargeError::MintUnreachable`]) is `503` — the token is NOT consumed and
/// the caller MAY retry it, so it MUST NEVER collapse into a `402` ("your
/// payment was wrong, re-pay"). A malformed *request frame*
/// ([`ChargeError::MalformedRequest`]) and an unsupported method
/// ([`ChargeError::MethodUnsupported`]) are `400` per the framework's status
/// handling. EVERY other variant — verification failures and a malformed
/// *credential* — is `402` with a fresh re-challenge.
pub fn problem_mapping(e: &ChargeError) -> ProblemMapping {
    const fn framework(
        slug: &'static str,
        type_uri: &'static str,
        status: u16,
        title: &'static str,
    ) -> ProblemMapping {
        ProblemMapping {
            slug: Some(slug),
            type_uri,
            status,
            title,
        }
    }

    match e {
        // Mint unreachability is an infrastructure failure, not a
        // payment-verification outcome, and carries NO problem type (spec
        // Errors §): a plain 503 + Retry-After with an about:blank body; the
        // token may still be good.
        ChargeError::MintUnreachable { .. } => ProblemMapping {
            slug: None,
            type_uri: "about:blank",
            status: 503,
            title: "Service Unavailable",
        },

        // The framework's payment-insufficient: the token's total value is
        // less than `amount + swap_fee` (spec step 8). There is no
        // over-payment counterpart — excess is accepted and retained.
        ChargeError::PaymentInsufficient { .. } => framework(
            "payment-insufficient",
            "https://paymentauth.org/problems/payment-insufficient",
            402,
            "Payment Insufficient",
        ),

        // Non-amount, non-expiry verification failures, per the spec's Errors §
        // list: unit mismatch (declared OR resolved-keyset, step 7), disallowed
        // mint, NUT-10 lock, unresolvable short keyset id, swap rejection
        // (double-spend, step 9), and the policy-disallowed fee-bearing keyset
        // ("unit otherwise disallowed by server policy"). A swap-output DLEQ
        // failure is deliberately NOT here — see the map tests: it is no
        // ChargeError at all.
        ChargeError::WrongUnit { .. }
        | ChargeError::MintNotAllowed { .. }
        | ChargeError::LockedToken
        | ChargeError::ShortKeysetIdUnresolved { .. }
        | ChargeError::DoubleSpend
        | ChargeError::FeeTooHigh { .. } => framework(
            "verification-failed",
            "https://paymentauth.org/problems/verification-failed",
            402,
            "Verification Failed",
        ),

        // Both expiry causes share one type per the spec (the client needs no
        // discriminator: re-present once, then abandon the token).
        ChargeError::Expired | ChargeError::ChallengeExpired => framework(
            "payment-expired",
            "https://paymentauth.org/problems/payment-expired",
            402,
            "Payment Expired",
        ),

        ChargeError::InvalidChallenge => framework(
            "invalid-challenge",
            "https://paymentauth.org/problems/invalid-challenge",
            402,
            "Invalid Challenge",
        ),

        // A bad credential is still a payment attempt → 402 + re-challenge
        // (the framework's status table), never a 400. The spec treats a
        // multi-mint/multi-unit token as a parse-level fault of the credential
        // (a valid TokenV4 structurally carries exactly one mint and unit), so
        // MultiMintOrUnit lands here rather than under verification-failed.
        ChargeError::MalformedCredential(_)
        | ChargeError::MultiMintOrUnit
        | ChargeError::TooManyProofs { .. } => framework(
            "malformed-credential",
            "https://paymentauth.org/problems/malformed-credential",
            402,
            "Malformed Credential",
        ),

        // Framework-registered 400: the credential names a method ≠ "cashu".
        ChargeError::MethodUnsupported { .. } => framework(
            "method-unsupported",
            "https://paymentauth.org/problems/method-unsupported",
            400,
            "Method Unsupported",
        ),

        // A malformed REQUEST (multiple Authorization: Payment credentials,
        // unparseable server-side requirement) is 400 per the framework WITHOUT
        // a registered problem type — RFC 9457's `about:blank` says "no
        // semantics beyond the status code". It MUST NOT borrow the
        // invalid-challenge slug (that is a 402 about the challenge echo).
        ChargeError::MalformedRequest(_) => ProblemMapping {
            slug: None,
            type_uri: "about:blank",
            status: 400,
            title: "Bad Request",
        },
        // Exhaustive ON PURPOSE (`ChargeError` is non_exhaustive only across
        // crates): a new variant fails compilation HERE, forcing a conscious
        // mapping decision instead of a silent default.
    }
}

/// An RFC-9457 `application/problem+json` body, identical across hosts:
/// `type` is the mapping's absolute URI, `status` mirrors the HTTP status,
/// `detail` is the error's `Display`.
#[derive(Debug, Clone, Serialize)]
pub struct Problem {
    /// Absolute problem-type URI.
    #[serde(rename = "type")]
    pub type_uri: &'static str,
    /// Human-readable summary of the problem type.
    pub title: &'static str,
    /// HTTP status, mirrored into the body per RFC 9457.
    pub status: u16,
    /// Human-readable detail for this occurrence.
    pub detail: String,
}

impl Problem {
    /// Build the problem body for a [`ChargeError`] from the shared mapping.
    pub fn for_error(e: &ChargeError) -> Self {
        let mapping = problem_mapping(e);
        Self {
            type_uri: mapping.type_uri,
            title: mapping.title,
            status: mapping.status,
            detail: e.to_string(),
        }
    }

    /// Build the bare "payment required, no attempt yet" body.
    pub fn payment_required(detail: impl Into<String>) -> Self {
        Self {
            type_uri: PAYMENT_REQUIRED.type_uri,
            title: PAYMENT_REQUIRED.title,
            status: PAYMENT_REQUIRED.status,
            detail: detail.into(),
        }
    }

    /// Serialize to the JSON body string. Infallible for these owned fields.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Problem always serializes")
    }
}

/// The `Content-Type` every problem body is served under.
pub const PROBLEM_JSON: &str = "application/problem+json";

#[cfg(test)]
mod tests {
    //! Pins the WHOLE map, documenting the spec choice for each variant
    //! (`draft-cashu-charge-01` Errors § + the framework's status table).

    use super::*;

    fn mint_unreachable() -> ChargeError {
        ChargeError::MintUnreachable {
            mint_url: "https://m.example".into(),
            transport_detail: "timeout".into(),
            indeterminate: false,
        }
    }

    #[test]
    fn mint_unreachable_is_plain_503_with_no_problem_type() {
        // Spec Errors §: mint unreachability is an infrastructure failure and
        // carries no problem type — a plain 503 (+ Retry-After at the hosts),
        // body about:blank. No cashu/ URI exists.
        let m = problem_mapping(&mint_unreachable());
        assert_eq!(m.slug, None);
        assert_eq!(m.type_uri, "about:blank");
        assert_eq!(m.status, 503);
    }

    #[test]
    fn payment_insufficient_is_the_framework_type_402() {
        // Spec step 8 + Errors §: an under-funded token is the framework's
        // payment-insufficient. Over-funding has no counterpart (accepted).
        let m = problem_mapping(&ChargeError::PaymentInsufficient {
            required: 10,
            presented: 8,
            amount: 10,
            expected_swap_fee: 0,
        });
        assert_eq!(m.slug, Some("payment-insufficient"));
        assert_eq!(
            m.type_uri,
            "https://paymentauth.org/problems/payment-insufficient"
        );
        assert_eq!(m.status, 402);
    }

    #[test]
    fn verification_failures_share_the_framework_type_402() {
        // Spec Errors §: every non-amount, non-expiry verification check —
        // including the fee-policy reject ("unit otherwise disallowed by
        // server policy") and a swap-rejected double-spend (step 9).
        //
        // DELIBERATELY ABSENT: a swap-output DLEQ failure. Spec step 9 +
        // §security-dleq make it a mint-trust incident, not a payment failure
        // ("The server MUST NOT fail the payment for it: it SHOULD serve the
        // resource, alert the operator, and quarantine the mint") — so the old
        // `ChargeError::DleqInvalid` variant was DELETED rather than kept as a
        // dead discriminant: no code path can produce a client-facing error
        // from that condition anymore. The verdict travels as
        // `Redeemed::dleq_ok` on the SUCCESS path instead.
        for e in [
            ChargeError::WrongUnit {
                expected: "pop_1".into(),
                got: "sat".into(),
            },
            ChargeError::MintNotAllowed {
                got: "https://evil.example".into(),
                allowed: vec!["https://m.example".into()],
            },
            ChargeError::LockedToken,
            ChargeError::ShortKeysetIdUnresolved {
                short_id: "00aabbccddeeff00".into(),
            },
            ChargeError::DoubleSpend,
            ChargeError::FeeTooHigh {
                keyset_id: "009a1f293253e41e".into(),
                input_fee_ppk: 100,
            },
        ] {
            let m = problem_mapping(&e);
            assert_eq!(m.slug, Some("verification-failed"), "{e}");
            assert_eq!(
                m.type_uri,
                "https://paymentauth.org/problems/verification-failed",
                "{e}"
            );
            assert_eq!(m.status, 402, "{e}");
        }
    }

    #[test]
    fn fee_too_high_detail_names_the_policy_not_a_double_spend() {
        // The reject must read as a policy denial with an honest detail —
        // never as a double-spend.
        let e = ChargeError::FeeTooHigh {
            keyset_id: "009a1f293253e41e".into(),
            input_fee_ppk: 250,
        };
        let p = Problem::for_error(&e);
        assert!(
            p.detail.contains("policy") && p.detail.contains("input_fee_ppk 250"),
            "detail must name the fee policy: {}",
            p.detail
        );
        assert!(
            !p.detail.contains("double-spend"),
            "a fee reject must not claim a double-spend: {}",
            p.detail
        );
    }

    #[test]
    fn both_expiry_causes_share_payment_expired_402() {
        // Spec: stale challenge echo AND keyset retirement/final_expiry both
        // map to payment-expired (the client needs no discriminator).
        for e in [ChargeError::Expired, ChargeError::ChallengeExpired] {
            let m = problem_mapping(&e);
            assert_eq!(m.slug, Some("payment-expired"), "{e}");
            assert_eq!(m.type_uri, "https://paymentauth.org/problems/payment-expired");
            assert_eq!(m.status, 402, "{e}");
        }
    }

    #[test]
    fn invalid_challenge_is_402() {
        let m = problem_mapping(&ChargeError::InvalidChallenge);
        assert_eq!(m.slug, Some("invalid-challenge"));
        assert_eq!(m.type_uri, "https://paymentauth.org/problems/invalid-challenge");
        assert_eq!(m.status, 402);
    }

    #[test]
    fn malformed_credential_proof_cap_and_multi_mint_are_402_not_400() {
        // Framework status table: a malformed CREDENTIAL is a 402 (it is still
        // a payment attempt, answered with a fresh challenge); the spec folds
        // the proof-count DoS bound AND the multi-mint/unit parse-level fault
        // into the same type (a valid TokenV4 carries exactly one mint/unit).
        for e in [
            ChargeError::MalformedCredential("bad base64".into()),
            ChargeError::MultiMintOrUnit,
            ChargeError::TooManyProofs { got: 99, max: 8 },
        ] {
            let m = problem_mapping(&e);
            assert_eq!(m.slug, Some("malformed-credential"), "{e}");
            assert_eq!(
                m.type_uri,
                "https://paymentauth.org/problems/malformed-credential"
            );
            assert_eq!(m.status, 402, "{e}");
        }
    }

    #[test]
    fn method_unsupported_is_400_with_its_own_framework_type() {
        // Spec Errors §: a credential naming an unsupported method follows the
        // framework's status handling — method-unsupported, HTTP 400, not a
        // 402 malformed-credential.
        let m = problem_mapping(&ChargeError::MethodUnsupported {
            method: "tempo".into(),
        });
        assert_eq!(m.slug, Some("method-unsupported"));
        assert_eq!(m.type_uri, "https://paymentauth.org/problems/method-unsupported");
        assert_eq!(m.status, 400);
    }

    #[test]
    fn malformed_request_is_400_about_blank_without_the_invalid_challenge_slug() {
        // The framework 400s a malformed request frame but registers NO problem
        // type for it; RFC 9457's about:blank is the correct `type`. The old
        // pairing (invalid-challenge slug on a 400) violated both halves:
        // invalid-challenge is a 402 type about the challenge echo.
        let m = problem_mapping(&ChargeError::MalformedRequest("two credentials".into()));
        assert_eq!(m.slug, None);
        assert_eq!(m.type_uri, "about:blank");
        assert_eq!(m.status, 400);
        assert_ne!(m.slug, Some("invalid-challenge"));
    }

    #[test]
    fn payment_required_constant_matches_the_framework_registry() {
        assert_eq!(PAYMENT_REQUIRED.slug, Some("payment-required"));
        assert_eq!(
            PAYMENT_REQUIRED.type_uri,
            "https://paymentauth.org/problems/payment-required"
        );
        assert_eq!(PAYMENT_REQUIRED.status, 402);
    }

    #[test]
    fn every_type_uri_is_absolute_and_no_cashu_namespace_remains() {
        // RFC 9457 `type` is a URI reference; the spec demands ABSOLUTE URIs
        // (about:blank included — it has a scheme). The method defines no
        // problem types of its own, so no cashu/-namespaced URI may exist.
        let all = [
            problem_mapping(&mint_unreachable()),
            problem_mapping(&ChargeError::DoubleSpend),
            problem_mapping(&ChargeError::Expired),
            problem_mapping(&ChargeError::InvalidChallenge),
            problem_mapping(&ChargeError::MalformedCredential("x".into())),
            problem_mapping(&ChargeError::MultiMintOrUnit),
            problem_mapping(&ChargeError::MethodUnsupported { method: "x".into() }),
            problem_mapping(&ChargeError::MalformedRequest("x".into())),
            problem_mapping(&ChargeError::PaymentInsufficient {
                required: 2,
                presented: 1,
                amount: 2,
                expected_swap_fee: 0,
            }),
            PAYMENT_REQUIRED,
        ];
        for m in all {
            assert!(
                m.type_uri.starts_with("https://paymentauth.org/problems/")
                    || m.type_uri == "about:blank",
                "non-absolute or off-registry type URI: {}",
                m.type_uri
            );
            assert!(
                !m.type_uri.contains("/problems/cashu/"),
                "no cashu/-namespaced problem type may remain: {}",
                m.type_uri
            );
        }
    }

    #[test]
    fn problem_body_mirrors_the_mapping() {
        let e = ChargeError::DoubleSpend;
        let p = Problem::for_error(&e);
        let m = problem_mapping(&e);
        assert_eq!(p.type_uri, m.type_uri);
        assert_eq!(p.title, m.title);
        assert_eq!(p.status, m.status);
        assert_eq!(p.detail, e.to_string());
        let v: serde_json::Value = serde_json::from_str(&p.to_json()).expect("valid JSON");
        assert_eq!(v["type"], m.type_uri);
        assert_eq!(v["status"], m.status);
    }
}
