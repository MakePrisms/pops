//! Stateless challenge binding per the framework (`draft-httpauth-payment-00`,
//! Challenge Binding): the challenge `id` is
//! `base64url(HMAC-SHA256(server_key, realm|method|intent|request|expires|digest|opaque))`
//! over exactly SEVEN fixed positional slots, pipe-joined, with the empty
//! string standing in for an absent optional. Binding is stateless: the only
//! record of "what was issued" is the id itself, so verifying a credential =
//! recomputing the HMAC over the echoed auth-params and comparing — any
//! tampered, added, or dropped param changes the input and the recomputation
//! fails.
//!
//! `description` is deliberately NOT a slot (the framework excludes it from
//! the binding: display-only, MUST NOT be relied upon for verification), so a
//! stateless server cannot and does not authenticate an echoed `description`.
//!
//! The server key is a secret (spec Privacy §: MUST NOT be logged or shared —
//! [`BindingKey`]'s `Debug` is redacted). It comes from operator config, with
//! a generate-at-boot fallback: a restart then invalidates outstanding
//! challenges, which clients resolve by refetching the 402.
//!
//! `draft-cashu-charge-01` step 3 + Challenge Binding §: a server operating
//! statelessly MUST include `expires` on every challenge (nothing else ever
//! lapses it), so issuance here always emits it and verification requires it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::envelope::EchoedChallenge;

type HmacSha256 = Hmac<Sha256>;

/// The server secret the challenge `id` is HMAC'd under.
///
/// `Debug` is redacted: the key MUST NOT appear in logs, error messages, or
/// debugging output (framework Challenge-Binding Secret Management §).
#[derive(Clone)]
pub struct BindingKey(Vec<u8>);

impl std::fmt::Debug for BindingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BindingKey(<{} bytes, redacted>)", self.0.len())
    }
}

impl BindingKey {
    /// Wrap raw key bytes (operator-supplied; 32 bytes RECOMMENDED).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Parse a hex-encoded key (the config wire form). Rejects an empty
    /// string, odd length, or a non-hex digit; requires at least 16 bytes
    /// (32 hex chars) so a typo'd key cannot quietly defeat the binding.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return Err("hex key must have an even number of digits".to_string());
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let digits = s.as_bytes();
        for pair in digits.chunks(2) {
            let hi = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| format!("non-hex digit {:?} in key", pair[0] as char))?;
            let lo = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| format!("non-hex digit {:?} in key", pair[1] as char))?;
            bytes.push(((hi << 4) | lo) as u8);
        }
        if bytes.len() < 16 {
            return Err(format!(
                "key is {} bytes; at least 16 (32 hex chars) required",
                bytes.len()
            ));
        }
        Ok(Self(bytes))
    }

    /// Generate a fresh 32-byte key from OS randomness — the at-boot fallback
    /// when no key is configured. Challenges issued under it die with the
    /// process; clients refetch the 402.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS randomness available");
        Self(bytes.to_vec())
    }
}

/// The framework's seven fixed positional HMAC slots, in table order. Required
/// slots carry their string value; an absent optional becomes the empty string
/// when joined, keeping every combination of optionals unambiguous.
#[derive(Debug, Clone, Copy)]
pub struct BindingSlots<'a> {
    /// Slot 0: the protection-space realm.
    pub realm: &'a str,
    /// Slot 1: the payment method identifier.
    pub method: &'a str,
    /// Slot 2: the payment intent.
    pub intent: &'a str,
    /// Slot 3: the `request` auth-param exactly as on the wire
    /// (JCS-serialized, base64url-encoded).
    pub request_b64: &'a str,
    /// Slot 4: `expires`, when issued.
    pub expires: Option<&'a str>,
    /// Slot 5: `digest`, when issued.
    pub digest: Option<&'a str>,
    /// Slot 6: `opaque` (base64url form), when issued.
    pub opaque: Option<&'a str>,
}

impl<'a> BindingSlots<'a> {
    /// The slots as a credential's echoed challenge populates them.
    pub fn from_echo(echo: &'a EchoedChallenge) -> Self {
        Self {
            realm: &echo.realm,
            method: &echo.method,
            intent: &echo.intent,
            request_b64: &echo.request,
            expires: echo.expires.as_deref(),
            digest: echo.digest.as_deref(),
            opaque: echo.opaque.as_deref(),
        }
    }

    /// The HMAC input: all seven slots pipe-joined, absent optionals as empty
    /// segments.
    fn joined(&self) -> String {
        [
            self.realm,
            self.method,
            self.intent,
            self.request_b64,
            self.expires.unwrap_or(""),
            self.digest.unwrap_or(""),
            self.opaque.unwrap_or(""),
        ]
        .join("|")
    }
}

/// Compute the challenge `id`: base64url-nopad over HMAC-SHA256 of the seven
/// pipe-joined slots (framework Challenge Binding, Recommended HMAC-SHA256
/// Binding).
pub fn compute_challenge_id(key: &BindingKey, slots: &BindingSlots<'_>) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&key.0).expect("HMAC-SHA256 accepts any key length");
    mac.update(slots.joined().as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Whether an echoed challenge is a faithful echo of one this server issued:
/// recompute the id-HMAC over the echoed auth-params and compare it (in
/// constant time) against the echoed `id`. Returns `false` for an id that is
/// not valid base64url, not 32 bytes, or whose MAC does not match — i.e. any
/// tampered, added, or dropped bound param.
pub fn verify_challenge_echo(key: &BindingKey, echo: &EchoedChallenge) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(&key.0).expect("HMAC-SHA256 accepts any key length");
    mac.update(BindingSlots::from_echo(echo).joined().as_bytes());
    match URL_SAFE_NO_PAD.decode(&echo.id) {
        // `verify_slice` is the constant-time comparison.
        Ok(id_bytes) => mac.verify_slice(&id_bytes).is_ok(),
        Err(_) => false,
    }
}

#[cfg(feature = "native")]
mod native {
    use std::time::Duration;

    use chrono::{DateTime, SecondsFormat, Utc};

    use super::{compute_challenge_id, verify_challenge_echo, BindingKey};
    use crate::charge::ChargeError;
    use crate::envelope::{EchoedChallenge, PAYMENT_SCHEME};

    /// Default challenge lifetime: 300 s (spec: `expires` is MUST under
    /// stateless operation; the TTL itself is operator-configurable).
    pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(300);

    /// One freshly-issued challenge: the HMAC-bound `id`, its RFC 3339
    /// `expires`, and the complete `WWW-Authenticate` header value.
    #[derive(Debug, Clone)]
    pub struct IssuedChallenge {
        /// The HMAC-SHA256 binding id (base64url-nopad).
        pub id: String,
        /// RFC 3339 expiry (`now + ttl`, second precision, `Z`).
        pub expires: String,
        /// The full `Payment id="…", realm="…", method="…", intent="…",
        /// request="…", expires="…"` header value.
        pub header_value: String,
    }

    /// Issue a fresh challenge: stamp `expires = now + ttl`, bind every
    /// emitted auth-param into the id, and format the header. No `digest` or
    /// `opaque` is emitted (their HMAC slots are empty), so a credential
    /// echoing either back fails the binding.
    pub fn issue_challenge(
        key: &BindingKey,
        realm: &str,
        method: &str,
        intent: &str,
        request_b64: &str,
        ttl: Duration,
    ) -> IssuedChallenge {
        let expires_ts = Utc::now()
            + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(300));
        let expires = expires_ts.to_rfc3339_opts(SecondsFormat::Secs, true);
        let id = compute_challenge_id(
            key,
            &super::BindingSlots {
                realm,
                method,
                intent,
                request_b64,
                expires: Some(&expires),
                digest: None,
                opaque: None,
            },
        );
        let header_value = format!(
            r#"{PAYMENT_SCHEME} id="{id}", realm="{realm}", method="{method}", intent="{intent}", request="{request_b64}", expires="{expires}""#
        );
        IssuedChallenge {
            id,
            expires,
            header_value,
        }
    }

    /// Whether an echoed RFC-3339 `expires` is in the past against the wall
    /// clock. An UNPARSEABLE timestamp is treated as expired — defense in
    /// depth; an echo that passed the HMAC carries the exact string this
    /// server issued, which always parses.
    pub fn expires_is_past(expires: &str) -> bool {
        match DateTime::parse_from_rfc3339(expires) {
            Ok(ts) => ts.with_timezone(&Utc) <= Utc::now(),
            Err(_) => true,
        }
    }

    /// Spec verification step 3 for a stateless server: authenticate the echo
    /// (recompute the id-HMAC over the echoed params — a tampered, added, or
    /// dropped param, or an `expires`-less echo, is `invalid-challenge`), then
    /// check freshness (`expires` in the past is `payment-expired`).
    pub fn validate_challenge_echo(
        key: &BindingKey,
        echo: &EchoedChallenge,
    ) -> Result<(), ChargeError> {
        if !verify_challenge_echo(key, echo) {
            return Err(ChargeError::InvalidChallenge);
        }
        // Statelessly-issued challenges always carry `expires` (the spec's
        // MUST); an echo without one cannot be a faithful echo. The HMAC
        // mismatch above already rejects it — this keeps the rule explicit.
        let Some(expires) = echo.expires.as_deref() else {
            return Err(ChargeError::InvalidChallenge);
        };
        if expires_is_past(expires) {
            return Err(ChargeError::ChallengeExpired);
        }
        Ok(())
    }
}

#[cfg(feature = "native")]
pub use native::{
    expires_is_past, issue_challenge, validate_challenge_echo, IssuedChallenge,
    DEFAULT_CHALLENGE_TTL,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> BindingKey {
        BindingKey::from_bytes(*b"0123456789abcdef0123456789abcdef")
    }

    fn echo_with(id: &str) -> EchoedChallenge {
        EchoedChallenge {
            id: id.to_string(),
            realm: "api.example.com".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "cmVxdWVzdA".into(),
            digest: None,
            opaque: None,
            expires: Some("2026-03-15T12:05:00Z".into()),
            description: None,
        }
    }

    /// An honestly-issued echo: id computed over the other fields.
    fn issued_echo() -> EchoedChallenge {
        let mut echo = echo_with("");
        echo.id = compute_challenge_id(&key(), &BindingSlots::from_echo(&echo));
        echo
    }

    /// Slots with every field defaulted; tests override what they exercise.
    fn slots<'a>(
        expires: Option<&'a str>,
        digest: Option<&'a str>,
        opaque: Option<&'a str>,
    ) -> BindingSlots<'a> {
        BindingSlots {
            realm: "r",
            method: "cashu",
            intent: "charge",
            request_b64: "q",
            expires,
            digest,
            opaque,
        }
    }

    #[test]
    fn id_is_hmac_over_the_seven_pipe_joined_slots() {
        // The expected input string is HAND-WRITTEN from the framework's slot
        // table (realm|method|intent|request|expires|digest|opaque, empty
        // string for an absent optional) — digest and opaque absent here, so
        // the string ends with two empty segments.
        let id = compute_challenge_id(
            &key(),
            &BindingSlots {
                realm: "api.example.com",
                method: "cashu",
                intent: "charge",
                request_b64: "cmVxdWVzdA",
                expires: Some("2026-03-15T12:05:00Z"),
                digest: None,
                opaque: None,
            },
        );
        let mut mac = HmacSha256::new_from_slice(b"0123456789abcdef0123456789abcdef")
            .expect("hmac key");
        mac.update(b"api.example.com|cashu|charge|cmVxdWVzdA|2026-03-15T12:05:00Z||");
        let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        assert_eq!(id, expected);
    }

    #[test]
    fn id_is_base64url_nopad_of_32_mac_bytes() {
        let id = compute_challenge_id(&key(), &slots(Some("2026-01-01T00:00:00Z"), None, None));
        let bytes = URL_SAFE_NO_PAD.decode(&id).expect("id is base64url-nopad");
        assert_eq!(bytes.len(), 32, "HMAC-SHA256 output is 32 bytes");
        assert!(!id.contains('='), "no padding on the id");
    }

    #[test]
    fn absent_optionals_occupy_distinct_fixed_slots() {
        // Framework: (expires set, no digest) and (no expires, digest set)
        // MUST produce distinct inputs — the positional empty-string slots
        // are what keeps them apart.
        let with_expires = compute_challenge_id(&key(), &slots(Some("X"), None, None));
        let with_digest = compute_challenge_id(&key(), &slots(None, Some("X"), None));
        let with_opaque = compute_challenge_id(&key(), &slots(None, None, Some("X")));
        assert_ne!(with_expires, with_digest);
        assert_ne!(with_expires, with_opaque);
        assert_ne!(with_digest, with_opaque);
    }

    #[test]
    fn faithful_echo_verifies() {
        assert!(verify_challenge_echo(&key(), &issued_echo()));
    }

    /// A named mutation of one echoed slot.
    type Tamper = (&'static str, fn(&mut EchoedChallenge));

    #[test]
    fn tampering_any_bound_slot_fails_verification() {
        // Every HMAC-bound auth-param: changing it (or injecting an unissued
        // optional) breaks the recomputation.
        let tampers: Vec<Tamper> = vec![
            ("realm", |e| e.realm = "evil.example.com".into()),
            ("method", |e| e.method = "tempo".into()),
            ("intent", |e| e.intent = "authorize".into()),
            ("request", |e| e.request = "cmVxdWVzdB".into()),
            ("expires", |e| {
                e.expires = Some("2999-03-15T12:05:00Z".into())
            }),
            ("expires-dropped", |e| e.expires = None),
            ("digest-injected", |e| e.digest = Some("sha-256=:x:".into())),
            ("opaque-injected", |e| e.opaque = Some("b3BhcXVl".into())),
        ];
        for (slot, tamper) in tampers {
            let mut echo = issued_echo();
            tamper(&mut echo);
            assert!(
                !verify_challenge_echo(&key(), &echo),
                "tampered slot {slot} must fail the binding"
            );
        }
    }

    #[test]
    fn tampered_id_fails_verification() {
        let mut echo = issued_echo();
        echo.id = compute_challenge_id(
            &key(),
            &BindingSlots {
                realm: "another.realm",
                ..slots(None, None, None)
            },
        );
        assert!(!verify_challenge_echo(&key(), &echo));
    }

    #[test]
    fn non_base64url_id_fails_verification_without_panicking() {
        let mut echo = issued_echo();
        echo.id = "not/base64+url=".into();
        assert!(!verify_challenge_echo(&key(), &echo));
    }

    #[test]
    fn echoed_description_is_not_bound() {
        // The framework excludes `description` from the 7 slots, so an echo
        // differing only in description still verifies (it is display-only
        // and unverifiable under stateless operation).
        let mut echo = issued_echo();
        echo.description = Some("display only".into());
        assert!(verify_challenge_echo(&key(), &echo));
    }

    #[test]
    fn different_key_fails_verification() {
        let other = BindingKey::from_bytes(*b"ffffffffffffffffffffffffffffffff");
        assert!(!verify_challenge_echo(&other, &issued_echo()));
    }

    #[test]
    fn from_hex_roundtrips_and_rejects_garbage() {
        let k = BindingKey::from_hex("000102030405060708090a0b0c0d0e0f").expect("16 bytes");
        assert_eq!(k.0, (0u8..16).collect::<Vec<_>>());
        assert!(BindingKey::from_hex("").is_err(), "empty key rejected");
        assert!(BindingKey::from_hex("abc").is_err(), "odd length rejected");
        assert!(BindingKey::from_hex("zz00").is_err(), "non-hex rejected");
        assert!(
            BindingKey::from_hex("aabb").is_err(),
            "a 2-byte key is too short to bind anything"
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        assert_ne!(BindingKey::generate().0, BindingKey::generate().0);
    }

    #[test]
    fn debug_is_redacted() {
        let k = BindingKey::from_bytes(*b"0123456789abcdef0123456789abcdef");
        let dbg = format!("{k:?}");
        assert!(
            !dbg.contains("0123456789abcdef"),
            "Debug must not leak key bytes: {dbg}"
        );
        assert!(dbg.contains("redacted"));
    }

    #[cfg(feature = "native")]
    mod native_tests {
        use std::time::Duration;

        use super::*;
        use crate::charge::ChargeError;

        #[test]
        fn issued_challenge_verifies_as_its_own_echo() {
            let issued = issue_challenge(
                &key(),
                "api.example.com",
                "cashu",
                "charge",
                "cmVxdWVzdA",
                DEFAULT_CHALLENGE_TTL,
            );
            let echo = EchoedChallenge {
                id: issued.id.clone(),
                realm: "api.example.com".into(),
                method: "cashu".into(),
                intent: "charge".into(),
                request: "cmVxdWVzdA".into(),
                digest: None,
                opaque: None,
                expires: Some(issued.expires.clone()),
                description: None,
            };
            validate_challenge_echo(&key(), &echo).expect("a faithful echo validates");
        }

        #[test]
        fn issued_header_carries_all_params_and_parses() {
            let issued = issue_challenge(
                &key(),
                "api.example.com",
                "cashu",
                "charge",
                "cmVxdWVzdA",
                DEFAULT_CHALLENGE_TTL,
            );
            let params = crate::envelope::parse_payment_params(&issued.header_value)
                .expect("issued header parses");
            assert_eq!(params.id, issued.id);
            assert_eq!(params.realm, "api.example.com");
            assert_eq!(params.method, "cashu");
            assert_eq!(params.intent, "charge");
            assert_eq!(params.request, "cmVxdWVzdA");
            assert_eq!(params.expires.as_deref(), Some(issued.expires.as_str()));
        }

        #[test]
        fn issued_expires_is_rfc3339_in_the_future() {
            let issued = issue_challenge(
                &key(),
                "r",
                "cashu",
                "charge",
                "q",
                DEFAULT_CHALLENGE_TTL,
            );
            assert!(!expires_is_past(&issued.expires));
            chrono::DateTime::parse_from_rfc3339(&issued.expires)
                .expect("expires is RFC 3339");
        }

        #[test]
        fn stale_expires_is_payment_expired_not_invalid_challenge() {
            // A zero TTL stamps `expires = now`, instantly past — the echo is
            // authentic (HMAC verifies) but stale.
            let issued =
                issue_challenge(&key(), "r", "cashu", "charge", "q", Duration::ZERO);
            let echo = EchoedChallenge {
                id: issued.id.clone(),
                realm: "r".into(),
                method: "cashu".into(),
                intent: "charge".into(),
                request: "q".into(),
                digest: None,
                opaque: None,
                expires: Some(issued.expires.clone()),
                description: None,
            };
            match validate_challenge_echo(&key(), &echo) {
                Err(ChargeError::ChallengeExpired) => {}
                other => panic!("expected ChallengeExpired, got {other:?}"),
            }
        }

        #[test]
        fn unparseable_expires_counts_as_past() {
            assert!(expires_is_past("not-a-timestamp"));
            assert!(expires_is_past("2000-01-01T00:00:00Z"));
            assert!(!expires_is_past("2999-01-01T00:00:00Z"));
        }
    }
}
