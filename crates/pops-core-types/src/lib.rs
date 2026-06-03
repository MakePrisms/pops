//! PoPs core types: the `pop_<ts_expiry>` unit grammar.
//!
//! Pure, branch-agnostic, and free of any cashu/cdk dependency. This crate
//! owns the wire grammar for the PoP currency unit string, whose shape is
//! `pop_<ts_expiry>` where `ts_expiry` is the Unix-seconds value embedded in
//! the funding CLTV. The mint, the funder wallet, and any future verifier
//! all parse and format the unit through these functions so the grammar
//! cannot drift.
//!
//! The `CurrencyUnit` adapter (`unit_to_string`) deliberately stays cdk-side;
//! this crate knows nothing about cashu types.

use thiserror::Error;

pub mod charge;
pub use charge::{ChargeError, DleqLocation, RedeemedProofs};

/// Errors from parsing the `pop_<ts_expiry>` unit grammar.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypesError {
    /// The unit string was not of the form `pop_<u64>`: either it lacked the
    /// `pop_` prefix or the remainder did not parse as a `u64`.
    #[error("invalid pop unit format: {0}")]
    InvalidUnitFormat(String),

    /// The `ts_expiry` parsed but fell below the BIP-65 timestamp floor.
    /// OP_CHECKLOCKTIMEVERIFY interprets a locktime `< 500_000_000` as a block
    /// *height*, not a Unix timestamp; a `pop_<ts>` expiry is always a Unix
    /// timestamp, so any value below the floor is malformed.
    #[error("ts_expiry {0} is below the BIP-65 timestamp floor of {1} (values below this are block heights, not timestamps)")]
    TsExpiryTooSmall(u64, u64),

    /// The `ts_expiry` parsed but exceeded `u32::MAX`. The CLTV locktime and
    /// `compute_leaf_script` require a `u32` (the year-2106 ceiling); rejecting
    /// here turns that limit into a clean parse error instead of a downstream
    /// `u32::try_from(...)` panic.
    #[error("ts_expiry {0} exceeds the u32::MAX ceiling of {1} (CLTV locktime must fit in a u32)")]
    TsExpiryTooLarge(u64, u64),
}

/// Parse `pop_<u64>` into the leaf `ts_expiry` value.
///
/// Wire shape is `pop_<ts_expiry>` where `ts_expiry` is the Unix-seconds
/// value embedded in the CLTV. Returns [`TypesError::InvalidUnitFormat`] for
/// anything that is not exactly the `pop_` prefix followed by the **canonical
/// decimal form** of a parseable `u64`.
///
/// "Canonical decimal form" is the load-bearing tightening: the remainder must
/// be byte-for-byte equal to `ts_expiry.to_string()` — i.e. exactly what
/// [`format_pop_unit`] emits. `u64::from_str` is otherwise lenient: it accepts a
/// leading `+` sign (`pop_+500000000`) and leading zeros (`pop_0500000000`),
/// both of which parse to the SAME integer as the canonical unit yet are a
/// DIFFERENT string. Because the unit string IS the currency identity
/// downstream (`CurrencyUnit::Custom(unit)`), letting a non-canonical spelling
/// through would silently mint a credential whose unit never matches the
/// canonical challenge unit — a permanent `WrongUnit`/402. Rejecting any
/// non-canonical spelling here (the single source of truth all consumers route
/// through) lets the gateway/verify/wallet/cdk-pop drop their own front gates.
/// (`from_str_radix` is ASCII-only, so no Unicode-digit case exists to guard.)
///
/// After parsing, `ts_expiry` is range-checked against the closed interval
/// `500_000_000 ..= 4_294_967_295` (`u32::MAX`); both bounds are intentional:
///
/// - **Floor `500_000_000`** ([`TypesError::TsExpiryTooSmall`]): BIP-65
///   OP_CHECKLOCKTIMEVERIFY interprets a locktime below `500_000_000` as a
///   block *height*, not a Unix timestamp. A `pop_<ts>` expiry is always a Unix
///   timestamp, so any value below the floor is malformed by definition.
/// - **Ceiling `u32::MAX`** ([`TypesError::TsExpiryTooLarge`]): the CLTV
///   locktime and `pops-core-funder::script::compute_leaf_script` require a
///   `u32` (the year-2106 ceiling). Enforcing it here turns that limit into a
///   clean parse error instead of the downstream `u32::try_from(...).expect(...)`
///   panic at script-build time.
pub fn parse_pop_unit(unit_str: &str) -> Result<u64, TypesError> {
    const TS_EXPIRY_FLOOR: u64 = 500_000_000;
    const TS_EXPIRY_CEILING: u64 = u32::MAX as u64;

    let Some(rest) = unit_str.strip_prefix("pop_") else {
        return Err(TypesError::InvalidUnitFormat(unit_str.to_string()));
    };
    let ts_expiry = rest
        .parse::<u64>()
        .map_err(|_| TypesError::InvalidUnitFormat(unit_str.to_string()))?;
    // Reject any non-canonical spelling (leading `+`, leading zeros, etc.):
    // `u64::from_str` is lenient, but the unit string IS the currency identity,
    // so it must round-trip `format_pop_unit` exactly or it would mint a
    // distinct-string/same-value unit that never matches the canonical
    // challenge unit (a silent permanent WrongUnit/402).
    if rest != ts_expiry.to_string() {
        return Err(TypesError::InvalidUnitFormat(unit_str.to_string()));
    }
    if ts_expiry < TS_EXPIRY_FLOOR {
        return Err(TypesError::TsExpiryTooSmall(ts_expiry, TS_EXPIRY_FLOOR));
    }
    if ts_expiry > TS_EXPIRY_CEILING {
        return Err(TypesError::TsExpiryTooLarge(ts_expiry, TS_EXPIRY_CEILING));
    }
    Ok(ts_expiry)
}

/// Format a `ts_expiry` value back into its canonical `pop_<ts_expiry>` unit
/// string. Inverse of [`parse_pop_unit`] on the valid domain.
pub fn format_pop_unit(ts_expiry: u64) -> String {
    format!("pop_{ts_expiry}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_pop_unit_round_trips() {
        assert_eq!(format_pop_unit(1_782_259_200), "pop_1782259200");
    }

    #[test]
    fn parse_pop_unit_parses_valid() {
        assert_eq!(parse_pop_unit("pop_1782259200"), Ok(1_782_259_200));
    }

    #[test]
    fn parse_format_are_inverse() {
        let ts = 1_782_259_200u64;
        assert_eq!(parse_pop_unit(&format_pop_unit(ts)), Ok(ts));
    }

    #[test]
    fn parse_pop_unit_rejects_malformed() {
        // Missing prefix.
        assert!(matches!(
            parse_pop_unit("sat"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        // Prefix present but non-numeric remainder.
        assert!(matches!(
            parse_pop_unit("pop_notanumber"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
    }

    #[test]
    fn parse_pop_unit_rejects_leading_zero() {
        // `u64::from_str` parses "0500000000" to 500_000_000, but the unit
        // string differs from the canonical `format_pop_unit` output, so the
        // currency identity would silently diverge → reject as malformed, NOT
        // accept as the in-range floor value.
        assert!(matches!(
            parse_pop_unit("pop_0500000000"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        // A single leading zero on an otherwise-valid value.
        assert!(matches!(
            parse_pop_unit("pop_01782259200"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        // "pop_0" alone (zero is below the floor anyway, but the canonical-form
        // gate must not be tricked into a TsExpiryTooSmall numeric error here:
        // "0" IS canonical for 0, so this one legitimately falls through to the
        // floor check — assert that exact behavior).
        assert_eq!(
            parse_pop_unit("pop_0"),
            Err(TypesError::TsExpiryTooSmall(0, 500_000_000))
        );
        // "pop_00" is non-canonical (two zeros) → InvalidUnitFormat, NOT floor.
        assert!(matches!(
            parse_pop_unit("pop_00"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
    }

    #[test]
    fn parse_pop_unit_rejects_leading_plus() {
        // `u64::from_str` accepts a leading '+'; the canonical form never has
        // one, so a `pop_+...` unit must be rejected as malformed.
        assert!(matches!(
            parse_pop_unit("pop_+500000000"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        assert!(matches!(
            parse_pop_unit("pop_+1782259200"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
    }

    #[test]
    fn parse_pop_unit_rejects_surrounding_whitespace() {
        // Internal/leading/trailing whitespace is not canonical. (Callers that
        // want to tolerate operator whitespace must `.trim()` BEFORE calling —
        // the gateway does; the grammar itself stays strict.)
        assert!(matches!(
            parse_pop_unit("pop_ 1782259200"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        assert!(matches!(
            parse_pop_unit("pop_1782259200 "),
            Err(TypesError::InvalidUnitFormat(_))
        ));
    }

    #[test]
    fn parse_pop_unit_accepts_canonical_only() {
        // The canonical decimal spelling (exactly what `format_pop_unit`
        // emits) is the ONLY accepted form for a given value, and it parses.
        let ts = 1_782_259_200u64;
        let canonical = format_pop_unit(ts);
        assert_eq!(canonical, "pop_1782259200");
        assert_eq!(parse_pop_unit(&canonical), Ok(ts));
        // Property: for every in-range ts, format → parse round-trips, and the
        // formatted string is the unique accepted spelling.
        for ts in [500_000_000u64, 1_782_259_200, 4_294_967_295] {
            let s = format_pop_unit(ts);
            assert_eq!(parse_pop_unit(&s), Ok(ts), "canonical {s} must parse");
        }
    }

    #[test]
    fn parse_pop_unit_rejects_below_floor() {
        // One below the BIP-65 timestamp floor -> height-vs-timestamp territory.
        assert_eq!(
            parse_pop_unit("pop_499999999"),
            Err(TypesError::TsExpiryTooSmall(499_999_999, 500_000_000))
        );
    }

    #[test]
    fn parse_pop_unit_accepts_floor_boundary() {
        // Exactly the floor is valid (closed lower bound).
        assert_eq!(parse_pop_unit("pop_500000000"), Ok(500_000_000));
    }

    #[test]
    fn parse_pop_unit_accepts_u32_max_boundary() {
        // Exactly u32::MAX is valid (closed upper bound).
        assert_eq!(parse_pop_unit("pop_4294967295"), Ok(4_294_967_295));
    }

    #[test]
    fn parse_pop_unit_rejects_above_u32_max() {
        // One above u32::MAX -> would overflow the CLTV/script u32.
        assert_eq!(
            parse_pop_unit("pop_4294967296"),
            Err(TypesError::TsExpiryTooLarge(4_294_967_296, 4_294_967_295))
        );
    }
}
