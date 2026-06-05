//! PoPs core types: the `pop_<ts_expiry>` unit grammar (cashu/cdk-free).
//!
//! The unit string is `pop_<ts_expiry>` where `ts_expiry` is the Unix-seconds
//! value in the funding CLTV. The mint, wallet, and verifier all parse/format
//! through these functions so the grammar cannot drift.

use thiserror::Error;

pub mod charge;
pub use charge::{ChargeError, DleqLocation, RedeemedProofs};

/// Errors from parsing the `pop_<ts_expiry>` unit grammar.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypesError {
    /// Not `pop_<u64>` (missing prefix or non-`u64` / non-canonical remainder).
    #[error("invalid pop unit format: {0}")]
    InvalidUnitFormat(String),

    /// Below the BIP-65 timestamp floor: OP_CHECKLOCKTIMEVERIFY reads a locktime
    /// `< 500_000_000` as a block HEIGHT, but a `pop_<ts>` expiry is always a Unix
    /// timestamp.
    #[error("ts_expiry {0} is below the BIP-65 timestamp floor of {1} (values below this are block heights, not timestamps)")]
    TsExpiryTooSmall(u64, u64),

    /// Above `u32::MAX`: the CLTV locktime / `compute_leaf_script` require a u32,
    /// so rejecting here avoids a downstream `try_from` panic.
    #[error("ts_expiry {0} exceeds the u32::MAX ceiling of {1} (CLTV locktime must fit in a u32)")]
    TsExpiryTooLarge(u64, u64),
}

/// Parse `pop_<u64>` into the leaf `ts_expiry`. The remainder must be the
/// CANONICAL decimal form (byte-for-byte [`format_pop_unit`]'s output), then is
/// range-checked to `500_000_000 ..= u32::MAX`.
///
/// Canonical-form is the load-bearing tightening: `u64::from_str` is lenient (a
/// leading `+` or zeros parse to the SAME integer but a DIFFERENT string), and
/// the unit string IS the currency identity downstream — so a non-canonical
/// spelling would mint a credential whose unit never matches the canonical
/// challenge unit (a silent permanent `WrongUnit`/402). This single source of
/// truth lets all consumers drop their own front gates. The range bounds:
/// [`TypesError::TsExpiryTooSmall`] (BIP-65 floor) and
/// [`TypesError::TsExpiryTooLarge`] (u32 ceiling) — see those variants.
pub fn parse_pop_unit(unit_str: &str) -> Result<u64, TypesError> {
    const TS_EXPIRY_FLOOR: u64 = 500_000_000;
    const TS_EXPIRY_CEILING: u64 = u32::MAX as u64;

    let Some(rest) = unit_str.strip_prefix("pop_") else {
        return Err(TypesError::InvalidUnitFormat(unit_str.to_string()));
    };
    let ts_expiry = rest
        .parse::<u64>()
        .map_err(|_| TypesError::InvalidUnitFormat(unit_str.to_string()))?;
    // Reject any non-canonical spelling — must round-trip `format_pop_unit`
    // exactly (see the canonical-form rationale on this fn).
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
        assert!(matches!(
            parse_pop_unit("sat"), // missing prefix
            Err(TypesError::InvalidUnitFormat(_))
        ));
        assert!(matches!(
            parse_pop_unit("pop_notanumber"), // non-numeric remainder
            Err(TypesError::InvalidUnitFormat(_))
        ));
    }

    #[test]
    fn parse_pop_unit_rejects_leading_zero() {
        // Non-canonical (parses to the same int, different string) → malformed.
        assert!(matches!(
            parse_pop_unit("pop_0500000000"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        assert!(matches!(
            parse_pop_unit("pop_01782259200"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
        // "0" IS canonical for 0, so this falls through to the floor check (NOT a
        // canonical-form error).
        assert_eq!(
            parse_pop_unit("pop_0"),
            Err(TypesError::TsExpiryTooSmall(0, 500_000_000))
        );
        // "pop_00" is non-canonical → InvalidUnitFormat, NOT floor.
        assert!(matches!(
            parse_pop_unit("pop_00"),
            Err(TypesError::InvalidUnitFormat(_))
        ));
    }

    #[test]
    fn parse_pop_unit_rejects_leading_plus() {
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
        // Whitespace is not canonical (callers `.trim()` before calling).
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
        let ts = 1_782_259_200u64;
        let canonical = format_pop_unit(ts);
        assert_eq!(canonical, "pop_1782259200");
        assert_eq!(parse_pop_unit(&canonical), Ok(ts));
        // format → parse round-trips for every in-range ts.
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
