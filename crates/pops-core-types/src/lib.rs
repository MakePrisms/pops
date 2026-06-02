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
//!
// TODO(co-design with cashu-mpp): ChargeError (envelope-mappable) + RedeemedProofs
// + cashu Token/Proofs re-export. Placeholder only — no impl yet.

use thiserror::Error;

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
/// anything that is not exactly the `pop_` prefix followed by a parseable
/// `u64`.
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
