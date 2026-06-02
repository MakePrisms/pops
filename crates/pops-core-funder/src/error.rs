//! Typed, exhaustive recovery errors.
//!
//! [`RecoverError`] is the kernel's stable error surface for the recovery
//! build/sign path. Every failure mode the pure construction can hit returns
//! one of these variants — the library never panics or prints on an error
//! path. (The two statistically-impossible curve-event `.expect()`s inside
//! [`crate::script`] are unreachable invariants, not error paths.)
//!
//! Each variant exposes a stable [`RecoverError::code`] string for agent /
//! FFI mapping; the textual `Display` carries human-readable diagnostics.
//!
//! ## Boundary note — `CltvNotExpired` is intentionally absent
//!
//! The kernel is pure-construction (no chain I/O): it cannot know the current
//! tip MTP, so it cannot verify CLTV maturity — it just sets
//! `nLockTime = ts_expiry` and the node rejects a premature spend (BIP-65 +
//! BIP-113). `CltvNotExpired` therefore belongs in pop-wallet's pre-flight
//! (which has the chain/MTP), not here.

use thiserror::Error;

/// Errors from building or signing a recovery transaction.
///
/// Exhaustive and stable: the variant set is part of the kernel's public
/// contract. Mismatch variants carry hex diagnostics for debugging without
/// widening the match surface (the [`RecoverError::code`] is variant-stable).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecoverError {
    /// The two independent output-key derivations (canonical `tap_tweak` vs
    /// the staged `compute_output_key`) disagreed — an internal invariant
    /// breach, not a user error.
    #[error("internal sanity check failed: tap_tweak and compute_output_key disagree on the output key")]
    OutputKeyMismatch,

    /// `build_and_sign`: the supplied secret's x-only key did not equal
    /// `RecoverInputs.funder_pubkey`. The hot-key wrapper refuses to sign with
    /// a key that does not match the declared funder.
    #[error("supplied secret's x-only key does not match inputs.funder_pubkey")]
    WrongFunderKey,

    /// The leaf re-derived from `(ts_expiry, funder_pubkey)` did not match the
    /// supplied `leaf_script`. The funder key (or ts_expiry) for this deposit
    /// does not match the stored construction.
    #[error(
        "stored leaf script does not match the script derived from (ts_expiry={ts_expiry}, funder_pubkey).\n  stored:  {stored}\n  derived: {derived}"
    )]
    ScriptMismatch {
        /// The CLTV expiry the leaf was re-derived against.
        ts_expiry: u64,
        /// Hex of the supplied `leaf_script`.
        stored: String,
        /// Hex of the leaf re-derived from `(ts_expiry, funder_pubkey)`.
        derived: String,
    },

    /// The on-chain UTXO scriptPubKey did not match the scriptPubKey
    /// reconstructed from the PoP commitment.
    #[error(
        "on-chain scriptPubKey does not match the reconstructed PoP commitment address.\n  utxo:     {utxo}\n  expected: {expected}\n  address:  {address}"
    )]
    ScriptPubkeyMismatch {
        /// Hex of the on-chain UTXO scriptPubKey.
        utxo: String,
        /// Hex of the reconstructed (expected) scriptPubKey.
        expected: String,
        /// The reconstructed bech32m address (for human cross-check).
        address: String,
    },

    /// The UTXO value was not greater than the resolved fee, so the recovered
    /// output would be non-positive. An uneconomical-to-sweep UTXO.
    #[error("UTXO value ({value_sats} sat) is not greater than the fee ({fee_sats} sat)")]
    ValueBelowFee {
        /// On-chain UTXO value, sats.
        value_sats: u64,
        /// Resolved absolute fee, sats.
        fee_sats: u64,
    },

    /// `ts_expiry` did not fit in a `u32` (post-year-2106), so it cannot be
    /// encoded as a consensus `nLockTime`.
    #[error("ts_expiry {0} does not fit in u32 (> year 2106)")]
    ExpiryOutOfRange(u64),

    /// The taproot script-spend sighash computation failed.
    #[error("taproot script-spend sighash failed: {0}")]
    SighashFailed(String),

    /// `apply_signature`: the supplied schnorr signature failed verification
    /// against `(sighash, funder_pubkey)`. Caught here so a bad signature is
    /// rejected at assembly time, not at broadcast.
    #[error("signature does not verify against (sighash, funder_pubkey)")]
    SignatureInvalid,

    /// The assembled single-leaf control block failed to verify against the
    /// reconstructed output key + leaf script.
    #[error("control block does not verify against the reconstructed output key + leaf script")]
    ControlBlockInvalid,

    /// The signed transaction's vsize did not equal the fee-computed vsize —
    /// the fixed-witness-size assumption underpinning the exact fee broke.
    #[error("signed tx vsize ({signed}) != fee-computed vsize ({expected})")]
    VsizeMismatch {
        /// vsize of the fully-signed transaction.
        signed: usize,
        /// vsize the fee was computed against (dummy-witness measure).
        expected: usize,
    },
}

impl RecoverError {
    /// A stable, variant-identifying snake_case code for agent / FFI mapping.
    /// Distinct from `Display`, which carries human diagnostics. These strings
    /// are part of the contract — do not rename.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            RecoverError::OutputKeyMismatch => "output_key_mismatch",
            RecoverError::WrongFunderKey => "wrong_funder_key",
            RecoverError::ScriptMismatch { .. } => "script_mismatch",
            RecoverError::ScriptPubkeyMismatch { .. } => "script_pubkey_mismatch",
            RecoverError::ValueBelowFee { .. } => "value_below_fee",
            RecoverError::ExpiryOutOfRange(_) => "expiry_out_of_range",
            RecoverError::SighashFailed(_) => "sighash_failed",
            RecoverError::SignatureInvalid => "signature_invalid",
            RecoverError::ControlBlockInvalid => "control_block_invalid",
            RecoverError::VsizeMismatch { .. } => "vsize_mismatch",
        }
    }
}
