//! PoPs funder-side core: pure-function crypto for the funding commitment.
//!
//! This crate holds the deterministic, I/O-free cryptographic construction
//! that both the mint (quote-create / funding-verify) and the funder wallet
//! must agree on bit-for-bit. [`script`] computes the taproot output key `Q`
//! and bech32m commitment address from the public quote inputs; it is the
//! single source of address-derivation truth, so the two sides cannot drift.
//!
//! The CLTV recovery leaf is the OP_VERIFY form:
//! `<ts_expiry> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <funder_xonly> OP_CHECKSIG`.
//!
//! ## Recovery (signer seam)
//!
//! [`recovery`] reconstructs a deposit's taproot construction from public
//! params; [`recover_tx`] builds and signs the script-path spend that reclaims
//! the CLTV-locked BTC, split into a custody-free [`recover_tx::build_unsigned`]
//! and a sign-agnostic [`recover_tx::apply_signature`] (with a hot-key
//! [`recover_tx::build_and_sign`] wrapper). All failures are typed
//! [`error::RecoverError`] — the library never panics or prints on an error
//! path.

pub mod error;
pub mod recover_tx;
pub mod recovery;
pub mod script;

pub use error::RecoverError;
pub use recover_tx::{
    apply_signature, build_and_sign, build_unsigned, recovery_address, FeePolicy, RecoverInputs,
    RecoverTx, UnsignedRecovery, MIN_RELAY_FEERATE_SAT_PER_VB,
};
pub use recovery::{descriptor, reconstruct, Construction, ConstructionParams};
