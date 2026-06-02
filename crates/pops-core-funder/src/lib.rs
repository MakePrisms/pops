//! PoPs funder-side core: pure-function crypto for the funding commitment.
//!
//! This crate holds the deterministic, I/O-free cryptographic construction
//! that both the mint (quote-create / funding-verify) and the funder wallet
//! must agree on bit-for-bit. The single module today is [`script`], which
//! computes the taproot output key `Q` and bech32m commitment address from
//! the public quote inputs.
//!
//! The CLTV recovery leaf is the OP_VERIFY form:
//! `<ts_expiry> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <funder_xonly> OP_CHECKSIG`.
//!
//! Extracted verbatim from `cdk-pop` so the address-derivation logic has a
//! single source of truth across the (eventually unified) PoPs kernel.

pub mod script;
