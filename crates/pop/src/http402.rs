//! HTTP-402 `Payment` envelope codec for the wallet.
//!
//! A thin re-export of the codec from [`pops_core_verify`], so the wallet and the
//! verifier share ONE wire (`draft-cashu-charge-01`) and cannot drift: the
//! cashu-free `Authorization` credentials envelope + the spec request object,
//! plus the cashu-coupled [`decode_charge_request`] that reads the request object
//! and enforces its mints-superset. Pulled with `default-features = false` to
//! keep `pops-core-verify`'s native surface (cdk/axum/http/uuid) out of the
//! wallet.
//!
//! If the two crates' `cashu` majors ever diverge, this is the sole module to
//! repoint.

pub use pops_core_verify::challenge::decode_charge_request;
pub use pops_core_verify::envelope::{
    encode_payment_credentials, parse_payment_params, CashuPayload, EchoedChallenge,
    PaymentCredentials, PaymentParams,
};
