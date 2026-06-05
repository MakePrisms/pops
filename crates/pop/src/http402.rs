//! HTTP-402 `Payment` envelope codec for the wallet.
//!
//! A thin re-export of the **cashu-free** codec from
//! [`pops_core_verify::envelope`], so the wallet and the gateway share ONE
//! envelope format (the `WWW-Authenticate` request envelope and the
//! `Authorization` credentials envelope) and cannot drift. Pulled with
//! `default-features = false` to keep `pops-core-verify`'s native surface
//! (cdk/axum/http/uuid) out of the wallet.
//!
//! If the two crates' `cashu` majors ever diverge, this is the sole module to
//! repoint.

pub use pops_core_verify::envelope::{
    decode_request_envelope, encode_payment_credentials, parse_payment_params, CashuPayload,
    EchoedChallenge, PaymentCredentials, PaymentParams,
};
