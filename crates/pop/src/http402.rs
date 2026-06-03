//! Client primitives for the HTTP-402 `Payment` auth-scheme dance.
//!
//! This is a thin re-export of the **cashu-free** codec from
//! [`pops_core_verify::envelope`] — the wallet and the gateway thus share ONE
//! source of envelope-format truth (the request envelope on the
//! `WWW-Authenticate` side, the credentials envelope on the `Authorization`
//! side) and cannot drift.
//!
//! ## Why a re-export (the dep-path decision)
//!
//! The DEP NOTE in the build spec flagged a possible `cashu`-version clash:
//! `pops-core-verify` is built on crates.io `cashu = "0.16"`, while this crate
//! drives the mint through `cdk-common`. In THIS workspace there is no clash —
//! `cdk-common = "0.16"` re-exports the very same `cashu 0.16` crate
//! (`cdk_common::nuts::*` ARE `cashu::nuts::*`), so both pull a single `cashu`
//! in the graph. The preferred path (reuse `pops-core-verify::envelope`) therefore
//! compiles cleanly and the local-copy fallback is unnecessary. Depending on
//! `pops-core-verify` with `default-features = false` keeps its native surface
//! (cdk/axum/http/uuid) out of the wallet; only the always-compiled,
//! cashu-free envelope codec is used here.
//!
//! If that ever changes (e.g. the two crates' `cashu` majors diverge), this is
//! the ONE module to swap to the local-copy fallback — the `pay` command imports
//! the envelope codec only through here.

pub use pops_core_verify::envelope::{
    decode_request_envelope, encode_payment_credentials, parse_payment_params, CashuPayload,
    EchoedChallenge, PaymentCredentials, PaymentParams,
};
