//! Injected-`fetch` [`MintClient`] for wasm32 (feature `wasm`).
//!
//! The second [`MintClient`] impl: where
//! [`CdkMintClient`][crate::cdk_mint_client::CdkMintClient] drives the shared
//! swap ceremony over cdk's native HTTP, [`WasmMintClient`] drives the *same*
//! [`swap_to_redeem`] ceremony over the JS `fetch` available on `globalThis`
//! (Vercel/Node serverless, browsers, workers). No new ceremony, no new
//! crypto — only the three raw HTTP calls of [`MintHttp`] are reimplemented on
//! top of `fetch`.
//!
//! `fetch` is reached by reflecting `"fetch"` off `globalThis` rather than
//! through `web_sys::window()` so the same code runs in a Node serverless
//! function (no `window`/`WorkerGlobalScope`) as in a browser. The async
//! plumbing is `wasm_bindgen_futures::JsFuture` over the two `Promise`s a fetch
//! yields — the response, then its body text.
//!
//! HTTP status drives the coarse [`MintClientError`] split the validator
//! needs: a 5xx (or a `fetch` that rejects — DNS/TCP/TLS/CORS) is
//! [`MintClientError::Unreachable`] (retryable); a 4xx (the mint refused) is
//! [`MintClientError::RejectedSwap`]. A 2xx whose body fails to deserialize is
//! a definitive `RejectedSwap` (the mint answered with something we can't use).

use async_trait::async_trait;
use cashu::nuts::nut02::{Id, KeySet, KeySetInfo, KeysetResponse};
use cashu::nuts::nut03::{SwapRequest, SwapResponse};
use cashu::{MintUrl, Proofs};
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::mint_client::{MintClient, MintClientError};
use crate::swap_ceremony::{swap_to_redeem, MintHttp};

/// `fetch`-backed [`MintClient`] for wasm32.
///
/// Stateless: every call reaches `globalThis.fetch` fresh and is addressed by
/// the [`MintUrl`] passed in, mirroring
/// [`CdkMintClient`][crate::cdk_mint_client::CdkMintClient]'s per-call design.
/// Requires a global `fetch` in the host (present on Vercel Node ≥18, browsers,
/// and workers); absence surfaces as [`MintClientError::Unreachable`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WasmMintClient;

impl WasmMintClient {
    /// Construct a fresh client. Costs nothing.
    pub fn new() -> Self {
        Self
    }
}

/// A JS-side failure before any HTTP status was observed (no global `fetch`,
/// the fetch Promise rejected on DNS/TCP/TLS/CORS, the body Promise rejected,
/// etc.). These are network-ambiguous → [`MintClientError::Unreachable`].
fn unreachable_js(context: &str, err: &JsValue) -> MintClientError {
    MintClientError::Unreachable(format!("{context}: {}", describe_js(err)))
}

/// Best-effort human string for a thrown [`JsValue`] (Error message if it is
/// one, else its debug form).
fn describe_js(v: &JsValue) -> String {
    if let Some(s) = v.as_string() {
        return s;
    }
    // An Error object stringifies via its `message`; `js_sys::Error` casting
    // avoids pulling extra web-sys surface.
    if let Some(err) = v.dyn_ref::<js_sys::Error>() {
        return String::from(err.message());
    }
    format!("{v:?}")
}

/// Build the full mint endpoint URL string from path segments, or a
/// definitive `RejectedSwap` if the mint URL cannot form a valid path (server
/// config problem, not a transport one).
fn endpoint(mint_url: &MintUrl, segments: &[&str]) -> Result<String, MintClientError> {
    mint_url
        .join_paths(segments)
        .map(|u| u.to_string())
        .map_err(|e| MintClientError::RejectedSwap(format!("bad mint url path {segments:?}: {e}")))
}

/// Core injected-`fetch` round-trip: call `globalThis.fetch(url, init)`, await
/// the response, map status → the coarse error split, await the body text, and
/// deserialize it as `T`.
///
/// `body` is `Some(json)` for a POST (sets method=POST + a JSON content-type)
/// and `None` for a GET. All the finicky async-across-wasm-bindgen work lives
/// here so [`MintHttp`] below is a thin three-line shell.
async fn fetch_json<T: DeserializeOwned>(
    url: &str,
    body: Option<String>,
) -> Result<T, MintClientError> {
    // Build the RequestInit-shaped options object by reflection (no web-sys
    // RequestInit needed; this keeps the web-sys feature surface to Response).
    let init = js_sys::Object::new();
    if let Some(ref json) = body {
        set(&init, "method", &JsValue::from_str("POST"))?;
        let headers = js_sys::Object::new();
        set(&headers, "content-type", &JsValue::from_str("application/json"))?;
        set(&init, "headers", &headers)?;
        set(&init, "body", &JsValue::from_str(json))?;
    } else {
        set(&init, "method", &JsValue::from_str("GET"))?;
    }

    // Resolve `globalThis.fetch` (works in Node serverless + browser + worker).
    let global = js_sys::global();
    let fetch_fn = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|e| unreachable_js("globalThis.fetch lookup", &e))?;
    let fetch_fn: js_sys::Function = fetch_fn
        .dyn_into()
        .map_err(|_| MintClientError::Unreachable("globalThis.fetch is not a function".into()))?;

    // fetch(url, init) -> Promise<Response>
    let promise = fetch_fn
        .call2(&global, &JsValue::from_str(url), &init)
        .map_err(|e| unreachable_js("fetch() threw", &e))?;
    let promise: js_sys::Promise = promise
        .dyn_into()
        .map_err(|_| MintClientError::Unreachable("fetch did not return a Promise".into()))?;

    let resp_val = JsFuture::from(promise)
        .await
        // A rejected fetch is the transport-failure case (DNS/TCP/TLS/CORS).
        .map_err(|e| unreachable_js("fetch rejected", &e))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| MintClientError::Unreachable("fetch result was not a Response".into()))?;

    // Status split: 5xx (or 0, an opaque/blocked response) → Unreachable;
    // any other non-2xx → RejectedSwap; 2xx → parse the body.
    let status = resp.status();
    if !(200..300).contains(&status) {
        let detail = response_text(&resp)
            .await
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(if status == 0 || (500..600).contains(&status) {
            MintClientError::Unreachable(format!("mint HTTP {status}: {detail}"))
        } else {
            MintClientError::RejectedSwap(format!("mint HTTP {status}: {detail}"))
        });
    }

    let text = response_text(&resp)
        .await
        .ok_or_else(|| MintClientError::RejectedSwap("could not read mint response body".into()))?;

    serde_json::from_str::<T>(&text).map_err(|e| {
        // A 2xx the mint sent but we can't parse is a definitive problem with
        // this exchange, not a retryable transport blip.
        MintClientError::RejectedSwap(format!("malformed mint response: {e}; body={text}"))
    })
}

/// Await `Response::text()` (itself a Promise) into a Rust `String`, or `None`
/// if either the `.text()` call or its Promise fails.
async fn response_text(resp: &web_sys::Response) -> Option<String> {
    let promise = resp.text().ok()?;
    let val = JsFuture::from(promise).await.ok()?;
    val.as_string()
}

/// `js_sys::Reflect::set` wrapper that maps a failure to an `Unreachable`
/// (building the request object should never fail; if it does the environment
/// is broken).
fn set(target: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), MintClientError> {
    js_sys::Reflect::set(target, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|e| unreachable_js(&format!("building request ({key})"), &e))
}

/// The raw mint HTTP over injected `fetch`. Three calls, each a thin shell over
/// [`fetch_json`] — the shared [`swap_to_redeem`] ceremony supplies all crypto.
#[async_trait(?Send)]
impl MintHttp for WasmMintClient {
    async fn get_keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<KeysetResponse, MintClientError> {
        let url = endpoint(mint_url, &["v1", "keysets"])?;
        fetch_json(&url, None).await
    }

    async fn get_keyset_keys(
        &self,
        mint_url: &MintUrl,
        keyset_id: Id,
    ) -> Result<KeySet, MintClientError> {
        let url = endpoint(mint_url, &["v1", "keys", &keyset_id.to_string()])?;
        // `GET /v1/keys/{id}` returns a NUT-01 KeysResponse `{ "keysets": [KeySet] }`;
        // take the first (and only) entry, matching cdk's `get_mint_keyset`.
        let resp: cashu::nuts::nut01::KeysResponse = fetch_json(&url, None).await?;
        resp.keysets.into_iter().next().ok_or_else(|| {
            MintClientError::RejectedSwap(format!("mint returned no keys for keyset {keyset_id}"))
        })
    }

    async fn post_swap(
        &self,
        mint_url: &MintUrl,
        request: SwapRequest,
    ) -> Result<SwapResponse, MintClientError> {
        let url = endpoint(mint_url, &["v1", "swap"])?;
        let body = serde_json::to_string(&request)
            .map_err(|e| MintClientError::RejectedSwap(format!("encode swap request: {e}")))?;
        fetch_json(&url, Some(body)).await
    }
}

#[async_trait(?Send)]
impl MintClient for WasmMintClient {
    async fn keysets(
        &self,
        mint_url: &MintUrl,
    ) -> Result<Vec<KeySetInfo>, MintClientError> {
        Ok(self.get_keysets(mint_url).await?.keysets)
    }

    async fn swap(
        &self,
        mint_url: &MintUrl,
        proofs: Proofs,
    ) -> Result<Proofs, MintClientError> {
        // Same shared ceremony as the native client — only the transport below
        // it differs.
        swap_to_redeem(self, mint_url, proofs).await
    }
}
