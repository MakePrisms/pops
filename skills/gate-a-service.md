# Gate a service with pops

You run an HTTP service and want each request to require a **pop** — an ecash
bearer credential backed by CLTV-locked Bitcoin (see
[AGENTS.md](../AGENTS.md)). A gated resource answers `402` + a
`WWW-Authenticate: Payment` challenge; a client retries with the pop in
`Authorization: Payment …`; you **verify + redeem** it (a NUT-03 swap against
your mint that proves the token is unspent and unexpired) and keep the value,
then serve the request. **You are non-custodial** — there is no third party.

This is the front door. There are **three modes**; pick by your stack, follow
the minimal steps, then defer to the authoritative doc linked for each.

---

## 1. Reverse-proxy — any stack, zero app code

Put the **pops-gateway** in front of your unmodified API. It challenges each
request with `402`, verifies + redeems valid pops, persists the value, and
forwards the original request upstream. One declarative `config.toml`, no code
changes in your app.

**Pick this when** your service is in any language/framework and you don't want
to touch its code, or you want gating as a separate operational layer.

Minimal steps — copy
[`config.example.toml`](../crates/pops-gateway/config.example.toml) →
`config.toml`, set the five required facts, then run the published image
(mount the config and a **persistent** volume for the proofs sink):

```sh
docker run -p 8080:8080 \
  -v ./config.toml:/etc/pops-gateway/config.toml \
  -v ./data:/data \
  ghcr.io/makeprisms/pops-gateway:latest
```

The **five required config facts** at a glance:

| key             | what it is                                                            |
|-----------------|-----------------------------------------------------------------------|
| `upstream_url`  | your existing API, forwarded to on a successful charge (absolute http(s)) |
| `mint_url`      | the pops mint the presented credential is redeemed against (NUT-03 swap) |
| `proofs_sink`   | path where received value lands — **this file is a wallet** (persist it) |
| `[charge].unit` | the `pop_<unix_ts>` unit you accept (rotates — see below)             |
| `[charge].amount` | exact net value required per request (must be > 0)                  |

Authoritative doc (optionals, per-path `[[routes]]` gating, value model,
build-from-source): **[crates/pops-gateway/README.md](../crates/pops-gateway/README.md)**.

---

## 2. Rust / axum — in-process

Embed the verifier directly with `pops-core-verify`'s axum middleware. No proxy
hop; the gate runs inside your own service.

**Pick this when** your service is already Rust/axum and you want the gate
in-process (one binary, no extra container).

The public surface (in
[`crates/pops-core-verify/src/middleware.rs`](../crates/pops-core-verify/src/middleware.rs),
re-exported from
[`lib.rs`](../crates/pops-core-verify/src/lib.rs) under the default `native`
feature):

- **`CashuRequirement`** — what a holder must present: `unit` (a
  `CurrencyUnit::Custom("pop_<ts>")`), `mints` (accepted mint set; empty means
  "any"), `amount` (exact), and optional `payment_id` / `description` /
  `single_use`. This is the config you build the challenge from. (Defined in
  [`challenge.rs`](../crates/pops-core-verify/src/challenge.rs).)
- **`require_charge_state(requirement) -> ChargeMiddlewareState<CashuCredential<CdkMintClient>>`**
  — the convenience constructor that wires the default cdk-backed mint client.
- **`require_charge`** — the axum middleware function. Register it with
  `axum::middleware::from_fn_with_state(Arc::new(state), require_charge)`.

Wiring sketch:

```rust
use std::sync::Arc;
use axum::{routing::get, Router, middleware::from_fn_with_state};
use pops_core_verify::middleware::{require_charge, require_charge_state};

// Build the requirement (unit/amount/mints/...) and the middleware state.
let state = Arc::new(require_charge_state(requirement)); // requirement: CashuRequirement

let app = Router::new()
    .route("/secret", get(secret_handler))
    .layer(from_fn_with_state(state, require_charge));
```

On a bare request the middleware returns `402` with the `WWW-Authenticate:
Payment` challenge; on a valid `Authorization: Payment <blob>` retry it runs the
full verify + NUT-03 swap, then inserts the redeemed result into the request
extensions, so your handler can read it via `Extension<Redeemed>` (the redeemed
proofs + amount/unit/token_hash — that is the value you now hold). Failure
mapping: mint unreachable → `503` (token NOT consumed, retry); malformed request
→ `400`; any other verification failure → `402` + a fresh challenge.

Authoritative source: the module docs in
[`middleware.rs`](../crates/pops-core-verify/src/middleware.rs).

---

## 3. Serverless / JS (Vercel / Node) — WASM

Run the verifier **in JavaScript** via the `pops-core-verify` WASM build. A
Node serverless function performs the full `402 → verify + NUT-03 swap → 200`
in-process over an injected `globalThis.fetch` — no proxy, no Rust at runtime.

**Pick this when** your service is a JS/TS serverless function (Vercel/Node) and
you want the gate inside the function.

Minimal shape — the route loads the WASM, 402s a bare request, and on retry
calls `parse_payment_credential` then `verify_and_redeem`:

```js
const credsJson = wasm.parse_payment_credential(authorization);   // extract the cashuB token
const cashuToken = JSON.parse(credsJson).payload.cashu_token;
const redeemed = await wasm.verify_and_redeem(                      // full verify + NUT-03 swap
  cashuToken,
  JSON.stringify(requirement),                                     // { amount, unit, mints, payment_id, description, single_use }
);                                                                  // resolves { ok, fresh_proofs, amount, unit, active_keyset_id, token_hash }
```

`verify_and_redeem` **resolves** with the fresh proofs you now hold, or
**rejects** with `{ ok:false, code, message }` whose `code` maps to a status:
`mint-unreachable` → `503`, `malformed-request` → `400`, everything else → `402`
+ a fresh challenge.

The bindings are **not on npm** — build them from source first
(`bash ts/build-wasm.sh`). Authoritative doc + toolchain:
**[ts/README.md](../ts/README.md)**. **Reference implementation** (a complete
gated route to copy):
[`ts/vercel-demo/app/api/secret/route.ts`](../ts/vercel-demo/app/api/secret/route.ts).

---

## Must-know for every mode

These hold no matter which mode you pick:

- **Non-custodial — there is no third party.** The pops clients present are
  bearer ecash; you redeem them (a NUT-03 swap) into **fresh proofs only you
  control**, and keep that value as payment for the request.
- **The proofs sink is a WALLET.** Whether it's the gateway's `proofs_sink`
  file or the `fresh_proofs` your in-process/serverless handler receives, each
  record holds **spendable bearer secrets**. Persist it durably (the gateway
  appends + flushes + fsyncs before forwarding), **back it up** (losing the file
  loses the money), and **restrict access** (anyone who can read it can spend
  it). Never log or share `fresh_proofs`.
- **Active-unit rotation.** `pop_<ts>` units are CLTV-dated and **rotate** — a
  given unit eventually goes **inactive**. Use your mint's currently-active
  unit: `GET <mint_url>/v1/keysets` and pick a keyset with `active: true`. A
  stale unit in your config silently stops accepting valid current pops.
- **Health + fail-fast (gateway).** `GET /healthz` → `200` whenever the process
  is up; `GET /readyz` → `200` only if the mint is reachable (a cheap `GET
  <mint_url>/v1/keysets`), else `503`. On boot the gateway validates the config
  and **exits nonzero** with a single structured stderr line on any problem
  (bad URL, malformed `pop_<ts>` unit, `amount <= 0`, unwritable `proofs_sink`
  parent) — never a panic. The in-process and WASM modes surface the same
  reachability concern as the `503` (mint-unreachable) mapping.
- **The "paid-but-upstream-down" v1 edge (gateway).** The pop is **redeemed
  before** the upstream call. If the upstream is down after a successful charge,
  the gateway returns `502`/`504`, the value is **already persisted** (you keep
  it), but the client has spent its pop without getting the response. A one-shot
  spend is not idempotent, so the client loses that pop. This is an accepted,
  documented v1 limitation.

---

## Test your gate

To exercise your own `402` by hand — build a credential, present it, and watch
it gate through — you need the wire format. Build the credential with the
canonical encoders (don't hand-roll the base64/JSON):
**[skills/payment-credential.md](payment-credential.md)**.

To pay your gate with a **real** held pop instead, drive the `pop` CLI:
`pop pay <your-url> --token <cashuB>` runs the full 402 dance — see
**[skills/pop-wallet.md](pop-wallet.md)**.

---

## Which mode for which stack

| Your service is…                          | Use mode |
|-------------------------------------------|----------|
| any language, don't want to touch its code | 1 — reverse-proxy (pops-gateway) |
| Rust + axum, want the gate in-process      | 2 — `require_charge` middleware |
| a JS/TS serverless function (Vercel/Node)  | 3 — WASM `verify_and_redeem` |
