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

The knobs worth knowing about (all optional, sane defaults):

| key | default | what it does |
|---|---|---|
| `binding_key` | generated at boot | Hex server secret the stateless challenge binding HMACs ids under (≥ 16 bytes; 32 recommended). The **`POPS_BINDING_KEY`** env var overrides it. Without a configured key, a restart invalidates outstanding challenges (clients just refetch the 402). The key is a secret — never log or share it. |
| `challenge_ttl_secs` | `300` | Lifetime stamped into each challenge's `expires` (must be > 0 — a 0-TTL challenge is born expired). |
| `mint_http_timeout_secs` | `10` | Bound on each mint HTTP call (keysets/keys/swap); a hung mint surfaces as the 503 mint-unavailable path. Must be > 0 — **`0` is a config error** (an unbounded mint call would hang a request whose token may already be consumed). |

Authoritative doc (all optionals, per-path `[[routes]]` gating, value model,
build-from-source): **[crates/pops-gateway/README.md](../crates/pops-gateway/README.md)**
and the commented [`config.example.toml`](../crates/pops-gateway/config.example.toml).

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
  `CurrencyUnit::Custom("pop_<ts>")`), `mints` (accepted mint set; **must be
  non-empty** — the challenge's `creqA` requires a non-empty `m`, so a Payment
  host cannot emit a challenge from an empty set and the middleware answers a
  bare request with `500` if misconfigured that way), `amount` (exact), and
  optional `payment_id` / `description` / `single_use`. This is the config you
  build the challenge from. (Defined in
  [`challenge.rs`](../crates/pops-core-verify/src/challenge.rs).)
- **`require_charge_state(requirement) -> ChargeMiddlewareState<CashuCredential<CdkMintClient>>`**
  — the convenience constructor that wires the default cdk-backed mint client
  (mint HTTP bounded at 10s; `require_charge_state_with_mint_timeout` takes an
  explicit bound). Chain **`.with_binding_key(BindingKey::from_hex(…)?)`** to
  keep challenges valid across restarts (default: a fresh per-boot key) and
  **`.with_challenge_ttl(Duration)`** to override the 300s `expires` TTL.
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
Payment` challenge (HMAC-bound `id` + `expires`); on a valid `Authorization:
Payment <blob>` retry it authenticates the echoed challenge, runs the full
verify + NUT-03 swap, then inserts the redeemed result into the request
extensions, so your handler can read it via `Extension<Redeemed>` (the redeemed
proofs + amount/unit/token_hash — that is the value you now hold — plus
**`dleq_ok`**: `false` means the mint's swap-returned signatures failed their
NUT-12 check, a mint-trust incident to alert on while still serving). Failure
mapping: mint unreachable → `503` (token NOT consumed, retry); malformed request
/ non-`cashu` method → `400`; stale challenge or retired keyset →
`402 payment-expired`; any other verification failure → `402` + a fresh
challenge. Every error body is RFC-9457 `application/problem+json`.

Authoritative source: the module docs in
[`middleware.rs`](../crates/pops-core-verify/src/middleware.rs).

---

## 3. Serverless / JS (Vercel / Node) — WASM

Run the verifier **in JavaScript** via the `pops-core-verify` WASM build. A
Node serverless function performs the full `402 → verify + NUT-03 swap → 200`
in-process over an injected `globalThis.fetch` — no proxy, no Rust at runtime.

**Pick this when** your service is a JS/TS serverless function (Vercel/Node) and
you want the gate inside the function.

**Scope this mode honestly: it is an advisory demo surface.** The wasm package
exports the credential codec + `verify_and_redeem` only — **no challenge
issuance or binding API** (a wasm issuance API is recorded backlog). So the
challenge-side MUSTs the two Rust hosts enforce (HMAC-bound `id`, `expires`,
echo authentication, the `Payment-Receipt` on the 200) are YOUR route's job in
JS; the vercel demo issues a fixed `id` with no `expires` and emits no receipt
— fine for a demo, not the full Payment wire.

Minimal shape — the route loads the WASM, 402s a bare request, and on retry
calls `parse_payment_credential` then `verify_and_redeem`:

```js
const credsJson = wasm.parse_payment_credential(authorization);   // extract the cashuB token
const cashuToken = JSON.parse(credsJson).payload.token;
const redeemed = await wasm.verify_and_redeem(                      // full verify + NUT-03 swap
  cashuToken,
  JSON.stringify(requirement),                                     // { amount, unit, mints, payment_id, description, single_use }
);     // resolves { ok, fresh_proofs, amount, unit, active_keyset_id, token_hash, dleq_ok }
```

`verify_and_redeem` **resolves** with the fresh proofs you now hold (PERSIST
them — they are the money; `dleq_ok: false` flags a mint-trust incident to
alert on while still serving), or **rejects** with
`{ ok:false, code, message, status, problem_type, problem_slug }` — answer with
the mapped `status` (`503` mint-unreachable + `Retry-After`, `400`
malformed-request/method-unsupported, everything else `402` + a fresh
challenge) and use `problem_type` for the RFC-9457 body, so the JS route emits
the same wire as the native hosts.

Install the bindings prebuilt from GitHub — no Rust/wasm toolchain, no
npm-registry auth:

```sh
npm install github:MakePrisms/pops#wasm-pkg          # tracks main
npm install github:MakePrisms/pops#wasm-v0.1.0       # pinned, immutable
```

(In `package.json`: `"@makeprisms/pops-core-wasm":
"github:MakePrisms/pops#wasm-pkg"`.) Building from source
(`bash ts/build-wasm.sh`) is only needed if you change the Rust kernel.
Authoritative doc + toolchain: **[ts/README.md](../ts/README.md)**. **Reference
implementation** (a complete gated route to copy):
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
- **Challenges are bound and they expire — in the two Rust hosts.** Every
  challenge the gateway (mode 1) and the axum middleware (mode 2) issue carries
  an HMAC-bound `id` (under `binding_key` / the middleware's `BindingKey`) and
  an `expires` (default TTL 300s). A credential must echo every issued param
  byte-for-byte or it is rejected as `invalid-challenge`; a stale echo is
  `payment-expired`. Configure a stable `binding_key` if challenges must
  survive a restart. Mode 3 has no issuance API, so binding/expiry are
  whatever your JS route implements (the demo implements neither — see the
  mode-3 scope note).
- **DLEQ serve-and-flag.** A missing/invalid NUT-12 DLEQ on the signatures the
  mint returns from the redeeming swap is a mint-trust incident, NOT a payment
  failure: the request still succeeds (the client's payment settled) and the
  verdict surfaces to YOU — `dleq_ok=false` on the gateway's settle log line
  (plus a WARN naming the mint), on `Extension<Redeemed>.dleq_ok` in-process,
  and on the WASM success object. Alert on it and consider quarantining the
  mint.
- **Health + fail-fast (gateway).** `GET /healthz` → `200` whenever the process
  is up; `GET /readyz` → `200` only if the mint is reachable (a cheap `GET
  <mint_url>/v1/keysets`), else `503`. On boot the gateway validates the config
  and **exits nonzero** with a single structured stderr line on any problem
  (bad URL, malformed `pop_<ts>` unit, `amount <= 0`, `mint_http_timeout_secs
  = 0`, `challenge_ttl_secs = 0`, unwritable `proofs_sink` parent) — never a
  panic. The in-process and WASM modes surface the same reachability concern as
  the `503` (mint-unreachable) mapping.
- **The "paid-but-upstream-down" v1 edge (gateway).** The pop is **redeemed
  before** the upstream call. If the upstream is down after a successful charge,
  the gateway returns `502`/`504`, the value is **already persisted** (you keep
  it), but the client has spent its pop without getting the response. A one-shot
  spend is not idempotent, so the client loses that pop. This is an accepted,
  documented v1 limitation.

---

## Test your gate

The easiest end-to-end test is the `pop` CLI with a **real** held pop:

```sh
pop pay <your-url> --token <cashuB> --max-amount 5000
```

It runs the full dance against the current wire: fetches the 402, refuses an
expired challenge outright (`challenge_expired`), decodes and cross-checks the
challenge's `paymentRequest` (amount/unit/mints), splits the held token to the
exact charge, echoes every issued challenge param verbatim (so the gate's
HMAC binding verifies), and presents. A `paid: true` JSON result (with any
`change_token`) proves the whole gate. See
**[skills/pop-wallet.md](pop-wallet.md)**.

To exercise the `402` by hand instead — build a credential yourself and watch
it gate through — you need the wire format:
**[skills/payment-credential.md](payment-credential.md)**. Two things bite
hand-rollers under the bound challenge: the credential must echo a challenge
**this server actually issued** (fetch a fresh 402 first; you cannot invent
`id`/`expires`), and the `request` param must be echoed **byte-for-byte**
(never decode-and-re-encode it). Build with the canonical encoders, not by
hand-assembling base64/JSON.

---

## Which mode for which stack

| Your service is…                          | Use mode |
|-------------------------------------------|----------|
| any language, don't want to touch its code | 1 — reverse-proxy (pops-gateway) |
| Rust + axum, want the gate in-process      | 2 — `require_charge` middleware |
| a JS/TS serverless function (Vercel/Node)  | 3 — WASM `verify_and_redeem` |
