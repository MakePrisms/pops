# pops-gateway

A native (no-WASM) reverse proxy that gates your **unmodified** API with
pops/cashu payment. Drop it in front of any HTTP service: each request is
challenged with `HTTP 402` + a `WWW-Authenticate: Payment` envelope, and on a
valid pops credential the gateway verifies + redeems it (a NUT-03 swap against
your mint), **persists the received value**, and forwards the original request
upstream — streaming the response straight back.

Zero app changes. One declarative config. Operator-run, **non-custodial**.

The gateway is a thin host around the `pops-core-verify` gate — it does not
re-implement verification.

---

## Quickstart

One command, two prep steps. Copy the shipped example, edit the five required
values, then run the published image:

1. Copy [`config.example.toml`](./config.example.toml) → `config.toml`.
2. Edit the five required facts (`upstream_url`, `mint_url`, `proofs_sink`,
   `[charge].unit`, `[charge].amount`) — they are commented inline in the file.
3. Run, mounting the config and a **persistent** volume for the proofs sink:

```sh
docker run -p 8080:8080 \
  -v ./config.toml:/etc/pops-gateway/config.toml \
  -v ./data:/data \
  ghcr.io/makeprisms/pops-gateway
```

Point your clients at `http://localhost:8080`. That's it — no local build.

A bare request gets a `402` with the challenge; a request carrying a valid
`Authorization: Payment <blob>` credential gates through to your upstream. See
[Paying the gateway (client side)](#paying-the-gateway-client-side) for how a
client builds that credential.

The five required facts, for reference (see
[`config.example.toml`](./config.example.toml) for the optionals and comments):

```toml
upstream_url = "http://your-api:3000"        # your existing API, unmodified
mint_url     = "https://mint.example.com"    # the pops mint to redeem against
proofs_sink  = "/data/proofs.jsonl"          # WHERE received value lands (a wallet!)

[charge]
unit   = "pop_1780372941"                    # the pop_<unix_ts> unit you accept
amount = 1                                   # exact net value required per request
```

> **NOTE:** pop units are CLTV-dated and ROTATE — a given `pop_<ts>` eventually
> goes inactive; use your mint's currently-**ACTIVE** unit: `GET
> <mint_url>/v1/keysets` and pick a keyset with `active: true`. The
> `pop_1780372941` above is currently active (also the Vercel demo's default),
> but confirm against your mint.

---

## Paying the gateway (client side)

A client that receives a `402` pays by **retrying with an `Authorization:
Payment <credential>` header**. The credential ECHOES the challenge from the
402 and carries a `cashuB…` token. The field names + encoding below are exact —
they are what the gateway parses (source of truth:
`crates/pops-core-verify/src/envelope.rs`).

### Flow

1. **`GET`** the protected resource → `402` with a challenge header:
   ```
   WWW-Authenticate: Payment id="…", realm="…", method="cashu", intent="charge", request="<envelope>"
   ```
2. **Base64url-nopad-decode** the `request` param → JSON
   `{"cashu_request":"creqA…"}`. The `creqA…` is a cashu payment-request that
   describes the charge (amount, unit, accepted mints).
3. With your **cashu wallet**, mint/select a `cashuB…` token for that amount +
   unit at one of the accepted mints.
4. **Build the credential** — a JSON object that echoes the challenge and
   carries the token, then base64url-nopad-encode it and prefix `Payment `:
   ```json
   {
     "challenge": {
       "id": "<echo>",
       "realm": "<echo>",
       "method": "cashu",
       "intent": "charge",
       "request": "<echo of the request param, verbatim>"
     },
     "payload": { "cashu_token": "cashuB…" }
   }
   ```
   → header value: `Payment <base64url-nopad(that JSON)>`
5. **Retry** the request with that `Authorization` header → `200` (gated
   content) or `402` (re-challenge — e.g. wrong amount/unit/mint, double-spend,
   or mint unreachable; on `503` retry, the token was **not** consumed).

### Rules

- The scheme `Payment` is **case-insensitive**.
- All **five** `challenge` fields (`id`, `realm`, `method`, `intent`, `request`)
  are **REQUIRED** and must be echoed **verbatim** from the 402.
- `method` **must** equal `cashu`.
- Extra fields (`source`, `description`, …) are tolerated and ignored.

### Canonical builder

Don't hand-roll the encoding. `pops-core-verify` exposes the builder:

- **WASM:** `build_payment_credential(credentials_json)` — takes the JSON object
  above as a string, returns the base64url-nopad blob; you prepend `Payment `.
- **Native (Rust):** `encode_payment_credentials(&PaymentCredentials)` — same
  blob.

Source of truth for the format: `crates/pops-core-verify/src/envelope.rs`.

---

## Non-custodial — `proofs_sink` is YOUR money

There is **no third party**. YOU run this gateway inside your own trust
boundary. The pops credentials clients present are **bearer ecash**; the gateway
redeems them (a NUT-03 swap) into **fresh proofs that only you control**, and
appends them to `proofs_sink`.

**`proofs_sink` is a WALLET.** Each line holds spendable bearer secrets
(`fresh_proofs`, a `cashuB…` token). Treat it accordingly:

- **It MUST be a persistent mount.** If `proofs_sink` lives on an ephemeral
  container layer, a restart **destroys received value**. The gateway logs a
  loud warning at startup for exactly this reason — heed it.
- **Back up the volume.** Losing the file loses the money.
- **Restrict access.** Anyone who can read it can spend the proofs.

The record written per settlement is one JSON line:

```json
{"received_at":1782668300,"token_hash":"<sha256-hex>","amount":1,"unit":"pop_1780372941","active_keyset_id":"<hex>","fresh_proofs":"cashuB…"}
```

`token_hash` is a SHA-256 of the *presented* token — a shareable receipt
reference that exposes no secret. `fresh_proofs` is the spendable value; never
log or share it.

### Value model

The gateway settles each spent pop into `proofs_sink`. The operator keeps that
value — it is the payment for the gated request.

---

## How a request is handled

1. **No / invalid credential** → `402 Payment Required` + `WWW-Authenticate:
   Payment id="…", realm="pops-gateway", method="cashu", intent="charge",
   request="<creqA-envelope>"`, body `{"error":"payment_required", …}`,
   `Cache-Control: no-store`.
2. **Valid credential** → verify + NUT-03 swap against `mint_url`.
3. On success the gateway **persists `fresh_proofs` durably (append + flush +
   fsync) BEFORE forwarding** — a crash between forward and persist would
   otherwise lose already-consumed value.
4. Then the **original** request (method/path/query/headers/body) is forwarded
   to `upstream_url` and the response is streamed back.
5. Error mapping (mirrors the reference verifier):
   - mint unreachable → `503` + `Retry-After` (token **not** consumed, retry).
   - malformed request → `400`.
   - any other verification failure → `402` + a fresh challenge.

### Known v1 edge — paid but upstream down

The pop is **redeemed before** the upstream call. If the upstream is **down**
after a successful charge, the gateway returns `502`/`504` and the value is
**already persisted** (the operator keeps it) — but the client has spent its pop
without receiving the response. A one-shot spend is not idempotent, so the
client loses that pop. This is an accepted, documented v1 limitation.

---

## Health & observability

- `GET /healthz` → `200` whenever the process is up.
- `GET /readyz` → `200` if the mint is reachable (a cheap `GET
  <mint_url>/v1/keysets`), else `503`.

Both are gateway-own and never forwarded upstream.

Logs are **JSON structured** (`tracing-subscriber` json) so an agent or operator
can parse outcomes. Set `RUST_LOG` to tune verbosity (default `info`).

---

## Fail-fast config validation

On boot the gateway validates the config and, on any problem, prints a single
structured line to stderr and **exits nonzero** (never a panic / stacktrace):

```
config field charge.amount: must be greater than 0
```

Checks: `upstream_url` / `mint_url` parse; `charge.unit` is a well-formed
`pop_<ts>`; `charge.amount > 0`; every `charge.mints` entry parses; and
`proofs_sink`'s parent directory exists and is writable.

---

## Building the image yourself

The crate is a workspace member (path deps on `pops-core-verify` /
`pops-core-types`, plus a git dep on `cdk`), so the Docker build context is the
**workspace root**.

The `cdk` git dep (`MakePrisms/cdk`, branch `feat/cdk-pop-readonly`) is a
**private** repo, so the builder needs a read credential, supplied as a BuildKit
secret (it is never baked into an image layer):

```sh
DOCKER_BUILDKIT=1 docker build \
  --secret id=ghtoken,src=<(gh auth token) \
  -f crates/pops-gateway/Dockerfile -t pops-gateway .
```

`gh auth token` must print a token with `repo` read on `MakePrisms/cdk`. In CI,
point `--secret` `src` at a file/env holding a token (or deploy key) with the
same read access.
