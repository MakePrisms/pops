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

The image is **published and public** (multi-arch: linux/amd64 + linux/arm64) at
[`ghcr.io/makeprisms/pops-gateway`](https://github.com/MakePrisms/pops/pkgs/container/pops-gateway)
(tag `latest`) — anonymously pullable, no login needed:

```sh
docker pull ghcr.io/makeprisms/pops-gateway:latest
```

Two prep steps, then one command:

1. Copy [`config.example.toml`](./config.example.toml) → `config.toml`.
2. Edit the five required facts (`upstream_url`, `mint_url`, `proofs_sink`,
   `[charge].unit`, `[charge].amount`) — they are commented inline in the file.
3. Run, mounting the config and a **persistent** volume for the proofs sink
   (`proofs_sink = "/data/proofs.jsonl"` in the example lands in `./data`):

```sh
docker run -p 8080:8080 \
  -v ./config.toml:/etc/pops-gateway/config.toml \
  -v ./data:/data \
  ghcr.io/makeprisms/pops-gateway:latest
```

The gateway reads its config from the path in the **`POPS_GATEWAY_CONFIG`**
env var, defaulting to **`/etc/pops-gateway/config.toml`** (which is why the
mount above lands there).

Prefer to build from source? See [Building the image
yourself](#building-the-image-yourself) — the run command is identical, just
swap the local tag for the `ghcr.io/...` one.

Point your clients at `http://localhost:8080`.

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
Payment <credential>` header** echoing the challenge and carrying a `cashuB…`
token. That wire format (the `402` challenge shape, the credential to build, the
rules, and the canonical encoders) is documented once, canonically, in
**[skills/payment-credential.md](../../skills/payment-credential.md)**.

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
- **It MUST be writable by the container uid.** The image runs as the non-root
  `pops` user (**uid 10001**). The gateway runs a **real write-probe** at startup
  (create + fsync + delete a temp file in the `proofs_sink` directory **as that
  uid**) and **fails fast** if it can't write — so a volume owned by host root is
  caught at boot, not on the first paid request. `chown 10001:10001` the host
  directory before mounting it (or run the container `--user "$(id -u):$(id -g)"`
  with the dir owned by that uid). A named docker volume needs no host chown. See
  the Dockerfile header for both recipes.
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
   request="<request-object>", expires="…"`, an RFC-9457
   `application/problem+json` body, and `Cache-Control: no-store`. The `id` is
   a per-request HMAC binding every issued param under **`binding_key`** (or
   the **`POPS_BINDING_KEY`** env var, which wins; omitted ⇒ a fresh key per
   boot), and `expires` stamps **`challenge_ttl_secs`** (default 300) into the
   challenge.
2. **Valid credential** → the echoed challenge is authenticated first (the
   HMAC recomputed over the echo; `expires` checked), then verify + NUT-03
   swap against `mint_url` (each mint call bounded by
   **`mint_http_timeout_secs`**, default 10s; `0` is a config error).
3. On success the gateway **persists `fresh_proofs` durably (append + flush +
   fsync) BEFORE forwarding** — a crash between forward and persist would
   otherwise lose already-consumed value.
4. Then the **original** request (method/path/query/headers/body) is forwarded
   to `upstream_url` (with a bounded **`upstream_timeout_secs`**, default 30s)
   and the response is streamed back.
5. Error mapping (the verifier's single-sourced problem map; every error body
   is `application/problem+json` with an absolute problem-type URI):
   - mint unreachable → `503` + `Retry-After` (token **not** consumed, retry).
   - request body over **`max_body_bytes`** (default 1 MiB) → `413 Payload Too
     Large`. On a gated path this is checked **before the charge**, so the pop
     is **not** consumed.
   - credential carrying more than **`[charge].max_proofs`** proofs (default
     64) → `402` BEFORE any swap (a pre-swap DoS guard; the pop is **not**
     consumed).
   - malformed request frame (>1 credential) / non-`cashu` method → `400`.
   - tampered or unissued challenge echo → `402 invalid-challenge`; stale
     `expires` or a keyset retired at the mint → `402 payment-expired`.
   - upstream hung past the timeout → `504`; upstream down → `502` (the pop, if
     gated, is already spent — see the v1 edge below).
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

Each settlement logs one INFO line (`charge settled and persisted; forwarding
upstream`) carrying `token_hash`, `amount`, `unit`, `active_keyset_id`, and
**`dleq_ok`** — the NUT-12 verdict on the signatures the mint returned from the
redeeming swap. `dleq_ok=false` is a **mint-trust incident**, not a payment
failure: the client's payment settled and was served, but the mint could not
prove it signed your fresh proofs with its advertised key (a WARN naming the
mint fires too). Alert on it and consider quarantining the mint.

---

## Fail-fast config validation

On boot the gateway validates the config and, on any problem, prints a single
structured line to stderr and **exits nonzero** (never a panic / stacktrace):

```
config field charge.amount: must be greater than 0
```

Checks: `upstream_url` / `mint_url` parse; `charge.unit` is a well-formed
`pop_<ts>`; `charge.amount > 0`; `max_body_bytes > 0`;
`mint_http_timeout_secs > 0` (an unbounded mint call would hang a request
whose token may already be consumed); `challenge_ttl_secs > 0` (a 0-TTL
challenge is born expired); a configured `binding_key` is plausible hex of at
least 16 bytes; every `charge.mints` entry parses; and `proofs_sink`'s parent
directory exists **and is actually writable by the running uid** — verified
with a real create+fsync+delete write-probe (not just an inode mode-bit
inspection), so a dir the process can't write is caught at boot rather than on
the first redeemed proof.

---

## Building the image yourself

The crate is a workspace member (path dep on `pops-core-verify`), so the
Docker build context is the **workspace root**:

```sh
docker build -f crates/pops-gateway/Dockerfile -t pops-gateway .
```
