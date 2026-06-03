# PoPs — Proof of Power

**Ecash credentials backed by CLTV-locked Bitcoin.** Access-control and
spam-protection without captchas or upfront payment. A client locks
(recoverable) Bitcoin capital to mint *pops* — bearer ecash tokens — then spends
a pop to access a gated resource. The operator verifies and redeems the pop,
receiving the value (non-custodial). It is spam-resistant because "power" =
locked capital, which can't be cheaply farmed at scale. The verifier is ecash-**agnostic**:
pops are one supported credential type.

The flow is HTTP-402-native: a gated resource answers a bare request with `402
Payment Required` + a `WWW-Authenticate: Payment` challenge; the client retries
with a pop credential in `Authorization: Payment <blob>`; the operator verifies
it and redeems it (a Cashu NUT-03 swap whose success proves the token is
unspent and unexpired), then serves the request.

---

## Three ways to use it

Pick one — they share the same verify core (`pops-core-verify`).

| You want to… | Use | App code change |
|---|---|---|
| Gate an existing HTTP service | **pops-gateway** (Docker reverse-proxy) | none |
| Gate a serverless function | **WASM verify+swap** in a Node/Vercel function | a few lines |
| Mint pops, pay an endpoint, recover BTC | **`pop`** CLI wallet | n/a (client side) |

---

### 1. Gate a server — drop-in, zero app code

Put the `pops-gateway` reverse-proxy in front of your unmodified API. Each
request is challenged with `402`; on a valid pop the gateway verifies + redeems
it, **persists the received value**, and forwards the original request upstream,
streaming the response back. Client → gateway (gates) → your upstream.

Write one `config.toml`:

```toml
# REQUIRED
upstream_url = "http://your-api:3000"        # your existing API, unmodified
mint_url     = "https://mint.example.com"    # the pops mint to redeem against
proofs_sink  = "/data/proofs.jsonl"          # WHERE received value lands — a WALLET (no default)

[charge]
unit   = "pop_1782668279"                    # the pop_<unix_ts> unit you accept
amount = 1                                   # exact net value required per request

# OPTIONAL
# listen = "0.0.0.0:8080"                    # default 0.0.0.0:8080
# [charge].mints       = ["https://mint.example.com"]   # default [mint_url]
# [charge].description = "my API"            # shown in the 402 challenge

# OPTIONAL per-path gating. Absent => gate EVERY path.
# [[routes]]
# path   = "/health/*"
# public = true                              # forwarded WITHOUT a gate
# [[routes]]
# path   = "/api/*"                          # gated (public defaults to false)
```

Run the published image, mounting the config and a **persistent** volume for the
proofs sink:

```sh
docker run -p 8080:8080 \
  -v ./config.toml:/etc/pops-gateway/config.toml \
  -v ./data:/data \
  ghcr.io/makeprisms/pops-gateway
```

Point your clients at `http://localhost:8080`. A bare request gets a `402` with
the challenge; a request carrying a valid `Authorization: Payment <blob>` gates
through to your upstream.

Health: `GET /healthz` (process up) and `GET /readyz` (mint reachable). Logs are
JSON-structured (`tracing-subscriber` json; tune with `RUST_LOG`, default
`info`).

> Full config reference, request-handling semantics, the persist-before-forward
> guarantee, and the known "paid-but-upstream-down" v1 edge:
> **[crates/pops-gateway/README.md](crates/pops-gateway/README.md)**.

---

### 2. Serverless verify — WASM verify+swap inside a function

`pops-core-verify` compiles to a Node-target WASM package
(`@makeprisms/pops-core-wasm`). Import it into a serverless function to run the
**full** verify + NUT-03 swap (over an injected `globalThis.fetch`) inside the
function — no separate gateway process. Reference: a Next.js (Node runtime)
route at `ts/vercel-demo/app/api/secret/route.ts`.

The shape of a gated handler (abridged from the demo route):

```ts
export const runtime = "nodejs";        // Node, not Edge — the wasm glue reads its .wasm via fs
export const dynamic = "force-dynamic"; // always gate; never cache the 402/200 decision

const wasm = await import("@makeprisms/pops-core-wasm");

const requirement = {
  amount: 1,
  unit: "pop_1780372941",
  mints: ["https://mint.example.com"],
  payment_id: "my-challenge",
  description: "my gated function",
  single_use: true,
};

const authorization = req.headers.get("authorization");
if (!authorization || !/^payment\s/i.test(authorization.trim())) {
  // 402 + WWW-Authenticate: Payment <wasm.encode_request_envelope(creqA)>
  return challenge402(wasm);
}

// Parse the credential blob (cashu-free), then verify + swap against the mint:
const creds = JSON.parse(wasm.parse_payment_credential(authorization));
const redeemed = await wasm.verify_and_redeem(creds.payload.cashu_token, JSON.stringify(requirement));
// success => operator now holds redeemed.fresh_proofs (a cashuB token); serve the gated payload.
```

WASM surface used: `encode_request_envelope`, `parse_payment_credential`,
`verify_and_redeem` (returns `{ ok, amount, unit, active_keyset_id, token_hash,
fresh_proofs }`). Error mapping mirrors the gateway: `mint-unreachable` → `503`
(token not consumed, retry), `malformed-request` → `400`, any other
verification failure → `402` + fresh challenge.

Build the WASM package (writes to `ts/pops-core-wasm/pkg/`, which is
git-ignored):

```sh
bash ts/build-wasm.sh
```

Run the demo:

```sh
cd ts/vercel-demo
npm install        # pulls @makeprisms/pops-core-wasm via a file: dep
npm run build:wasm # (re)build the wasm package
npm run dev        # then: curl -i localhost:3000/api/secret  →  402, retry with a credential
```

> The mint URL / unit / amount in the demo are overridable at deploy time via
> `POPS_MINT_URL` / `POPS_UNIT` / `POPS_AMOUNT`. See
> `ts/vercel-demo/app/api/secret/route.ts`.

---

### 3. Wallet CLI (`pop`) — mint pops, pay an endpoint, recover BTC

`pop` is the **funder-side** wallet: lock BTC, mint a pop credential, and
reclaim the BTC after the timelock. The minted ecash is **printed** (a `cashuB`
token), not stored — this wallet manages deposits and recovery, not a balance.
**JSON is the default output** of every command (stdout, on success and
failure); pass `--human` (alias `--pretty`) for text.

Build (Rust 1.95):

```sh
cargo build --release        # binary at target/release/pop
cargo install --path crates/pop   # or install the `pop` binary
```

The funder lifecycle:

```sh
# 1. Create a seed (BIP-39 mnemonic shown ONCE — it is the only backup).
pop init --network mainnet

# 2. Lock BTC + mint a pop. Funding is on-chain (~1 confirmation), not instant:
#    this prints a funding address; broadcast EXACTLY --amount sats to it, then
#    `mint` polls until the mint confirms funding and prints the cashuB token.
#    --mint-pubkey (the mint's 33-byte compressed identity key) is REQUIRED on
#    first use of a mint (TOFU-pinned into config.toml).
pop mint --mint-url https://mint.example.com --amount 50000 \
         --mint-pubkey <hex33> --duration 30d

# 3. After the CLTV matures, reclaim the locked BTC to a fresh address.
pop recover --deposit <deposit_id> --dest <bc1...> --target 6
```

Two-step (non-blocking) variant — preferred for agents, so the funding address
can be surfaced for confirmation before any poll:

```sh
pop quote --mint-url https://mint.example.com --amount 50000 \
          --mint-pubkey <hex33> --duration 30d   # creates+verifies the address, persists, exits
# ...fund the printed funding_address with EXACTLY amount_sats...
pop mint --resume <deposit_id>                    # polls until funded, prints the cashuB token
```

Other commands:

```sh
pop list   [--state unpaid|paid|minted|recovered|expired]   # local deposit table
pop status [--deposit <id>]                                  # one deposit, with chain-overlay recoverability
pop balance                                                  # aggregate: total locked, per-state, mintable/recoverable now
pop recover --all --dest <bc1...>                            # sweep every matured deposit
```

Globals: `--wallet-dir <PATH>` (default `~/.pop-wallet/`), `--human` /
`--pretty`. The wallet dir holds `config.toml`, the `seed` (plaintext, `0600` —
the **only** secret), `wallet.db`, and one `recovery/<id>.recovery.json` per
deposit. Recovery needs only the seed mnemonic + the recovery file (or Bitcoin
Core ≥ 26 with the file's descriptor) — no live mint, no third party.

> An agent SKILL with the full machine contract — exact JSON output shapes per
> command, the 20-code frozen error contract (branch on `code`, never on
> `message`), and the onboarding/safety rails for locking real BTC on a human's
> behalf — lives at **[crates/pop/SKILL.md](crates/pop/SKILL.md)**.

---

## For AI agents

This repo is built to be driven by agents.

**Paying an endpoint / managing funds with `pop`:** stdout carries **exactly one
JSON object per invocation** in the default (json) mode — all progress, poll
status, and warnings go to **stderr**. Parse stdout; ignore stderr (or surface
it as live progress). Every object has top-level `"schema_version": 1`. Failures
are `{ "schema_version": 1, "error": { "code", "retriable", "message",
"details"? } }` on stdout with exit code 1 — **branch on `code`**, never on
`message`. (clap arg-parse errors exit 2 with no JSON envelope — that means you
invoked `pop` wrong.) The command surface, every output shape, and the frozen
error-code table are in **[crates/pop/SKILL.md](crates/pop/SKILL.md)**;
`crates/pop/agent-state.schema.json` is the persisted-state schema. Funding is
on-chain and exact — fund the address with EXACTLY `amount_sats` or it will not
credit.

**Adding the gateway to a service:** write the one `config.toml` (the five
required facts: `upstream_url`, `mint_url`, `proofs_sink`, `[charge].unit`,
`[charge].amount`), `docker run` the published image with a **persistent** mount
for `proofs_sink`, and point clients at it — see use-path 1 above. On any config
problem the gateway prints a single structured line (`config field <X>:
<reason>`) to stderr and exits nonzero (never a panic). Gateway logs are
JSON-structured; outcomes are machine-parseable. The full config + behavior
reference is **[crates/pops-gateway/README.md](crates/pops-gateway/README.md)**.

---

## Value model — non-custodial

There is **no third party.** You run the gateway (or the serverless verifier)
inside your own trust boundary.

- **The operator keeps the value clients spend.** A spent pop is bearer ecash;
  the gateway redeems it (a NUT-03 swap) into **fresh proofs only you control**
  and appends them to `proofs_sink` — append + flush + fsync, **before**
  forwarding the request upstream.
- **`proofs_sink` is your wallet / your money.** Each line holds spendable
  bearer secrets (a `cashuB…` token). It **must** be a persistent mount — on an
  ephemeral container layer a restart destroys received value (the gateway logs
  a loud startup warning for exactly this). **Back up the volume. Restrict
  access** — anyone who can read it can spend the proofs.
- **Clients recover their UNSPENT pops** after the CLTV expiry, using their own
  seed (`pop recover`). Spent pops are gone (the operator has them); only
  capital that was never spent is reclaimable.

---

## Repo layout

A Rust workspace (five crates) plus a `ts/` directory for the WASM build and
serverless demo.

| Path | What it is |
|---|---|
| `crates/pops-core-types` | The `pop_<ts_expiry>` unit grammar + the shared `ChargeError` / `RedeemedProofs` contract. Pure, no cashu/cdk dep. |
| `crates/pops-core-funder` | Pure-function funder crypto: the taproot funding-commitment construction + CLTV recovery (build/sign the script-path spend). |
| `crates/pops-core-verify` | The ecash-**agnostic** verify core: HTTP-402 challenge + verify + redeem (NUT-03 swap) behind a swappable `MintClient`. Native (axum middleware / cdk) **and** WASM surfaces. |
| `crates/pop` | The funder-side CLI wallet (mint / pay / recover). JSON-default output. |
| `crates/pops-gateway` | The Docker reverse-proxy that gates an unmodified upstream — a thin host around `pops-core-verify` (does not re-implement verification). |
| `ts/` | `build-wasm.sh` (builds `pops-core-verify --features wasm` to a Node wasm-pack package), `pops-core-wasm/` (the generated package), and `vercel-demo/` (the Next.js Node-runtime gating demo). |

To embed the verifier natively in your own Rust (axum) service instead of the
Docker gateway, use the `pops_core_verify::middleware` layer directly — see its
module docs in `crates/pops-core-verify/src/middleware.rs`.

---

## Links

- **Gateway (drop-in reverse-proxy):** [crates/pops-gateway/README.md](crates/pops-gateway/README.md)
- **`pop` CLI wallet:** [crates/pop/README.md](crates/pop/README.md)
- **Agent SKILL (machine contract for `pop`):** [crates/pop/SKILL.md](crates/pop/SKILL.md)
- **Serverless verify demo:** `ts/vercel-demo/app/api/secret/route.ts`

PoP credentials build on Cashu (ecash) and a CLTV-locked Bitcoin UTXO; the
funder crypto and quote/mint/recover flow derive from
[`MakePrisms/cdk`](https://github.com/MakePrisms/cdk) (`cdk-pop`).
