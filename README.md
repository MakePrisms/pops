# PoPs: Proof of Power

> **Agents → [AGENTS.md](AGENTS.md).** That's the entry point: it maps the two
> pathways: **use pops** (drive the `pop` wallet from its machine contract,
> **[skills/pop-wallet.md](skills/pop-wallet.md)**: exact per-command JSON, the
> frozen 33-code error table, and the safety rails for locking real BTC) and
> **gate your own service** (**[skills/gate-a-service.md](skills/gate-a-service.md)**),
> plus the shared `Payment` wire format.

---

PoPs are **ecash access-control credentials backed by CLTV-locked Bitcoin**. A
client locks (recoverable) Bitcoin capital to mint a *pop* (a bearer ecash
token) and presents it to reach a gated resource. No upfront payment and no
account: spam-resistance comes from the **locked capital** ("power"), which
can't be cheaply farmed at scale. It's HTTP-402-native (a gated resource answers
with `402` + a `WWW-Authenticate: Payment` challenge; the client retries with
the pop in `Authorization: Payment …`), conforming to `draft-cashu-charge-00`:
challenges are stateless-bound (HMAC `id`) and expire, value at or above the
charge is accepted (excess retained), and a mint-trust DLEQ incident is
flagged to the operator rather than failing a settled payment. The verifier is
**ecash-agnostic**: pops are one supported credential type.

## How it works

- **[Mint](https://github.com/cashubtc/nuts/blob/main/04.md) a pop** by sending
  BTC to a Taproot (P2TR) address that commits to the mint pubkey, an expiry, a
  nonce, and your recovery pubkey. The internal key is a NUMS point, so the key
  path is unspendable and the funds move only through the one script leaf.
- **Locking script** (that single Taproot leaf):
  `<ts_expiry> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <funder_pubkey> OP_CHECKSIG`, the
  funder's recovery path, spendable only after `ts_expiry`.
- **Unit and expiry**: the pop's unit is `pop_<ts_expiry>`, where `ts_expiry` is
  that CLTV locktime (a Unix timestamp). The
  [keyset](https://github.com/cashubtc/nuts/blob/main/02.md) `final_expiry`
  tracks it, so a unit is mintable and redeemable only until its Bitcoin unlocks.
- **[Redeem](https://github.com/cashubtc/nuts/blob/main/03.md) a pop** by
  swapping it at the mint for fresh proofs the operator controls.
- **Recover** the unspent BTC after `ts_expiry` through the leaf, signing with
  your recovery key.

## Use it with your agent

Point your agent at **[skills/pop-wallet.md](skills/pop-wallet.md)** and it will
drive the `pop` wallet for you: create a seed, lock BTC to mint a pop, and
recover the BTC after the timelock matures. The skill keeps you in the loop on
the three numbers that matter every lock: amount, duration, and the
recover-after date.

`pop` also **spends**: `pop pay <URL> --token <cashuB>` runs the HTTP-402 dance
against a gated endpoint and pays it with an exact-amount token: it swaps the
held pop down to the exact charge and hands back the change as a new `cashuB`. It
is token-in / change-out (you supply the `cashuB` to spend), so the wallet still
holds no token custody. See the pay contract in
**[skills/pop-wallet.md](skills/pop-wallet.md)** (the `--max-amount` cap, the JSON
result, and recovering both tokens on a post-swap failure).

## What you can do

- **Gate any HTTP server**: put the **pops-gateway** reverse-proxy in front of
  your unmodified API. One `config.toml`, zero app-code changes; it challenges
  each request with `402`, verifies + redeems valid pops, and forwards upstream.
  Run the published, public, multi-arch image (no build):
  `docker run … ghcr.io/makeprisms/pops-gateway:latest` (building from source is
  the fallback, see the gateway README). You can also embed the verifier
  directly in a Rust/axum service, or in a serverless function via the WASM
  bindings, installed prebuilt with
  `npm install github:MakePrisms/pops#wasm-pkg` (no toolchain needed).
- **Let your agent pay automatically**: `pop pay <URL> --token <cashuB>` does the
  `402` dance for an agent driving the `pop` wallet (see "Use it with your agent"
  above for the exact-amount / change mechanics).
- **Mint and recover via the CLI**: lock BTC, get a pop, and reclaim the
  unspent BTC after the CLTV expiry, all from the `pop` command.

## Docs

- **Agent entry point (both pathways):** [AGENTS.md](AGENTS.md)
- **Gate a service (routes the 3 modes):** [skills/gate-a-service.md](skills/gate-a-service.md)
  → reverse-proxy: [crates/pops-gateway/README.md](crates/pops-gateway/README.md)
- **`pop` CLI wallet:** [crates/pop/README.md](crates/pop/README.md)
- **Agent machine contract for `pop`:** [skills/pop-wallet.md](skills/pop-wallet.md)
- **`Payment` wire format (canonical):** [skills/payment-credential.md](skills/payment-credential.md)
- **Serverless verify demo:** `ts/vercel-demo/app/api/secret/route.ts`

Built on Cashu (ecash) + a CLTV-locked Bitcoin UTXO. The funder crypto kernel
lives **in-repo** in the `pops-core-funder` crate (extracted verbatim from
[`MakePrisms/cdk`](https://github.com/MakePrisms/cdk)'s `cdk-pop`, which consumes
the same construction); `cdk-common` is a normal crates.io `0.16` dependency. To
build from source, clone the public repo and `cargo build`:

```sh
git clone https://github.com/MakePrisms/pops && cd pops && cargo build --release
```
