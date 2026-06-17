# PoPs: Proof of Power

> **Agents →  Orient yourself by reading [AGENTS.md](AGENTS.md). Skills for everything you can do with pops are found in [./skills](./skills)** 

---

PoPs are **ecash access-control credentials backed by CLTV-locked Bitcoin**. A
client locks (recoverable) Bitcoin capital to mint a *pop* (a bearer ecash
token) and presents it to reach a gated resource. No upfront payment and no
account: spam-resistance comes from the **locked capital** ("power"), which
can't be cheaply farmed at scale.

This is a rust repo that provides an agent native pop wallet CLI and the necessary
tooling to challenge HTTP requests `402` using [cashu-mpp](github.com/gudnuf/mpp-specs/pull/1)

## How it works

- **Mint ([NUT-04](https://github.com/cashubtc/nuts/blob/main/04.md)) a pop** by
  sending BTC to a Taproot (P2TR) address that commits to the mint pubkey, an expiry, a
  nonce, and your recovery pubkey. The internal key is a NUMS point, so the key
  path is unspendable and the funds move only through the one script leaf.
- **Locking script** (that single Taproot leaf):
  `<ts_expiry> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <funder_pubkey> OP_CHECKSIG`, the
  funder's recovery path, spendable only after `ts_expiry`.
- **Unit and expiry**: the pop's unit is `pop_<ts_expiry>`, where `ts_expiry` is
  that CLTV locktime (a Unix timestamp). The keyset
  ([NUT-02](https://github.com/cashubtc/nuts/blob/main/02.md)) `final_expiry`
  tracks it, so a unit is mintable and redeemable only until its Bitcoin unlocks.
- **Recover** the unspent BTC after `ts_expiry` through the leaf, signing with
  your recovery key.

## Use it with your agent

Point your agent at **[skills/pop-wallet.md](skills/pop-wallet.md)** to drive the `pop` 
wallet locally: create a seed, lock BTC to mint a pop, and recover the BTC after the timelock matures.

`pop` also **spends**: `pop pay <URL> --token <cashuB>` runs the HTTP-402 dance
against a gated endpoint and pays it with an exact-amount token: it swaps the
held pop down to the exact charge and hands back the change as a new `cashuB`. It
is token-in / change-out (you supply the `cashuB` to spend), so the wallet still
holds no token custody. See the pay contract in
**[skills/pop-wallet.md](skills/pop-wallet.md)** (the `--max-amount` cap, the JSON
result, and recovering both tokens on a post-swap failure).

## Gate any HTTP server
Put the **pops-gateway** reverse-proxy in front of
  your unmodified API. One `config.toml`, zero app-code changes; it challenges
  each request with `402`, verifies + redeems valid pops, and forwards upstream.
  We offer a multi-arch image: `docker run … ghcr.io/makeprisms/pops-gateway:latest`.
  You can also embed the verifier
  directly in a Rust/axum service, or in TS via the WASM
  bindings, installed prebuilt with
  `npm install github:MakePrisms/pops#wasm-pkg` (no toolchain needed).
  
## Docs

- **Agent entry point (both pathways):** [AGENTS.md](AGENTS.md)
- **Gate a service (routes the 3 modes):** [skills/gate-a-service.md](skills/gate-a-service.md)
  → reverse-proxy: [crates/pops-gateway/README.md](crates/pops-gateway/README.md)
- **`pop` CLI wallet:** [crates/pop/README.md](crates/pop/README.md)
- **Agent machine contract for `pop`:** [skills/pop-wallet.md](skills/pop-wallet.md)
- **`Payment` wire format (canonical):** [skills/payment-credential.md](skills/payment-credential.md)
- **Serverless verify demo:** `ts/vercel-demo/app/api/secret/route.ts`

Built on Cashu (ecash) + a CLTV-locked Bitcoin UTXO.

```sh
git clone https://github.com/MakePrisms/pops && cd pops && cargo build --release
```
