# PoPs — Proof of Power

> **Agents:** drive the `pop` wallet from its machine contract —
> **[crates/pop/SKILL.md](crates/pop/SKILL.md)** (exact per-command JSON, the
> frozen 20-code error table, and the safety rails for locking real BTC). To gate
> a server, see the gateway contract in
> **[crates/pops-gateway/README.md](crates/pops-gateway/README.md)**.

---

PoPs are **ecash access-control credentials backed by CLTV-locked Bitcoin**. A
client locks (recoverable) Bitcoin capital to mint a *pop* — a bearer ecash
token — and presents it to reach a gated resource. No upfront payment and no
account: spam-resistance comes from the **locked capital** ("power"), which
can't be cheaply farmed at scale. It's HTTP-402-native (a gated resource answers
with `402` + a `WWW-Authenticate: Payment` challenge; the client retries with
the pop in `Authorization: Payment …`). The verifier is **ecash-agnostic** —
pops are one supported credential type.

**Non-custodial:** there is no third party. A spent pop is bearer ecash that the
operator redeems into fresh proofs **only they control** — the operator keeps the
value clients spend.

## Use it with your agent

Point your agent at **[crates/pop/SKILL.md](crates/pop/SKILL.md)** and it will
drive the `pop` wallet for you: create a seed, lock BTC to mint a pop, and
recover the BTC after the timelock matures. The skill keeps you in the loop on
the three numbers that matter every lock — amount, duration, and the
recover-after date.

`pop` also **spends**: `pop pay <URL> --token <cashuB>` runs the HTTP-402 dance
against a gated endpoint and pays it with an exact-amount token — it swaps the
held pop down to the exact charge and hands back the change as a new `cashuB`. It
is token-in / change-out (you supply the `cashuB` to spend), so the wallet still
holds no token custody. See the pay contract in
**[crates/pop/SKILL.md](crates/pop/SKILL.md)** (the `--max-amount` cap, the JSON
result, and recovering both tokens on a post-swap failure).

## What you can do

- **Gate any HTTP server** — put the **pops-gateway** reverse-proxy in front of
  your unmodified API. One `config.toml`, zero app-code changes; it challenges
  each request with `402`, verifies + redeems valid pops, and forwards upstream.
  (Pull and run the published image — `docker run … ghcr.io/makeprisms/pops-gateway`;
  or build it yourself per the gateway README. You can also embed the verifier
  directly in a Rust/axum service or a serverless function via the WASM build.)
- **Let your agent pay automatically** — `pop pay <URL> --token <cashuB>` does the
  `402` dance and pays a gated endpoint with an exact-amount token (swapping the
  held pop to the exact charge and returning the change), so an agent driving the
  `pop` wallet can satisfy the challenge on your behalf.
- **Mint and recover via the CLI** — lock BTC, get a pop, and reclaim the
  unspent BTC after the CLTV expiry, all from the `pop` command.

## Docs

- **Gate a server:** [crates/pops-gateway/README.md](crates/pops-gateway/README.md)
- **`pop` CLI wallet:** [crates/pop/README.md](crates/pop/README.md)
- **Agent machine contract for `pop`:** [crates/pop/SKILL.md](crates/pop/SKILL.md)
- **Serverless verify demo:** `ts/vercel-demo/app/api/secret/route.ts`

Built on Cashu (ecash) + a CLTV-locked Bitcoin UTXO; funder crypto derives from
[`MakePrisms/cdk`](https://github.com/MakePrisms/cdk) (`cdk-pop`).
