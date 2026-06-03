# AGENTS.md

Entry point for any coding agent (Cursor, Codex, Aider, Claude, …) working in
this repo. Tool-agnostic: plain Markdown, no editor-specific assumptions.

**pops** = ecash access-control credentials backed by CLTV-locked Bitcoin. A
client locks recoverable BTC to mint a *pop* (a Cashu `cashuB` bearer token) and
presents it to a gated HTTP resource. It is HTTP-402-native: a gated resource
answers `402` + a `WWW-Authenticate: Payment` challenge, and the client retries
with the pop in `Authorization: Payment …`.

## Agents — two things you can do here

1. **Use pops** — hold/lock BTC, mint pops, and pay HTTP-402-gated resources.
   Drive the `pop` CLI wallet from its machine contract:
   **[skills/pop-wallet.md](skills/pop-wallet.md)** (exact per-command JSON, the
   frozen 31-code error table, and the safety rails for locking real BTC).
   `pop pay <URL> --token <cashuB>` runs the 402 dance for you.

2. **Accept pops** — gate your own HTTP service so it charges a pop per request.
   Start at the front door:
   **[skills/gate-a-service.md](skills/gate-a-service.md)** — it routes the three
   integration modes (reverse-proxy, Rust/axum in-process, serverless/JS WASM).
   Two of the three need **no build**: the reverse-proxy is a published public
   image (`docker run ghcr.io/makeprisms/pops-gateway:latest`) and the WASM
   bindings install prebuilt from GitHub
   (`npm install github:MakePrisms/pops#wasm-pkg`).

## The wire format both sides share

The `Authorization: Payment` credential and the `WWW-Authenticate: Payment` 402
challenge are one canonical format, documented once:
**[skills/payment-credential.md](skills/payment-credential.md)**. Read it if you
are writing a non-CLI client or testing a gate by hand. (If you drive the `pop`
CLI, you don't build this yourself — `pop pay` does.)

## Build / test

This is a **public** repo — `git clone https://github.com/MakePrisms/pops` and
build with no special access (`cdk-common` is a normal crates.io `0.16` dep). The
`pop` CLI is a Cargo workspace member: `cargo build -p pop` / `cargo test -p
pop`. The toolchain is pinned in `rust-toolchain.toml` (Rust 1.95). The other
crates: `pops-core-verify` (the verifier), `pops-gateway` (the reverse-proxy),
`pops-core-funder` (the in-repo funder crypto kernel, extracted from `cdk-pop`) /
`pops-core-types` (support), plus `ts/` (WASM bindings + a Next.js serverless
demo). The gateway image and the WASM bindings are also published (ghcr +
`wasm-pkg` branch) if you want to consume rather than build.
