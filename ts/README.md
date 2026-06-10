# pops — TypeScript / WASM

The `pops-core-verify` Rust crate compiled to WebAssembly, plus a Next.js (Node
runtime) demo that gates a real endpoint with it. This is how you run pops
verification **in JS** — a Vercel/Node serverless function performs the full
`402 → verify + NUT-03 swap → 200` entirely in-process, over an injected
`globalThis.fetch`.

> **Install (no build needed).** The prebuilt bindings are published to the
> public `wasm-pkg` branch, so a Node project consumes them straight from GitHub —
> no Rust/wasm toolchain, no npm-registry auth:
>
> ```sh
> npm install github:MakePrisms/pops#wasm-pkg
> ```
>
> Or pin the immutable dist tag for reproducible installs:
> `npm install github:MakePrisms/pops#wasm-v0.1.0`. In `package.json` that is
> `"@makeprisms/pops-core-wasm": "github:MakePrisms/pops#wasm-pkg"`. The package
> name is `@makeprisms/pops-core-wasm`. Building from source (below) is only
> needed if you are changing the Rust kernel.

---

## Layout

| Path | What it is |
|------|------------|
| `ts/pops-core-wasm/` | The WASM bindings package `@makeprisms/pops-core-wasm`. A thin hand-written manifest wrapping the **generated** `pkg/` (wasm-pack nodejs-target output). `pkg/` is git-ignored — it is produced by `ts/build-wasm.sh`, never committed. |
| `ts/vercel-demo/` | Next.js app (Node runtime). `GET /api/secret` is pops-gated: a bare request 402s; an `Authorization: Payment <blob>` retry runs `verify_and_redeem` (WASM) → NUT-03 swap against the mint → 200. Depends on the bindings via `"@makeprisms/pops-core-wasm": "file:../pops-core-wasm"`. |
| `ts/smoke/` | Standalone smoke script (`async-fetch-smoke.mjs`) that drives the WASM `verify_and_redeem` over `globalThis.fetch` against a local pops mint — proves the async-across-wasm-bindgen + injected-fetch boundary without a funded token. |
| `ts/build-wasm.sh` | Builds `pops-core-verify --features wasm` to a Node-target wasm-pack package in `ts/pops-core-wasm/pkg/`. The single source of the bindings. |

---

## Build from source (fallback — only if you change the kernel)

Consuming the bindings does **not** require this — `npm install
github:MakePrisms/pops#wasm-pkg` ships them prebuilt. Build from source only when
you are modifying the Rust crate and want to regenerate the WASM locally.

The bindings (`ts/pops-core-wasm/pkg/`) are **generated, not committed**. Build
them with `ts/build-wasm.sh`, which runs:

```sh
wasm-pack build crates/pops-core-verify \
  --target nodejs \
  --out-dir ts/pops-core-wasm/pkg \
  --mode no-install \
  -- --no-default-features --features wasm
```

This compiles the crate's `wasm` feature (`--no-default-features` drops the
native `cdk`/`axum` deps; `wasm` selects `wasm-bindgen` + the `getrandom/js` /
`uuid/js` randomness backends) to `wasm32-unknown-unknown` and emits the
nodejs/CommonJS glue + the `.wasm` binary into `ts/pops-core-wasm/pkg/`.

`cdk-common` is a normal crates.io `0.16` dependency, so the crate builds clean
from a plain public checkout.

### Nix (reproducible toolchain)

The repo ships a `flake.nix` dev shell that pins the entire toolchain below
(including the exact `wasm-bindgen` 0.2.122 that must match `Cargo.lock` — nixpkgs
ships 0.2.121, which aborts `wasm-pack` on a schema mismatch). From the repo root:

```sh
nix develop          # rust 1.95 + wasm32, wasm-pack, wasm-bindgen 0.2.122, node, llvm
bash ts/build-wasm.sh
```

The shell wires `CC_wasm32_unknown_unknown` / `AR_wasm32_unknown_unknown` to an
unwrapped clang + `llvm-ar` (the wrapped clang's darwin flags break a wasm32
target) and includes `binaryen`, so `wasm-opt` actually runs and the emitted
`.wasm` is optimized. If you prefer to assemble the toolchain by hand, the exact
requirements follow.

### Toolchain

`build-wasm.sh` needs the following on `PATH` (it is intentionally hands-off
about *how* you install them):

- **A Rust toolchain (1.95)** with the `wasm32-unknown-unknown` target, and a C
  toolchain for the secp256k1 C→wasm compile. The wasm32-scoped env vars
  `CC_wasm32_unknown_unknown` (clang) and `AR_wasm32_unknown_unknown` (llvm-ar)
  must point at a clang/llvm-ar.
- **`wasm-pack`** (0.13.x works; e.g. `nix build nixpkgs#wasm-pack`).
- **`wasm-bindgen` CLI pinned to Cargo.lock's `wasm-bindgen` version** — today
  **0.2.122**. This MUST match exactly or the build aborts on a schema mismatch.
  `--mode no-install` in the script makes wasm-pack use the on-PATH binary
  instead of auto-downloading its own, so the pin is honored. nixpkgs only ships
  an older `wasm-bindgen-cli`; vendoring the prebuilt 0.2.122 release binary from
  the rustwasm GitHub releases is the reliable route until the env provisions a
  matching version.
- A **writable `CARGO_HOME`**.

Run it from the repo root:

```sh
bash ts/build-wasm.sh
```

On success it prints the emitted `pkg/*.wasm`. (`[INFO] Skipping wasm-opt as no
downloading was requested` under `--mode no-install` is expected — the `.wasm`
is valid but unoptimized; install `binaryen`/`wasm-opt` separately to shrink it
for production.)

The package exports (see `pkg/pops_core_verify.d.ts` after a build):
`verify_and_redeem` (the full verify+redeem, async), `parse_payment_credential`,
`build_payment_credential`, `parse_payment_params`, `encode_request_object`,
`decode_request_object`.

---

## Run the demo

```sh
# 1. Build the bindings (above) so the file: dep resolves.
bash ts/build-wasm.sh

# 2. Install + run the Next.js demo.
cd ts/vercel-demo
npm install          # resolves @makeprisms/pops-core-wasm from ../pops-core-wasm
npm run dev          # or: npm run build && npm start

# 3. Exercise the gate.
curl -i localhost:3000/api/secret        # 402 + WWW-Authenticate: Payment challenge
# retry with an `Authorization: Payment <blob>` credential → 200 + gated payload
```

`vercel-demo/package.json` also exposes `npm run build:wasm` (a passthrough to
`../build-wasm.sh`) so the bindings can be (re)built from inside the demo.

The mint the demo redeems against defaults to a local pops mint; override at
runtime with `POPS_MINT_URL` / `POPS_UNIT` / `POPS_AMOUNT`. The gated route runs
on the **Node** runtime (not Edge) — the wasm-pack nodejs glue reads its `.wasm`
via `fs.readFileSync`, and `next.config.js` keeps the package un-bundled
(`serverExternalPackages` + a webpack external) so `__dirname` stays intact for
that read.

---

## Publishing (how the prebuilt branch is produced)

External users do **not** build from source — they install the prebuilt bindings
straight from GitHub:

```sh
npm install github:MakePrisms/pops#wasm-pkg          # tracks main
npm install github:MakePrisms/pops#wasm-v0.1.0       # pinned, immutable
```

The `wasm-pkg` branch is an orphan dist branch produced by the
[`publish-wasm`](../.github/workflows/publish-wasm.yml) workflow: it rebuilds the
WASM in the pinned flake toolchain and force-pushes only the generated artifacts
(plus a derived `package.json`/`README.md`). It refreshes on pushes to `main`
that touch the bindings source, and `workflow_dispatch` can also cut an immutable
dist tag (e.g. `wasm-v0.1.0`). The `vercel-demo` here consumes the bindings via a
local `file:` dependency instead, because it lives in-repo and rebuilds them
locally — but **your** project should use the git install above. (The
`ghcr.io/makeprisms/pops-gateway` Docker image is likewise published and public —
see `crates/pops-gateway/README.md`.)
