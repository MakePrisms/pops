# @makeprisms/pops-core-wasm — prebuilt (dist branch)

This is a **generated dist branch**, not source. It holds the prebuilt
`wasm-pack` (nodejs target) output of `pops-core-verify --features wasm` so a
Node project can consume the bindings **without** a Rust / wasm-pack /
wasm-bindgen toolchain.

Source lives on `main` (`crates/pops-core-verify`, `ts/`). Do not edit here —
this branch is overwritten by the build.

## Use it

In your Node project's `package.json`:

```json
{
  "dependencies": {
    "@makeprisms/pops-core-wasm": "github:MakePrisms/pops#wasm-pkg"
  }
}
```

then `npm install`. (Pin to an immutable tag instead of the branch for
reproducible installs once tags are published, e.g. `#wasm-v0.1.0`.)

```js
const pops = require("@makeprisms/pops-core-wasm");
// exports: verify_and_redeem, build_payment_credential,
// parse_payment_credential, parse_payment_params,
// encode_request_envelope, decode_request_envelope
```

The package targets the **Node** runtime (the glue reads its `.wasm` via
`fs.readFileSync`). A single `.wasm` is architecture-independent, so one artifact
works on every OS.

## How this branch is produced

From `main`, in the pinned toolchain (`nix develop`):

```sh
bash ts/build-wasm.sh        # -> ts/pops-core-wasm/pkg/
```

then the contents of `ts/pops-core-wasm/` (the manifest + generated `pkg/`) are
published to this orphan branch.
