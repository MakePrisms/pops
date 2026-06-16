# @makeprisms/pops-core-wasm — prebuilt (dist branch)

Generated dist branch (not source): the prebuilt wasm-pack (nodejs target)
build of pops-core-verify --features wasm, so a Node project can consume the
bindings without a Rust/wasm toolchain. Overwritten by the publish-wasm
workflow — do not edit. Source is on main.

## Use it

```json
{ "dependencies": { "@makeprisms/pops-core-wasm": "github:MakePrisms/pops#wasm-pkg" } }
```

Pin an immutable dist tag (e.g. #wasm-v0.1.0) for reproducible installs.
