#!/usr/bin/env bash
# Build pops-core-verify (feature `wasm`) to a Node-target wasm-pack package
# consumed by ts/vercel-demo. Output lands in ts/pops-core-wasm/pkg/, which is
# git-ignored (wasm-pack writes its own .gitignore there); only this script and
# the package manifests are committed.
#
# Prereqs:
#   * Rust 1.95 with CC_wasm32 / AR_wasm32 set for the wasm32 target
#   * wasm-pack 0.13.1 + wasm-bindgen-cli 0.2.122 on PATH
#     (wasm-bindgen-cli must match Cargo.lock; --mode no-install pins to it)
#   * a writable CARGO_HOME
#
# Usage:  bash ts/build-wasm.sh
set -euo pipefail

# Resolve repo root from this script's location (ts/ is one below root).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUT_DIR="${REPO_ROOT}/ts/pops-core-wasm/pkg"

echo ">> building pops-core-verify --features wasm --target nodejs"
echo ">> out: ${OUT_DIR}"

# Cargo feature flags go AFTER `--`; wasm-pack's own flags come before the
# crate path.
wasm-pack build "${REPO_ROOT}/crates/pops-core-verify" \
  --target nodejs \
  --out-dir "${OUT_DIR}" \
  --mode no-install \
  -- --no-default-features --features wasm

echo ">> done. wasm artifact:"
ls -lh "${OUT_DIR}"/*.wasm
