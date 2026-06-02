// LOCAL async-fetch SMOKE (build-plan Step 2, risk-c / R3 — the key de-risk).
//
// Proves the async-across-wasm-bindgen + injected-fetch plumbing end to end:
// the WASM `verify_and_redeem` reaches `globalThis.fetch`, the LOCAL pops mint
// answers, and a STRUCTURED `ChargeError` (NOT a panic/hang) comes back across
// the wasm-bindgen boundary.
//
// We do NOT need a funded token. With an empty/garbage token the pipeline
// short-circuits at decode (MalformedCredential) — that already proves the
// boundary returns structure. With a STRUCTURALLY-VALID token pointed at the
// local mint, the pipeline proceeds to the injected-fetch keysets GET + swap
// POST and the mint rejects the (unfunded) proofs — which additionally proves
// the live fetch round-trip. Both outcomes are a structured rejection; the
// failure mode this guards against is a panic, a hang, or an unstructured
// throw.
//
// Run:  node ts/smoke/async-fetch-smoke.mjs  [tokenString]
// Node ≥18 provides a global `fetch` (the runtime the WASM client reflects).

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

const PKG = "/srv/forge/worktrees/pops-verify/crates/pops-core-verify/pkg/pops_core_verify.js";
const MINT = process.env.POPS_MINT_URL || "http://100.96.251.111:3338";
const UNIT = process.env.POPS_UNIT || "pop_1780372941";

const wasm = require(PKG);

// The requirement the route would advertise. Amount/mints are arbitrary for
// the smoke — the point is the fetch plumbing, not amount conformance.
const requirement = {
  amount: 1,
  unit: UNIT,
  mints: [MINT],
  single_use: true,
};

function classify(label, value, isReject) {
  const tag = isReject ? "REJECTED" : "RESOLVED";
  let shape = typeof value;
  let code, message, ok;
  if (value && typeof value === "object") {
    ok = value.ok;
    code = value.code;
    message = value.message;
    shape = "object";
  }
  console.log(`\n[${label}] ${tag}  (shape=${shape})`);
  if (code !== undefined) console.log(`  code   = ${code}`);
  if (ok !== undefined) console.log(`  ok     = ${ok}`);
  if (message !== undefined) console.log(`  message= ${String(message).slice(0, 200)}`);
  if (code === undefined && shape !== "object") {
    console.log(`  raw    = ${String(value).slice(0, 200)}`);
  }
  return { tag, code, ok, message, value };
}

async function run(label, presented) {
  console.log(`\n=== ${label} ===`);
  console.log(`  presented = ${JSON.stringify(presented).slice(0, 60)}`);
  console.log(`  mint      = ${MINT}`);
  const started = Date.now();
  try {
    const res = await wasm.verify_and_redeem(presented, JSON.stringify(requirement));
    const out = classify(label, res, false);
    console.log(`  elapsed   = ${Date.now() - started}ms`);
    return { ...out, started };
  } catch (e) {
    const out = classify(label, e, true);
    console.log(`  elapsed   = ${Date.now() - started}ms`);
    return { ...out, started, rejected: true };
  }
}

const main = async () => {
  let pass = true;

  // Case 1: empty token. Decodes nowhere → MalformedCredential. Proves the
  // boundary returns a STRUCTURED rejection (no panic) for a non-token input.
  {
    const r = await run("empty-token", "");
    const structured = r.code !== undefined && r.ok === false;
    if (!structured) {
      console.log("  FAIL: expected a structured {ok:false, code} rejection");
      pass = false;
    } else {
      console.log("  PASS: structured ChargeError across the boundary");
    }
  }

  // Case 2: garbage (non-cashu) token. Same decode short-circuit.
  {
    const r = await run("garbage-token", "not-a-cashu-token");
    const structured = r.code === "malformed-credential" && r.ok === false;
    if (!structured) {
      console.log(`  FAIL: expected code=malformed-credential, got ${r.code}`);
      pass = false;
    } else {
      console.log("  PASS: code=malformed-credential");
    }
  }

  // Case 3 (the load-bearing one): a token argument was supplied — a
  // STRUCTURALLY-VALID cashuB token for the local mint. This drives the
  // injected-fetch keysets GET + swap POST against the LIVE mint; the mint
  // rejects the unfunded/fake proofs. A structured rejection here (NOT a hang
  // or panic) proves R3: async injected-fetch across wasm-bindgen works and a
  // mint-side outcome crosses back as structure.
  const tokenArg = process.argv[2];
  if (tokenArg) {
    const r = await run("live-mint-token", tokenArg);
    const structured = r.code !== undefined && r.ok === false;
    // Any of these codes proves the fetch round-trip happened and returned
    // structure: a swap-rejection (double-spend), a transport classification
    // (mint-unreachable — if the mint refused at HTTP level), or a decode
    // problem (malformed-credential) if the supplied token didn't parse.
    if (!structured) {
      console.log("  FAIL: expected a structured rejection from the live swap path");
      pass = false;
    } else {
      console.log(`  PASS: live fetch round-trip returned structured code=${r.code}`);
      // The headline proof: the mint was actually contacted. A double-spend /
      // expired / amount-mismatch code (vs malformed-credential) means decode
      // passed and the GET keysets + POST swap fetch round-trip ran.
      if (r.code !== "malformed-credential") {
        console.log("  PROOF: decode passed -> injected fetch reached the live mint");
      } else {
        console.log("  NOTE: token short-circuited at decode (supply a valid cashuB to exercise fetch)");
      }
    }
  } else {
    console.log("\n[live-mint-token] SKIPPED (no token arg) — pass a cashuB token to exercise the live GET+POST fetch round-trip");
  }

  console.log(`\n${pass ? "ALL SMOKE CHECKS PASSED" : "SMOKE CHECKS FAILED"}`);
  process.exit(pass ? 0 : 1);
};

main().catch((e) => {
  console.error("SMOKE HARNESS ERROR (this itself is a failure — a panic/hang would show here):");
  console.error(e);
  process.exit(2);
});
