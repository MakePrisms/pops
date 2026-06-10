/**
 * The Proof-of-Payment gated endpoint.
 *
 * A bare GET 402s with a `WWW-Authenticate: Payment …` challenge. On retry with
 * an `Authorization: Payment <blob>` credential, the route parses the credential
 * (WASM `parse_payment_credential`) and runs the full verify+redeem (WASM
 * `verify_and_redeem`), which performs the NUT-03 swap against the pops mint
 * over an injected `globalThis.fetch`, inside this Node serverless function. On
 * success it returns 200 + the gated payload; a rejection carries its mapped
 * HTTP `status` and absolute `problem_type` from the verifier's single-sourced
 * problem map, so this route answers with the same RFC-9457 wire as the native
 * hosts (402 + fresh challenge / 503 + Retry-After / 400).
 *
 * DEMO SIMPLIFICATIONS (deliberate; a production host does more):
 * - The challenge id is a fixed string and the echoed challenge is NOT
 *   authenticated. The framework's stateless HMAC binding + `expires` live in
 *   the Rust hosts (pops-gateway / the axum middleware); the wasm surface
 *   exposes the codec + verify_and_redeem, not challenge issuance.
 * - `CREQ_A` is pre-encoded for the DEFAULT requirement below. If you override
 *   POPS_MINT_URL / POPS_UNIT / POPS_AMOUNT you must supply a matching creqA
 *   (POPS_CREQ_A): clients cross-check the request object's amount/currency
 *   against the creqA's `a`/`u` and refuse a challenge where they disagree.
 *
 * Node runtime, not Edge: the wasm-pack `nodejs` glue reads its `.wasm` via
 * `fs.readFileSync`, which Edge cannot do.
 */
import { NextRequest } from "next/server";
import { appendFileSync } from "node:fs";

// Node runtime is required: Edge cannot `fs.readFileSync` the wasm.
export const runtime = "nodejs";
// Always run the gate; never cache the 402/200 decision.
export const dynamic = "force-dynamic";

/** What `verify_and_redeem` resolves with: the swap executed and the server
 * (you) now holds `fresh_proofs` — spendable bearer value. `dleq_ok: false`
 * means the mint's swap-returned signatures failed their NUT-12 check: a
 * mint-trust incident to alert on, NOT a payment failure (the request is
 * still served). */
type Redeemed = {
  ok: boolean;
  amount: number;
  unit: string;
  active_keyset_id: string;
  token_hash: string;
  fresh_proofs: string;
  dleq_ok: boolean;
};

/** What `verify_and_redeem` rejects with: the fine-grained `code` plus the
 * verifier's problem mapping (HTTP `status`, absolute `problem_type` URI,
 * `problem_slug` or null). */
type ChargeRejection = {
  ok: false;
  code: string;
  message: string;
  status: number;
  problem_type: string;
  problem_slug: string | null;
};

// Structural type for the wasm-pack (nodejs target) module's exports.
type PopsWasm = {
  encode_request_object(requestObjectJson: string): string;
  parse_payment_credential(authorization: string): string;
  verify_and_redeem(presented: string, reqJson: string): Promise<Redeemed>;
};

// Lazy, request-time load of the WASM package. Deferred (not a top-level
// import) so Next's build-time "collect page data" pass does not instantiate
// the .wasm; only an actual request does. `serverExternalPackages` +
// `webpack.externals` (next.config.js) keep the package un-bundled so its glue
// reads `${__dirname}/...bg.wasm` from node_modules with `__dirname` intact.
let wasmPromise: Promise<PopsWasm> | null = null;
function loadWasm(): Promise<PopsWasm> {
  if (!wasmPromise) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    wasmPromise = import("@makeprisms/pops-core-wasm") as unknown as Promise<PopsWasm>;
  }
  return wasmPromise;
}

const REALM = "pops-vercel-demo";
const CHALLENGE_ID = "pops-demo";

// The demo charge requirement that gates verification, passed to the WASM
// `verify_and_redeem`. The default mint is a PLACEHOLDER for a locally-run
// pops mint — it MUST be configured (POPS_MINT_URL) for any real deployment.
// TRAP: overriding POPS_MINT_URL / POPS_UNIT / POPS_AMOUNT without a matching
// POPS_CREQ_A yields a SELF-CONTRADICTING challenge that conformant clients
// refuse (they cross-check the request object against the creqA's a/u/m).
const MINT_URL = process.env.POPS_MINT_URL || "http://localhost:3338";
const UNIT = process.env.POPS_UNIT || "pop_1780372941";
const AMOUNT = Number(process.env.POPS_AMOUNT || "1");
const DESCRIPTION = "pops Vercel-Node gating demo";

const requirement = {
  amount: AMOUNT,
  unit: UNIT,
  mints: [MINT_URL],
  payment_id: CHALLENGE_ID,
  description: DESCRIPTION,
  single_use: true,
};

// A pre-encoded NUT-18 `creqA` matching the DEFAULT requirement above
// (i=pops-demo, a=1, u=pop_1780372941, m=["http://localhost:3338"], empty
// transports, no nut10). The authoritative payment artifact inside the request
// object — any env override of the requirement needs a matching POPS_CREQ_A.
const CREQ_A =
  process.env.POPS_CREQ_A ||
  "creqApmFpaXBvcHMtZGVtb2FhAWF1bnBvcF8xNzgwMzcyOTQxYXP1YW2BdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGFkeBxwb3BzIFZlcmNlbC1Ob2RlIGdhdGluZyBkZW1v";

// Where redeemed proofs are appended, one JSON line per settlement (same line
// shape as pops-gateway's proofs_sink). Set it to a path on durable storage
// when running on a real Node host (`next start`, a container, …).
const PROOFS_SINK = process.env.POPS_PROOFS_SINK;

/** Build the `WWW-Authenticate: Payment …` header value for a 402. The
 * `request` param is the base64url-nopad JCS request object — amount/currency
 * at the top level, the authoritative creqA under
 * `methodDetails.paymentRequest`. */
function wwwAuthenticate(wasm: PopsWasm): string {
  const requestObject = wasm.encode_request_object(
    JSON.stringify({
      amount: String(AMOUNT),
      currency: UNIT,
      description: DESCRIPTION,
      methodDetails: { paymentRequest: CREQ_A },
    }),
  );
  return [
    `Payment id="${CHALLENGE_ID}"`,
    `realm="${REALM}"`,
    `method="cashu"`,
    `intent="charge"`,
    `request="${requestObject}"`,
  ].join(", ");
}

/** RFC-9457 problem response helpers (`application/problem+json`). */
function problemBody(type: string, status: number, detail: string): string {
  return JSON.stringify({ type, status, detail });
}

/** A fresh 402 carrying the challenge. `problem` defaults to the framework's
 * bare payment-required type when no attempt failed. */
function challenge402(
  wasm: PopsWasm,
  problem?: { type: string; detail: string },
): Response {
  const p = problem ?? {
    type: "https://paymentauth.org/problems/payment-required",
    detail: `payment required for realm "${REALM}"`,
  };
  return new Response(problemBody(p.type, 402, p.detail), {
    status: 402,
    headers: {
      "WWW-Authenticate": wwwAuthenticate(wasm),
      "Content-Type": "application/problem+json",
      "Cache-Control": "no-store",
    },
  });
}

/** Map a `verify_and_redeem` rejection onto the HTTP answer using the mapped
 * `status` + `problem_type` it carries — the same wire the native hosts emit:
 * 503 (+ Retry-After; token not consumed, retryable), 400 (malformed request
 * frame), anything else 402 + a fresh challenge. */
function rejectionToResponse(wasm: PopsWasm, err: unknown): Response {
  const r = (err ?? {}) as Partial<ChargeRejection>;
  const status = typeof r.status === "number" ? r.status : 402;
  const type = typeof r.problem_type === "string" ? r.problem_type : "about:blank";
  const detail =
    typeof r.message === "string" ? r.message : String(err ?? "charge error");

  if (status === 402) {
    return challenge402(wasm, { type, detail });
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/problem+json",
    "Cache-Control": "no-store",
  };
  if (status === 503) {
    headers["Retry-After"] = "2";
  }
  return new Response(problemBody(type, status, detail), { status, headers });
}

/** Keep the redeemed value. `fresh_proofs` ARE the money: the presented token
 * is consumed by the swap, and these proofs are its only surviving form. A
 * real deployment MUST persist them durably (a database, the gateway's
 * proofs_sink pattern, …) — discarding them destroys the value the client
 * just paid. This demo appends to POPS_PROOFS_SINK when configured (fine on a
 * persistent Node host; a Vercel function has no durable disk) and otherwise
 * falls back to logging the proofs so they are at least recoverable from the
 * function logs. */
function keepRedeemedValue(redeemed: Redeemed): void {
  const line = JSON.stringify({
    received_at: Math.floor(Date.now() / 1000),
    token_hash: redeemed.token_hash,
    amount: redeemed.amount,
    unit: redeemed.unit,
    active_keyset_id: redeemed.active_keyset_id,
    fresh_proofs: redeemed.fresh_proofs,
  });
  if (PROOFS_SINK) {
    appendFileSync(PROOFS_SINK, line + "\n");
    return;
  }
  // LAST RESORT — proofs in logs are spendable bearer secrets; anyone who can
  // read the logs can spend them. Configure POPS_PROOFS_SINK (or persist to
  // your own store) before taking real value.
  console.error(
    "POPS_PROOFS_SINK is not set; logging redeemed proofs so the value is not destroyed. " +
      "PERSIST THIS LINE — it is spendable money:",
    line,
  );
}

export async function GET(req: NextRequest): Promise<Response> {
  const wasm = await loadWasm();
  const authorization = req.headers.get("authorization");

  // No credential presented -> 402 challenge.
  if (!authorization || !/^payment\s/i.test(authorization.trim())) {
    return challenge402(wasm);
  }

  // Parse the credential blob (WASM, cashu-free). A parse failure is a
  // malformed credential -> 402.
  let cashuToken: string;
  try {
    const credsJson = wasm.parse_payment_credential(authorization);
    const creds = JSON.parse(credsJson);
    cashuToken = creds?.payload?.token;
    if (typeof cashuToken !== "string" || cashuToken.length === 0) {
      throw new Error("credential payload missing token");
    }
  } catch (e) {
    return challenge402(wasm, {
      type: "https://paymentauth.org/problems/malformed-credential",
      detail: String(e),
    });
  }

  // FULL verify + NUT-03 swap over injected fetch, in this Node function.
  try {
    const redeemed = await wasm.verify_and_redeem(cashuToken, JSON.stringify(requirement));

    // The swap consumed the client's token; keep its only surviving form.
    keepRedeemedValue(redeemed);

    if (!redeemed.dleq_ok) {
      // Mint-trust incident (NOT a payment failure — the payment settled and
      // the resource is served): the mint could not prove it signed the fresh
      // proofs with its advertised key. Alert; consider quarantining the mint.
      console.warn(
        `swap-output DLEQ missing/invalid from mint ${MINT_URL} ` +
          `(token_hash=${redeemed.token_hash}) — serving anyway per the spec`,
      );
    }

    return new Response(
      JSON.stringify({
        secret: "the eagle lands at midnight",
        settled: {
          amount: redeemed.amount,
          unit: redeemed.unit,
          active_keyset_id: redeemed.active_keyset_id,
          token_hash: redeemed.token_hash,
          dleq_ok: redeemed.dleq_ok,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } },
    );
  } catch (err) {
    return rejectionToResponse(wasm, err);
  }
}
