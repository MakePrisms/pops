/**
 * The Proof-of-Payment gated endpoint.
 *
 * A bare GET 402s with a `WWW-Authenticate: Payment …` challenge. On retry with
 * an `Authorization: Payment <blob>` credential, the route parses the credential
 * (WASM `parse_payment_credential`) and runs the full verify+redeem (WASM
 * `verify_and_redeem`), which performs the NUT-03 swap against the pops mint
 * over an injected `globalThis.fetch`, inside this Node serverless function. On
 * success it returns 200 + the gated payload; a `ChargeError` becomes 402 (or
 * 503 for a transport failure / 400 for a malformed request), mapped off the
 * structured `code` the WASM rejection carries.
 *
 * Node runtime, not Edge: the wasm-pack `nodejs` glue reads its `.wasm` via
 * `fs.readFileSync`, which Edge cannot do.
 */
import { NextRequest } from "next/server";

// Node runtime is required: Edge cannot `fs.readFileSync` the wasm.
export const runtime = "nodejs";
// Always run the gate; never cache the 402/200 decision.
export const dynamic = "force-dynamic";

// Structural type for the wasm-pack (nodejs target) module's exports.
type PopsWasm = {
  encode_request_envelope(creqA: string): string;
  parse_payment_credential(authorization: string): string;
  verify_and_redeem(presented: string, reqJson: string): Promise<{
    ok: boolean;
    amount: number;
    unit: string;
    active_keyset_id: string;
    token_hash: string;
    fresh_proofs: string;
  }>;
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
// `verify_and_redeem`. Points at the local pops mint; override the mint at
// deploy time via POPS_MINT_URL if reachable from the function.
const MINT_URL = process.env.POPS_MINT_URL || "http://100.96.251.111:3338";
const UNIT = process.env.POPS_UNIT || "pop_1780372941";
const AMOUNT = Number(process.env.POPS_AMOUNT || "1");

const requirement = {
  amount: AMOUNT,
  unit: UNIT,
  mints: [MINT_URL],
  payment_id: CHALLENGE_ID,
  description: "pops Vercel-Node gating demo",
  single_use: true,
};

// A fixed pre-encoded `creqA` matching `requirement`. Wrapped in the request
// envelope at response time via the WASM `encode_request_envelope`.
const CREQ_A =
  "creqApmFpaXBvcHMtZGVtb2FhAWF1bnBvcF8xNzgwMzcyOTQxYXP1YW2BeBpodHRwOi8vMTAwLjk2LjI1MS4xMTE6MzMzOGFkeBxwb3BzIFZlcmNlbC1Ob2RlIGdhdGluZyBkZW1v";

/** Build the `WWW-Authenticate: Payment …` header value for a 402. */
function wwwAuthenticate(wasm: PopsWasm): string {
  const requestEnvelope = wasm.encode_request_envelope(CREQ_A);
  return [
    `Payment id="${CHALLENGE_ID}"`,
    `realm="${REALM}"`,
    `method="cashu"`,
    `intent="charge"`,
    `request="${requestEnvelope}"`,
  ].join(", ");
}

/** A fresh 402 carrying the challenge. */
function challenge402(wasm: PopsWasm, detail?: { code: string; message: string }) {
  const body = {
    error: "payment_required",
    ...(detail ? { code: detail.code, detail: detail.message } : {}),
    realm: REALM,
  };
  return new Response(JSON.stringify(body), {
    status: 402,
    headers: {
      "WWW-Authenticate": wwwAuthenticate(wasm),
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

/**
 * Map a structured `ChargeError` rejection from the WASM boundary onto an HTTP
 * status. These three concerns map to distinct statuses:
 *   (A) transport          -> 503 (token not consumed, retryable)
 *   (B) verification        -> 402 (+ fresh challenge, terminal for this token)
 *   (C) malformed request   -> 400 (not 402)
 */
function errorToResponse(wasm: PopsWasm, err: unknown): Response {
  const code =
    err && typeof err === "object" && "code" in err
      ? String((err as { code: unknown }).code)
      : "charge-error";
  const message =
    err && typeof err === "object" && "message" in err
      ? String((err as { message: unknown }).message)
      : String(err);

  // (A) transport — keep the token, retry.
  if (code === "mint-unreachable") {
    return new Response(
      JSON.stringify({ error: "mint_unavailable", code, detail: message }),
      {
        status: 503,
        headers: { "Content-Type": "application/json", "Retry-After": "2", "Cache-Control": "no-store" },
      },
    );
  }

  // (C) malformed request (server-side config / method) — 400, not 402.
  if (code === "malformed-request") {
    return new Response(JSON.stringify({ error: "bad_request", code, detail: message }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  }

  // (B) everything else is a verification failure — 402 + fresh challenge.
  return challenge402(wasm, { code, message });
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
    return challenge402(wasm, { code: "malformed-credential", message: String(e) });
  }

  // FULL verify + NUT-03 swap over injected fetch, in this Node function.
  try {
    const redeemed = await wasm.verify_and_redeem(cashuToken, JSON.stringify(requirement));
    // Success: the swap executed, the operator now holds `fresh_proofs`. A real
    // operator would stash those; here we confirm settlement and gate.
    return new Response(
      JSON.stringify({
        secret: "the eagle lands at midnight",
        settled: {
          amount: redeemed.amount,
          unit: redeemed.unit,
          active_keyset_id: redeemed.active_keyset_id,
          token_hash: redeemed.token_hash,
        },
      }),
      { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } },
    );
  } catch (err) {
    return errorToResponse(wasm, err);
  }
}
