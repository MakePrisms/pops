/* tslint:disable */
/* eslint-disable */

/**
 * Build the base64url-nopad credentials blob from a JSON
 * [`PaymentCredentials`] object (the inverse of
 * [`parse_payment_credential`]). Returns the bare blob — the caller
 * prepends `Payment ` to form the header value.
 */
export function build_payment_credential(credentials_json: string): string;

/**
 * Decode the base64url-nopad `request` auth-param into the JSON
 * `draft-cashu-charge-00` request object (`{amount, currency, description?,
 * externalId?, methodDetails:{paymentRequest}}`).
 */
export function decode_request_object(b64: string): string;

/**
 * Encode a JSON `draft-cashu-charge-00` request object as the base64url-nopad
 * JCS-canonical `request="…"` auth-param value.
 */
export function encode_request_object(request_object_json: string): string;

/**
 * Parse an `Authorization: Payment <blob>` header (or a bare base64url
 * credentials blob) into a JSON [`PaymentCredentials`] object. Validates
 * the method is `cashu`.
 */
export function parse_payment_credential(authorization: string): string;

/**
 * Parse a `WWW-Authenticate: Payment …` header (the 402 challenge the
 * client receives) into a JSON object `{id, realm, method, intent,
 * request}`. The `request` stays the raw base64url request object — decode
 * it with [`decode_request_object`].
 */
export function parse_payment_params(www_authenticate: string): string;

/**
 * Full verify + redeem over an injected `fetch`.
 *
 * `presented_token` is the holder's `cashuB…` token string; `requirement_json` is the
 * JSON form of a [`ChargeRequirement`] (`{ amount, unit, mints, external_id,
 * description }`). Constructs a
 * [`CashuCredential<WasmMintClient>`] and runs the same decode → structural
 * checks → NUT-03 swap pipeline the native path runs, with all HTTP issued
 * via `globalThis.fetch` against the token's mint.
 *
 * Returns a `Promise` that RESOLVES to
 * `{ ok:true, fresh_proofs, amount, unit, active_keyset_id, token_hash,
 * dleq_ok }` on success — `dleq_ok: false` means the swap-returned
 * signatures' NUT-12 DLEQ was missing/invalid, a mint-trust incident the
 * route should alert on while STILL serving (spec §security-dleq) — or
 * REJECTS with
 * `{ ok:false, code, message, status, problem_type, problem_slug }` — the
 * fine-grained [`ChargeError`] discriminant plus the mapped spec status and
 * absolute problem-type URI, so the JS route answers 402 / 503 / 400 with the
 * same problem body the native hosts emit.
 *
 * A malformed `requirement_json` (server-side config error, never the holder's fault)
 * rejects with `code = "malformed-request"`.
 */
export function verify_and_redeem(presented_token: string, requirement_json: string): Promise<any>;
