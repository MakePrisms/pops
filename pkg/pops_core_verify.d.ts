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
 * Unwrap the base64url-nopad `request` envelope and return the inner
 * `creqA…` payment-request string.
 */
export function decode_request_envelope(b64: string): string;

/**
 * Wrap a `creqA…` string in the `request` envelope and base64url-nopad
 * encode it (what goes inside `request="…"` of `WWW-Authenticate:
 * Payment`). Infallible.
 */
export function encode_request_envelope(creq_a: string): string;

/**
 * Parse an `Authorization: Payment <blob>` header (or a bare base64url
 * credentials blob) into a JSON [`PaymentCredentials`] object. Validates
 * the method is `cashu`.
 */
export function parse_payment_credential(authorization: string): string;

/**
 * Parse a `WWW-Authenticate: Payment …` header (the 402 challenge the
 * client receives) into a JSON object `{id, realm, method, intent,
 * request}`. The `request` stays the raw base64url envelope — unwrap it
 * with [`decode_request_envelope`].
 */
export function parse_payment_params(www_authenticate: string): string;

/**
 * Full verify + redeem over an injected `fetch`. THE Step-2 export.
 *
 * `presented` is the holder's `cashuB…` token string; `req_json` is the
 * JSON form of a [`ChargeRequirement`] (`{ amount, unit, mints, payment_id,
 * description, single_use }`). Constructs a
 * [`CashuCredential<WasmMintClient>`] and runs the same decode → structural
 * checks → NUT-03 swap pipeline the native path runs, with all HTTP issued
 * via `globalThis.fetch` against the token's mint.
 *
 * Returns a `Promise` that RESOLVES to
 * `{ ok:true, fresh_proofs, amount, unit, active_keyset_id, token_hash }` on
 * success, or REJECTS with `{ ok:false, code, message }` carrying the
 * [`ChargeError`] discriminant so the JS route maps 402 / 503 / 400.
 *
 * A malformed `req_json` (server-side config error, never the holder's fault)
 * rejects with `code = "malformed-request"`.
 */
export function verify_and_redeem(presented: string, req_json: string): Promise<any>;
