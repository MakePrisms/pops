# The `Payment` credential — wire format

The single canonical description of the `Payment` HTTP auth-scheme that pops
uses (the `draft-cashu-charge-01` wire): the `402` challenge a gate sends, and
the `Authorization: Payment` credential a client sends back. **Source of
truth:**
[`crates/pops-core-verify/src/envelope.rs`](../crates/pops-core-verify/src/envelope.rs)
(every field name + encoding below matches it exactly).

Read this if you are **writing a non-CLI client** or **testing a gate by hand**.
If you drive the `pop` CLI, you do **not** build this yourself — `pop pay <URL>`
runs the whole dance for you (see **[skills/pop-wallet.md](pop-wallet.md)**).

---

## 1. The 402 challenge (`WWW-Authenticate`)

A gated resource answers a bare request with `402` and this response header
(plus `Cache-Control: no-store` and an `application/problem+json` body):

```
WWW-Authenticate: Payment id="…", realm="…", method="cashu", intent="charge", request="<request-object>", expires="2026-03-15T12:05:00Z"
```

- Quoted-string auth-params. `id`, `realm`, `method`, `intent`, `request` are
  always present; pops servers also always emit `expires` (RFC 3339) — the
  challenge is **stateless-bound**: `id` is an HMAC-SHA256 over the issued
  params under a server secret, and `expires` is the challenge's only expiry
  signal. A server MAY additionally issue `digest` and/or `opaque`.
- `request` is a **base64url-nopad** (padding rejected) encoding of the
  JCS-canonical (RFC 8785) JSON **request object**:

  ```json
  {
    "amount": "1",
    "currency": "pop_1780372941",
    "description": "optional memo",
    "methodDetails": { "paymentRequest": "creqA…" }
  }
  ```

  `methodDetails` carries exactly ONE field: **`paymentRequest`**, a NUT-18
  Cashu payment request (`creqA…`). It is **authoritative** for every payment
  parameter and MUST encode `a` (amount), `u` (unit), and a non-empty `m`
  (accepted mint URLs); its transport set is empty (in-band: the credential
  comes back over this same HTTP channel) and it carries no `nut10`
  spending-condition kind (bearer proofs only). `amount`/`currency` at the top
  level MUST equal the creqA's `a`/`u` (amount compared as integers).

**Client MUSTs before paying:** decode the payment request yourself and verify
its amount, unit, and mint set (reject a challenge whose creqA omits `a`/`u`/`m`
or disagrees with the top-level `amount`/`currency` — the codec in §4 does
this); and **do not submit a credential against a challenge whose `expires` is
past** — re-fetch the resource for a fresh challenge instead.

## 2. The credential to build (`Authorization`)

Retry the **same URL and method** with an `Authorization` header carrying a
single opaque token: the scheme `Payment`, a space, then a **base64url-nopad**
encoding of the JCS-canonical JSON object of this exact shape:

```json
{
  "challenge": {
    "id":      "<echo of the 402's id, verbatim>",
    "realm":   "<echo of realm, verbatim>",
    "method":  "cashu",
    "intent":  "charge",
    "request": "<echo of the request param, byte-for-byte>",
    "expires": "<echo of expires, verbatim — iff the 402 carried it>"
  },
  "payload": { "token": "cashuB…" },
  "source": "<optional payer id; bearer tokens need none — omit it>"
}
```

- `challenge` echoes **every issued auth-param verbatim** — `digest`,
  `opaque`, and `description` too, iff the 402 carried them. The server
  recomputes the HMAC `id` over the echo, so a dropped, altered, or invented
  param (a decode/re-encode of `request` included) makes the credential
  `invalid-challenge`.
- `payload.token` is the `cashuB…` (TokenV4) token you present. Its **total
  value MUST be at least `amount + swap_fee`** — the fee the mint's keyset
  charges on the redeeming swap, `ceil(sum_over_proofs(input_fee_ppk)/1000)`
  (0 on the fee-free `pop_<ts>` keysets, so exactly `amount` there). The
  server makes **no change**: value above the requirement is accepted and
  **retained by the server**, so present the exact total (split your token
  locally first; `pop pay` automates this).

Then: `header value = "Payment " + base64url_nopad(JCS(that object))`.

## 3. What the verifier enforces

From `envelope.rs` (`parse_payment_authorization`) and the verify core:

1. **Scheme is case-insensitive** (`Payment`/`PAYMENT`/`payment`); surrounding
   whitespace trimmed. More than one `Authorization: Payment` credential on a
   request → `400`.
2. **The blob is base64url-nopad.** No `=` padding (a padded blob is
   rejected), URL-safe alphabet. The `creqA…`/`cashuB…` strings *inside* the
   JSON keep their own padding-tolerant encodings.
3. **Required fields:** all five `challenge` echoes plus `payload.token`.
   `source` is optional and never required. Unknown extra fields are
   tolerated.
4. **`method` must equal `cashu`** — exact, lowercase. Any other value is
   `method-unsupported` (HTTP **400**, not 402).
5. **The echo must authenticate:** the server recomputes the `id`-HMAC over
   the echoed params — any mismatch is `invalid-challenge` (402). A
   past `expires` is `payment-expired` (402): re-fetch and pay the fresh
   challenge.
6. **The token must be a `cashuB` (TokenV4)** carrying ≥ 1 proof —
   `cashuA…`/TokenV3 and over-the-proof-cap tokens are `malformed-credential`.
   Bearer proofs only: a NUT-10 (P2PK/HTLC) locked proof is
   `verification-failed`. The token's mint must be in the creqA's mint set
   (canonicalized-URL comparison) and every proof's **resolved keyset** must
   carry the required unit (the mint's published keyset, not the token's
   declared unit, is the authority).
7. **Value check:** total < `amount + swap_fee` → `payment-insufficient`
   (402). There is no over-payment rejection — excess is retained.
8. **Redemption = a NUT-03 swap at the issuing mint.** A swap rejected because
   the keyset retired or its `final_expiry` passed → `payment-expired`; any
   other rejection (a spent proof above all) → `verification-failed`. A
   missing/invalid NUT-12 DLEQ on the signatures the swap *returns* is a
   mint-trust incident, **not** a payment failure: the request still succeeds
   and the server surfaces `dleq_ok: false` to its operator (the gateway's
   settle log / `Redeemed.dleq_ok` / the wasm success object).

### Outcomes

| Status | Body `type` | Meaning |
|---|---|---|
| `200` | — | Paid. Carries `Payment-Receipt` (base64url JSON: `method`, `challengeId`, `reference` = SHA-256 hex of your exact token string, `status`, `timestamp`) + `Cache-Control: private`. |
| `402` | `https://paymentauth.org/problems/<slug>` | A payment-verification failure + a **fresh challenge** in `WWW-Authenticate`. Slugs: `payment-required` (no attempt yet), `malformed-credential`, `invalid-challenge`, `payment-expired`, `payment-insufficient`, `verification-failed`. On `payment-expired`, re-present the **same token** against the fresh challenge once; a second consecutive `payment-expired` means the token's keyset expired — abandon it. |
| `400` | `https://paymentauth.org/problems/method-unsupported`, or `about:blank` | A malformed *request frame* (non-`cashu` method; >1 `Payment` credential), not a payment failure. |
| `503` | `about:blank` (+ `Retry-After`) | Mint unreachable — an infrastructure failure with **no problem type**. If the swap was never transmitted your token is NOT consumed: retry the same token. If a swap's outcome is unknown, check your proofs' state (NUT-07) before reusing or writing off the token. |

Error bodies are RFC 9457 `application/problem+json` with absolute `type`
URIs.

## 4. Canonical builders — don't hand-roll the encoding

The same crate that parses the credential exposes the inverse builders:

- **WASM (JS/TS):** `build_payment_credential(credentials_json)` — takes the
  JSON object from §2 **as a string**, returns the bare base64url-nopad blob;
  you prepend `Payment `. Also: `parse_payment_params(www_authenticate)` to
  read the 402 header, `decode_request_object(b64)` /
  `encode_request_object(json)` for the `request` object,
  `parse_payment_credential(authorization)` to parse a credential, and the
  full `verify_and_redeem(token, requirement_json)` for the server side. (See
  [`crates/pops-core-verify/src/wasm.rs`](../crates/pops-core-verify/src/wasm.rs).)
- **Native (Rust):** `encode_payment_credentials(&PaymentCredentials)` —
  returns the same bare blob; prepend `Payment `. The inverse is
  `parse_payment_authorization(header_value)`; the request object codec is
  `encode_request_object`/`decode_request_object` (cashu-aware:
  `challenge::encode_charge_request`/`decode_charge_request`, which also
  enforce the creqA `a`/`u`/`m` rules). (See `envelope.rs`.)

---

## Worked shape

402 challenge in:

```
WWW-Authenticate: Payment id="kM9xPqWvT2nJrHsY4aDfEb", realm="my-gate", method="cashu", intent="charge", request="eyJhbW91bnQ…", expires="2026-03-15T12:05:00Z"
```

Credential out (before base64url-nopad-encoding the JCS object):

```json
{
  "challenge": {
    "expires": "2026-03-15T12:05:00Z",
    "id": "kM9xPqWvT2nJrHsY4aDfEb",
    "intent": "charge",
    "method": "cashu",
    "realm": "my-gate",
    "request": "eyJhbW91bnQ…"
  },
  "payload": { "token": "cashuBpGFt…" }
}
```

→ `Authorization: Payment <base64url-nopad of that object>`
