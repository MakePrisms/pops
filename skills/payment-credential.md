# The `Payment` credential — wire format

The single canonical description of the `Payment` HTTP auth-scheme that pops
uses: the `402` challenge a gate sends, and the `Authorization: Payment`
credential a client sends back. **Source of truth:**
[`crates/pops-core-verify/src/envelope.rs`](../crates/pops-core-verify/src/envelope.rs)
(every field name + encoding below matches it exactly).

Read this if you are **writing a non-CLI client** or **testing a gate by hand**.
If you drive the `pop` CLI, you do **not** build this yourself — `pop pay <URL>`
runs the whole dance for you (see **[skills/pop-wallet.md](pop-wallet.md)**).

---

## 1. The 402 challenge (`WWW-Authenticate`)

A gated resource answers a bare request with `402` and this response header:

```
WWW-Authenticate: Payment id="…", realm="…", method="cashu", intent="charge", request="<envelope>"
```

- Five quoted-string auth-params: `id`, `realm`, `method`, `intent`, `request`.
- `request` is a **base64url-nopad**-encoded JSON object `{"cashu_request":"creqA…"}`.
  The inner `creqA…` is a Cashu payment-request describing the charge (amount,
  unit, accepted mints). Decode `request` (base64url-nopad), then read
  `cashu_request` to get the `creqA…`.

The scheme prefix (`Payment`) is tolerated present or absent when parsing the
params, and extra/reordered params are ignored — only those five are surfaced.

## 2. The credential to build (`Authorization`)

Retry the **same URL and method** with an `Authorization` header carrying a
single opaque token: the scheme `Payment`, a space, then a
**base64url-nopad**-encoded JSON object of this exact shape:

```json
{
  "challenge": {
    "id":      "<echo of the 402's id, verbatim>",
    "realm":   "<echo of realm, verbatim>",
    "method":  "cashu",
    "intent":  "<echo of intent, e.g. charge, verbatim>",
    "request": "<echo of the request param, verbatim>"
  },
  "payload": { "cashu_token": "cashuB…" }
}
```

- `challenge` echoes all five `WWW-Authenticate` fields **verbatim**.
- `payload.cashu_token` is the `cashuB…` token you mint/select (with your Cashu
  wallet) worth the charge's amount + unit at one of its accepted mints.

Then: `header value = "Payment " + base64url_nopad(JSON.stringify(that object))`.

On retry you get `200` (gated content) or `402` (re-challenge — e.g. wrong
amount/unit/mint, double-spend, or mint unreachable; on a `503` the token was
**not** consumed, so retry).

## 3. Rules (exactly what the verifier enforces)

From `envelope.rs` (`parse_payment_authorization` + the struct definitions):

1. **Scheme is case-insensitive.** `Payment`, `PAYMENT`, `payment` all parse
   (`PAYMENT_SCHEME`, matched with `eq_ignore_ascii_case`). Surrounding
   whitespace is trimmed.
2. **The blob is base64url-nopad.** No padding (`=`), URL-safe alphabet
   (`-`/`_`, never `+`/`/`). Any other form — including a legacy
   `key="value"` param style — fails the base64 decode and is rejected.
3. **All five `challenge` fields are REQUIRED** — `id`, `realm`, `method`,
   `intent`, `request` — and `payload.cashu_token` is required. A missing field
   fails JSON parse.
4. **`method` must equal `cashu`** — exact, lowercase, case-sensitive
   (`CASHU_METHOD`). Any other value is rejected as a wrong-method error.
5. **Extra fields are tolerated and ignored.** Unknown keys on `challenge`
   (`source`, `description`, `opaque`, `digest`, `expires`, …) or on `payload`
   round-trip silently — they neither help nor break parsing.

## 4. Canonical builders — don't hand-roll the encoding

The same crate that parses the credential exposes the inverse builder, so you
never assemble the base64/JSON yourself:

- **WASM (JS/TS):** `build_payment_credential(credentials_json)` — takes the
  JSON object from §2 **as a string**, returns the bare base64url-nopad blob;
  you prepend `Payment ` to form the header value. (Also available:
  `parse_payment_params(www_authenticate)` to read the 402 header,
  `decode_request_envelope(b64)` to unwrap the `request` → `creqA…`, and
  `parse_payment_credential(authorization)` to parse a credential. See
  [`crates/pops-core-verify/src/wasm.rs`](../crates/pops-core-verify/src/wasm.rs).)
- **Native (Rust):** `encode_payment_credentials(&PaymentCredentials)` — returns
  the same bare base64url-nopad blob; prepend `Payment `. The inverse is
  `parse_payment_authorization(header_value)`. (See `envelope.rs`.)

Both live in
[`crates/pops-core-verify/src/envelope.rs`](../crates/pops-core-verify/src/envelope.rs)
(the WASM names are thin wrappers over it in `wasm.rs`).

---

## Worked shape

402 challenge in:

```
WWW-Authenticate: Payment id="ch-1", realm="my-gate", method="cashu", intent="charge", request="eyJjYXNo…"
```

Credential out (before base64url-nopad-encoding the object):

```json
{
  "challenge": { "id": "ch-1", "realm": "my-gate", "method": "cashu", "intent": "charge", "request": "eyJjYXNo…" },
  "payload": { "cashu_token": "cashuBpGFt…" }
}
```

→ `Authorization: Payment <base64url-nopad of that object>`
