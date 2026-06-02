---
name: pop-wallet
description: >-
  Manage a human's PoP funder wallet via the `pop` CLI: lock real bitcoin into a
  CLTV-timelocked output, mint PoP Cashu ecash (cashuB tokens) against it, and
  recover the locked bitcoin after the timelock matures. Use whenever the human
  wants to lock/time-lock bitcoin, get/mint pops or PoP credentials, pay with PoP
  ecash, check or recover locked/timelocked bitcoin, or asks "lock N sats" /
  "recover my bitcoin" / "how much do I have locked". Keeps the human aware of
  exactly how their BTC is being locked and when it unlocks.
---

# pop-wallet — managing PoP funds on a human's behalf

## PRIMER (read this first, every time the skill loads)

`pop` is the **funder** wallet for PoP (Proof-of-Power) credentials. The model,
in plain terms:

- To get a PoP credential, you **lock REAL bitcoin** into a Bitcoin output that
  is **timelocked** (CLTV) until a fixed future instant. The exact sat amount is
  sent to a special taproot address.
- Once the mint sees the funding confirm on-chain, it issues **Cashu ecash** of
  the same sat value — a `cashuB` bearer token. The wallet **prints** this token;
  it does **not** store it. Losing the printed token loses the ecash.
- The locked bitcoin is **illiquid until the timelock**. It can be reclaimed
  **only after** the CLTV instant, and **only by this wallet's seed** (or, as a
  fallback, the per-deposit recovery file plus Bitcoin Core ≥ 26). No third party
  and no live mint is needed to recover.
- The **BIP-39 mnemonic shown once at `pop init` is the ONLY backup.** The seed
  is stored on disk **unencrypted** (file perms 0600), no passphrase. Lose the
  mnemonic and every deposit becomes unrecoverable.

So three numbers matter on every lock and the human must always see them: the
**amount** (real BTC), the **lock duration**, and the resulting **recover-after
date**. Funding is on-chain (~1 confirmation), not instant.

This skill teaches you to drive `pop` for a human while keeping them in the loop.
**JSON is the DEFAULT output** on every command — parse it, never scrape human
text. (`--human` / `--pretty` switches to human-readable text for a person to
read; you should not normally pass it.)

---

## Output & error contract (FROZEN, schema_version 1)

`pop` speaks a frozen machine contract — see the per-code table under ERROR
CONTRACT below and `agent-state.schema.json` for the schema.

- **JSON is the default** on success AND failure, written to **stdout**.
  `--human` (alias `--pretty`) switches to text (success → stdout, failure →
  stderr).
- **stdout is pure**: in the default (json) mode, stdout carries **exactly one
  JSON object per invocation and nothing else**. ALL progress / poll-status /
  diagnostics / warnings go to **stderr** — parse stdout, ignore stderr (or
  surface it to the human as live progress).
- Every JSON object carries top-level **`"schema_version": 1`** (success and
  failure).
- **Success**: `{ "schema_version": 1, <command fields> }`.
- **Failure**: `{ "schema_version": 1, "error": { "code", "retriable",
  "message", "details"? } }` on **stdout**, with a **non-zero exit (1)**. Two
  failure signals: the `error` key AND the non-zero exit.
  - `code` — stable lower_snake_case enum (the 20 codes below). **Branch on
    `code`, never on `message`.**
  - `retriable` — bool; `true` ⟺ the failure is transient (safe to retry the
    same call as-is).
  - `message` — HUMAN help only; do not parse it.
  - `details` — structured object; **populated for the codes marked REQ below**.
    Fix your call from these fields, never from prose.
  - clap **argument-parse** errors (missing/invalid flags) exit **2** with no
    JSON envelope — that's a bug in how you invoked `pop`, not a wallet error.

---

## The `pop` command surface (the only commands you may use)

```
pop init    [--network mainnet|testnet|signet|regtest] [--mnemonic "<words>"] [--force --yes]
pop quote   --mint-url <url> --amount <sats> (--duration <30d> | --unit pop_<ts>) --mint-pubkey <hex33>
pop mint    --resume <deposit_id>
pop recover (--deposit <id> | --all) --dest <addr> [--fee <sats> | --target <blocks>] [--no-broadcast]
pop list    [--state unpaid|paid|minted|recovered|expired]
pop status  [--deposit <id>]
pop balance
```

Global: `--wallet-dir <PATH>` (default `~/.pop-wallet`); `--human` (alias
`--pretty`) for text output (json is the default — omit it for machine use);
`--json` is an accepted deprecated no-op (json is already the default). Pass the
`wallet_dir` from the state file to every command if it isn't the default.

Output is **json by default** — the examples below show that default object.

`quote` is **non-blocking**: it creates + independently verifies the funding
address, writes the recovery file, persists the deposit (state `unpaid`), prints
the funding details, and **exits**. The human/agent funds the address out of
band; then `mint --resume <id>` polls until paid and prints the token. (`pop
mint` without `--resume` does quote+poll+mint in one blocking call — prefer the
`quote` → fund → `mint --resume` split so you stay non-blocking and can surface
the address for confirmation.)

Deposit lifecycle (the `state` field): `unpaid` → `paid` → `minted`, then
`recovered` after the timelock sweep. `expired` = funding deadline passed.
`pop list/status` overlay a `display_state` like `Minted / Recoverable now` or
`Minted / Recoverable-after <UTC>` computed from the chain tip. Each deposit
object in `status --json` also carries the structured, machine-checkable fields
`is_locked` (bool — funded BTC still in the CLTV address, the same funding-gated
definition `balance` uses), `recoverable_now` (bool, or **`null` when
`mtp_available` is `false`** — chain unreachable), and `mtp_available` (bool); the
list envelope carries `mtp_available` at the top level too. Prefer these over
string-matching `display_state`. The recoverability gate is funding-aware: a
`paid` deposit becomes `recoverable_now` once matured, and an `expired` quote that
was never funded is never `recoverable_now`.

---

## ONBOARDING (first use — before any funds move)

Do this the first time the human asks you to use PoP, or whenever
`~/.pop-wallet/agent-state.json` is missing.

1. **Explain the model and the risks, plainly**, and get the human to
   acknowledge. Cover: locking real BTC, the fixed lock term, that funds are
   illiquid and recoverable only after the timelock, that the mnemonic is the
   only backup, and that the minted ecash token is printed (you'll hand it to
   them / a service) and not stored.

2. **Initialize the wallet** (skip if `pop list` already succeeds — a wallet
   exists; never `--force` an existing wallet without an explicit human
   instruction, it destroys the only secret):

   ```
   pop init --network mainnet
   ```
   Output: `{ "schema_version": 1, "wallet_dir", "network", "esplora_url",
   "mnemonic", "imported" }`.

   The `mnemonic` is shown **once**. **Surface it to the human and have them back
   it up BEFORE locking any real funds.** Do not write the mnemonic into the
   state file, the activity log, or any other file — it is the secret. Once the
   human confirms they've stored it, set `mnemonic_backed_up: true` in the state
   file. (To restore an existing seed instead: `pop init --mnemonic "<words>"`.)

3. **Capture preferences and write the state file** at
   `~/.pop-wallet/agent-state.json` (schema: `agent-state.schema.json`). Ask the
   human for, and record: default mint URL + mint-pubkey, network, default lock
   duration, **max amount per lock**, default recovery destination address, and
   any authorized services/marketplaces. Stamp `onboarded_at`.

The state file is policy you will honor on every later run; it holds **no keys**.

---

## PER-USE (every time after onboarding)

1. **Read the state file** `~/.pop-wallet/agent-state.json` and apply its
   defaults (mint, duration, max-per-lock, recovery dest, wallet_dir).
2. **Read the ledger** with `pop list` (source of truth for deposit state; json
   is the default — output is `{ "schema_version": 1, "deposits": [ ... ] }`) —
   see CONTINUITY below for mapping the human's words to deposit ids.
3. Carry out the request under the SAFETY RAILS, logging every action.

### Locking bitcoin + minting a credential

Resolve amount, duration (→ recover-after date), and mint from the request +
state file. **Then, BEFORE creating the quote, surface to the human and get
explicit confirmation:**

> Locking **<amount> sats** of real bitcoin at **<mint_url>** for **<duration>**.
> It will be recoverable by you only **after <recover-after UTC>** — until then
> the bitcoin is locked and cannot be moved. Proceed?

On confirmation, create the quote (non-blocking):

```
pop quote --mint-url https://mint.example --amount 50000 --duration 30d --mint-pubkey <hex33>
```
Returns:
```json
{
  "schema_version": 1,
  "deposit_id": "…uuid…",
  "funding_address": "bc1p…",
  "amount_sats": 50000,
  "unit": "pop_1788000000",
  "ts_expiry": 1788000000,
  "recover_after_utc": "2026-12-29T00:00:00Z",
  "bip21_uri": "bitcoin:bc1p…?amount=0.00050000",
  "mint_url": "https://mint.example"
}
```

Log the lock (see ACTIVITY LOG). Now **fund `funding_address` with EXACTLY
`amount_sats`** (over- or under-funding will NOT credit) — via the human's
on-chain wallet or whatever funding path the human authorized; the `bip21_uri`
is scannable. Funding is on-chain and takes ~1 confirmation.

After funding is sent, mint the credential (polls until the mint confirms
funding, then issues):

```
pop mint --resume <deposit_id>
```
Returns:
```json
{ "schema_version": 1, "deposit_id": "…", "mint_url": "…", "unit": "pop_1788000000",
  "amount_sats": 50000, "state": "minted", "token": "cashuB…" }
```

While `mint --resume` polls for funding it prints poll-status / progress to
**stderr** (stdout stays empty until the single final token object). If it
fails, you get the failure envelope — e.g. `funding_pending` (keep polling,
retriable), `quote_expired` (stop + re-quote), or `amount_mismatch` (the
on-chain funds are safe — recover that deposit). See the code table.

**The `token` (a `cashuB` string) is the credential and is NOT stored by the
wallet.** Deliver it to the human (or, per an entry in `authorized_services`,
hand it to the consumer that will spend it). Record the mint event in the log.

### Paying with PoP ecash

The `pop` wallet itself does not spend ecash — it produces the `cashuB` token.
"Paying with pops" means handing a minted token to a downstream consumer (e.g. a
402-paying flow). Only do this for a service listed in `authorized_services`,
respect any `max_amount_sats_per_payment`, and log it. If the human asks to pay a
service that isn't authorized, confirm and add it to the state file first.

### Recovering locked bitcoin (after the timelock)

Recovery is only possible once the **chain's median-time-past (MTP) ≥ the
deposit's `ts_expiry`** (BIP-113 — not your wall clock). `pop recover` refuses an
immature deposit and reports an ETA.

1. Identify the target deposit(s) — see CONTINUITY for mapping phrases like
   "last week's bitcoin" to ids.
2. Check recoverability: `pop status --deposit <id>` → `recoverable_now: true`
   (or `display_state` ending `… / Recoverable now`) means it's matured. If
   `mtp_available` is `false`, `recoverable_now` is `null` (chain unreachable —
   retry), not a "no".
3. **Confirm the destination address with the human** (default from
   `default_recovery_dest`; recommend a fresh address). **Never recover to an
   unconfirmed/unverified destination.** Optionally dry-run with
   `--no-broadcast` to show the fee + sweep amount first.

```
pop recover --deposit <id> --dest <addr> --target 6
```
Returns:
```json
{ "schema_version": 1, "tip_height": 870123, "tip_mtp": 1788000050,
  "results": [ { "deposit_id": "…", "status": "recovered",
                 "recovery_txid": "…", "fee": { "feerate_sat_per_vb": 6.0,
                 "vsize": 150, "fee_sat": 900, "input_sat": 50000,
                 "output_sat": 49100 } } ] }
```
Per-result `status` is one of `recovered` (broadcast, has `recovery_txid`),
`built` (with `--no-broadcast`, has `txid` + `tx_hex`), `immature` (not matured,
has `recover_after`), `already_spent`, or `failed`. Record the recovery (with
`recovery_txid` + swept sats) in the log. `--all --dest <addr>` sweeps every
matured deposit, reporting each in `results`.

Note: a **single** `pop recover --deposit <id>` that isn't matured yet returns
the `cltv_not_expired` **error** envelope (retriable — wait until `matures_at`,
details carry `matures_at` + `now`), whereas a `--all` sweep keeps an immature
deposit as a per-deposit `"status":"immature"` row so the sweep can proceed.

### Checking the aggregate balance

`pop balance` rolls the whole local ledger into one object — use it to answer
"how much have I got locked / mintable / recoverable" without joining per-deposit
rows yourself. It is **local-first**: `by_state`, `total_locked_sats`, and
`mintable_now` need no network; only `recoverable_now` reaches the chain tip (for
median-time-past), and that degrades gracefully like `status`.

> **Scope — ON-CHAIN DEPOSITS ONLY.** `balance` accounts the on-chain CLTV
> deposits this wallet tracks. It does **NOT** count spendable ecash: this wallet
> mints-and-prints `cashuB` tokens and holds **no token custody**, so
> already-minted spendable-pops are not in any number here — `balance` ≠ your
> spendable ecash. (If a phase-2 `pay` command later gives the wallet ecash
> custody, `balance` would surface spendable-pops then.)

```
pop balance
```
Returns:
```json
{
  "schema_version": 1,
  "total_locked_sats": 9400,
  "by_state": {
    "unpaid":    { "count": 1, "sats": 100 },
    "paid":      { "count": 2, "sats": 600 },
    "minted":    { "count": 2, "sats": 2400 },
    "recovered": { "count": 1, "sats": 3200 },
    "expired":   { "count": 1, "sats": 6400 }
  },
  "mintable_now":    { "count": 2, "sats": 600 },
  "recoverable_now": { "count": 3, "sats": 7400 },
  "mtp_available": true
}
```

Semantics:
- `total_locked_sats` — sat sum of **funded-but-not-recovered** deposits (BTC
  still in the CLTV address). This is **funding-gated, not state-gated**:
  `paid` + `minted` (always funded — the mint credited them) + `expired` **only
  if funding was actually sent** (`funding_txid` present). Excludes `unpaid`
  (never funded), `recovered` (swept back out), and an `expired` quote that was
  never funded (it holds no BTC — counting its quoted amount would overstate
  your locked total).
- `by_state` — `{count, sats}` for each of the five lifecycle states. This buckets
  purely by stored `state`, so a never-funded `expired` row still appears under
  `expired` (a state tally) even though it is excluded from `total_locked_sats`
  (a money figure).
- `mintable_now` — the `paid` set (funded, credential not yet issued): run `pop
  mint --resume <id>` to issue these.
- `recoverable_now` — locked (funded-not-recovered) deposits whose `ts_expiry` ≤
  the chain tip's median-time-past (the same BIP-113 maturity gate `recover`
  uses), i.e. the sats you could sweep right now. Same funding-gated locked set
  as `total_locked_sats`, so a matured-but-never-funded `expired` row is excluded.
  **`null` when `mtp_available` is `false`** (esplora was unreachable — the count
  is unknown, NOT zero).
- `mtp_available` — `false` iff the chain-tip MTP fetch failed; then
  `recoverable_now` is `null` and a warning is on stderr. `balance` does **not**
  hard-fail or raise `chain_unreachable` on a chain read — it is best-effort.

Errors are only `wallet_not_initialized` (no wallet at the dir) or
`internal_error` (an unexpected db failure). With `--human`, the same numbers
print as a readable totals-plus-per-state table.

---

## ACTIVITY LOG (continuity across sessions)

Append one JSON object per line to `~/.pop-wallet/agent-activity.jsonl` for
**every** wallet action you take. This is your memory of *when* and *why*; the
wallet's `pop list --json` is the source of truth for current *state*. (Note: the
wallet's `list/status --json` exposes `ts_expiry` and `recover_after_utc` but NOT
the deposit's creation time — so your log's `at` timestamp is what lets you
answer "the bitcoin I locked last Tuesday".)

**Line format** (compact JSON, one per line):

```
{"at":"<UTC ISO-8601>","action":"lock|mint|pay|recover|init|note","deposit_id":"<id|null>","amount_sats":<int|null>,"unit":"pop_<ts>|null","mint_url":"<url|null>","ts_expiry":<int|null>,"recover_after_utc":"<UTC|null>","funding_address":"<addr|null>","funding_txid":"<hex|null>","recovery_txid":"<hex|null>","dest":"<addr|null>","service":"<name|null>","note":"<text>"}
```

Fields not relevant to an action may be `null` or omitted. Examples (one line
each):

```
{"at":"2026-06-01T12:00:00Z","action":"lock","deposit_id":"7f3a…","amount_sats":50000,"unit":"pop_1788000000","mint_url":"https://mint.example","ts_expiry":1788000000,"recover_after_utc":"2026-12-29T00:00:00Z","funding_address":"bc1p…","note":"human-confirmed 30d lock for marketplace credits"}
{"at":"2026-06-01T12:04:30Z","action":"mint","deposit_id":"7f3a…","amount_sats":50000,"unit":"pop_1788000000","mint_url":"https://mint.example","funding_txid":"abcd…","note":"cashuB token delivered to human; not stored"}
{"at":"2026-12-29T09:00:00Z","action":"recover","deposit_id":"7f3a…","amount_sats":49100,"dest":"bc1q…","recovery_txid":"ef01…","note":"matured; swept to human's fresh address, 900 sat fee"}
```

**Mapping the human's words to deposits.** When the human says e.g. "recover last
week's bitcoin" or "how much have I got locked":
- Run `pop list --json` and join it with your activity log on `deposit_id`.
- Use the log's `at` (creation time) for relative dates ("last week",
  "the rent one"); use the wallet's `ts_expiry` / `recover_after_utc` /
  `display_state` for maturity and current state.
- A deposit is reclaimable now iff its `display_state` is `… / Recoverable now`.
- Present matches back to the human (amount, lock date, recover-after, state)
  and confirm before acting.

---

## SAFETY RAILS (non-negotiable)

- **Mnemonic before money.** Refuse to lock real (mainnet) funds unless
  `mnemonic_backed_up: true` in the state file (the human has confirmed the
  one-time mnemonic is stored). The mnemonic is the only backup.
- **Never write the mnemonic or seed anywhere.** Not into the state file, the
  activity log, Mercury, chat history, or any file. Surface it to the human once
  and let them store it.
- **Always show the three numbers before a lock:** exact amount (real BTC), lock
  duration, and the computed recover-after date — and that the BTC is illiquid
  and recoverable only after that date. Get explicit confirmation every time.
- **Respect the per-lock max.** Never lock more than
  `max_amount_sats_per_lock` without a fresh, explicit human approval that names
  the larger amount (then optionally update the state file).
- **Recovery destinations:** always re-confirm the `--dest` with the human;
  never recover to an unconfirmed/unverified address; prefer a fresh address
  (recovery reveals the construction on-chain). Consider `--no-broadcast` to
  preview the fee first.
- **Don't fight the timelock.** If `pop recover` reports `immature`, surface the
  ETA — the funds genuinely cannot move yet.
- **Exact funding only.** Fund `funding_address` with EXACTLY `amount_sats`;
  over/under-funding will not credit.
- **Trust the wallet's verification, don't bypass it.** `pop quote/mint`
  independently re-derive and verify the funding address and abort on any
  mismatch; if a command fails with the **`address_mismatch`** code (terminal,
  security — `details.expected` is our reconstruction, `details.got` is the
  mint's), do NOT fund — report it to the human.
- **Protect the wallet directory.** The seed lives there unencrypted (0600);
  anyone who can read it can derive the keys. Don't copy it around.

---

## State-file reference

Schema: `agent-state.schema.json` (next to this file). Filled example
(`~/.pop-wallet/agent-state.json`):

```json
{
  "version": 1,
  "wallet_dir": "/home/alice/.pop-wallet",
  "network": "mainnet",
  "mnemonic_backed_up": true,
  "default_mint": {
    "mint_url": "https://mint.example",
    "mint_pubkey": "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
  },
  "additional_mints": [],
  "default_lock_duration": "30d",
  "max_amount_sats_per_lock": 100000,
  "default_recovery_dest": "bc1qexampledestaddressforrecovery00000000",
  "default_fee": { "target_blocks": 6, "absolute_sats": null },
  "authorized_services": [
    { "name": "pops-402-extension", "url": "https://app.example", "max_amount_sats_per_payment": 5000 }
  ],
  "onboarded_at": "2026-06-01T12:00:00Z",
  "updated_at": "2026-06-01T12:00:00Z"
}
```

---

## ERROR CONTRACT — the 20 codes (FROZEN, additive-only)

On failure, `pop` writes `{ "schema_version": 1, "error": { "code", "retriable",
"message", "details"? } }` to **stdout** and exits **1**. Branch on `code` +
`details`; never parse `message`.

`retriable` is a bool. The finer **retry-class** below is doc-only (keyed by
`code`): **transient** = retry the same call as-is (`retriable:true`);
**needs_input** = fix the call / ask the human, then retry; **terminal** = do not
retry. **details = REQ** means those fields are always populated — fix your call
from them.

| code | retriable | retry-class | details (REQ = always present) | what to do |
|---|---|---|---|---|
| `insufficient_funds` | false | needs_input | `{required_sats, available_sats}` REQ | need more funds; don't retry as-is |
| `mint_unreachable` | true | transient | `{mint_url}` REQ | network blip — retry |
| `chain_unreachable` | true | transient | `{esplora_url, operation?}` REQ(esplora_url); `operation` ∈ `tip_mtp`\|`utxo_fetch`\|`fee_estimate` | esplora (chain backend) read unreachable — retry |
| `mint_error` | false | terminal | `{status?, mint_message}` REQ(mint_message) | the mint rejected it; surface `mint_message` |
| `funding_pending` | true | transient | `{address, expires_at, confs_seen?, confs_required?}` REQ(address, expires_at) | funding not credited yet — keep polling (`mint --resume`) |
| `cltv_not_expired` | true | transient (gated) | `{matures_at, now}` REQ | not matured — wait until `matures_at`, then retry the SAME recover |
| `quote_expired` | false | needs_input | `{quote_id, expired_at}` REQ | STOP polling + re-`quote`; funds sent are recoverable after CLTV |
| `amount_mismatch` | false | needs_input | `{expected_sats, funded_sats}` REQ | PoP is exact-amount; funds are safe on-chain — `recover` that deposit |
| `value_below_fee` | false | needs_input | `{value_sats, fee_sats}` REQ | UTXO uneconomical to sweep — lower `--fee` or wait for feerate |
| `not_402` | false | terminal | `{url, status_got}` REQ | (phase-2 `pay`) the URL didn't ask for payment |
| `payment_rejected` | false | terminal/needs_input | `{required_amount?, unit?, reason?}` REQ when the 402 told us | (phase-2 `pay`) service rejected the payment |
| `address_mismatch` | false | terminal (security) | `{expected, got}` REQ | mint's address ≠ our reconstruction — do NOT fund; tell the human |
| `network_mismatch` | false | needs_input | `{expected, got}` REQ | wrong-network `--dest`; supply a `expected`-network address |
| `deposit_not_found` | false | needs_input | `{deposit_id}` REQ | no such deposit id — re-check `pop list` |
| `broadcast_failed` | true | transient | `{reject_reason?, txid?}` | retry; the recovery tx is RBF-enabled and the funds stay safe |
| `wallet_not_initialized` | false | needs_input | message-only | run `pop init` first |
| `wallet_exists` | false | needs_input | message-only | a wallet already exists; do not `--force` without explicit human say-so |
| `invalid_mnemonic` | false | needs_input | message-only (never echoes the phrase) | the imported mnemonic is invalid; re-enter it |
| `invalid_input` | false | needs_input | message-only | a bad argument; fix the call |
| `internal_error` | false | terminal | message-only | an unexpected failure; surface it, don't loop |

Notes:
- **Unreachable (read) vs rejection (write):** `mint_unreachable` +
  `chain_unreachable` are the transient-network **read** side (the mint or the
  esplora backend couldn't be reached — retry as-is). `broadcast_failed` +
  `mint_error` are the **write/rejection** side (the chain's POST/broadcast path,
  resp. an application-level mint rejection). `chain_unreachable` specifically
  covers esplora GET/read transport failures (tip-MTP, UTXO lookup, fee
  estimate); a malformed esplora response stays `internal_error`.
- `funding_pending` (keep polling, transient) vs `quote_expired` (window closed,
  STOP + re-quote): do not loop forever on a dead quote.
- `cltv_not_expired` is the **single**-`--deposit` immature signal; a `--all`
  sweep instead returns a per-deposit `"status":"immature"` row (see recover).
- `not_402` / `payment_rejected` are defined now for the future `pay` command,
  which is a separate follow-up feature not yet part of this surface. (`balance`
  IS part of the surface — see "Checking the aggregate balance" above.)
