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

## PRIMER (read this first, every time this guide loads)

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

This guide teaches you to drive `pop` for a human while keeping them in the loop.
**JSON is the DEFAULT output** on every command — parse it, never scrape human
text. (`--human` / `--pretty` switches to human-readable text for a person to
read; you should not normally pass it.)

> **Build note.** `pop` is a Cargo crate in the `pops` workspace; build/test it
> with `cargo build -p pop` / `cargo test -p pop`. The workspace toolchain is
> pinned in `rust-toolchain.toml` (Rust 1.95).

---

## Output & error contract (FROZEN, schema_version 1)

`pop` speaks a frozen machine contract — see the per-code table under ERROR
CONTRACT below and `pop-wallet.schema.json` for the schema.

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
  - `code` — stable lower_snake_case enum (the 33 codes below). **Branch on
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
pop init    [--network mainnet|testnet|signet|regtest] [--mnemonic "<words>"] [--show-mnemonic] [--force --yes]
pop quote   --mint-url <url> --amount <sats> (--duration <30d> | --unit pop_<ts>) --mint-pubkey <hex33>
pop mint    --resume <deposit_id>                                    # bare resume; mint-url/amount/unit reloaded from the deposit
pop mint    --mint-url <url> --amount <sats> (--duration <30d> | --unit pop_<ts>) [--mint-pubkey <hex33>]  # fresh: quote+poll+mint in one
pop recover (--deposit <id> | --all) --dest <addr> [--fee <sats> | --target <blocks>] [--no-broadcast]
pop list    [--state unpaid|paid|minted|recovered|expired]
pop status  [--deposit <id>]
pop balance
pop pay     <URL> [--token <cashuB> | --token-file <path> | <stdin>] [--max-amount <sats>] [--method GET]
```

For a **fresh** `pop mint` (no `--resume`), `--mint-url`, `--amount`, and exactly
one of `--duration`/`--unit` are required (missing them is a clap usage error,
exit 2). With `--resume <id>` all of those are OPTIONAL — they're reloaded from
the persisted deposit, so `pop mint --resume <id>` works bare.

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
   Output (stdout JSON): `{ "schema_version": 1, "wallet_dir", "network",
   "esplora_url", "mnemonic_delivery", "imported" }`.

   **SECURITY — the mnemonic is NOT on stdout by default.** Because stdout is the
   channel you parse AND may log, the secret mnemonic is printed to **stderr**
   instead (a clearly-labelled `mnemonic (write this down, shown once): …` line),
   and the stdout JSON only carries a non-secret `"mnemonic_delivery": "stderr"`
   marker. **Surface the stderr mnemonic line to the human and have them back it
   up BEFORE locking any real funds.** Do not write the mnemonic into the state
   file, the activity log, stdout capture, or any other file — it is the secret.
   Once the human confirms they've stored it, set `mnemonic_backed_up: true` in
   the state file. (To restore an existing seed instead: `pop init --mnemonic
   "<words>"` — the imported phrase is likewise kept off stdout.)

   Only if a caller deliberately needs to capture the mnemonic programmatically,
   pass `--show-mnemonic`: that ALSO includes `"mnemonic"` in the stdout JSON (and
   flips `mnemonic_delivery` to `"stdout"`). Avoid it unless you have a specific,
   secure reason — it puts the secret on the parse/log channel.

3. **Capture preferences and write the state file** at
   `~/.pop-wallet/agent-state.json` (schema: `pop-wallet.schema.json`). Ask the
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

`--mint-pubkey` is the mint's **33-byte compressed identity pubkey** (66 hex
chars), available from the mint's **`GET /v1/info`** endpoint. The wallet commits
it into the funding-address construction and uses it to independently verify the
address, so it is REQUIRED on the **first** use of a mint; it is then **TOFU-pinned**
(trust-on-first-use) into the wallet's `config.toml` and reused automatically on
later mints to that mint (a changed key for a known mint is a hard error). Record
it as `default_mint.mint_pubkey` in the state file.
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

**Funding on test networks.** On a non-mainnet wallet (signet/testnet/regtest)
you fund with TEST coins, not real BTC. When `mint --resume` times out still
waiting, the `funding_pending` error carries a machine-readable
`details.faucet_hint` pointing at where to get them (signet →
`https://faucet.mutinynet.com`, testnet → a testnet faucet, regtest → fund via
your regtest node / `generatetoaddress`). On **mainnet** there is no
`faucet_hint` (real bitcoin has no faucet) — fund from the human's wallet.

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
retriable), `quote_expired` (stop + re-quote), or `amount_mismatch` (the mint
credited a different sat amount than was quoted — PoP is exact-amount, so the
deposit is NOT minted; the on-chain funds are safe in the CLTV address —
`recover` that deposit). In the rare case the ecash is issued but its `cashuB`
string cannot be encoded, `token_encode_failed` carries the raw proofs
(`details.send_proofs`) to re-encode — the value is never silently lost. See the
code table.

**The `token` (a `cashuB` string) is the credential and is NOT stored by the
wallet.** Deliver it to the human (or, per an entry in `authorized_services`,
hand it to the consumer that will spend it). Record the mint event in the log.

### Paying with PoP ecash (`pop pay`)

`pop pay <URL>` performs the **HTTP-402 client dance**: it fetches a
pops-gateway-protected resource, and if the resource answers `402 Payment` it
satisfies the challenge by presenting a Cashu token worth **EXACTLY** the charge,
then returns the resource. PoP charges are exact-amount (the mint gives no change
on a redeem), so `pop pay` always sends the exact amount — never more.

The wallet holds **no ecash of its own** (it reads no proofs from any DB — there
are none). So `pay` is **token-in**: you supply the `cashuB` to pay WITH, and any
leftover comes back OUT as a NEW change `cashuB` in the JSON for the human to
keep. Supply the token by **`--token <cashuB>`**, **`--token-file <path>`**, or
piped on **stdin** (in that precedence).

Only pay a service listed in `authorized_services`; respect any
`max_amount_sats_per_payment` and pass it as **`--max-amount <sats>`** (a hard
cap — `pay` refuses a charge larger than it, so a malicious 402 cannot trick you
into overspending). If the human asks to pay a service that isn't authorized,
confirm and add it to the state file first.

```
pop pay https://app.example/resource --token cashuB... --max-amount 5000
```

**Three outcomes:**

1. **Already accessible (no payment needed)** — the resource returned 2xx on the
   first request:
   ```json
   { "schema_version": 1, "paid": false, "status": 200, "url": "https://…", "body": "…" }
   ```
   Exit 0. No token was spent.

2. **Paid** — the resource answered 402, the exact-amount token was presented,
   and the retry succeeded:
   ```json
   { "schema_version": 1, "paid": true, "status": 200, "url": "https://…",
     "amount": 600, "unit": "pop_1788000000", "mint": "https://mint.example",
     "change_token": "cashuB…or null", "body": "…" }
   ```
   Exit 0. **`amount`** sats of **`unit`** were spent at **`mint`**. If the held
   token was worth more than the charge, **`change_token`** is a spendable
   `cashuB` for the remainder — **deliver it to the human / save it; it is NOT
   stored.** When the held token equalled the charge exactly, `change_token` is
   `null`.

3. **Failure** — the standard `{schema_version, error:{…}}` envelope on stdout,
   exit 1. The pay-specific codes (see the table) tell you exactly what to fix.
   Notably, the **post-swap** codes **`gateway_rejected_payment`** and
   **`gateway_retry_failed`** carry BOTH `details.send_token` (worth the charge)
   AND any `details.change_token` — once the swap ran, the held input is spent,
   so **recover BOTH tokens; never lose them** (don't gate on `change_token`
   being present — a no-change swap still spent the input). In `--human` mode
   these recovery tokens are printed verbatim to stderr (json `details` is not
   printed in human mode). `token_encode_failed` is the rare post-swap case where
   even the `cashuB` string couldn't be built — it carries the raw proofs
   (`details.send_proofs`/`change_proofs`) to re-encode instead.

**Exactness is a money-safety invariant.** Internally, if the held token > the
charge, `pay` does a NUT-03 swap that splits the proofs into a send set summing
to EXACTLY the charge plus a change set; a hard assertion verifies the send set
before anything leaves the wallet. You don't manage any of this — just present
the token and read the result — but it's why `pay` never overspends.

Log the payment (see ACTIVITY LOG): `action: "pay"`, the `amount_sats`, `unit`,
the service, and whether a `change_token` came back.

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
   `--no-broadcast` (see the dry-run note below) to preview the fee + sweep
   amount for a **matured** deposit first.

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

**`--no-broadcast` is a true DRY-RUN, not a timelock bypass.** It builds and signs
the recovery tx but does NOT broadcast — for a **matured** deposit it returns the
fee + sweep amount (`"status":"built"` with `txid` + `tx_hex`). It does **NOT**
skip the maturity gate: for an **immature** deposit it reports maturity exactly
like a real recover — a single `--deposit` still returns the `cltv_not_expired`
error (with `matures_at`/`now`), and `--all` still emits an `"status":"immature"`
row. There is no flag that moves funds before the CLTV.

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
> spendable ecash. `pop pay` does not change this — it is token-IN / change-OUT
> (you supply the `cashuB` to spend and it hands back any change), so the wallet
> still custodies no ecash and `balance` still reflects only on-chain deposits.

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
  (recovery reveals the construction on-chain). Consider `--no-broadcast` (a true
  dry-run — builds + signs but does not broadcast; still honors the timelock) to
  preview the fee for a matured deposit first.
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

Schema: `pop-wallet.schema.json` (next to this file). Filled example
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

## ERROR CONTRACT — the 33 codes (FROZEN, additive-only)

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
| `funding_pending` | true | transient | `{address, expires_at, confs_seen?, confs_required?, faucet_hint?}` REQ(address, expires_at); `faucet_hint` present on non-mainnet only | funding not credited yet — keep polling (`mint --resume`); on a test network `faucet_hint` says where to get coins |
| `cltv_not_expired` | true | transient (gated) | `{matures_at, now}` REQ | not matured — wait until `matures_at`, then retry the SAME recover |
| `quote_expired` | false | needs_input | `{quote_id, expired_at}` REQ | STOP polling + re-`quote`; funds sent are recoverable after CLTV |
| `amount_mismatch` | false | needs_input | `{expected_sats, funded_sats}` REQ | PoP is exact-amount; funds are safe on-chain — `recover` that deposit |
| `value_below_fee` | false | needs_input | `{value_sats, fee_sats}` REQ | UTXO uneconomical to sweep — lower `--fee` or wait for feerate |
| `fee_too_high` | false | needs_input | `{fee_sats, value_sats, max_percent}` REQ | (`recover`) the AUTO-estimated sweep fee would eat ≥ `max_percent`% of the UTXO — refused BEFORE broadcast. Pass an explicit `--fee <sats>` if intentional, `--no-broadcast` to inspect, or wait for the feerate to drop |
| `not_402` | false | terminal | `{url, status_got}` REQ | (`pay`) the URL answered neither 2xx nor 402 — it isn't gating with payment; check the URL |
| `payment_rejected` | false | terminal/needs_input | `{required_amount?, unit?, reason?}` REQ when the 402 told us | (`pay`) service rejected the payment |
| `no_payment_challenge` | false | terminal | `{url, reason}` REQ | (`pay`) the 402 had no parseable `WWW-Authenticate: Payment` challenge; nothing to satisfy |
| `challenge_parse_failed` | false | terminal | `{reason}` REQ | (`pay`) the challenge didn't decode into a charge (bad request object/`creqA`, or missing amount) |
| `challenge_expired` | false | needs_input | `{url, expires}` REQ | (`pay`) the 402 challenge's `expires` is already past — a credential must NOT be submitted against it, so NOTHING was sent and the held token is intact. Re-request the resource for a fresh challenge, then pay that |
| `token_unit_mismatch` | false | needs_input | `{required, got}` REQ | (`pay`) `--token` unit ≠ the charge's unit; present a token in `required` — SENT NOTHING |
| `token_mint_mismatch` | false | needs_input | `{token_mint, accepted_mints}` REQ | (`pay`) `--token`'s mint isn't accepted by the charge (or the charge named no mints); use an accepted-mint token — SENT NOTHING |
| `insufficient_token_value` | false | needs_input | `{have, need}` REQ | (`pay`) `--token` is worth less than the charge (+ any swap fee, folded into `need`); present a bigger token — SENT NOTHING |
| `amount_exceeds_cap` | false | needs_input | `{amount, cap}` REQ | (`pay`) the charge exceeds `--max-amount`; raise the cap only if you trust the charge — SENT NOTHING |
| `swap_failed` | false | terminal | `{reason}` REQ | (`pay`) the NUT-03 swap-to-exact failed; the token may be unspent (verify) — nothing presented to the gateway |
| `exact_amount_assertion_failed` | false | terminal | `{required, got}` REQ | (`pay`) INTERNAL money-safety abort — the send set didn't equal the charge; SENT NOTHING. Must never happen — report it |
| `gateway_rejected_payment` | false | terminal | `{status, body, send_token, change_token?}` REQ(status, body, send_token) | (`pay`) the gateway answered non-2xx after a valid payment; surface `body`. The gateway did NOT redeem, so **`send_token` (worth the charge) AND any `change_token` are unspent ecash — RECOVER BOTH** (the pop's input was spent by the swap). `--human` mode prints both tokens to stderr |
| `gateway_retry_failed` | false | terminal | `{reason, send_token, change_token?}` REQ(reason, send_token) | (`pay`) the payment-retry HTTP call failed at the transport layer AFTER the swap spent the input — the retry never reached the gateway. **`send_token` (worth the charge) AND any `change_token` are unspent ecash — RECOVER BOTH and present `send_token` to the gateway directly; do NOT retry with the original `--token` (it is spent).** `--human` prints both to stderr |
| `token_encode_failed` | false | terminal | `{reason, send_proofs?, change_proofs?}` REQ(reason) | (`pay`/`mint`) INTERNAL: the ecash was issued (`mint`) or swapped (`pay`) but a proof set could not be encoded to a `cashuB` string. The raw proofs are in `details.send_proofs`/`details.change_proofs` (and printed in `--human`) — they ARE your ecash; re-encode to recover. On `mint` only `send_proofs` is present (the freshly-issued token). Must never happen — report it |
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
- **`pay`-path codes** (`not_402`, `payment_rejected`, `no_payment_challenge`,
  `challenge_parse_failed`, `challenge_expired`, `token_unit_mismatch`,
  `token_mint_mismatch`, `insufficient_token_value`, `amount_exceeds_cap`,
  `swap_failed`, `exact_amount_assertion_failed`, `gateway_rejected_payment`,
  `gateway_retry_failed`, `token_encode_failed`) all belong to `pop pay` —
  EXCEPT `token_encode_failed`, which `pop mint` ALSO emits if a freshly-issued
  token cannot be encoded to its `cashuB` string (then only `send_proofs` is
  present; the issued ecash is recoverable from them). The
  validation codes (`challenge_expired`, `token_*`,
  `insufficient_token_value`, `amount_exceeds_cap`)
  and `swap_failed` are raised BEFORE / without a completed swap — when you see
  them, **no token was sent and the held pop is intact** (verify on `swap_failed`).
  `exact_amount_assertion_failed` also sends nothing (it fires before the gateway).
  But **`gateway_rejected_payment`, `gateway_retry_failed`, and
  `token_encode_failed` are POST-SWAP** — the swap already spent the held input,
  so the freshly-minted ecash exists ONLY in the error: **always recover the
  `send_token` (worth the charge) AND any `change_token` from their details**
  (`token_encode_failed` carries raw `send_proofs`/`change_proofs` instead, when
  even the cashuB string couldn't be built). In `--human` mode these tokens/proofs
  are printed verbatim to stderr (details are not printed in human mode). Do NOT
  gate recovery on `change_token` being present: a swap with no change still spent
  the input, so `send_token` alone must be recovered.
