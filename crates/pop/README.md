# pop — a PoP funder wallet

`pop` is a command-line wallet for the **funder** lifecycle of PoP
(Proof-of-Power) credentials. PoP credentials are Cashu bearer tokens backed by
a CLTV-locked Bitcoin UTXO. This wallet is the funder's single tool to:

- **`init`** — create a seed (the only secret),
- **`mint`** — lock BTC in a CLTV-backed P2TR, wait for funding, and get a
  `cashuB` credential token,
- **`recover`** — reclaim the locked BTC after the timelock matures,
- **`list` / `status`** — track deposits, and
- **`balance`** — an aggregated ledger summary (total locked, per-state
  counts/sats, mintable/recoverable now).

It is a downstream consumer of [`cdk-pop`](https://github.com/MakePrisms/cdk)
(it reuses `cdk-pop`'s `script::*` address-derivation functions and the proven
quote/mint/recover crypto from `pop_test_tool`), built as its own standalone
crate.

## Two realities to understand up front

1. **Funding is on-chain (~1 confirmation), not instant.** Unlike a Lightning
   mint quote, `mint` shows you a Bitcoin address; you broadcast a funding
   transaction and the mint waits a configured depth before crediting and
   letting you issue credentials. `mint` shows a "waiting for funding" state.

2. **Recovery uses this wallet's OWN key.** The PoP funding output uses a
   sign-to-contract internal key that generic consumer wallets cannot sign.
   Recovery never needs a third party: this wallet rebuilds the construction
   from the per-deposit recovery file and signs with the seed-derived funder
   key. Bitcoin Core ≥ 26 (with the recovery file's explicit descriptor) is the
   wallet-independent fallback.

## Build

Rust 1.95+. `cdk-common = "0.16"` is a normal crates.io dependency — no
private fork or git CLI access required to build.

```
cargo build --release
```

The binary is `target/release/pop`. Install with
`cargo install --path .` (installs a single `pop` binary).

## Wallet directory

Default `~/.pop-wallet/` (override with `--wallet-dir`):

```
~/.pop-wallet/
  config.toml          # network, esplora_url, derivation version, mint_pubkey pinset
  seed                 # BIP-39 seed, stored as plaintext hex with 0600 perms (the ONLY secret)
  wallet.db            # SQLite: deposits + the derivation counter
  recovery/            # one non-secret JSON recovery file per deposit
    <deposit_id>.recovery.json
```

The seed is stored **unencrypted** (file `seed`, perms `0600`) — there is no
passphrase. The BIP-39 mnemonic shown once at `init` is the real cold backup,
so an at-rest passphrase would only add a footgun (lose it → the seed is bricked
with no import path). Anyone who can read the wallet directory can derive your
keys, so protect the directory (perms + disk) and keep the mnemonic offline.

The minted ecash is **printed**, not stored — this wallet manages deposits and
recovery, not a balance.

## Key derivation (frozen)

Funder keys are BIP-32 children of the seed at:

```
m / 5271376' / coin_type' / 0' / 0 / index
```

- purpose `5271376'` = `0x506F50` = ASCII `"PoP"` (frozen),
- `coin_type'` per SLIP-44 (`0'` mainnet, `1'` test/signet/regtest),
- one fresh non-hardened `index` per deposit (monotonic counter in `wallet.db`).

The single derived child secret is both the NUT-20 quote-lock key (compressed
pubkey) and the on-chain recovery key (x-only pubkey).

## Commands

### init

```
pop init [--words 12|24] [--network mainnet|testnet|signet|regtest] [--esplora-url URL] [--force]
```

Generates a BIP-39 mnemonic, writes the derived seed in plaintext (file `seed`,
perms `0600`), writes `config.toml` and an empty db, and prints the mnemonic
**once**. Write it down — it is the only secret and the only backup. There is no
passphrase. Default network is **mainnet**.

### mint

```
pop mint --mint-url URL --amount SATS --mint-pubkey HEX33
         [--duration 30d | --unit pop_<ts>]
         [--label TEXT] [--token-out PATH]
         [--poll-interval 5] [--poll-timeout 1800]
         [--resume DEPOSIT_ID]
```

Derives a fresh funder key, creates a PoP quote, **independently re-verifies**
the returned funding address (recomputes the whole construction and asserts it
matches the mint's address + internal key + leaf script — aborts on any
mismatch), writes the recovery file **before** showing the address, polls for
funding, records the funding outpoint, mints the ecash, and **prints the
`cashuB` token** (optionally also to `--token-out`).

`--mint-pubkey` (the mint's 33-byte compressed identity key) is **required on
first use** of a mint and is TOFU-pinned in `config.toml`; the quote response
does not carry it, and it is needed to verify the address. A changed key for a
known mint is a hard error.

### pay

```
pop pay <URL> [--token <cashuB> | --token-file PATH | <stdin>]
        [--max-amount SATS] [--method GET]
```

Spends a held pop at a gated endpoint via the **HTTP-402 dance**: fetches the
URL, and if it answers `402` with a `WWW-Authenticate: Payment` challenge,
presents a Cashu token worth **exactly** the charge, then returns the resource.
It is **token-in / change-out** — you supply the `cashuB` to pay with (flag,
file, or stdin), and `pay` does a NUT-03 swap that splits it into a send set
summing to exactly the charge plus a change set, asserts the send set is exact
(never overspends), and hands the leftover back as a new `change_token` in the
JSON. `--max-amount` is a hard cap so a malicious 402 cannot trick you into
overpaying. On a **post-swap** failure the input is already spent, so the error
carries BOTH the send token and any change token to recover. Full per-field
contract: **[SKILL.md](SKILL.md)**.

### recover

```
pop recover (--deposit ID | --all) --dest ADDRESS [--fee 200] [--no-broadcast]
```

Refuses (with an ETA) any deposit whose CLTV has not matured — maturity is
evaluated against the chain tip's **median-time-past** (BIP-113), not
wall-clock. For matured deposits it rebuilds the construction from stored
params, derives the funder privkey, fetches the funding UTXO, asserts the
on-chain scriptPubKey matches, builds the `nLockTime = ts_expiry` script-path
spend, schnorr-signs, and broadcasts. `--no-broadcast` prints the raw tx hex
instead. `--all` sweeps every matured deposit (and every UTXO at a
double-funded address).

### list / status

```
pop list [--state unpaid|paid|minted|recovered|expired]
pop status [--deposit ID]
```

`list` is a local table. `status` adds a recoverability overlay computed from
the chain tip's MTP (degrades gracefully if esplora is unreachable), and
`--deposit` prints a full dashboard including the recovery params.

### balance

```
pop balance
```

An **aggregated** summary over the whole ledger (distinct from the per-deposit
`list`/`status`): `total_locked_sats` (funded-but-not-recovered = the
`paid`+`minted`+`expired` states), a `by_state` `{count, sats}` breakdown,
`mintable_now` (the `paid` set), and `recoverable_now` (funded-not-recovered
deposits whose CLTV has matured against the chain tip's MTP). The first three are
local-only; `recoverable_now` reaches esplora for the tip MTP and degrades to
`null` (with `mtp_available: false`) if it's unreachable — `balance` is
best-effort and never hard-fails on a chain read.

Machine-readable **JSON is the default output** of every command (on success and
failure, on stdout). Pass `--human` (alias `--pretty`) for human-readable text
instead; `--json` is still accepted as a deprecated no-op.

## Recovery

Two documented paths (both need only the seed mnemonic + the recovery file):

1. **This wallet** — `pop recover`. Depends on no live mint and no third party.
2. **Bitcoin Core ≥ 26** — import the recovery file's `descriptor` (private
   form, using the seed-derived funder key), create a funded PSBT with the
   right `nLockTime` and a non-final sequence, process/finalize, and broadcast.
   The `how_to_recover` field in each recovery file spells out the steps with
   the deposit's actual values.

The one mint-random value the recovery file preserves is the `nonce`; every
other field is public or seed-derivable.
