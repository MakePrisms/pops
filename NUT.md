# PoP: Proof of Power Credentials

`optional`

`depends on: NUT-00, NUT-02, NUT-03, NUT-04, NUT-12, NUT-18, NUT-20, NUT-23`

---

A PoP credential is a Cashu bearer token whose backing is a time-locked Bitcoin UTXO. A funder locks an exact amount of BTC into a single-purpose taproot output, and in exchange the mint issues Cashu credentials of equal sat denomination under a dedicated unit. The credentials are ordinary Cashu ecash and inherit Cashu's blind-signature privacy and double-spend protection ([NUT-00][00], [NUT-03][03]). They differ from money-bearing ecash in one way: they are designed to expire, and they expire *before* the funder can reclaim the locked BTC. After a fixed wall-clock moment the funder unilaterally recovers the BTC with no mint involvement.

A PoP credential therefore proves that its bearer, or an upstream party, committed Bitcoin capital that is currently locked and unspendable. It is not a financial instrument: by the time the BTC is recoverable, the credential is already dead. Use cases include anti-spam, rate-limiting, ticketing, sybil resistance, and agent-to-agent credentialing: any context where a party must demonstrate a costly, time-bound commitment without the credential carrying transferable monetary value.

PoP is a custom payment method layered on the Cashu mint-quote and mint flow ([NUT-04][04]) with mint-quote signatures ([NUT-20][20]). Credentials are spent and verified through the ordinary swap ([NUT-03][03]) and presented over a challenge that names the required amount with a payment request ([NUT-18][18]). PoP is parallel to, not derived from, any on-chain Cashu method.

## Roles

- **Funder**: locks BTC, authorizes issuance, and is the only party that can recover the BTC after expiry. Holds the recovery secret key.
- **Holder**: possesses PoP credentials and presents them to a verifier. May or may not be the funder; credentials are bearer instruments.
- **Verifier**: a service that demands proof of power. It challenges a holder for an exact credential amount and consumes (charges) the presented credential by swapping it.
- **Mint**: issues PoP credentials against confirmed funding, watches the chain, and honors swaps until the credential's keyset retires. The mint never touches the BTC and never participates in recovery.

## Construction

The locking output is a BIP-341 ([BIP-341][bip341]) taproot (P2TR) output with:

- a NUMS-commit internal key that has no spendable key path, and
- a single-leaf script tree carrying one CLTV recovery script spendable only by the funder after a fixed timestamp.

All cryptographic values are deterministic functions of four public inputs: the mint identity key `mint_pubkey`, the expiry timestamp `ts_expiry`, a per-quote `nonce`, and the funder's `funder_pubkey`. Both the mint (at quote time) and the funder's wallet (to verify the address, and later to recover) compute the output key from these four inputs independently.

### Commitment hash `cm`

```
cm = TaggedHash("PoPCommit/v1",
        mint_pubkey ‖ ts_expiry_be ‖ nonce ‖ funder_pubkey)
```

`TaggedHash(tag, m) = SHA256( SHA256(tag) ‖ SHA256(tag) ‖ m )` is the BIP-340 tagged-hash construction ([BIP-340][bip340]). The tag is the literal ASCII string `PoPCommit/v1` with no trailing NUL.

The pre-image is the byte concatenation, in this exact order:

| # | Field          | Encoding                              | Size  |
|---|----------------|---------------------------------------|-------|
| 1 | `mint_pubkey`  | compressed secp256k1 public key (raw) | 33 B  |
| 2 | `ts_expiry`    | unsigned 64-bit, big-endian           | 8 B   |
| 3 | `nonce`        | random bytes                          | 32 B  |
| 4 | `funder_pubkey`| x-only secp256k1 public key (BIP-340) | 32 B  |

The total pre-image is **105 bytes**. `cm` is the 32-byte SHA-256 output, interpreted big-endian as a scalar modulo the curve order in the next step.

`mint_pubkey` is hashed in full 33-byte compressed form, parity preserved; it is not reduced to x-only. It appears only as a hash input and has no on-chain script presence. `ts_expiry` is the same Unix-seconds value that names the credential unit and is baked into the CLTV; the unit name, the CLTV value, and this pre-image field are the same number. `nonce` is sampled by the mint, not the funder.

### Internal key (NUMS commit)

```
P_internal = NUMS_H + cm·G
```

`NUMS_H` is the BIP-341 "nothing-up-my-sleeve" point with x-coordinate

```
0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
```

lifted to its even-Y point. This x-coordinate is `SHA256(0x04 ‖ G_x ‖ G_y)` (SHA-256 of the 65-byte uncompressed encoding of the secp256k1 generator G, per BIP-341) and has no known discrete logarithm. The addend `cm·G` is added to `NUMS_H` on the curve; `P_internal` is the x-only projection of the sum.

Because `NUMS_H` has no known discrete log and `cm·G` does not introduce one, the key path of the taproot output is unspendable. The only spend path is the script path.

### Output key and address

```
leaf_hash = TapLeafHash(0xc0, leaf_script)          # BIP-341 tapscript leaf
t         = TapTweakHash(P_internal ‖ leaf_hash)    # BIP-341/BIP-340 tweak
Q         = P_internal + t·G
```

`leaf_script` is the recovery script. `leaf_hash` uses tapscript leaf version `0xc0`. `t` is the BIP-341 tap-tweak hash over the internal key and the single-leaf Merkle root, which equals the leaf hash. `Q` is the x-only taproot output key. The funding `scriptPubKey` is the standard P2TR program `OP_1 ‖ <Q>`, and the funding address is its bech32m encoding under the mint's configured Bitcoin network (mainnet `bc1p…`, signet/testnet `tb1p…`, regtest `bcrt1p…`).

### Recovery leaf script

The single tapscript leaf is:

```
<ts_expiry> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <funder_pubkey> OP_CHECKSIG
```

- `<ts_expiry>` is pushed as a minimally-encoded script integer (little-endian CScriptNum), e.g. `1782259200` → `04 00 1e 3b 6a`. The push is 4 bytes for `ts_expiry < 2^31` and 5 bytes for `ts_expiry ≥ 2^31` (a `0x00` sign byte is appended), i.e. for timestamps from 2038-01-19 onward.
- `OP_CHECKLOCKTIMEVERIFY` ([BIP-65][bip65]) enforces that the spending transaction's `nLockTime` is **≥ `ts_expiry`** and that the input is non-final, i.e. it enforces an absolute-time lock interpreted as a Unix timestamp. The lock is interpreted as a timestamp rather than a block height because `ts_expiry ≥ 500_000_000` (see [Credential unit naming](#credential-unit-naming)).
- `OP_VERIFY` (`0x69`) clears the `ts_expiry` value `OP_CHECKLOCKTIMEVERIFY` leaves on the stack (CLTV does not pop its argument). Because `ts_expiry ≥ 500_000_000` is always a nonzero (truthy) value, `OP_VERIFY`'s truthiness assertion always passes, so it functions purely as a stack-clear before the signature check.
- `<funder_pubkey>` is pushed as the raw 32-byte x-only key and checked by `OP_CHECKSIG` under BIP-341 tapscript signature rules (BIP-340 schnorr).

The byte layout is: `[push of ts_expiry as minimal CScriptNum, little-endian]` ‖ `0xb1` (OP_CHECKLOCKTIMEVERIFY) ‖ `0x69` (OP_VERIFY) ‖ `0x20` (push 32 bytes) ‖ `<32-byte funder x-only pubkey>` ‖ `0xac` (OP_CHECKSIG). The fully-serialized leaf is **41 bytes** for `ts_expiry < 2^31` (`1 (push) + 4 (ts) + 1 (OP_CLTV) + 1 (OP_VERIFY) + 1 (push 32) + 32 (key) + 1 (OP_CHECKSIG)`) and **42 bytes** for `ts_expiry ≥ 2^31` (the `ts` push is 5 bytes).

`OP_VERIFY` is used rather than `OP_DROP` to clear the leftover CLTV value because it is the opcode taproot miniscript emits for `and_v(v:after(ts_expiry), pk(funder))`; the two opcodes are functionally identical for any positive `ts_expiry`, but only `OP_VERIFY` makes the leaf a standard miniscript fragment. This is what lets the funding output be reproduced and recovered by any miniscript-capable descriptor wallet (see [Recover](#recover)).

### Spend paths

- **Key path**: foreclosed. `P_internal = NUMS_H + cm·G` has no known discrete log.
- **Script path (recovery)**: only the funder, holding the discrete log of `funder_pubkey`, can satisfy the leaf. The spend is valid once the leaf's CLTV matures: the spending transaction sets `nLockTime ≥ ts_expiry` with a non-final input sequence, and Bitcoin accepts it only when the candidate block's median-time-past (MTP) is `≥ ts_expiry` ([BIP-113][bip113]). The witness is

  ```
  [ schnorr_signature, leaf_script, control_block ]
  ```

  where `control_block = (0xc0 | parity_bit(Q)) ‖ P_internal ‖ <empty>` (leaf version `0xc0` OR-ed with the output-key Y parity, the 32-byte internal key, and an empty Merkle branch; the tree has exactly one leaf). The signature is the bare 64-byte BIP-340 schnorr signature (default sighash, no trailing sighash-type byte). Recovery is unilateral: the mint cannot prevent, delay, accelerate, or extract value from it.

## Credential unit naming

PoP credentials are denominated in a dedicated Cashu unit string of the form:

```
pop_<ts_expiry>
```

`<ts_expiry>` is the Unix-seconds timestamp embedded in the recovery leaf's CLTV and committed in `cm`. The unit name, the CLTV value, and the `cm` pre-image field are the same number.

A conformant mint MUST enforce this unit grammar:

- Lowercase literal prefix `pop_`.
- `<ts_expiry>` is a base-10 integer in canonical form: ASCII digits only, no leading zeros, no sign, no whitespace, no separators.
- `500_000_000 ≤ ts_expiry ≤ 2^32 − 1`. The lower bound is the BIP-65 threshold separating block-height locks from Unix-timestamp locks: a CLTV value `< 500_000_000` is interpreted as a block height, which would break PoP's wall-clock semantics. The upper bound is the maximum value that fits the on-chain locktime field (4 bytes); above it the construction is unrepresentable.

A conformant mint SHOULD additionally require `ts_expiry > now` at quote time, and MAY restrict the accepted set further (e.g. to midnight-UTC boundaries, or to a bounded forward window) to limit the number of distinct units and watch entries it maintains. The currently-quotable set, if restricted, MUST be discoverable from the mint's published settings.

## Lifecycle

### Quote (funding request)

The funder requests a mint quote ([NUT-04][04]) for unit `pop_<ts_expiry>` and an exact `amount` in sats, supplying two public keys with distinct roles:

- A **quote-lock pubkey**: the **compressed 33-byte** secp256k1 key supplied as the [NUT-20][20] mint-quote-signature lock. The mint requires an issuance signature from this key; it authorizes *who may mint the credentials*.
- A **funder pubkey**: an **x-only** ([BIP-340][bip340]) secp256k1 key supplied as the method-specific `funder_pubkey` field. It is baked into the `cm` commitment and the CLTV recovery leaf; it controls *who may recover the locked BTC* after `ts_expiry`.

The two MAY be the same underlying key (its compressed form for the lock, its x-only form for the commitment) but are distinct inputs with distinct roles (issuance authorization versus on-chain recovery), and a funder MAY use different keys for each (e.g. to delegate issuance while retaining recovery).

The quote request carries the unit, the amount, the quote-lock pubkey, and the funder pubkey:

```json
{
  "unit": "pop_<ts_expiry>",     // str
  "amount": <int>,               // sats, exact
  "pubkey": <hex_str>,           // quote-lock: compressed 33-byte secp256k1 (NUT-20 issuance lock)
  "funder_pubkey": <hex_str>     // x-only secp256k1, on-chain recovery key, into cm + the CLTV leaf
}
```

The mint MUST:

1. Reject the quote unless the unit satisfies the unit grammar, and the unit-set policy if any.
2. Reject the quote unless `amount` is within the mint's published `[min_amount, max_amount]`.
3. Reject the quote if either the quote-lock pubkey (the [NUT-20][20] issuance lock) or the `funder_pubkey` (the on-chain recovery key) is missing or malformed. Issuance is gated on a NUT-20 signature, and the construction requires the funder pubkey; a quote lacking either cannot be completed and MUST NOT be created.
4. Sample a fresh `nonce` of ≥ 32 bytes from a CSPRNG. The mint, not the funder, samples the nonce.
5. Compute `cm`, `P_internal`, `leaf_script`, `leaf_hash`, `t`, `Q`, and the bech32m funding address.
6. Persist a quote record binding the quote id to `{ unit, ts_expiry, amount, nonce, funder_pubkey, funding address, funding scriptPubKey, funding_deadline }` in the `UNPAID` state.

The mint returns the quote id, the bech32m funding address, the unit, the amount, a funding deadline, and reconstruction material so the funder can independently verify the address and later recover: the `nonce`, the `internal_key` (`P_internal`), the `leaf_script`, and a canonicalized echo of the `funder_pubkey`:

```json
{
  "quote": <str>,                // quote id
  "request": <str>,              // bech32m funding address
  "unit": "pop_<ts_expiry>",     // str
  "amount": <int>,               // sats
  "funding_deadline": <int>,     // unix seconds; see Two independent deadlines
  "nonce": <hex_str>,            // 32 B, mint-sampled
  "internal_key": <hex_str>,    // P_internal, x-only
  "leaf_script": <hex_str>,     // recovery leaf (41 B; 42 B for ts_expiry ≥ 2^31)
  "funder_pubkey": <hex_str>    // canonicalized lowercase x-only hex echo; the wallet SHOULD verify this matches what it sent
}
```

The funder's wallet MUST independently recompute `cm → P_internal → leaf_hash → t → Q` from the four public inputs, using the known stable `mint_pubkey`, and confirm that the bech32m encoding of `Q` equals the address the mint returned. It MUST abort funding on any mismatch. This is the funder's only protection against a malicious mint that returns an address it can itself spend.

### Two independent deadlines

PoP has two distinct expiry concepts, which MUST NOT be conflated:

1. **Funding deadline (`funding_deadline`)**: the wall-clock moment after which the mint will no longer credit a newly-confirmed funding UTXO for this quote. This is the quote's [NUT-04][04] expiry. Funding that confirms after it is not turned into credentials, but remains the funder's and is recoverable.
2. **Credential expiry (`final_expiry`)**: the wall-clock moment after which the issued credentials stop being honored, expressed as the `final_expiry` of the `pop_<ts_expiry>` keyset ([NUT-02][02]).

PoP fixes the credential expiry relative to the CLTV:

```
final_expiry = ts_expiry − safety_margin
```

`safety_margin` is a positive mint-configured gap. The funding deadline MUST also be `≤ final_expiry`, so a quote is never fundable after the credentials it would mint have already retired. A mint MAY set the funding deadline to `final_expiry` or earlier.

### Fund

The funder broadcasts a Bitcoin transaction with exactly one output whose `scriptPubKey` equals the P2TR program for `Q` and whose value equals `amount` exactly. Inputs and change are at the wallet's discretion. No `OP_RETURN` and no second output to `Q` are required or expected. Any taproot-capable wallet can fund a PoP commitment; the funder's wallet does not need to build the script tree to send, only to verify the address and later to recover.

### Detect and credit

The mint watches the funding address on the Bitcoin chain. When it observes a confirmed output paying that address, the mint MUST:

1. Credit the quote only if the output value equals the quote's `amount` exactly. A value that does not match is not credited; the funds remain the funder's and are CLTV-recoverable.
2. Require at least `confirmations` confirmations before crediting.
3. Judge the funding deadline against the confirming block's time, not the mint's wall-clock detection time. A UTXO that confirmed before the deadline MUST be creditable even if the mint observes it later; a UTXO whose confirming block is after the deadline MUST NOT be credited. The mint's own sync latency can never cost a funder a deposit that confirmed in time.
4. Credit the quote at most once, regardless of how many matching outputs land at the address. Once a quote is credited, the mint MUST stop crediting further deposits to that address through this quote. A second exact-amount UTXO to the same address, or a reorg that replaces the funding transaction, MUST NOT credit the quote twice.

On crediting, the quote moves `UNPAID → PAID`. A PoP quote carries a `state` field (the enum vocabulary is [NUT-23][23]'s, but PoP, as a custom method, defines the field itself): `UNPAID` (created, not yet funded), `PAID` (funding credited, not yet issued), `ISSUED` (credentials minted; terminal), and `EXPIRED` (funding deadline passed uncredited; terminal). A `GET` on the quote returns its current state.

Recovery gates on MTP ([BIP-113][bip113]). Under honest mining MTP lags wall-clock, delaying recovery, but a miner may set block timestamps up to `MAX_FUTURE_BLOCK_TIME` (7200 s) ahead, advancing MTP up to ~2 h *before* wall-clock `ts_expiry`. The `safety_margin` must therefore cover this ~2 h adversarial MTP advance in addition to confirmation/reorg depth and clock skew; honest MTP lag is an additional, unbudgeted bonus.

### Issue

To obtain credentials for a `PAID` quote, the funder submits a mint request ([NUT-04][04]) carrying the quote id, the blinded outputs, and a [NUT-20][20] signature:

```json
{
  "quote": <str>,                       // quote id
  "outputs": <Array[BlindedMessage]>,  // blinded outputs, NUT-00
  "signature": <hex_str>               // BIP-340 schnorr signature, NUT-20
}
```

The signed message is `msg = quote_id ‖ B_0 ‖ … ‖ B_(n−1)` (the quote id as UTF-8 and each `B_i` as the hex blinded output), signed as a BIP-340 schnorr signature over `SHA-256(msg)` ([NUT-20][20]).

The mint MUST verify that signature against the quote-lock pubkey bound to the quote (the [NUT-20][20] lock), and MUST reject issuance if the signature is missing or invalid ([NUT-20][20]).

The mint MUST also:

1. Issue only when the quote is `PAID`, rejecting `UNPAID`.
2. Issue against a quote at most once for its full credited amount, then move the quote to `ISSUED` and reject any further issuance against it. PoP credentials MUST be issued in a single, full-amount operation; partial or repeated issuance against one PoP quote is forbidden, because the backing is a single indivisible UTXO and any second issuance would create `pop_<ts>` ecash with no corresponding locked BTC. The generic Cashu mint-and-quote flow does not by itself guarantee single, full-amount issuance for a custom (non-bolt11) method, so a conformant PoP mint MUST treat a `pop_<ts>` quote as all-or-nothing.
3. Sum-check the outputs: `Σ outputs.amount == amount`. The mint signs the blinded outputs ([NUT-00][00]) and returns the blind signatures, which the funder unblinds into proofs and assembles into a standard Cashu token:

```json
{
  "signatures": <Array[BlindSignature]>
}
```

The issued proofs are ordinary Cashu proofs under the `pop_<ts_expiry>` keyset. They carry no special fields; their expiry is the keyset's `final_expiry`.

### Recover

After `ts_expiry`, the funder reclaims the BTC with a script-path spend: input is the funding outpoint; witness is `[ schnorr_signature, leaf_script, control_block ]`; `nLockTime = ts_expiry`; the input sequence is non-final; the output is any destination the funder chooses. Bitcoin accepts the spend once a candidate block's MTP is `≥ ts_expiry` ([BIP-113][bip113]). The mint plays no part.

Because the recovery leaf uses `OP_VERIFY` to clear the CLTV value, the funding output is exactly the standard output-script descriptor

```
tr(<P_internal>, and_v(v:after(<ts_expiry>), pk(<funder_pubkey>)))
```

with `P_internal` the x-only internal key and `<funder_pubkey>` the x-only funder key. `P_internal = NUMS_H + cm·G` is key-path-unspendable by construction, so the descriptor is script-path-only (it can only spend via the recovery leaf). A conformant funder MAY therefore recover in any wallet that implements taproot miniscript descriptors with absolute (`after`) timelocks; the wallet derives the same funding address from this descriptor, watches for the UTXO, and signs the recovery script-path spend with the funder key. Bitcoin Core ≥ 26 reproduces the funding address from this descriptor (confirmed) and can sign the recovery spend.

Because `final_expiry = ts_expiry − safety_margin` and `safety_margin` exceeds the worst-case adversarial MTP advance (~2 h) plus reorg and clock-skew headroom, credentials retire before the earliest moment the funder can move the coins.

### Present and verify

A holder presents a credential to a verifier over a challenge-response exchange.

1. The holder requests the gated resource with no credential. The verifier responds with a challenge that names an exact required amount, the unit, and optionally an allowed mint set, using a Cashu payment request ([NUT-18][18]). The payment request is the `creqA…` string `"creq" + "A" + base64url(CBOR(PaymentRequest))` with fields `a` (amount), `u` (unit = `pop_<ts_expiry>`), and optionally `m` (mints), `s` (single-use), and `d` (description). Its transport set is empty, which [NUT-18][18] defines as in-band: the credential travels back over the same channel.
2. The holder makes its own exact-amount change locally and non-custodially before presenting. If the holder's token is worth more than the required amount, the holder swaps ([NUT-03][03]) its token at the issuing mint into (a) a token worth exactly the required amount and (b) a remainder it keeps, generating the blinded outputs for both halves itself, so neither the mint nor the verifier learns the remainder secrets. The verifier never makes change.
3. The holder re-requests the resource, presenting a token worth exactly the challenged amount in-band.
4. The verifier validates the presented token: the unit MUST match; the mint MUST be in the allowed set if the verifier specified one; and the token's total value MUST equal the required amount exactly (an over-funded token is rejected just like an under-funded one). The verifier then swaps the whole token at the issuing mint ([NUT-03][03]). A successful swap is simultaneously proof that the proofs are unspent (the mint marks the input nullifiers spent and invalidates them, [NUT-03][03]) and that the credential's keyset has not yet retired (the mint refuses a swap whose keyset is expired). The swap transfers the credential's value to the verifier: presentation consumes (charges) the credential.

If validation fails for any reason other than the mint being unreachable (wrong unit, wrong mint, wrong amount, malformed token, or a mint that refused the swap because the proofs were already spent or the keyset retired), the verifier re-issues the challenge; the presentation did not succeed and nothing was charged. Only a transport-level failure to reach the mint is a server-side error.

PoP presentation is exact-amount and transfer-on-use: the holder presents precisely the challenged amount, the verifier swaps all of it, and each presentation consumes the presented credential. This avoids any verifier-side change path and keeps the holder's remainder private.

The wire envelope that carries the challenge and the credential over a transport (the header scheme and JSON framing) is out of scope and is not specified here.

## The `pop_<ts>` keyset and `final_expiry`

Each `pop_<ts_expiry>` unit is served by its own Cashu keyset whose `final_expiry` is set to `ts_expiry − safety_margin`. Because the unit encodes the timestamp, there is exactly one active keyset per unit, and the per-unit keyset retires as a whole at its `final_expiry`.

PoP's soundness depends on credentials becoming unspendable at `final_expiry`. PoP therefore requires:

- A conformant PoP mint MUST set a non-null `final_expiry` ([NUT-02][02]) on every `pop_<ts>` keyset, equal to `ts_expiry − safety_margin`.
- A conformant PoP mint MUST reject any operation (swap, melt, or issuance) that uses a keyset whose `final_expiry` has passed. This rejection is what makes a verifier's swap a proof of non-expiry.

A mint that honors expired `pop_<ts>` keysets is not a conformant PoP mint: it would let a holder spend a credential after the funder can already reclaim the BTC, breaking backing soundness.

The exact boundary (reject at `final_expiry`, or one second after) is an implementation choice as long as it is applied consistently and `safety_margin` comfortably exceeds the boundary's slack.

## Invariants and security properties

### Backing soundness

Every issued `pop_<ts>` credential corresponds to a confirmed Bitcoin UTXO of equal value locked until `ts`. This holds if and only if the mint enforces all of:

- **Exact amount at crediting**: only an output whose value equals the quote amount credits the quote. A different amount never credits.
- **At-most-once credit per quote**: a quote is credited at most once no matter how many matching outputs appear, and crediting stops after the first. Deduplication is per-quote, not per-deposit, so this MUST be robust to a second exact-amount UTXO sent to the same address and to a fee-bump/RBF that changes the funding txid. Crediting is one-way: the mint does not revalidate or reverse a credit after the fact. Reorg safety comes not from un-crediting but from requiring funding to reach `confirmations` depth before crediting. `confirmations` MUST be deep enough, and SHOULD scale with amount, that a reorg displacing an already-credited funding output is negligibly unlikely and uneconomical to induce (see **Mint settings**).
- **Single full-amount issuance**: credentials are issued exactly once for the full credited amount, after which the quote is `ISSUED` and closed.
- **`final_expiry` enforced**: the keyset retires and the mint rejects expired-keyset operations, so a credential cannot outlive its backing.

### No issuance without funder authorization

Issuance requires a [NUT-20][20] signature from the quote-lock key bound at quote time, and a quote with no quote-lock key MUST be refused. An attacker who funds an address but does not hold the funder secret cannot obtain credentials, and cannot steal credentials from a quote someone else created.

### Anti-double-backing and replay resistance

- **Across mints.** `mint_pubkey` is in the `cm` pre-image, so the same `(ts_expiry, nonce, funder_pubkey)` yields a different `Q` at a different mint. A funder cannot back credentials at two mints with one UTXO: the on-chain output only matches the mint whose key it committed to.
- **Across quotes at one mint.** The mint samples `nonce` per quote. Two quotes, even with the same funder key, amount, and expiry, get distinct nonces, hence distinct `cm`, distinct `Q`, and distinct funding addresses. A funder cannot point one UTXO at two quotes. A funder-chosen nonce could be reused across quotes to collide addresses; sampling it on the mint forecloses that.

### Recovery sovereignty and time-bounding

The funder can always recover after `ts_expiry` via the script path; the mint has no key, no veto, and no claim. Conversely, credentials retire at `final_expiry = ts_expiry − safety_margin`, strictly before `ts_expiry`. Provided `safety_margin` covers the worst-case adversarial MTP advance (~2 h) plus reorg and clock skew, there is no window in which a credential is both spendable and its backing reclaimable.

### Mint identity key stability

`mint_pubkey` is the mint's long-term identity public key. Funders, holders, and verifiers rely on it being stable:

- A conformant PoP mint's identity key MUST be stable and MUST NOT rotate while any `pop_<ts>` unit remains quotable or any issued `pop_<ts>` credential is unexpired. A funder verifies the funding address against this key; if it changed, in-flight verifications and recoveries would break.
- A mint that does not publish a stable identity key MUST NOT offer PoP.

### Holder privacy

Holder anonymity at presentation is provided by Cashu's blind-signature property ([NUT-00][00]) and the holder's local non-custodial change: the verifier and mint never see the holder's remainder. PoP does not weaken this.

## Funder requirements

A conformant funder:

1. Generates a quote-lock key (issuance auth) and a funder recovery key (on-chain), which MAY be the same key or distinct. RECOMMENDED: derive the recovery key deterministically so its secret can be re-derived from a seed. Supplies the quote-lock key (compressed) as the [NUT-20][20] lock and the recovery key (x-only) as the `funder_pubkey` field.
2. MUST recompute `Q` from the four public inputs and verify the bech32m address the mint returned before sending any BTC. Aborts on mismatch.
3. Broadcasts a single output of value exactly `amount` to the verified funding address.
4. Persists enough material (the funder secret, `ts_expiry`, `nonce`, `funder_pubkey`, `internal_key`, and `leaf_script`) to reconstruct the script tree and recover, at least until recovery is complete.
5. Signs the issuance request with the funder key ([NUT-20][20]) to obtain credentials.
6. After `ts_expiry`, constructs and broadcasts the script-path recovery spend. RECOMMENDED: recover to a fresh address, since the recovery spend reveals the construction on-chain.

## Holder and verifier requirements

A conformant holder:

1. Treats credentials as bearer Cashu tokens of unit `pop_<ts>`.
2. On a challenge, makes exact-amount change locally and non-custodially via a swap at the issuing mint ([NUT-03][03]), keeps the remainder private, and presents a token worth exactly the challenged amount.

A conformant verifier:

1. Maintains a policy for acceptable issuing mints (by identity key) and for acceptable `pop_<ts>` units. The unit policy SHOULD be expressed as a prefix-plus-minimum-remaining-lifetime rule, e.g. "any `pop_<ts>` whose `ts` is at least N from now". The verifier SHOULD NOT parse `ts` and re-derive lifetime locally; it can let the mint's keyset `final_expiry` enforce liveness via the swap.
2. Challenges for an exact amount and unit via a [NUT-18][18] payment request.
3. Validates unit, mint-allowlist, and exact amount before any network call, then swaps the whole presented token ([NUT-03][03]) to charge it.
4. MUST verify any DLEQ proofs ([NUT-12][12]) present on the blind signatures returned by the swap, and SHOULD reject a mint that omits them; otherwise a malicious mint could make the verifier report success for proofs it never signed.
5. Rejects (re-challenges) on any validation or swap failure, and surfaces only a transport failure to the mint as a server-side error.

## Mint settings

A PoP mint publishes, in its settings, at least:

- `confirmations`: minimum Bitcoin confirmations before crediting funding.
- the safety-margin setting (the reference mint publishes it as `keyset_expiry_margin_seconds`): the gap `ts_expiry − final_expiry` in seconds.
- `min_amount`, `max_amount`: the accepted quote-amount range.
- the quotable `pop_<ts>` unit set or policy, if restricted.

`safety_margin` MUST exceed the worst-case adversarial MTP advance (`MAX_FUTURE_BLOCK_TIME`, 7200 s; a miner can push MTP that far ahead of wall-clock, opening recovery early) plus confirmation/reorg depth and clock skew, with comfortable headroom. Honest MTP lag only delays recovery and is not budgeted against. A margin on the order of a day (e.g. 86 400 s) is a safe default; anything under ~2 h is unsafe regardless of reorg headroom.

`confirmations` is the confirmation depth a funding output must reach before the mint credits it. It MAY be `0` (credit as soon as the funding confirms in a block, fast settlement accepting shallow-reorg risk) and SHOULD scale with amount. Because credit is one-way (the mint never reverses it), a reorg deeper than `confirmations` that removes an already-credited funding output leaves that credential unbacked; the mint trades settlement latency against that risk.

These values are mint policy, not protocol constants; only their existence and publication are required.

Quote creation is unauthenticated and unmetered in the minimal protocol, which lets an attacker bloat the mint's watch set with junk quotes. A mint SHOULD rate-limit or authenticate quote creation and sweep `UNPAID` quotes past their funding deadline.

Any change to the `cm` pre-image layout MUST bump the `TaggedHash` domain tag (e.g. `PoPCommit/v2`) to prevent cross-version address collisions.

## References

- [BIP-65][bip65] OP_CHECKLOCKTIMEVERIFY
- [BIP-113][bip113] Median time-past as lock-time endpoint
- [BIP-340][bip340] Schnorr signatures and tagged hashes
- [BIP-341][bip341] Taproot
- [NUT-00][00] Notation, blinding, proofs
- [NUT-02][02] Keysets and `final_expiry`
- [NUT-03][03] Swap
- [NUT-04][04] Mint quote and mint
- [NUT-12][12] DLEQ proofs
- [NUT-18][18] Payment requests (`creqA`)
- [NUT-20][20] Mint-quote signatures
- [NUT-23][23] BOLT11 mint quote (the `state` enum)

[bip65]: https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
[bip113]: https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki
[bip340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[bip341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
[00]: https://github.com/cashubtc/nuts/blob/main/00.md
[02]: https://github.com/cashubtc/nuts/blob/main/02.md
[03]: https://github.com/cashubtc/nuts/blob/main/03.md
[04]: https://github.com/cashubtc/nuts/blob/main/04.md
[12]: https://github.com/cashubtc/nuts/blob/main/12.md
[18]: https://github.com/cashubtc/nuts/blob/main/18.md
[20]: https://github.com/cashubtc/nuts/blob/main/20.md
[23]: https://github.com/cashubtc/nuts/blob/main/23.md
