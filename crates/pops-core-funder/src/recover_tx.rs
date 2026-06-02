//! Script-path recovery transaction: build, verify, and sign the spend that
//! returns the CLTV-locked BTC to a destination address.
//!
//! Lifted from `pop-wallet/src/recover_tx.rs`'s proven logic, refactored to a
//! **signer seam** — custody is split out of the kernel. Defence-in-depth at
//! every step: reconstruct the output key two ways and assert they agree,
//! re-derive the leaf script from `(ts_expiry, funder_pubkey)` and assert it
//! matches the stored one, assert the on-chain scriptPubKey matches the
//! reconstruction, and have the control block verify itself before assembling
//! the witness.
//!
//! The three-function surface:
//!
//! * [`build_unsigned`] performs every sanity check that does NOT need the
//!   secret and returns an [`UnsignedRecovery`] carrying the BIP-341
//!   script-path sighash to sign (plus everything [`apply_signature`] needs so
//!   the caller never re-passes the internal key / leaf script).
//! * [`apply_signature`] attaches a schnorr signature, verifies it early
//!   against `(sighash, funder_pubkey)`, assembles and self-verifies the
//!   witness, and returns the broadcastable [`RecoverTx`].
//! * [`build_and_sign`] is the hot-key convenience wrapper
//!   (`build_unsigned` + sign(sighash) + `apply_signature`).
//!
//! The kernel is sync + custody-free; async/hardware/remote signing lives
//! entirely in the consumer's `Signer`, never here.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{Keypair, Message, Parity, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapNodeHash};
use bitcoin::{
    transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighash,
    Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::error::RecoverError;
use crate::script::{compute_leaf_hash, compute_leaf_script, compute_output_key, compute_tap_tweak};

/// The mempool-relay floor we never go below (BIP-141 min-relay is 1 sat/vB).
///
/// Brought in from `pop-wallet/src/chain.rs`; the kernel owns the floor used
/// by the feerate fee policy so it carries no chain-I/O dependency.
pub const MIN_RELAY_FEERATE_SAT_PER_VB: f64 = 1.0;

/// Input `nSequence` for the recovery spend: `0xFFFFFFFD`. Two properties,
/// both required:
///
/// * **CLTV stays enforced** — the leaf's `OP_CHECKLOCKTIMEVERIFY` (BIP-65)
///   only requires the input be *non-final*, i.e. `nSequence != 0xFFFFFFFF`.
///   `0xFFFFFFFD` is non-final, so the `nLockTime = ts_expiry` timelock is
///   still enforced.
/// * **Opt-in BIP-125 replace-by-fee** — RBF opt-in requires *any* input have
///   `nSequence < 0xFFFFFFFE` (i.e. `<= 0xFFFFFFFD`). `0xFFFFFFFE` would be
///   non-final but **NOT** replaceable; `0xFFFFFFFD` opts in, so the recovery
///   tx can be fee-bumped if mempool feerates rise after broadcast (its fee is
///   mempool-estimated, so an underestimate must be bumpable rather than
///   leaving funds stuck).
const SEQUENCE_LOCKTIME_RBF: u32 = 0xFFFF_FFFD;

/// Size in bytes of a BIP-340 schnorr signature with `SIGHASH_DEFAULT` (no
/// trailing sighash byte). The real signed witness item is always exactly this
/// size, so a 64-byte placeholder yields a vsize identical to the final tx.
const SCHNORR_SIG_LEN: usize = 64;

/// Size in bytes of a single-leaf taproot control block: 1 (leaf-version|parity
/// byte) + 32 (internal key) + 0 (empty merkle branch). The real control block
/// we build is exactly this length.
const SINGLE_LEAF_CONTROL_BLOCK_LEN: usize = 33;

/// Script-path spends sign with `Default` (== `All`); the wire signature is
/// the bare 64-byte schnorr sig (no trailing sighash-type byte).
const SIGHASH: TapSighashType = TapSighashType::Default;

/// Inputs for building a recovery transaction.
///
/// Carries the funder's **x-only public key** (not the secret) — the leaf is
/// re-derived from `(ts_expiry, funder_pubkey)` and checked against
/// `leaf_script`, and the same key verifies the signature in
/// [`apply_signature`]. Owned fields (no lifetimes) for FFI / agent
/// friendliness.
pub struct RecoverInputs {
    /// Funder x-only pubkey. RE-DERIVES the leaf and is checked vs
    /// `leaf_script`; also the key the recovery signature must verify against.
    pub funder_pubkey: XOnlyPublicKey,
    /// Funding outpoint txid.
    pub funding_txid: Txid,
    /// Funding outpoint vout.
    pub funding_vout: u32,
    /// On-chain UTXO value, sats (fetched from chain).
    pub utxo_value_sat: u64,
    /// On-chain scriptPubKey of the UTXO (fetched from chain).
    pub utxo_script_pubkey: ScriptBuf,
    /// Recovery leaf script (from stored params).
    pub leaf_script: ScriptBuf,
    /// Taproot internal key `P_internal` (from stored params).
    pub internal_key: XOnlyPublicKey,
    /// CLTV expiry (unix seconds). Must be ≥ the value baked into the leaf.
    pub ts_expiry: u64,
    /// Destination address for the recovered BTC (owned).
    pub dest_address: Address,
    /// Network (for the reconstruction sanity-checks).
    pub network: Network,
    /// How to determine the fee subtracted from the output. Either an absolute
    /// sat amount (a `--fee` override) or a mempool feerate to multiply by the
    /// tx's exact vsize.
    pub fee_policy: FeePolicy,
}

/// How the recovery builder decides the fee subtracted from the recovered
/// output.
///
/// The fee is resolved to an absolute sat amount **after** the tx skeleton is
/// built, because vsize depends on the exact (and fixed-size) witness this
/// recovery spend will carry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FeePolicy {
    /// A fixed fee in sats — an explicit `--fee` override; used verbatim.
    Absolute(u64),
    /// A mempool feerate in sat/vB. The absolute fee is
    /// `ceil(vsize_vbytes × feerate)`, with `feerate` floored at the min-relay
    /// rate so we never produce a sub-relay tx.
    Feerate(f64),
}

impl FeePolicy {
    /// Resolves this policy to an absolute fee (sats) for a tx of `vsize`
    /// virtual bytes.
    ///
    /// `Absolute` is returned unchanged. `Feerate(r)` becomes
    /// `ceil(vsize × max(r, MIN_RELAY))`. The feerate floor is applied here so
    /// every feerate-derived fee path is min-relay safe.
    #[must_use]
    pub fn resolve_fee_sat(&self, vsize: usize) -> u64 {
        match *self {
            FeePolicy::Absolute(sat) => sat,
            FeePolicy::Feerate(rate) => {
                let rate = rate.max(MIN_RELAY_FEERATE_SAT_PER_VB);
                // ceil(vsize × rate); vsize is small (≈150 vB) so f64 is exact.
                #[allow(
                    clippy::cast_precision_loss,
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss
                )]
                let fee = (vsize as f64 * rate).ceil() as u64;
                fee
            }
        }
    }

    /// The effective feerate (sat/vB) this policy applies for a `vsize`-vbyte
    /// tx — for display. For `Absolute`, that is the implied `fee / vsize`.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn effective_feerate(&self, vsize: usize) -> f64 {
        match *self {
            FeePolicy::Absolute(sat) => {
                if vsize == 0 {
                    0.0
                } else {
                    sat as f64 / vsize as f64
                }
            }
            FeePolicy::Feerate(rate) => rate.max(MIN_RELAY_FEERATE_SAT_PER_VB),
        }
    }
}

/// An unsigned recovery transaction plus everything needed to finish it.
///
/// The signer needs only [`UnsignedRecovery::sighash`]; the remaining fields
/// are what [`apply_signature`] consumes so the caller never re-passes the
/// internal key / leaf script. Produced by [`build_unsigned`].
#[derive(Debug, Clone)]
pub struct UnsignedRecovery {
    /// The unsigned transaction (empty witness); value + fee already set.
    pub tx: Transaction,
    /// BIP-341 script-path sighash, `SIGHASH_DEFAULT` — **sign this**.
    pub sighash: TapSighash,
    /// Funder x-only pubkey the signature must verify against.
    pub funder_pubkey: XOnlyPublicKey,
    /// The recovery leaf script (witness item 2).
    pub leaf_script: ScriptBuf,
    /// Taproot internal key `P_internal` (control-block field).
    pub internal_key: XOnlyPublicKey,
    /// Parity of the taproot output key `Q` (control-block parity bit).
    pub output_key_parity: Parity,
    /// Absolute fee subtracted, sats.
    pub fee_sat: u64,
    /// The tx's exact virtual size (vbytes) the fee was computed against.
    pub vsize: usize,
    /// Output value (utxo_value − fee), sats.
    pub output_value_sat: u64,
    /// Effective feerate applied (sat/vB) — for display.
    pub feerate_sat_per_vb: f64,
}

/// A built + signed recovery transaction, ready to broadcast.
#[derive(Debug, Clone)]
pub struct RecoverTx {
    /// The signed transaction (exposed for inspection/tests; the broadcast
    /// path consumes `tx_hex`).
    pub tx: Transaction,
    /// Hex serialization.
    pub tx_hex: String,
    /// Computed txid.
    pub txid: Txid,
    /// Output value (utxo_value − fee), sats.
    pub output_value_sat: u64,
    /// Absolute fee actually subtracted, sats.
    pub fee_sat: u64,
    /// The tx's exact virtual size (vbytes) the fee was computed against.
    pub vsize: usize,
    /// Effective feerate applied (sat/vB) — for display. For a `--fee`
    /// override this is the implied `fee / vsize`.
    pub feerate_sat_per_vb: f64,
}

/// Builds a P2TR [`Address`] for an already-tweaked x-only output key on
/// `network`. The key is the taproot output key `Q`; we wrap it as a
/// [`TweakedPublicKey`] (the tweak was applied during construction).
///
/// Relocated from `pop-wallet/src/main.rs`. The wrap is infallible, so this
/// returns an `Address` directly (no `Result`); the kernel reconstructs
/// addresses internally and never fails on this step.
#[must_use]
pub fn recovery_address(output_key: &XOnlyPublicKey, network: Network) -> Address {
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(*output_key);
    Address::p2tr_tweaked(tweaked, network)
}

/// Builds the unsigned recovery spend, performing every defence-in-depth check
/// that does NOT require the funder secret.
///
/// Checks, in order: output-key two-way agreement
/// ([`RecoverError::OutputKeyMismatch`]); the leaf re-derived from
/// `(ts_expiry, funder_pubkey)` vs `leaf_script`
/// ([`RecoverError::ScriptMismatch`]); the on-chain scriptPubKey vs the
/// reconstruction ([`RecoverError::ScriptPubkeyMismatch`]); the value exceeds
/// the resolved fee ([`RecoverError::ValueBelowFee`]). It then builds the tx
/// (`nLockTime = ts_expiry`, RBF sequence), measures the exact vsize with a
/// fixed-size dummy witness, resolves the fee, sets the output value, and
/// computes the taproot script-path sighash to sign.
///
/// # Errors
///
/// Returns the relevant [`RecoverError`] on any failed check, an out-of-range
/// `ts_expiry`, or a sighash-computation error.
pub fn build_unsigned(inputs: RecoverInputs) -> Result<UnsignedRecovery, RecoverError> {
    let secp = Secp256k1::new();

    // Range-check ts_expiry FIRST: it must fit in a u32 to encode as nLockTime,
    // and `compute_leaf_script` (called below to re-derive the leaf) would
    // otherwise hit its internal u32 `.expect()` on an out-of-range value. We
    // turn that into a typed `ExpiryOutOfRange` so no error path can panic.
    let lock_time_u32 = u32::try_from(inputs.ts_expiry)
        .map_err(|_| RecoverError::ExpiryOutOfRange(inputs.ts_expiry))?;
    let lock_time = LockTime::from_consensus(lock_time_u32);

    // Recompute the leaf hash from the supplied leaf script.
    let leaf_hash = compute_leaf_hash(&inputs.leaf_script);

    // Reconstruct the output key two ways (canonical tap_tweak + staged
    // compute_output_key) and assert they agree; capture the output-key parity
    // for the control block.
    let merkle_root = TapNodeHash::from(leaf_hash);
    let (canonical_tweaked, output_key_parity) =
        inputs.internal_key.tap_tweak(&secp, Some(merkle_root));
    let tweak_bytes = compute_tap_tweak(&inputs.internal_key, &leaf_hash);
    let recomputed_output_key = compute_output_key(&inputs.internal_key, &tweak_bytes);
    if recomputed_output_key != canonical_tweaked.to_x_only_public_key() {
        return Err(RecoverError::OutputKeyMismatch);
    }

    // The expected funding scriptPubKey, from the reconstructed output key.
    let expected_address = recovery_address(&recomputed_output_key, inputs.network);
    let expected_script_pubkey = expected_address.script_pubkey();

    // Re-derive the leaf script from (ts_expiry, funder_pubkey) and assert it
    // matches what we stored — catches a key/ts mismatch.
    let recomputed_leaf_script = compute_leaf_script(inputs.ts_expiry, &inputs.funder_pubkey);
    if recomputed_leaf_script != inputs.leaf_script {
        return Err(RecoverError::ScriptMismatch {
            ts_expiry: inputs.ts_expiry,
            stored: hex::encode(inputs.leaf_script.as_bytes()),
            derived: hex::encode(recomputed_leaf_script.as_bytes()),
        });
    }

    // Assert the on-chain scriptPubKey matches our reconstruction.
    if inputs.utxo_script_pubkey != expected_script_pubkey {
        return Err(RecoverError::ScriptPubkeyMismatch {
            utxo: hex::encode(inputs.utxo_script_pubkey.as_bytes()),
            expected: hex::encode(expected_script_pubkey.as_bytes()),
            address: expected_address.to_string(),
        });
    }

    // Build the unsigned tx skeleton: nLockTime = ts_expiry (range-checked
    // above), RBF sequence.
    let txin = TxIn {
        previous_output: OutPoint::new(inputs.funding_txid, inputs.funding_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence(SEQUENCE_LOCKTIME_RBF),
        witness: Witness::new(),
    };
    // The real destination scriptPubKey — its size (and thus the tx's vsize)
    // depends on the address type, so we build it from the actual dest.
    let dest_script_pubkey = inputs.dest_address.script_pubkey();
    // The output value is filled in after we know the fee; the satoshi amount
    // is a fixed 8-byte field, so its value does not affect vsize.
    let txout = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: dest_script_pubkey,
    };
    let prev_txout = TxOut {
        value: Amount::from_sat(inputs.utxo_value_sat),
        script_pubkey: expected_script_pubkey,
    };

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![txin],
        output: vec![txout],
    };

    // Compute the EXACT vsize the final signed tx will have, then resolve the
    // fee policy against it. The signed witness is fixed-shape: a 64-byte
    // schnorr sig, the real leaf script, and a 33-byte single-leaf control
    // block. We attach a correctly-SIZED dummy witness (placeholder sig +
    // control block, real leaf bytes), measure `vsize`, then clear it. Because
    // every witness item's byte length is identical to the final one (BIP-340
    // sigs are always 64 bytes), this vsize equals the signed tx's vsize — it
    // is exact, not an estimate.
    let dummy_witness = Witness::from_slice(&[
        vec![0u8; SCHNORR_SIG_LEN].as_slice(),
        inputs.leaf_script.as_bytes(),
        vec![0u8; SINGLE_LEAF_CONTROL_BLOCK_LEN].as_slice(),
    ]);
    tx.input[0].witness = dummy_witness;
    let vsize = tx.vsize();
    tx.input[0].witness = Witness::new();

    let fee_sat = inputs.fee_policy.resolve_fee_sat(vsize);
    let feerate_sat_per_vb = inputs.fee_policy.effective_feerate(vsize);

    // Value must exceed the fee. An uneconomical-to-sweep UTXO is its own typed
    // signal (ValueBelowFee), distinct from a build/broadcast failure.
    if inputs.utxo_value_sat <= fee_sat {
        return Err(RecoverError::ValueBelowFee {
            value_sats: inputs.utxo_value_sat,
            fee_sats: fee_sat,
        });
    }
    let output_value_sat = inputs.utxo_value_sat - fee_sat;
    tx.output[0].value = Amount::from_sat(output_value_sat);

    // Compute the script-path sighash to sign.
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev_txout]), leaf_hash, SIGHASH)
        .map_err(|e| RecoverError::SighashFailed(e.to_string()))?;

    Ok(UnsignedRecovery {
        tx,
        sighash,
        funder_pubkey: inputs.funder_pubkey,
        leaf_script: inputs.leaf_script,
        internal_key: inputs.internal_key,
        output_key_parity,
        fee_sat,
        vsize,
        output_value_sat,
        feerate_sat_per_vb,
    })
}

/// Attaches a schnorr signature to an [`UnsignedRecovery`], verifying and
/// self-checking before producing the broadcastable [`RecoverTx`].
///
/// Verifies the signature against `(sighash, funder_pubkey)` EARLY
/// ([`RecoverError::SignatureInvalid`] — not at broadcast), builds the
/// single-leaf control block, has it self-verify
/// ([`RecoverError::ControlBlockInvalid`]), assembles the witness
/// `[sig, leaf_script, control_block]`, and asserts the signed tx's vsize
/// equals the fee-computed vsize ([`RecoverError::VsizeMismatch`]).
///
/// # Errors
///
/// Returns [`RecoverError::SignatureInvalid`], [`RecoverError::ControlBlockInvalid`],
/// or [`RecoverError::VsizeMismatch`] on the respective failure.
pub fn apply_signature(
    unsigned: UnsignedRecovery,
    sig: schnorr::Signature,
) -> Result<RecoverTx, RecoverError> {
    let secp = Secp256k1::new();

    // Verify the signature against (sighash, funder_pubkey) before we assemble
    // anything — reject a bad sig here, not at broadcast.
    let msg = Message::from_digest(unsigned.sighash.to_byte_array());
    if secp
        .verify_schnorr(&sig, &msg, &unsigned.funder_pubkey)
        .is_err()
    {
        return Err(RecoverError::SignatureInvalid);
    }

    // Reconstruct the output key (for the control-block self-verify) the same
    // staged way build_unsigned did; build_unsigned already proved it agrees
    // with the canonical tap_tweak.
    let leaf_hash = compute_leaf_hash(&unsigned.leaf_script);
    let tweak_bytes = compute_tap_tweak(&unsigned.internal_key, &leaf_hash);
    let recomputed_output_key = compute_output_key(&unsigned.internal_key, &tweak_bytes);

    // Single-leaf tree → empty merkle branch.
    let control_block = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        output_key_parity: unsigned.output_key_parity,
        internal_key: unsigned.internal_key,
        merkle_branch: Default::default(),
    };
    let control_block_bytes = control_block.serialize();

    // Defence-in-depth: control block must verify against the reconstructed
    // output key + leaf script before we spend a fee on a doomed broadcast.
    if !control_block.verify_taproot_commitment(
        &secp,
        recomputed_output_key,
        unsigned.leaf_script.as_script(),
    ) {
        return Err(RecoverError::ControlBlockInvalid);
    }

    let sig_bytes = sig.as_ref().to_vec();

    // The real witness items must be byte-for-byte the SIZE we assumed when we
    // measured vsize, or the fee we computed is wrong. (Sizes only; values
    // differ.) This is the invariant that makes the vsize exact.
    debug_assert_eq!(sig_bytes.len(), SCHNORR_SIG_LEN);
    debug_assert_eq!(control_block_bytes.len(), SINGLE_LEAF_CONTROL_BLOCK_LEN);

    // Assemble the witness stack: [sig, leaf_script, control_block].
    let witness = Witness::from_slice(&[
        sig_bytes.as_slice(),
        unsigned.leaf_script.as_bytes(),
        control_block_bytes.as_slice(),
    ]);
    let mut tx = unsigned.tx;
    tx.input[0].witness = witness;

    // Final paranoia: the signed tx's vsize must equal what we charged the fee
    // against. If they ever diverge, the schnorr-sig / control-block size
    // assumption broke — fail rather than under/over-pay silently.
    if tx.vsize() != unsigned.vsize {
        return Err(RecoverError::VsizeMismatch {
            signed: tx.vsize(),
            expected: unsigned.vsize,
        });
    }

    let tx_hex = serialize_hex(&tx);
    let txid = tx.compute_txid();

    Ok(RecoverTx {
        tx,
        tx_hex,
        txid,
        output_value_sat: unsigned.output_value_sat,
        fee_sat: unsigned.fee_sat,
        vsize: unsigned.vsize,
        feerate_sat_per_vb: unsigned.feerate_sat_per_vb,
    })
}

/// Hot-key convenience wrapper: `build_unsigned` + sign(sighash) +
/// `apply_signature`.
///
/// Asserts the secret's x-only key equals `inputs.funder_pubkey`
/// ([`RecoverError::WrongFunderKey`]) so the wrapper never signs with a key
/// that does not match the declared funder, then schnorr-signs the sighash
/// deterministically (no aux randomness — sufficient for a one-shot recovery
/// and avoids rand-std in the sighash path).
///
/// # Errors
///
/// Returns [`RecoverError::WrongFunderKey`] if the secret does not match, or
/// any error from [`build_unsigned`] / [`apply_signature`].
pub fn build_and_sign(
    inputs: RecoverInputs,
    funder_secret: &SecretKey,
) -> Result<RecoverTx, RecoverError> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, funder_secret);
    let (derived_xonly, _parity) = keypair.x_only_public_key();
    if derived_xonly != inputs.funder_pubkey {
        return Err(RecoverError::WrongFunderKey);
    }

    let unsigned = build_unsigned(inputs)?;

    let msg = Message::from_digest(unsigned.sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    apply_signature(unsigned, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{reconstruct, ConstructionParams};

    /// Build a deterministic funder secret + its x-only.
    fn funder() -> (SecretKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        // Fixed non-trivial scalar.
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xo, _) = kp.x_only_public_key();
        (sk, xo)
    }

    /// A full build+sign over a self-consistent regtest construction must
    /// succeed and produce a 3-item witness whose control block verifies. We
    /// fabricate the on-chain UTXO from our own reconstruction so the
    /// scriptPubKey matches.
    #[test]
    fn build_and_sign_succeeds_on_consistent_inputs() {
        let (sk, funder_xonly) = funder();
        let ts_expiry = 1_782_259_200u64;
        let params = ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry,
            nonce: [0x42; 32],
            funder_pubkey: funder_xonly,
            network: Network::Regtest,
        };
        let c = reconstruct(&params);
        let expected_spk = recovery_address(&c.output_key, Network::Regtest).script_pubkey();

        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        let out = build_and_sign(
            RecoverInputs {
                funder_pubkey: funder_xonly,
                funding_txid: txid,
                funding_vout: 0,
                utxo_value_sat: 10_000,
                utxo_script_pubkey: expected_spk,
                leaf_script: c.leaf_script.clone(),
                internal_key: c.internal_key,
                ts_expiry,
                dest_address: dest,
                network: Network::Regtest,
                fee_policy: FeePolicy::Absolute(200),
            },
            &sk,
        )
        .unwrap();

        assert_eq!(out.output_value_sat, 9_800);
        assert_eq!(out.fee_sat, 200);
        assert_eq!(out.tx.input[0].witness.len(), 3);
        assert_eq!(out.tx.lock_time, LockTime::from_consensus(ts_expiry as u32));
        // nSequence is exactly 0xFFFFFFFD on the wire (the const value).
        assert_eq!(out.tx.input[0].sequence, Sequence(SEQUENCE_LOCKTIME_RBF));
        assert_eq!(out.tx.input[0].sequence, Sequence(0xFFFF_FFFD));
    }

    /// The canary for the recovery spend's two load-bearing nSequence
    /// properties. Pins them as literals (independent of the const) so a future
    /// edit to `SEQUENCE_LOCKTIME_RBF` that breaks either property fails here:
    ///   (a) NON-FINAL (`!= 0xFFFFFFFF`) → the CLTV nLockTime stays enforced
    ///       (BIP-65 only needs non-final), and
    ///   (b) BIP-125 RBF OPT-IN (`< 0xFFFFFFFE`, i.e. `<= 0xFFFFFFFD`) → the
    ///       stuck-fee recovery tx can be fee-bumped.
    #[test]
    fn recovery_input_is_nonfinal_and_rbf_opt_in() {
        let out = build_with_policy(FeePolicy::Absolute(200));
        let seq = out.tx.input[0].sequence.0;
        // (a) non-final: CLTV (BIP-65) is enforced.
        assert_ne!(seq, 0xFFFF_FFFF, "sequence must be non-final so CLTV is enforced");
        // (b) opt-in RBF: any input sequence < 0xFFFFFFFE signals BIP-125.
        assert!(
            seq < 0xFFFF_FFFE,
            "sequence {seq:#010x} must be < 0xFFFFFFFE to opt into BIP-125 RBF"
        );
    }

    /// A wrong funder key (whose x-only doesn't match the leaf) must be
    /// rejected, never signed. The hot-key wrapper catches it at the
    /// secret-vs-`funder_pubkey` gate (`WrongFunderKey`).
    #[test]
    fn wrong_funder_key_is_rejected() {
        let (_sk_real, funder_xonly) = funder();
        let ts_expiry = 1_782_259_200u64;
        let params = ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry,
            nonce: [0x42; 32],
            funder_pubkey: funder_xonly,
            network: Network::Regtest,
        };
        let c = reconstruct(&params);
        let expected_spk = recovery_address(&c.output_key, Network::Regtest).script_pubkey();
        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        // A different secret than the one committed in the leaf — and we pass
        // its x-only as funder_pubkey, so the leaf re-derivation ALSO mismatches.
        let wrong = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let wrong_xonly = {
            let secp = Secp256k1::new();
            Keypair::from_secret_key(&secp, &wrong).x_only_public_key().0
        };
        let res = build_and_sign(
            RecoverInputs {
                funder_pubkey: wrong_xonly,
                funding_txid: txid,
                funding_vout: 0,
                utxo_value_sat: 10_000,
                utxo_script_pubkey: expected_spk,
                leaf_script: c.leaf_script.clone(),
                internal_key: c.internal_key,
                ts_expiry,
                dest_address: dest,
                network: Network::Regtest,
                fee_policy: FeePolicy::Absolute(200),
            },
            &wrong,
        );
        // The wrong key's leaf does not match the stored leaf → ScriptMismatch.
        assert!(
            matches!(res, Err(RecoverError::ScriptMismatch { .. })),
            "wrong funder key must be rejected before signing, got {res:?}"
        );
    }

    /// Passing a secret that disagrees with `funder_pubkey` is caught by the
    /// hot-key wrapper's gate as `WrongFunderKey`.
    #[test]
    fn secret_not_matching_funder_pubkey_is_wrong_funder_key() {
        let (_sk_real, funder_xonly) = funder();
        let ts_expiry = 1_782_259_200u64;
        let params = ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry,
            nonce: [0x42; 32],
            funder_pubkey: funder_xonly,
            network: Network::Regtest,
        };
        let c = reconstruct(&params);
        let expected_spk = recovery_address(&c.output_key, Network::Regtest).script_pubkey();
        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        // funder_pubkey is the REAL funder, but we hand build_and_sign a
        // different secret — the wrapper's xonly gate must reject it.
        let wrong = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let res = build_and_sign(
            RecoverInputs {
                funder_pubkey: funder_xonly,
                funding_txid: txid,
                funding_vout: 0,
                utxo_value_sat: 10_000,
                utxo_script_pubkey: expected_spk,
                leaf_script: c.leaf_script.clone(),
                internal_key: c.internal_key,
                ts_expiry,
                dest_address: dest,
                network: Network::Regtest,
                fee_policy: FeePolicy::Absolute(200),
            },
            &wrong,
        );
        assert_eq!(res.err(), Some(RecoverError::WrongFunderKey));
    }

    /// utxo_value ≤ fee must refuse with `ValueBelowFee`.
    #[test]
    fn refuses_when_value_not_greater_than_fee() {
        let (sk, funder_xonly) = funder();
        let ts_expiry = 1_782_259_200u64;
        let params = ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry,
            nonce: [0x42; 32],
            funder_pubkey: funder_xonly,
            network: Network::Regtest,
        };
        let c = reconstruct(&params);
        let expected_spk = recovery_address(&c.output_key, Network::Regtest).script_pubkey();
        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        let res = build_and_sign(
            RecoverInputs {
                funder_pubkey: funder_xonly,
                funding_txid: txid,
                funding_vout: 0,
                utxo_value_sat: 200,
                utxo_script_pubkey: expected_spk,
                leaf_script: c.leaf_script,
                internal_key: c.internal_key,
                ts_expiry,
                dest_address: dest,
                network: Network::Regtest,
                fee_policy: FeePolicy::Absolute(200),
            },
            &sk,
        );
        assert!(matches!(res, Err(RecoverError::ValueBelowFee { .. })), "got {res:?}");
    }

    /// A `ts_expiry` past `u32::MAX` (post-year-2106) must return
    /// `ExpiryOutOfRange`, NOT panic — even though the leaf re-derivation runs
    /// `compute_leaf_script`, whose internal u32 `.expect()` we must guard
    /// against. The range check is hoisted before any `compute_leaf_script`.
    #[test]
    fn expiry_above_u32_max_is_expiry_out_of_range() {
        let (sk, funder_xonly) = funder();
        let ts_expiry = u64::from(u32::MAX) + 1; // 4_294_967_296
        // The leaf_script we pass is irrelevant — the range check fires first.
        let dummy_leaf = compute_leaf_script(1_782_259_200, &funder_xonly);
        let dummy_spk = recovery_address(&funder_xonly, Network::Regtest).script_pubkey();
        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        let res = build_unsigned(RecoverInputs {
            funder_pubkey: funder_xonly,
            funding_txid: txid,
            funding_vout: 0,
            utxo_value_sat: 100_000,
            utxo_script_pubkey: dummy_spk,
            leaf_script: dummy_leaf,
            internal_key: funder_xonly,
            ts_expiry,
            dest_address: dest,
            network: Network::Regtest,
            fee_policy: FeePolicy::Absolute(200),
        });
        assert_eq!(res.err(), Some(RecoverError::ExpiryOutOfRange(ts_expiry)));

        // And the hot-key wrapper surfaces the same typed error (no panic).
        let dummy_leaf2 = compute_leaf_script(1_782_259_200, &funder_xonly);
        let dummy_spk2 = recovery_address(&funder_xonly, Network::Regtest).script_pubkey();
        let dest2 = recovery_address(&funder_xonly, Network::Regtest);
        let res2 = build_and_sign(
            RecoverInputs {
                funder_pubkey: funder_xonly,
                funding_txid: txid,
                funding_vout: 0,
                utxo_value_sat: 100_000,
                utxo_script_pubkey: dummy_spk2,
                leaf_script: dummy_leaf2,
                internal_key: funder_xonly,
                ts_expiry,
                dest_address: dest2,
                network: Network::Regtest,
                fee_policy: FeePolicy::Absolute(200),
            },
            &sk,
        );
        assert_eq!(res2.err(), Some(RecoverError::ExpiryOutOfRange(ts_expiry)));
    }

    /// Builds a self-consistent recovery tx and returns it. Shared by the
    /// fee-math tests below.
    fn build_with_policy(policy: FeePolicy) -> RecoverTx {
        let (sk, funder_xonly) = funder();
        let ts_expiry = 1_782_259_200u64;
        let params = ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry,
            nonce: [0x42; 32],
            funder_pubkey: funder_xonly,
            network: Network::Regtest,
        };
        let c = reconstruct(&params);
        let expected_spk = recovery_address(&c.output_key, Network::Regtest).script_pubkey();
        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());
        build_and_sign(
            RecoverInputs {
                funder_pubkey: funder_xonly,
                funding_txid: txid,
                funding_vout: 0,
                utxo_value_sat: 100_000,
                utxo_script_pubkey: expected_spk,
                leaf_script: c.leaf_script.clone(),
                internal_key: c.internal_key,
                ts_expiry,
                dest_address: dest,
                network: Network::Regtest,
                fee_policy: policy,
            },
            &sk,
        )
        .unwrap()
    }

    /// The feerate policy charges EXACTLY `ceil(vsize × feerate)`, the reported
    /// vsize equals the signed tx's real vsize, and `output = input − fee`.
    #[test]
    fn feerate_fee_is_ceil_vsize_times_rate() {
        let rate = 5.0_f64;
        let out = build_with_policy(FeePolicy::Feerate(rate));

        // The vsize the policy charged against is the signed tx's real vsize.
        assert_eq!(out.vsize, out.tx.vsize());

        // Fee is the exact ceil of vsize × rate (no rounding slack).
        let expected_fee = (out.vsize as f64 * rate).ceil() as u64;
        assert_eq!(out.fee_sat, expected_fee);
        assert_eq!(out.feerate_sat_per_vb, rate);

        // Conservation: output is input minus the exact fee.
        assert_eq!(out.output_value_sat, 100_000 - expected_fee);
    }

    /// A feerate below the 1 sat/vB min-relay floor is raised to 1 sat/vB:
    /// the charged fee equals `ceil(vsize × 1.0) == vsize`.
    #[test]
    fn feerate_floors_at_one_sat_per_vb() {
        let out = build_with_policy(FeePolicy::Feerate(0.1));
        assert_eq!(out.fee_sat, out.vsize as u64, "floored fee == vsize × 1 sat/vB");
        assert_eq!(out.feerate_sat_per_vb, 1.0);
    }

    /// `FeePolicy::Absolute` is used verbatim regardless of vsize, and the
    /// reported effective feerate is the implied `fee / vsize`.
    #[test]
    fn absolute_fee_overrides_vsize_math() {
        let out = build_with_policy(FeePolicy::Absolute(1234));
        assert_eq!(out.fee_sat, 1234);
        assert_eq!(out.output_value_sat, 100_000 - 1234);
        // Effective feerate is fee/vsize for an absolute override.
        let implied = 1234.0 / out.vsize as f64;
        assert!((out.feerate_sat_per_vb - implied).abs() < 1e-9);
    }

    /// `resolve_fee_sat` is the pure fee kernel: exercise it directly for the
    /// ceil, the floor, and the absolute pass-through, independent of any tx.
    #[test]
    fn resolve_fee_sat_kernel() {
        // ceil rounds up a fractional product.
        assert_eq!(FeePolicy::Feerate(5.0).resolve_fee_sat(111), 555);
        assert_eq!(FeePolicy::Feerate(4.1).resolve_fee_sat(150), 615); // 615.0 exact
        assert_eq!(FeePolicy::Feerate(4.1).resolve_fee_sat(151), 620); // 619.1 -> 620
        // floor at 1 sat/vB.
        assert_eq!(FeePolicy::Feerate(0.0).resolve_fee_sat(150), 150);
        assert_eq!(FeePolicy::Feerate(0.5).resolve_fee_sat(150), 150);
        // absolute is verbatim.
        assert_eq!(FeePolicy::Absolute(777).resolve_fee_sat(150), 777);
    }

    // ----- signer-seam additions -----

    /// Shared self-consistent inputs builder for the seam tests, parameterised
    /// by fee policy. Returns the inputs plus the funder secret.
    fn consistent_inputs(policy: FeePolicy) -> (RecoverInputs, SecretKey) {
        let (sk, funder_xonly) = funder();
        let ts_expiry = 1_782_259_200u64;
        let params = ConstructionParams {
            mint_pubkey: [0x02; 33],
            ts_expiry,
            nonce: [0x42; 32],
            funder_pubkey: funder_xonly,
            network: Network::Regtest,
        };
        let c = reconstruct(&params);
        let expected_spk = recovery_address(&c.output_key, Network::Regtest).script_pubkey();
        let dest = recovery_address(&funder_xonly, Network::Regtest);
        let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());
        let inputs = RecoverInputs {
            funder_pubkey: funder_xonly,
            funding_txid: txid,
            funding_vout: 0,
            utxo_value_sat: 100_000,
            utxo_script_pubkey: expected_spk,
            leaf_script: c.leaf_script.clone(),
            internal_key: c.internal_key,
            ts_expiry,
            dest_address: dest,
            network: Network::Regtest,
            fee_policy: policy,
        };
        (inputs, sk)
    }

    /// (a) `build_unsigned` alone yields a tx + a sighash, with the fee already
    /// resolved and the output value set, and no witness yet.
    #[test]
    fn build_unsigned_yields_tx_and_sighash() {
        let (inputs, _sk) = consistent_inputs(FeePolicy::Absolute(200));
        let u = build_unsigned(inputs).unwrap();
        assert_eq!(u.fee_sat, 200);
        assert_eq!(u.output_value_sat, 99_800);
        // Unsigned: empty witness, value set, RBF sequence, CLTV locktime.
        assert!(u.tx.input[0].witness.is_empty());
        assert_eq!(u.tx.output[0].value, Amount::from_sat(99_800));
        assert_eq!(u.tx.input[0].sequence, Sequence(0xFFFF_FFFD));
        // The sighash is a real 32-byte digest (non-zero).
        assert_ne!(u.sighash.to_byte_array(), [0u8; 32]);
    }

    /// (b) `apply_signature` with a sig from the WRONG key is rejected with
    /// `SignatureInvalid` (the sig parses fine but fails verification).
    #[test]
    fn apply_signature_rejects_wrong_key_sig() {
        let (inputs, _sk) = consistent_inputs(FeePolicy::Absolute(200));
        let u = build_unsigned(inputs).unwrap();

        // Sign the correct sighash but with a DIFFERENT key.
        let secp = Secp256k1::new();
        let wrong = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
        let wrong_kp = Keypair::from_secret_key(&secp, &wrong);
        let msg = Message::from_digest(u.sighash.to_byte_array());
        let bad_sig = secp.sign_schnorr_no_aux_rand(&msg, &wrong_kp);

        let res = apply_signature(u, bad_sig);
        assert_eq!(res.err(), Some(RecoverError::SignatureInvalid));
    }

    /// (c) Round-trip equivalence: `build_unsigned` + external sign +
    /// `apply_signature` produces the SAME tx_hex / txid as
    /// `build_and_sign(same inputs, secret)`. Proves the seam is a faithful
    /// split of the monolith (deterministic no-aux-rand signing).
    #[test]
    fn seam_roundtrip_matches_build_and_sign() {
        // Path 1: monolithic hot-key wrapper.
        let (inputs_a, sk) = consistent_inputs(FeePolicy::Absolute(200));
        let mono = build_and_sign(inputs_a, &sk).unwrap();

        // Path 2: split build + external sign + apply.
        let (inputs_b, sk2) = consistent_inputs(FeePolicy::Absolute(200));
        let u = build_unsigned(inputs_b).unwrap();
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &sk2);
        let msg = Message::from_digest(u.sighash.to_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let split = apply_signature(u, sig).unwrap();

        assert_eq!(mono.tx_hex, split.tx_hex, "tx_hex must match across the seam");
        assert_eq!(mono.txid, split.txid, "txid must match across the seam");
        assert_eq!(mono.fee_sat, split.fee_sat);
        assert_eq!(mono.vsize, split.vsize);
        assert_eq!(mono.output_value_sat, split.output_value_sat);
    }
}
