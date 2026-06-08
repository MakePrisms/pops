//! Script-path recovery transaction: build, verify, and sign the spend that
//! returns the CLTV-locked BTC to a destination address.
//!
//! Defence-in-depth — every step is checked WITHOUT the secret before signing:
//! reconstruct the output key two ways and assert they agree, re-derive the leaf
//! from `(ts_expiry, funder_pubkey)` and assert it matches the stored one,
//! assert the on-chain scriptPubKey matches the reconstruction, and have the
//! control block verify itself before assembling the witness.
//!
//! The kernel is sync + custody-free; the secret enters only via
//! [`apply_signature`] / [`build_and_sign`], so async/hardware/remote signing
//! lives entirely in the consumer's `Signer`.

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

/// The mempool-relay floor we never go below. 1 sat/vB is Bitcoin Core's
/// historical min-relay *policy* default (not consensus, not a BIP). Core 29.1
/// (2025) lowered the default to 0.1 sat/vB; we keep 1 so the tx still relays
/// on the majority of nodes that have not yet adopted the lower floor.
pub const MIN_RELAY_FEERATE_SAT_PER_VB: f64 = 1.0;

/// Input `nSequence` for the recovery spend: `0xFFFFFFFD`. Two properties, both
/// required and both pinned by `recovery_input_is_nonfinal_and_rbf_opt_in`:
///
/// * **CLTV stays enforced** — `OP_CHECKLOCKTIMEVERIFY` (BIP-65) only needs the
///   input non-final (`!= 0xFFFFFFFF`), so the `nLockTime = ts_expiry` timelock
///   is still enforced.
/// * **Opt-in BIP-125 RBF** — needs `nSequence < 0xFFFFFFFE`. `0xFFFFFFFE` is
///   non-final but NOT replaceable; `0xFFFFFFFD` opts in, so a mempool-estimated
///   fee that underestimates can be bumped rather than leaving funds stuck.
const SEQUENCE_LOCKTIME_RBF: u32 = 0xFFFF_FFFD;

/// A BIP-340 schnorr sig with `SIGHASH_DEFAULT` is always exactly 64 bytes, so a
/// 64-byte placeholder yields a vsize identical to the final tx (see the
/// vsize-exactness invariant in `build_unsigned`).
const SCHNORR_SIG_LEN: usize = 64;

/// Single-leaf control block = 1 (leaf-version|parity) + 32 (internal key) + 0
/// (empty merkle branch). The control block we build is exactly this length.
const SINGLE_LEAF_CONTROL_BLOCK_LEN: usize = 33;

/// Script-path spends sign with `Default` (== `All`); the wire sig is the bare
/// 64-byte schnorr sig (no trailing sighash-type byte).
const SIGHASH: TapSighashType = TapSighashType::Default;

/// Inputs for building a recovery transaction. Carries the funder's x-only
/// public key (not the secret); owned fields (no lifetimes) for FFI / agent
/// friendliness.
pub struct RecoverInputs {
    /// RE-DERIVES the leaf and is checked vs `leaf_script`; also the key the
    /// recovery signature must verify against.
    pub funder_pubkey: XOnlyPublicKey,
    pub funding_txid: Txid,
    pub funding_vout: u32,
    pub utxo_value_sat: u64,
    pub utxo_script_pubkey: ScriptBuf,
    pub leaf_script: ScriptBuf,
    /// Taproot internal key `P_internal` (from stored params).
    pub internal_key: XOnlyPublicKey,
    /// CLTV expiry (unix seconds). Must be ≥ the value baked into the leaf.
    pub ts_expiry: u64,
    pub dest_address: Address,
    pub network: Network,
    pub fee_policy: FeePolicy,
}

/// How the recovery builder decides the fee subtracted from the recovered
/// output. Resolved to an absolute amount AFTER the tx skeleton is built,
/// because vsize depends on the (fixed-size) witness this spend will carry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FeePolicy {
    /// A `--fee` override, used verbatim.
    Absolute(u64),
    /// A mempool feerate in sat/vB; `feerate` is floored at the min-relay rate
    /// so we never produce a sub-relay tx.
    Feerate(f64),
}

impl FeePolicy {
    /// Resolve to an absolute fee (sats) for a `vsize`-vbyte tx. The feerate
    /// floor is applied here, so every feerate-derived path is min-relay safe.
    #[must_use]
    pub fn resolve_fee_sat(&self, vsize: usize) -> u64 {
        match *self {
            FeePolicy::Absolute(sat) => sat,
            FeePolicy::Feerate(rate) => {
                let rate = rate.max(MIN_RELAY_FEERATE_SAT_PER_VB);
                // vsize is small (≈150 vB) so the f64 product is exact.
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

    /// The effective feerate (sat/vB) for display. For `Absolute`, the implied
    /// `fee / vsize`.
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

/// An unsigned recovery transaction plus everything [`apply_signature`] needs,
/// so the caller never re-passes the internal key / leaf script. The signer
/// needs only [`UnsignedRecovery::sighash`].
#[derive(Debug, Clone)]
pub struct UnsignedRecovery {
    /// Unsigned tx (empty witness); value + fee already set.
    pub tx: Transaction,
    /// BIP-341 script-path sighash, `SIGHASH_DEFAULT` — **sign this**.
    pub sighash: TapSighash,
    /// The key the signature must verify against.
    pub funder_pubkey: XOnlyPublicKey,
    pub leaf_script: ScriptBuf,
    /// Taproot internal key `P_internal` (control-block field).
    pub internal_key: XOnlyPublicKey,
    /// Parity of the taproot output key `Q` (control-block parity bit).
    pub output_key_parity: Parity,
    pub fee_sat: u64,
    /// The exact vsize (vbytes) the fee was computed against.
    pub vsize: usize,
    pub output_value_sat: u64,
    pub feerate_sat_per_vb: f64,
}

/// A built + signed recovery transaction, ready to broadcast.
#[derive(Debug, Clone)]
pub struct RecoverTx {
    pub tx: Transaction,
    pub tx_hex: String,
    pub txid: Txid,
    pub output_value_sat: u64,
    pub fee_sat: u64,
    /// The exact vsize (vbytes) the fee was computed against.
    pub vsize: usize,
    pub feerate_sat_per_vb: f64,
}

/// Builds a P2TR [`Address`] for an already-tweaked x-only output key `Q`. The
/// `dangerous_assume_tweaked` wrap is sound because `Q` already had the tap
/// tweak applied during construction.
#[must_use]
pub fn recovery_address(output_key: &XOnlyPublicKey, network: Network) -> Address {
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(*output_key);
    Address::p2tr_tweaked(tweaked, network)
}

/// Builds the unsigned recovery spend, performing every defence-in-depth check
/// that does NOT require the funder secret (each documented inline below).
///
/// # Errors
///
/// Returns the relevant [`RecoverError`] on any failed check, an out-of-range
/// `ts_expiry`, or a sighash-computation error.
pub fn build_unsigned(inputs: RecoverInputs) -> Result<UnsignedRecovery, RecoverError> {
    let secp = Secp256k1::new();

    // Range-check ts_expiry FIRST: it must fit in u32 to encode as nLockTime,
    // and `compute_leaf_script` below would otherwise hit its internal u32
    // `.expect()` — turn that into a typed error so no path can panic.
    let lock_time_u32 = u32::try_from(inputs.ts_expiry)
        .map_err(|_| RecoverError::ExpiryOutOfRange(inputs.ts_expiry))?;
    let lock_time = LockTime::from_consensus(lock_time_u32);

    let leaf_hash = compute_leaf_hash(&inputs.leaf_script);

    // Reconstruct the output key two ways (canonical tap_tweak + staged
    // compute_output_key) and assert they agree; capture parity for the
    // control block.
    let merkle_root = TapNodeHash::from(leaf_hash);
    let (canonical_tweaked, output_key_parity) =
        inputs.internal_key.tap_tweak(&secp, Some(merkle_root));
    let tweak_bytes = compute_tap_tweak(&inputs.internal_key, &leaf_hash);
    let recomputed_output_key = compute_output_key(&inputs.internal_key, &tweak_bytes);
    if recomputed_output_key != canonical_tweaked.to_x_only_public_key() {
        return Err(RecoverError::OutputKeyMismatch);
    }

    let expected_address = recovery_address(&recomputed_output_key, inputs.network);
    let expected_script_pubkey = expected_address.script_pubkey();

    // Re-derive the leaf from (ts_expiry, funder_pubkey) vs the stored one —
    // catches a key/ts mismatch.
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

    let txin = TxIn {
        previous_output: OutPoint::new(inputs.funding_txid, inputs.funding_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence(SEQUENCE_LOCKTIME_RBF),
        witness: Witness::new(),
    };
    // Built from the actual dest because the scriptPubKey size (and thus vsize)
    // depends on the address type.
    let dest_script_pubkey = inputs.dest_address.script_pubkey();
    // Value is filled in after the fee; the satoshi amount is a fixed 8-byte
    // field, so it does not affect vsize.
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

    // vsize-exactness invariant: the signed witness is fixed-shape (64-byte
    // schnorr sig, real leaf script, 33-byte single-leaf control block). We
    // attach a correctly-SIZED dummy witness, measure `vsize`, then clear it.
    // Because every item's byte length equals the final one (BIP-340 sigs are
    // always 64 bytes), this vsize is EXACT, not an estimate — so the fee
    // computed against it is correct. `apply_signature` re-asserts it.
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

    // An uneconomical-to-sweep UTXO is its own typed signal (ValueBelowFee),
    // distinct from a build/broadcast failure.
    if inputs.utxo_value_sat <= fee_sat {
        return Err(RecoverError::ValueBelowFee {
            value_sats: inputs.utxo_value_sat,
            fee_sats: fee_sat,
        });
    }
    let output_value_sat = inputs.utxo_value_sat - fee_sat;
    tx.output[0].value = Amount::from_sat(output_value_sat);

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
/// self-checking (each step inline below) before producing the broadcastable
/// [`RecoverTx`].
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

    // Reject a bad sig HERE, not at broadcast.
    let msg = Message::from_digest(unsigned.sighash.to_byte_array());
    if secp
        .verify_schnorr(&sig, &msg, &unsigned.funder_pubkey)
        .is_err()
    {
        return Err(RecoverError::SignatureInvalid);
    }

    // Reconstruct the output key for the control-block self-verify (build_unsigned
    // already proved it agrees with the canonical tap_tweak).
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

    // Defence-in-depth: the control block must verify against the reconstructed
    // output key + leaf script before we spend a fee on a doomed broadcast.
    if !control_block.verify_taproot_commitment(
        &secp,
        recomputed_output_key,
        unsigned.leaf_script.as_script(),
    ) {
        return Err(RecoverError::ControlBlockInvalid);
    }

    let sig_bytes = sig.as_ref().to_vec();

    // The witness items must be the exact SIZES vsize was measured against, or
    // the computed fee is wrong (see the vsize-exactness invariant).
    debug_assert_eq!(sig_bytes.len(), SCHNORR_SIG_LEN);
    debug_assert_eq!(control_block_bytes.len(), SINGLE_LEAF_CONTROL_BLOCK_LEN);

    // Witness stack: [sig, leaf_script, control_block].
    let witness = Witness::from_slice(&[
        sig_bytes.as_slice(),
        unsigned.leaf_script.as_bytes(),
        control_block_bytes.as_slice(),
    ]);
    let mut tx = unsigned.tx;
    tx.input[0].witness = witness;

    // The signed tx's vsize must equal what the fee was charged against; if they
    // diverge, the size assumption broke — fail rather than mis-pay silently.
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

/// Hot-key convenience wrapper: `build_unsigned` + sign + `apply_signature`.
/// Asserts the secret's x-only key equals `inputs.funder_pubkey`
/// ([`RecoverError::WrongFunderKey`]) so it never signs with a mismatched key,
/// then signs deterministically (no aux randomness — fine for a one-shot
/// recovery, and avoids pulling rand-std into the sighash path).
///
/// # Errors
///
/// [`RecoverError::WrongFunderKey`], or any error from the two callees.
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
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xo, _) = kp.x_only_public_key();
        (sk, xo)
    }

    /// A full build+sign over a self-consistent construction must succeed and
    /// produce a 3-item witness. The on-chain UTXO is fabricated from our own
    /// reconstruction so the scriptPubKey matches.
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
        assert_eq!(out.tx.input[0].sequence, Sequence(SEQUENCE_LOCKTIME_RBF));
        assert_eq!(out.tx.input[0].sequence, Sequence(0xFFFF_FFFD));
    }

    /// Canary for the two load-bearing nSequence properties (see
    /// `SEQUENCE_LOCKTIME_RBF`). Pins them as literals — independent of the
    /// const — so an edit that breaks CLTV-enforcement or RBF-opt-in fails here.
    #[test]
    fn recovery_input_is_nonfinal_and_rbf_opt_in() {
        let out = build_with_policy(FeePolicy::Absolute(200));
        let seq = out.tx.input[0].sequence.0;
        assert_ne!(seq, 0xFFFF_FFFF, "sequence must be non-final so CLTV is enforced");
        assert!(
            seq < 0xFFFF_FFFE,
            "sequence {seq:#010x} must be < 0xFFFFFFFE to opt into BIP-125 RBF"
        );
    }

    /// A wrong funder key whose x-only is ALSO passed as funder_pubkey makes the
    /// leaf re-derivation mismatch → rejected as `ScriptMismatch` before signing.
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
        assert!(
            matches!(res, Err(RecoverError::ScriptMismatch { .. })),
            "wrong funder key must be rejected before signing, got {res:?}"
        );
    }

    /// The complement: funder_pubkey is the REAL funder but a DIFFERENT secret
    /// is handed in → caught by the wrapper's xonly gate as `WrongFunderKey`.
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

    /// A `ts_expiry` past `u32::MAX` must return `ExpiryOutOfRange`, NOT panic —
    /// the range check is hoisted before `compute_leaf_script`'s internal u32
    /// `.expect()`.
    #[test]
    fn expiry_above_u32_max_is_expiry_out_of_range() {
        let (sk, funder_xonly) = funder();
        let ts_expiry = u64::from(u32::MAX) + 1; // 4_294_967_296
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

        // The hot-key wrapper surfaces the same typed error (no panic).
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

    /// Builds a self-consistent recovery tx. Shared by the fee-math tests.
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

    /// Feerate charges EXACTLY `ceil(vsize × feerate)` against the signed tx's
    /// real vsize, and `output = input − fee`.
    #[test]
    fn feerate_fee_is_ceil_vsize_times_rate() {
        let rate = 5.0_f64;
        let out = build_with_policy(FeePolicy::Feerate(rate));

        assert_eq!(out.vsize, out.tx.vsize());
        let expected_fee = (out.vsize as f64 * rate).ceil() as u64;
        assert_eq!(out.fee_sat, expected_fee);
        assert_eq!(out.feerate_sat_per_vb, rate);
        assert_eq!(out.output_value_sat, 100_000 - expected_fee);
    }

    /// A feerate below the 1 sat/vB min-relay floor is raised to 1 sat/vB.
    #[test]
    fn feerate_floors_at_one_sat_per_vb() {
        let out = build_with_policy(FeePolicy::Feerate(0.1));
        assert_eq!(out.fee_sat, out.vsize as u64, "floored fee == vsize × 1 sat/vB");
        assert_eq!(out.feerate_sat_per_vb, 1.0);
    }

    /// `Absolute` is used verbatim regardless of vsize; the reported feerate is
    /// the implied `fee / vsize`.
    #[test]
    fn absolute_fee_overrides_vsize_math() {
        let out = build_with_policy(FeePolicy::Absolute(1234));
        assert_eq!(out.fee_sat, 1234);
        assert_eq!(out.output_value_sat, 100_000 - 1234);
        let implied = 1234.0 / out.vsize as f64;
        assert!((out.feerate_sat_per_vb - implied).abs() < 1e-9);
    }

    /// Exercises the pure fee kernel directly: ceil, floor, absolute.
    #[test]
    fn resolve_fee_sat_kernel() {
        assert_eq!(FeePolicy::Feerate(5.0).resolve_fee_sat(111), 555);
        assert_eq!(FeePolicy::Feerate(4.1).resolve_fee_sat(150), 615); // 615.0 exact
        assert_eq!(FeePolicy::Feerate(4.1).resolve_fee_sat(151), 620); // 619.1 -> 620
        assert_eq!(FeePolicy::Feerate(0.0).resolve_fee_sat(150), 150); // floor
        assert_eq!(FeePolicy::Feerate(0.5).resolve_fee_sat(150), 150); // floor
        assert_eq!(FeePolicy::Absolute(777).resolve_fee_sat(150), 777);
    }

    // ----- signer-seam additions -----

    /// Shared self-consistent inputs builder for the seam tests.
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

    /// `build_unsigned` alone yields a tx + sighash with fee resolved and value
    /// set, and no witness yet.
    #[test]
    fn build_unsigned_yields_tx_and_sighash() {
        let (inputs, _sk) = consistent_inputs(FeePolicy::Absolute(200));
        let u = build_unsigned(inputs).unwrap();
        assert_eq!(u.fee_sat, 200);
        assert_eq!(u.output_value_sat, 99_800);
        assert!(u.tx.input[0].witness.is_empty());
        assert_eq!(u.tx.output[0].value, Amount::from_sat(99_800));
        assert_eq!(u.tx.input[0].sequence, Sequence(0xFFFF_FFFD));
        assert_ne!(u.sighash.to_byte_array(), [0u8; 32]);
    }

    /// A sig from the WRONG key parses fine but fails verification →
    /// `SignatureInvalid`.
    #[test]
    fn apply_signature_rejects_wrong_key_sig() {
        let (inputs, _sk) = consistent_inputs(FeePolicy::Absolute(200));
        let u = build_unsigned(inputs).unwrap();

        let secp = Secp256k1::new();
        let wrong = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
        let wrong_kp = Keypair::from_secret_key(&secp, &wrong);
        let msg = Message::from_digest(u.sighash.to_byte_array());
        let bad_sig = secp.sign_schnorr_no_aux_rand(&msg, &wrong_kp);

        let res = apply_signature(u, bad_sig);
        assert_eq!(res.err(), Some(RecoverError::SignatureInvalid));
    }

    /// Round-trip equivalence: split build + external sign + apply produces the
    /// SAME tx_hex / txid as the monolithic `build_and_sign` — proves the seam
    /// is a faithful split (relies on deterministic no-aux-rand signing).
    #[test]
    fn seam_roundtrip_matches_build_and_sign() {
        let (inputs_a, sk) = consistent_inputs(FeePolicy::Absolute(200));
        let mono = build_and_sign(inputs_a, &sk).unwrap();

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
