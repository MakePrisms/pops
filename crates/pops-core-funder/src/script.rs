//! Taproot output-key construction for PoPs commitment addresses.
//!
//! Pure-function module. Computes the taproot output key `Q`, ancillary
//! cryptographic values, and bech32m address for a PoPs funding commitment
//! from public quote inputs (`mint_pubkey`, `ts_expiry`, `nonce`,
//! `funder_pubkey`). Used at quote-create time (to populate the response
//! address) and at funding-verification time (to reconstruct the expected
//! address for chain-side matching).
//!
//! The construction is taproot with a NUMS-commit internal key and a
//! single-leaf script tree containing the CLTV recovery script.
//!
//! No I/O, no state. Every function here is deterministic over its inputs.
//!
//! ## Layered API
//!
//! Individual stage functions (`compute_cm`, `compute_internal_key`,
//! `compute_leaf_script`, `compute_leaf_hash`, `compute_tap_tweak`,
//! `compute_output_key`, `compute_bech32m_address`) expose each
//! intermediate value so callers (and tests) can pin or inspect each
//! step. `compute_funding_address` is the all-in-one convenience that
//! wires them together.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash, TapTweakHash};
use bitcoin::{
    absolute::LockTime, key::TweakedPublicKey, opcodes::all::OP_CHECKSIG, Address, Network,
    ScriptBuf,
};

/// NUMS H point, x-coordinate, as 32 bytes big-endian.
///
/// `lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`.
/// Derived from `SHA256("G")` so it has no known discrete log.
pub const NUMS_H_X: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Domain-separation tag for the PoP commitment hash:
/// `cm = TaggedHash("PoPCommit/v1", ...)`.
pub const POP_COMMIT_TAG: &[u8] = b"PoPCommit/v1";

/// Returns the NUMS H point as an [`XOnlyPublicKey`] via `lift_x` of
/// [`NUMS_H_X`].
///
/// # Panics
///
/// Never. [`NUMS_H_X`] is a fixed valid x-only pubkey and `lift_x`
/// succeeds by construction.
pub fn nums_h() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_H_X).expect("NUMS_H_X is a valid x-only pubkey")
}

/// Computes `cm = TaggedHash("PoPCommit/v1", mint_pubkey || ts_expiry_be ||
/// nonce || funder_pubkey)`.
///
/// Pre-image layout (105 bytes total):
///
/// | Field           | Type                              | Size |
/// |-----------------|-----------------------------------|------|
/// | `mint_pubkey`   | compressed secp256k1 pubkey       | 33 B |
/// | `ts_expiry`     | u64 big-endian                    | 8 B  |
/// | `nonce`         | random bytes                      | 32 B |
/// | `funder_pubkey` | x-only secp256k1 pubkey           | 32 B |
///
/// The mint pubkey is hashed in compressed (33-byte, parity-preserving)
/// form — no x-only stripping.
pub fn compute_cm(
    mint_pubkey: &[u8; 33],
    ts_expiry: u64,
    nonce: &[u8; 32],
    funder_pubkey: &XOnlyPublicKey,
) -> [u8; 32] {
    // Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
    let tag_hash = sha256::Hash::hash(POP_COMMIT_TAG);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(mint_pubkey);
    eng.input(&ts_expiry.to_be_bytes());
    eng.input(nonce);
    eng.input(&funder_pubkey.serialize());
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// Computes `P_internal = NUMS_H + cm·G`.
///
/// `cm` is interpreted as a scalar modulo the curve order. The addition
/// `NUMS_H + cm·G` is implemented via secp256k1's `add_exp_tweak`. The
/// returned key is the x-only projection (even-y).
///
/// # Panics
///
/// Panics only on a statistically impossible event: `cm` colliding with
/// the secp256k1 curve order (probability ~ 2^-256), or the resulting
/// point being the point at infinity. Both are vanishingly improbable
/// for a SHA-256 output.
pub fn compute_internal_key(cm: &[u8; 32]) -> XOnlyPublicKey {
    let secp = Secp256k1::verification_only();
    // Lift NUMS_H to a full PublicKey on the even-y branch.
    let nums = nums_h().public_key(bitcoin::key::Parity::Even);
    let scalar = Scalar::from_be_bytes(*cm)
        .expect("cm is a 32-byte hash; collision with curve order is statistically impossible");
    let combined = nums
        .add_exp_tweak(&secp, &scalar)
        .expect("NUMS_H + cm·G collision with infinity is statistically impossible");
    combined.x_only_public_key().0
}

/// Builds the single recovery leaf script:
///
/// ```text
/// <ts_expiry> OP_CHECKLOCKTIMEVERIFY OP_VERIFY <funder_pubkey> OP_CHECKSIG
/// ```
///
/// `ts_expiry` is emitted as a `LockTime` so `script::Builder::push_lock_time`
/// produces the correct minimal `CScriptNum` encoding. `funder_pubkey`
/// is pushed as 32 raw x-only bytes for tapscript `OP_CHECKSIG`.
///
/// # Panics
///
/// Panics if `ts_expiry` does not fit in a `u32` (i.e. > 2^32 - 1 ≈
/// year 2106). Quote-create-time validation rejects out-of-range values
/// before reaching here.
pub fn compute_leaf_script(ts_expiry: u64, funder_pubkey: &XOnlyPublicKey) -> ScriptBuf {
    let locktime = LockTime::from_consensus(
        u32::try_from(ts_expiry).expect("ts_expiry fits in u32 (≤ year 2106 sec timestamp)"),
    );
    Builder::new()
        .push_lock_time(locktime)
        .push_opcode(bitcoin::opcodes::all::OP_CLTV)
        .push_opcode(bitcoin::opcodes::all::OP_VERIFY)
        .push_slice(funder_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Returns the tap-leaf hash for the recovery script using
/// `LeafVersion::TapScript` (leaf version `0xc0`).
pub fn compute_leaf_hash(leaf_script: &ScriptBuf) -> TapLeafHash {
    TapLeafHash::from_script(leaf_script, LeafVersion::TapScript)
}

/// Computes the tap-tweak: `t = H_TapTweak(P_internal.x || leaf_hash)`.
///
/// Returned as raw 32 bytes for symmetric pin-testing; convert via
/// [`Scalar::from_be_bytes`] for use with the key-tweaking API.
pub fn compute_tap_tweak(internal_key: &XOnlyPublicKey, leaf_hash: &TapLeafHash) -> [u8; 32] {
    let node_hash = TapNodeHash::from(*leaf_hash);
    TapTweakHash::from_key_and_tweak(*internal_key, Some(node_hash)).to_byte_array()
}

/// Computes `Q = P_internal + t·G` and returns the x-only output key.
///
/// `tweak` must be a valid scalar (modulo the curve order). The returned
/// key is the x-only projection.
///
/// # Panics
///
/// Panics only on a statistically impossible event: `tweak` colliding with
/// the secp256k1 curve order, or the resulting point being the point at
/// infinity. Both are vanishingly improbable for a SHA-256 output.
pub fn compute_output_key(internal_key: &XOnlyPublicKey, tweak: &[u8; 32]) -> XOnlyPublicKey {
    let secp = Secp256k1::verification_only();
    let scalar = Scalar::from_be_bytes(*tweak).expect(
        "tap tweak is a 32-byte hash; collision with curve order is statistically impossible",
    );
    let internal_full = internal_key.public_key(bitcoin::key::Parity::Even);
    let tweaked = internal_full
        .add_exp_tweak(&secp, &scalar)
        .expect("tap-tweak addition collision with infinity is statistically impossible");
    tweaked.x_only_public_key().0
}

/// Encodes the taproot output key as a bech32m P2TR address (`bc1p…`,
/// `tb1p…`, `bcrt1p…`).
pub fn compute_bech32m_address(output_key: &XOnlyPublicKey, network: Network) -> String {
    // The output key is already tweaked. Wrap as a TweakedPublicKey to
    // bypass the "must call tap_tweak" lint; the tweak was computed in
    // compute_output_key.
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(*output_key);
    Address::p2tr_tweaked(tweaked, network).to_string()
}

/// All-in-one convenience: computes `cm`, `P_internal`, leaf script, leaf
/// hash, tap tweak, output key, and returns the bech32m address.
///
/// Used at quote-create time and at funding-verification time to recompute
/// the expected address.
pub fn compute_funding_address(
    mint_pubkey: &[u8; 33],
    ts_expiry: u64,
    nonce: &[u8; 32],
    funder_pubkey: &XOnlyPublicKey,
    network: Network,
) -> String {
    let cm = compute_cm(mint_pubkey, ts_expiry, nonce, funder_pubkey);
    let internal_key = compute_internal_key(&cm);
    let leaf_script = compute_leaf_script(ts_expiry, funder_pubkey);
    let leaf_hash = compute_leaf_hash(&leaf_script);
    let tweak = compute_tap_tweak(&internal_key, &leaf_hash);
    let output_key = compute_output_key(&internal_key, &tweak);
    compute_bech32m_address(&output_key, network)
}

#[cfg(test)]
mod tests {
    //! Cryptographic vector tests.
    //!
    //! Each intermediate stage gets its own pinned-vector test so a
    //! single-step bug surfaces in the right place (rather than only
    //! at the final address comparison). All vectors are generated
    //! from this crate's own functions over a fixed input tuple; once
    //! pinned, regressions in any step will break exactly one test.
    //!
    //! The fixed input tuple uses deterministically chosen byte
    //! patterns so a human can read them off the test:
    //!
    //! - `mint_pubkey` = 33-byte compressed pubkey starting `0x02` with
    //!   x-coordinate `01..21` (sequential bytes).
    //! - `ts_expiry` = `1_782_259_200` (2026-06-01T00:00:00Z).
    //! - `nonce` = bytes `0x42` repeated 32 times.
    //! - `funder_pubkey` = x-only pubkey with x-coordinate bytes
    //!   `0xaa` repeated 32 times (chosen to be a valid x-only).
    use super::*;
    use bitcoin::hashes::Hash;

    /// Fixed mint pubkey for vector tests: compressed, even-parity,
    /// x-coordinate = 0x01..0x21 (sequential).
    const TEST_MINT_PUBKEY: [u8; 33] = [
        0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20,
    ];

    /// Fixed `ts_expiry` for vector tests: 2026-06-01T00:00:00Z.
    const TEST_TS_EXPIRY: u64 = 1_782_259_200;

    /// Fixed nonce: 32 × 0x42.
    const TEST_NONCE: [u8; 32] = [0x42; 32];

    /// Returns the fixed test funder pubkey. We pick an x-coordinate
    /// that is a valid x-only point: derived from a deterministic
    /// scalar `1` (which gives the secp256k1 generator G).
    fn test_funder_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::verification_only();
        // Generator G has x = 0x79be667e..., y even.
        // We construct it by deriving from the trivial scalar 1·G; here
        // we just hard-code its x-only x-coordinate.
        const G_X: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let xo = XOnlyPublicKey::from_slice(&G_X).expect("G_X is a valid x-only pubkey");
        // Round-trip through full pubkey to assert validity.
        let _full = xo.public_key(bitcoin::key::Parity::Even);
        let _ = &secp; // silence unused
        xo
    }

    #[test]
    fn nums_h_matches_nums_constant() {
        // The NUMS_H_X constant must lift_x to a valid point.
        let h = nums_h();
        assert_eq!(h.serialize(), NUMS_H_X);
        // Double-check raw bytes match the pinned hex literal.
        let expected_hex = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let mut actual_hex = String::with_capacity(64);
        for b in NUMS_H_X.iter() {
            actual_hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(actual_hex, expected_hex);
    }

    #[test]
    fn compute_cm_pinned_vector() {
        // Hand-computed reference: SHA256(SHA256(tag) || SHA256(tag) ||
        // mint_pubkey || ts_be || nonce || funder_xonly), tag =
        // "PoPCommit/v1". Re-derived here from primitives so the test
        // catches any future bug in compute_cm without trusting the
        // implementation's own output.
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);

        // Reference re-derivation from raw sha256 primitives.
        let tag_hash = sha256::Hash::hash(b"PoPCommit/v1");
        let mut eng = sha256::Hash::engine();
        eng.input(tag_hash.as_ref());
        eng.input(tag_hash.as_ref());
        eng.input(&TEST_MINT_PUBKEY);
        eng.input(&TEST_TS_EXPIRY.to_be_bytes());
        eng.input(&TEST_NONCE);
        eng.input(&funder.serialize());
        let expected = sha256::Hash::from_engine(eng).to_byte_array();
        assert_eq!(cm, expected);

        // Pin the actual byte value so any drift in any input field
        // (tag bytes, encoding, ordering) breaks this test loudly.
        let mut hex = String::with_capacity(64);
        for b in cm.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "4973a92f7fa6f1f5499a1e28ec79d20555762750d469b9412ae06b241d30c25e",
            "compute_cm vector drifted; check tag bytes, field encoding, or ordering"
        );
    }

    #[test]
    fn compute_cm_pre_image_size_is_105_bytes() {
        // Pre-image is exactly 105 bytes (33 + 8 + 32 + 32). Guard
        // against future drift via a local length check on every
        // component.
        assert_eq!(TEST_MINT_PUBKEY.len(), 33);
        assert_eq!(TEST_TS_EXPIRY.to_be_bytes().len(), 8);
        assert_eq!(TEST_NONCE.len(), 32);
        assert_eq!(test_funder_pubkey().serialize().len(), 32);
        let total = TEST_MINT_PUBKEY.len()
            + TEST_TS_EXPIRY.to_be_bytes().len()
            + TEST_NONCE.len()
            + test_funder_pubkey().serialize().len();
        assert_eq!(total, 105);
    }

    #[test]
    fn compute_internal_key_pinned() {
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);
        // Pin x-only x-coordinate.
        let mut hex = String::with_capacity(64);
        for b in p_internal.serialize().iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "0d13150199eb60fb907b6e00bd4efe0c3caadb9a4d7dfb8295a4f85428016db6",
            "compute_internal_key vector drifted; check NUMS_H + cm·G arithmetic"
        );
    }

    #[test]
    fn compute_internal_key_reconstructs_via_combine() {
        // Cross-check: NUMS_H + cm·G must equal compute_internal_key(cm).
        // Computed two different ways: via add_exp_tweak (inside
        // compute_internal_key) and via explicit PublicKey::combine.
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);

        // Independent reconstruction: cm·G via SecretKey, then combine.
        let secp = Secp256k1::new();
        let cm_secret = bitcoin::secp256k1::SecretKey::from_slice(&cm).expect("valid scalar");
        let cm_g = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &cm_secret);
        let nums_full = nums_h().public_key(bitcoin::key::Parity::Even);
        let combined = nums_full.combine(&cm_g).expect("non-infinity");
        assert_eq!(p_internal, combined.x_only_public_key().0);
    }

    #[test]
    fn compute_leaf_script_pinned() {
        let funder = test_funder_pubkey();
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        // Layout (decimal positions):
        //   [0]      = 0x04                       push 4 bytes
        //   [1..5]   = 0x00 0x1e 0x3b 0x6a        ts_expiry = 1_782_259_200 (LE)
        //   [5]      = 0xb1                       OP_CHECKLOCKTIMEVERIFY
        //   [6]      = 0x69                       OP_VERIFY
        //   [7]      = 0x20                       push 32 bytes
        //   [8..40]  = 79be667e..f81798           funder x-only (32 B)
        //   [40]     = 0xac                       OP_CHECKSIG
        let bytes = script.as_bytes();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex,
            "04001e3b6ab1692079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
            "compute_leaf_script vector drifted; check locktime encoding or opcode order"
        );
        // The script always has the same length: 1 + 4 + 1 + 1 + 1 + 32 + 1 = 41 bytes.
        assert_eq!(bytes.len(), 41);
    }

    #[test]
    fn compute_leaf_hash_pinned() {
        // TapLeafHash = sha256t("TapLeaf", leaf_version
        // || compact_size(script) || script). Verified by re-derivation
        // through the bitcoin crate's primitive.
        let funder = test_funder_pubkey();
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        let leaf_hash = compute_leaf_hash(&script);

        // Pin the leaf hash bytes.
        let bytes = leaf_hash.to_byte_array();
        let mut hex = String::with_capacity(64);
        for b in bytes.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "311239a05687b5786be79fc0c2485f51fdf2c9d9b9c41c728d48b6735e5e3bd4",
            "compute_leaf_hash vector drifted; check LeafVersion::TapScript (0xc0)"
        );

        // Independent re-derivation through TapLeafHash::from_script
        // with explicit LeafVersion — the same primitive, so this test
        // mostly guards against a future API rename.
        let reference = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        assert_eq!(leaf_hash, reference);
    }

    #[test]
    fn compute_tap_tweak_pinned() {
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        let leaf_hash = compute_leaf_hash(&script);
        let tweak = compute_tap_tweak(&p_internal, &leaf_hash);

        // Pin the tweak bytes.
        let mut hex = String::with_capacity(64);
        for b in tweak.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "ee12eae0da460fbc2758325fdfc1427e9f194c3c882d349a11fea80acb03c3b4",
            "compute_tap_tweak vector drifted; check TapTweakHash inputs"
        );

        // Cross-check against TapTweakHash::from_key_and_tweak called
        // independently with Some(TapNodeHash::from(leaf_hash)).
        let reference =
            TapTweakHash::from_key_and_tweak(p_internal, Some(TapNodeHash::from(leaf_hash)))
                .to_byte_array();
        assert_eq!(tweak, reference);
    }

    #[test]
    fn compute_output_key_pinned() {
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        let leaf_hash = compute_leaf_hash(&script);
        let tweak = compute_tap_tweak(&p_internal, &leaf_hash);
        let output_key = compute_output_key(&p_internal, &tweak);

        let mut hex = String::with_capacity(64);
        for b in output_key.serialize().iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "849d526c91c7dfd5603154e77ada522a7903ee8def20bad9b5b89d3b6fd85eee",
            "compute_output_key vector drifted; check P_internal + t·G"
        );
    }

    #[test]
    fn compute_output_key_matches_tap_tweak_trait() {
        // Cross-check against the bitcoin crate's UntweakedPublicKey::tap_tweak
        // trait method, which performs the entire tweak in one call.
        // If our staged decomposition matches the canonical path, both
        // produce the identical output key.
        use bitcoin::key::TapTweak;
        let secp = Secp256k1::new();
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        let leaf_hash = compute_leaf_hash(&script);
        let tweak = compute_tap_tweak(&p_internal, &leaf_hash);
        let ours = compute_output_key(&p_internal, &tweak);

        let merkle_root = TapNodeHash::from(leaf_hash);
        let (canonical_tweaked, _parity) = p_internal.tap_tweak(&secp, Some(merkle_root));
        assert_eq!(ours, canonical_tweaked.to_x_only_public_key());
    }

    #[test]
    fn compute_bech32m_address_pinned_regtest_and_signet() {
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        let leaf_hash = compute_leaf_hash(&script);
        let tweak = compute_tap_tweak(&p_internal, &leaf_hash);
        let output_key = compute_output_key(&p_internal, &tweak);

        let regtest = compute_bech32m_address(&output_key, Network::Regtest);
        assert_eq!(
            regtest, "bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd",
            "regtest bech32m address drifted; check Network::Regtest HRP or output key"
        );

        let signet = compute_bech32m_address(&output_key, Network::Signet);
        // Signet differs only in the bech32 HRP ("tb" vs "bcrt"); both
        // wrap the same 32-byte output key, so the data section is
        // identical until the bech32m checksum (which is HRP-dependent).
        assert_eq!(
            signet, "tb1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq8ugvmh",
            "signet bech32m address drifted; check Network::Signet HRP or output key"
        );
    }

    #[test]
    fn compute_funding_address_end_to_end() {
        let funder = test_funder_pubkey();
        let address = compute_funding_address(
            &TEST_MINT_PUBKEY,
            TEST_TS_EXPIRY,
            &TEST_NONCE,
            &funder,
            Network::Regtest,
        );
        // Must match the pinned regtest address from the staged test.
        assert_eq!(
            address, "bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd",
            "convenience wrapper output diverges from staged composition"
        );
    }
}
