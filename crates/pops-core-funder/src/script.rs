//! Taproot output-key construction for PoPs commitment addresses (pure
//! functions). Computes `Q`, its ancillary values, and the bech32m address from
//! public quote inputs (`mint_pubkey`, `ts_expiry`, `nonce`, `funder_pubkey`),
//! used at quote-create time and at funding-verification time (to reconstruct
//! the expected address for chain-side matching).
//!
//! The construction is taproot with a NUMS-commit internal key and a single-leaf
//! script tree holding the CLTV recovery script. The stage functions expose each
//! intermediate value so callers/tests can pin one stage in isolation;
//! [`compute_funding_address`] wires them together.

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

/// The NUMS H point as an [`XOnlyPublicKey`] (`lift_x` of [`NUMS_H_X`]; never
/// panics — fixed valid key).
pub fn nums_h() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_H_X).expect("NUMS_H_X is a valid x-only pubkey")
}

/// Computes `cm = TaggedHash("PoPCommit/v1", mint_pubkey || ts_expiry_be ||
/// nonce || funder_pubkey)`. Pre-image layout (105 bytes):
///
/// | Field           | Type                        | Size |
/// |-----------------|-----------------------------|------|
/// | `mint_pubkey`   | compressed secp256k1 pubkey | 33 B |
/// | `ts_expiry`     | u64 big-endian              | 8 B  |
/// | `nonce`         | random bytes                | 32 B |
/// | `funder_pubkey` | x-only secp256k1 pubkey     | 32 B |
///
/// The mint pubkey is hashed COMPRESSED (33-byte, parity-preserving) — no x-only
/// stripping.
pub fn compute_cm(
    mint_pubkey: &[u8; 33],
    ts_expiry: u64,
    nonce: &[u8; 32],
    funder_pubkey: &XOnlyPublicKey,
) -> [u8; 32] {
    // Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
    let tag_hash = sha256::Hash::hash(POP_COMMIT_TAG);
    let mut hash_engine = sha256::Hash::engine();
    hash_engine.input(tag_hash.as_ref());
    hash_engine.input(tag_hash.as_ref());
    hash_engine.input(mint_pubkey);
    hash_engine.input(&ts_expiry.to_be_bytes());
    hash_engine.input(nonce);
    hash_engine.input(&funder_pubkey.serialize());
    sha256::Hash::from_engine(hash_engine).to_byte_array()
}

/// Computes `P_internal = NUMS_H + cm·G` (`cm` as a scalar mod the curve order,
/// via `add_exp_tweak`), returned x-only (even-y).
///
/// # Panics
///
/// Only on a statistically impossible event (~2^-256): `cm` equal to the curve
/// order, or the sum being the point at infinity.
pub fn compute_internal_key(cm: &[u8; 32]) -> XOnlyPublicKey {
    let secp = Secp256k1::verification_only();
    // Lift NUMS_H on the even-y branch.
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
/// `ts_expiry` is emitted as a `LockTime` so `push_lock_time` produces the
/// minimal `CScriptNum` encoding; `funder_pubkey` is 32 raw x-only bytes for
/// tapscript `OP_CHECKSIG`.
///
/// # Panics
///
/// If `ts_expiry` does not fit in u32 (≈ year 2106). Quote-create validation
/// rejects out-of-range values before here.
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

/// Computes the tap-tweak `t = H_TapTweak(P_internal.x || leaf_hash)`, raw 32
/// bytes (convert via [`Scalar::from_be_bytes`] for the key-tweaking API).
pub fn compute_tap_tweak(internal_key: &XOnlyPublicKey, leaf_hash: &TapLeafHash) -> [u8; 32] {
    let node_hash = TapNodeHash::from(*leaf_hash);
    TapTweakHash::from_key_and_tweak(*internal_key, Some(node_hash)).to_byte_array()
}

/// Computes `Q = P_internal + t·G`, returned x-only.
///
/// # Panics
///
/// Only on a statistically impossible event (~2^-256): `tweak` equal to the
/// curve order, or the sum being the point at infinity.
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

/// Encodes the taproot output key as a bech32m P2TR address.
pub fn compute_bech32m_address(output_key: &XOnlyPublicKey, network: Network) -> String {
    // `Q` is already tweaked (in compute_output_key), so the
    // `dangerous_assume_tweaked` wrap is sound and bypasses the "must call
    // tap_tweak" lint.
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(*output_key);
    Address::p2tr_tweaked(tweaked, network).to_string()
}

/// All-in-one: `cm` → `P_internal` → leaf script → leaf hash → tap tweak →
/// output key → bech32m address.
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
    //! Cryptographic vector tests. Each intermediate stage gets its own
    //! pinned-vector test so a single-step bug surfaces in the right place, not
    //! only at the final address compare.
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

    /// The fixed test funder pubkey: the secp256k1 generator G (x = 0x79be667e…,
    /// even y), a known-valid x-only point.
    fn test_funder_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::verification_only();
        const G_X: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let xo = XOnlyPublicKey::from_slice(&G_X).expect("G_X is a valid x-only pubkey");
        let _full = xo.public_key(bitcoin::key::Parity::Even); // assert validity
        let _ = &secp;
        xo
    }

    #[test]
    fn nums_h_matches_nums_constant() {
        let h = nums_h();
        assert_eq!(h.serialize(), NUMS_H_X);
        let expected_hex = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let mut actual_hex = String::with_capacity(64);
        for b in NUMS_H_X.iter() {
            actual_hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(actual_hex, expected_hex);
    }

    #[test]
    fn compute_cm_pinned_vector() {
        // Re-derived from raw sha256 primitives so the test catches a compute_cm
        // bug without trusting the implementation's own output.
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);

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

        // Pin the byte value so any input-field drift breaks this loudly.
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
        // 33 + 8 + 32 + 32 = 105.
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
        // Cross-check via explicit PublicKey::combine (vs add_exp_tweak inside
        // compute_internal_key).
        let funder = test_funder_pubkey();
        let cm = compute_cm(&TEST_MINT_PUBKEY, TEST_TS_EXPIRY, &TEST_NONCE, &funder);
        let p_internal = compute_internal_key(&cm);

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
        // Fixed length: 1 + 4 + 1 + 1 + 1 + 32 + 1 = 41 bytes.
        assert_eq!(bytes.len(), 41);
    }

    #[test]
    fn compute_leaf_hash_pinned() {
        // TapLeafHash = sha256t("TapLeaf", leaf_version || compact_size(script)
        // || script).
        let funder = test_funder_pubkey();
        let script = compute_leaf_script(TEST_TS_EXPIRY, &funder);
        let leaf_hash = compute_leaf_hash(&script);

        let bytes = leaf_hash.to_byte_array();
        let mut hex = String::with_capacity(64);
        for b in bytes.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "311239a05687b5786be79fc0c2485f51fdf2c9d9b9c41c728d48b6735e5e3bd4",
            "compute_leaf_hash vector drifted; check LeafVersion::TapScript (0xc0)"
        );

        // Re-derive via the explicit-LeafVersion primitive (guards an API rename).
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

        let mut hex = String::with_capacity(64);
        for b in tweak.iter() {
            hex.push_str(&format!("{:02x}", b));
        }
        assert_eq!(
            hex, "ee12eae0da460fbc2758325fdfc1427e9f194c3c882d349a11fea80acb03c3b4",
            "compute_tap_tweak vector drifted; check TapTweakHash inputs"
        );

        // Cross-check against TapTweakHash::from_key_and_tweak directly.
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
        // Cross-check our staged decomposition against the canonical one-call
        // UntweakedPublicKey::tap_tweak.
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
        // Signet differs only in the bech32 HRP ("tb" vs "bcrt"); same 32-byte
        // output key, so only the HRP-dependent checksum changes.
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
        assert_eq!(
            address, "bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd",
            "convenience wrapper output diverges from staged composition"
        );
    }
}
