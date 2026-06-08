//! Taproot construction reconstruction for a PoP deposit.
//!
//! Rebuilds the entire taproot construction (commitment scalar, internal key,
//! recovery leaf script, output key, bech32m address) from public,
//! seed-derivable params using the SAME [`crate::script`] functions the mint
//! uses. This is the single source of address truth shared by the wallet and
//! the mint — they cannot drift.

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Network, ScriptBuf};
use crate::script::{
    compute_bech32m_address, compute_cm, compute_internal_key, compute_leaf_hash,
    compute_leaf_script, compute_output_key, compute_tap_tweak,
};

/// The public, seed-derivable parameters that fully determine a funding
/// address. Feed to [`reconstruct`] to rebuild the taproot construction.
#[derive(Debug, Clone)]
pub struct ConstructionParams {
    /// Mint identity key, 33-byte compressed.
    pub mint_pubkey: [u8; 33],
    /// CLTV expiry / unit ts.
    pub ts_expiry: u64,
    /// 32-byte mint-sampled nonce.
    pub nonce: [u8; 32],
    /// Funder x-only pubkey.
    pub funder_pubkey: XOnlyPublicKey,
    /// Network.
    pub network: Network,
}

/// The full reconstructed taproot construction for a deposit.
#[derive(Debug, Clone)]
pub struct Construction {
    /// `cm = TaggedHash("PoPCommit/v1", ...)` (the commitment scalar; exposed
    /// for inspection / break-glass).
    pub cm: [u8; 32],
    /// `P_internal = NUMS_H + cm·G` (x-only).
    pub internal_key: XOnlyPublicKey,
    /// The recovery leaf script.
    pub leaf_script: ScriptBuf,
    /// `Q = P_internal + t·G` (x-only output key; the address derives from it).
    pub output_key: XOnlyPublicKey,
    /// bech32m funding address for `network`.
    pub address: String,
}

/// Rebuilds the entire taproot construction from public params using the same
/// [`crate::script`] functions the mint uses.
#[must_use]
pub fn reconstruct(params: &ConstructionParams) -> Construction {
    let cm = compute_cm(
        &params.mint_pubkey,
        params.ts_expiry,
        &params.nonce,
        &params.funder_pubkey,
    );
    let internal_key = compute_internal_key(&cm);
    let leaf_script = compute_leaf_script(params.ts_expiry, &params.funder_pubkey);
    let leaf_hash = compute_leaf_hash(&leaf_script);
    let tweak = compute_tap_tweak(&internal_key, &leaf_hash);
    let output_key = compute_output_key(&internal_key, &tweak);
    let address = compute_bech32m_address(&output_key, params.network);
    Construction {
        cm,
        internal_key,
        leaf_script,
        output_key,
        address,
    }
}

/// Builds the canonical Bitcoin Core descriptor:
/// `tr(<P_internal>, and_v(v:after(<ts_expiry>), pk(<funder_xonly>)))`.
///
/// Bitcoin Core ≥ 26 accepts the raw x-only internal key as data; the leaf is
/// the miniscript-canonical CLTV-then-checksig. The wallet emits the
/// public-key form here; recovery via Core uses the matching private form
/// (the funder key derived from the seed).
#[must_use]
pub fn descriptor(internal_key: &XOnlyPublicKey, ts_expiry: u64, funder: &XOnlyPublicKey) -> String {
    format!(
        "tr({},and_v(v:after({}),pk({})))",
        hex::encode(internal_key.serialize()),
        ts_expiry,
        hex::encode(funder.serialize())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    /// Fixed inputs the script-stage tests also pin against, so we can
    /// cross-check the address our reconstruction produces.
    const TEST_MINT_PUBKEY: [u8; 33] = [
        0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20,
    ];
    const TEST_TS_EXPIRY: u64 = 1_782_259_200;
    const TEST_NONCE: [u8; 32] = [0x42; 32];

    fn test_funder() -> XOnlyPublicKey {
        // secp256k1 generator G's x-coordinate — a known valid x-only point.
        const G_X: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        XOnlyPublicKey::from_slice(&G_X).unwrap()
    }

    fn test_params(network: Network) -> ConstructionParams {
        ConstructionParams {
            mint_pubkey: TEST_MINT_PUBKEY,
            ts_expiry: TEST_TS_EXPIRY,
            nonce: TEST_NONCE,
            funder_pubkey: test_funder(),
            network,
        }
    }

    /// Our reconstruction must reproduce the pinned regtest address — proving
    /// the wallet uses the exact same construction as the mint, and
    /// cross-validating that `script.rs` builds the OP_VERIFY leaf form (any
    /// drift to a non-OP_VERIFY script changes this address).
    #[test]
    fn reconstruct_matches_cdk_pop_pinned_address() {
        let c = reconstruct(&test_params(Network::Regtest));
        assert_eq!(
            c.address,
            "bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd"
        );
        // And the internal key matches the pinned P_internal.
        assert_eq!(
            hex::encode(c.internal_key.serialize()),
            "0d13150199eb60fb907b6e00bd4efe0c3caadb9a4d7dfb8295a4f85428016db6"
        );
    }

    /// The descriptor string is well-formed and embeds the right pieces.
    #[test]
    fn descriptor_is_well_formed() {
        let c = reconstruct(&test_params(Network::Bitcoin));
        let d = descriptor(&c.internal_key, TEST_TS_EXPIRY, &test_funder());
        assert!(d.starts_with("tr("));
        assert!(d.contains(&hex::encode(c.internal_key.serialize())));
        assert!(d.contains(&format!("after({TEST_TS_EXPIRY})")));
        assert!(d.contains(&hex::encode(test_funder().serialize())));
    }

    /// Sanity: the funder x-only round-trips through serialize/parse.
    #[test]
    fn funder_xonly_roundtrips() {
        let secp = Secp256k1::new();
        let _ = &secp;
        let f = test_funder();
        let hex_str = hex::encode(f.serialize());
        let back = XOnlyPublicKey::from_slice(&hex::decode(hex_str).unwrap()).unwrap();
        assert_eq!(f, back);
    }
}
