//! The per-deposit recovery file — the funder's portable "you can always get
//! your BTC back" artifact (`recovery/<deposit_id>.recovery.json`).
//!
//! NON-SECRET (every field is public or seed-derivable; no private key). It
//! preserves the one mint-random datum (`nonce`) plus the construction params,
//! so the BTC is reclaimable with this wallet OR with Bitcoin Core (the explicit
//! descriptor + seed-derived funder key) even if the mint disappears. It is a
//! PROJECTION of the deposit DB row, kept standalone so it survives the database.

use std::path::{Path, PathBuf};

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Network;
use pops_core_funder::{descriptor, reconstruct, ConstructionParams};
use serde::{Deserialize, Serialize};

/// Recovery-file schema version string.
pub const RECOVERY_VERSION: &str = "pop-recovery/v1";

/// A fully self-describing recovery record. Serialized to
/// `recovery/<deposit_id>.recovery.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFile {
    /// Schema version (`pop-recovery/v1`).
    pub version: String,
    /// Wallet-local deposit id (uuid).
    pub deposit_id: String,
    /// Optional human label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Mint base URL.
    pub mint_url: String,
    /// The mint identity key (33-byte compressed, hex) the address was
    /// verified against and committed into `cm`.
    pub mint_pubkey: String,
    /// Credential unit, `pop_<ts_expiry>`.
    pub unit: String,
    /// CLTV expiry (unix seconds) == the unit ts == the `cm` ts field.
    pub ts_expiry: u64,
    /// Funded amount, sats (exact).
    pub amount_sats: u64,
    /// The 32-byte mint-sampled nonce (hex) — the ONLY non-derivable datum.
    pub nonce: String,
    /// Funder x-only pubkey (hex) — seed-derived at `funder_derivation_path`.
    pub funder_pubkey: String,
    /// Frozen BIP-32 path the funder key derives at:
    /// `m/5271376'/coin_type'/0'/0/<index>`.
    pub funder_derivation_path: String,
    /// Network the funding address / descriptor is for.
    pub network: String,
    /// Taproot internal key `P_internal` (x-only, hex) — reproducible from
    /// `cm`; stored for convenience and cross-check.
    pub p_internal: String,
    /// Recovery leaf script bytes (hex).
    pub leaf_script: String,
    /// Canonical, portable descriptor for Bitcoin Core recovery.
    pub descriptor: String,
    /// bech32m funding address.
    pub funding_address: String,
    /// `txid:vout` — filled in after funding confirms (empty until then).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_outpoint: Option<String>,
    /// Human-readable recover-after instant (UTC ISO-8601), derived from
    /// `ts_expiry`.
    pub recover_after_utc: String,
    /// Plain-language recovery instructions.
    pub how_to_recover: String,
}

/// Formats a unix-seconds instant as a UTC ISO-8601 string for display.
pub fn utc_iso8601(ts: u64) -> String {
    use chrono::TimeZone;
    match chrono::Utc.timestamp_opt(ts as i64, 0).single() {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => format!("unix:{ts}"),
    }
}

impl RecoveryFile {
    /// Assembles a recovery file from the deposit's construction params.
    /// `funding_outpoint` is `None` until funding confirms.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        deposit_id: &str,
        label: Option<&str>,
        mint_url: &str,
        amount_sats: u64,
        unit: &str,
        params: &ConstructionParams,
        funder_derivation_path: &str,
        funding_outpoint: Option<&str>,
    ) -> Self {
        let c = reconstruct(params);
        let descriptor = descriptor(&c.internal_key, params.ts_expiry, &params.funder_pubkey);
        RecoveryFile {
            version: RECOVERY_VERSION.to_string(),
            deposit_id: deposit_id.to_string(),
            label: label.map(str::to_string),
            mint_url: mint_url.to_string(),
            mint_pubkey: hex::encode(params.mint_pubkey),
            unit: unit.to_string(),
            ts_expiry: params.ts_expiry,
            amount_sats,
            nonce: hex::encode(params.nonce),
            funder_pubkey: hex::encode(params.funder_pubkey.serialize()),
            funder_derivation_path: funder_derivation_path.to_string(),
            network: params.network.to_string(),
            p_internal: hex::encode(c.internal_key.serialize()),
            leaf_script: hex::encode(c.leaf_script.as_bytes()),
            descriptor,
            funding_address: c.address,
            funding_outpoint: funding_outpoint.map(str::to_string),
            recover_after_utc: utc_iso8601(params.ts_expiry),
            how_to_recover: format!(
                "After {} (UTC): `pop recover --deposit {} --dest <your-address>`. \
                 OR import `descriptor` (private form) into Bitcoin Core >= 26, then \
                 walletcreatefundedpsbt with nLockTime={} and a non-final sequence, \
                 walletprocesspsbt, finalizepsbt, sendrawtransaction.",
                utc_iso8601(params.ts_expiry),
                deposit_id,
                params.ts_expiry
            ),
        }
    }

    /// Parses the stored hex fields back into typed `ConstructionParams` — the
    /// break-glass reload path (reconstruct a deposit's funding output from the
    /// file alone).
    ///
    /// # Errors
    ///
    /// A malformed/wrong-length hex field or an unknown network string.
    #[allow(dead_code)]
    pub fn construction_params(&self) -> Result<ConstructionParams, Box<dyn std::error::Error>> {
        let mint_pubkey_bytes = hex::decode(&self.mint_pubkey)
            .map_err(|e| format!("recovery mint_pubkey hex decode failed: {e}"))?;
        let mint_pubkey: [u8; 33] = mint_pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "recovery mint_pubkey must be 33 bytes")?;

        let nonce_bytes =
            hex::decode(&self.nonce).map_err(|e| format!("recovery nonce hex decode failed: {e}"))?;
        let nonce: [u8; 32] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "recovery nonce must be 32 bytes")?;

        let funder_bytes = hex::decode(&self.funder_pubkey)
            .map_err(|e| format!("recovery funder_pubkey hex decode failed: {e}"))?;
        let funder_pubkey = XOnlyPublicKey::from_slice(&funder_bytes)
            .map_err(|e| format!("recovery funder_pubkey is not a valid x-only key: {e}"))?;

        let network: Network = self
            .network
            .parse()
            .map_err(|e| format!("recovery network `{}` is invalid: {e}", self.network))?;

        Ok(ConstructionParams {
            mint_pubkey,
            ts_expiry: self.ts_expiry,
            nonce,
            funder_pubkey,
            network,
        })
    }

    /// Path of a deposit's recovery file inside `recovery/`.
    pub fn path_in(recovery_dir: &Path, deposit_id: &str) -> PathBuf {
        recovery_dir.join(format!("{deposit_id}.recovery.json"))
    }

    /// Writes (or overwrites) the recovery file as pretty JSON.
    ///
    /// # Errors
    ///
    /// Propagates filesystem and serialization errors.
    pub fn write(&self, recovery_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(recovery_dir)
            .map_err(|e| format!("failed to create recovery dir: {e}"))?;
        let path = Self::path_in(recovery_dir, &self.deposit_id);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize recovery file: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("failed to write recovery file: {e}"))?;
        Ok(path)
    }

    /// Loads a recovery file from disk.
    ///
    /// # Errors
    ///
    /// Propagates filesystem and parse errors.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read recovery file {}: {e}", path.display()))?;
        let file: RecoveryFile = serde_json::from_str(&json)
            .map_err(|e| format!("failed to parse recovery file {}: {e}", path.display()))?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same fixed inputs the script tests pin, to cross-check the address.
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

    /// THE core round-trip: build → JSON → reload → re-derive, asserting the
    /// rebuilt address + internal key + leaf script match the original. The
    /// wallet's central guarantee: the file alone reconstructs the funding output.
    #[test]
    fn recovery_file_roundtrip_reconstructs_address() {
        let params = test_params(Network::Signet);
        let original = reconstruct(&params);

        let rf = RecoveryFile::build(
            "11111111-1111-1111-1111-111111111111",
            Some("test deposit"),
            "https://mint.example",
            10_000,
            "pop_1782259200",
            &params,
            "m/5271376'/1'/0'/0/0",
            None,
        );

        let json = serde_json::to_string_pretty(&rf).unwrap();
        let reloaded: RecoveryFile = serde_json::from_str(&json).unwrap();
        assert_eq!(reloaded.funding_address, original.address);

        // Rebuild purely from the reloaded file's params.
        let reparsed_params = reloaded.construction_params().unwrap();
        let rebuilt = reconstruct(&reparsed_params);

        assert_eq!(
            rebuilt.address, original.address,
            "address rebuilt from recovery file must match the original"
        );
        assert_eq!(
            rebuilt.internal_key, original.internal_key,
            "P_internal rebuilt from recovery file must match the original"
        );
        assert_eq!(
            rebuilt.leaf_script, original.leaf_script,
            "leaf script rebuilt from recovery file must match the original"
        );
        // The stored hex projections agree with the rebuild.
        assert_eq!(reloaded.p_internal, hex::encode(rebuilt.internal_key.serialize()));
        assert_eq!(reloaded.leaf_script, hex::encode(rebuilt.leaf_script.as_bytes()));
    }

    /// Writing then loading from a temp dir is lossless.
    #[test]
    fn write_then_load_is_lossless() {
        let dir = tempfile::tempdir().unwrap();
        let params = test_params(Network::Regtest);
        let rf = RecoveryFile::build(
            "22222222-2222-2222-2222-222222222222",
            None,
            "https://mint.example",
            5000,
            "pop_1782259200",
            &params,
            "m/5271376'/1'/0'/0/2",
            Some("abcd1234:0"),
        );
        let path = rf.write(dir.path()).unwrap();
        let loaded = RecoveryFile::load(&path).unwrap();
        assert_eq!(loaded.deposit_id, rf.deposit_id);
        assert_eq!(loaded.funding_outpoint.as_deref(), Some("abcd1234:0"));
        assert_eq!(loaded.funding_address, rf.funding_address);
    }
}
