//! `config.toml` — per-wallet, non-secret settings.
//!
//! Records the network (pinned at `init`), the default esplora URL, the
//! derivation-scheme version, and the mint identity-key pinset (TOFU at first
//! `mint`; a changed key for a known mint is a hard error).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::derive::DERIVATION_VERSION;

/// File name of the config inside the wallet dir.
pub const CONFIG_FILE: &str = "config.toml";

/// Default mainnet esplora endpoint.
pub const DEFAULT_ESPLORA_MAINNET: &str = "https://blockstream.info/api";
/// Default signet (Mutinynet) esplora endpoint — matches `pop_test_tool`.
pub const DEFAULT_ESPLORA_SIGNET: &str = "https://mutinynet.com/api";
/// Default testnet esplora endpoint.
pub const DEFAULT_ESPLORA_TESTNET: &str = "https://blockstream.info/testnet/api";
/// Default regtest esplora endpoint (local).
pub const DEFAULT_ESPLORA_REGTEST: &str = "http://127.0.0.1:3002";

/// The default esplora URL for a network.
pub fn default_esplora_url(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => DEFAULT_ESPLORA_MAINNET,
        Network::Signet => DEFAULT_ESPLORA_SIGNET,
        Network::Testnet => DEFAULT_ESPLORA_TESTNET,
        Network::Regtest => DEFAULT_ESPLORA_REGTEST,
        // bitcoin::Network is non-exhaustive; fall back to mainnet's.
        _ => DEFAULT_ESPLORA_MAINNET,
    }
}

/// Persisted wallet configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bitcoin network, pinned at `init` (serialized as its lowercase name).
    #[serde(with = "network_serde")]
    pub network: Network,
    /// Default esplora base URL for chain I/O.
    pub esplora_url: String,
    /// Derivation-scheme version (see `derive::DERIVATION_VERSION`).
    pub derivation_version: u32,
    /// Mint identity-key pinset: `mint_url -> compressed-pubkey-hex` (TOFU).
    #[serde(default)]
    pub mint_pubkeys: BTreeMap<String, String>,
}

impl Config {
    /// A fresh config for a new wallet on `network` with an esplora override.
    pub fn new(network: Network, esplora_url: Option<String>) -> Self {
        Config {
            network,
            esplora_url: esplora_url
                .unwrap_or_else(|| default_esplora_url(network).to_string()),
            derivation_version: DERIVATION_VERSION,
            mint_pubkeys: BTreeMap::new(),
        }
    }

    /// Path of the config inside `wallet_dir`.
    pub fn path_in(wallet_dir: &Path) -> PathBuf {
        wallet_dir.join(CONFIG_FILE)
    }

    /// Writes the config as TOML.
    ///
    /// # Errors
    ///
    /// Propagates serialization and filesystem errors.
    pub fn write(&self, wallet_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let toml = toml::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize config: {e}"))?;
        std::fs::write(Self::path_in(wallet_dir), toml)
            .map_err(|e| format!("failed to write config.toml: {e}"))?;
        Ok(())
    }

    /// Loads the config from `wallet_dir`.
    ///
    /// # Errors
    ///
    /// Propagates filesystem and parse errors.
    pub fn load(wallet_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let path = Self::path_in(wallet_dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read config.toml at {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| format!("failed to parse config.toml: {e}"))?;
        Ok(cfg)
    }

    /// TOFU-pins a mint's identity key, or errors if a different key was
    /// already pinned for that mint (the spec requires the identity key be
    /// stable; a change is a hard error). Returns `true` if newly pinned.
    ///
    /// # Errors
    ///
    /// Errors if `mint_url` already maps to a different pubkey.
    pub fn pin_mint_pubkey(
        &mut self,
        mint_url: &str,
        pubkey_hex: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match self.mint_pubkeys.get(mint_url) {
            Some(existing) if existing == pubkey_hex => Ok(false),
            Some(existing) => Err(format!(
                "mint identity key changed for {mint_url}!\n  pinned:  {existing}\n  \
                 returned: {pubkey_hex}\nThis is a hard error — refusing to trust a \
                 mint that rotated its identity key."
            )
            .into()),
            None => {
                self.mint_pubkeys
                    .insert(mint_url.to_string(), pubkey_hex.to_string());
                Ok(true)
            }
        }
    }
}

/// Serde for `bitcoin::Network` as its lowercase core name.
mod network_serde {
    use bitcoin::Network;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(net: &Network, s: S) -> Result<S::Ok, S::Error> {
        let name = match net {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            other => return Err(serde::ser::Error::custom(format!("unknown network {other:?}"))),
        };
        s.serialize_str(name)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Network, D::Error> {
        let s = String::deserialize(d)?;
        crate::network::parse_network(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_per_network() {
        assert_eq!(default_esplora_url(Network::Bitcoin), DEFAULT_ESPLORA_MAINNET);
        assert_eq!(default_esplora_url(Network::Signet), DEFAULT_ESPLORA_SIGNET);
    }

    #[test]
    fn config_toml_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::new(Network::Signet, None);
        cfg.pin_mint_pubkey("https://mint.example", "02abcd").unwrap();
        cfg.write(dir.path()).unwrap();
        let loaded = Config::load(dir.path()).unwrap();
        assert_eq!(loaded.network, Network::Signet);
        assert_eq!(loaded.esplora_url, DEFAULT_ESPLORA_SIGNET);
        assert_eq!(loaded.derivation_version, DERIVATION_VERSION);
        assert_eq!(
            loaded.mint_pubkeys.get("https://mint.example").map(String::as_str),
            Some("02abcd")
        );
    }

    #[test]
    fn re_pinning_same_key_is_noop() {
        let mut cfg = Config::new(Network::Bitcoin, None);
        assert!(cfg.pin_mint_pubkey("m", "02aa").unwrap());
        assert!(!cfg.pin_mint_pubkey("m", "02aa").unwrap());
    }

    #[test]
    fn re_pinning_different_key_errors() {
        let mut cfg = Config::new(Network::Bitcoin, None);
        cfg.pin_mint_pubkey("m", "02aa").unwrap();
        assert!(cfg.pin_mint_pubkey("m", "02bb").is_err());
    }
}
