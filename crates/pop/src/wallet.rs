//! Wallet directory layout and seed loading.

use std::path::{Path, PathBuf};

use bitcoin::Network;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::db::Db;
use crate::derive::{derive_funder_key, FunderKey};
use crate::error::PopError;
use crate::seed;

/// Sub-directory under the wallet dir holding per-deposit recovery files.
pub const RECOVERY_SUBDIR: &str = "recovery";

/// Resolves the effective wallet directory: an explicit `--wallet-dir`, else
/// `~/.pop-wallet/`.
///
/// # Errors
///
/// Errors if neither an override nor a home directory is available.
pub fn resolve_wallet_dir(
    override_dir: Option<&Path>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(dir) = override_dir {
        return Ok(dir.to_path_buf());
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        PopError::invalid_input("HOME is not set; pass --wallet-dir explicitly")
    })?;
    Ok(home.join(".pop-wallet"))
}

/// The recovery sub-directory inside a wallet dir.
pub fn recovery_dir(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(RECOVERY_SUBDIR)
}

/// True if a wallet appears initialized at `wallet_dir` (a seed exists).
pub fn is_initialized(wallet_dir: &Path) -> bool {
    seed::seed_path(wallet_dir).exists()
}

/// An opened, configured wallet (config + db). The seed is loaded on demand.
pub struct Wallet {
    /// The wallet directory.
    pub dir: PathBuf,
    /// Loaded config.
    pub config: Config,
    /// Open state db.
    pub db: Db,
}

impl Wallet {
    /// Opens an initialized wallet (loads config + db). Does NOT load the
    /// seed — read-only commands (`list`/`status`) never need it.
    ///
    /// # Errors
    ///
    /// Errors if the wallet is not initialized, or config/db fail to load.
    pub fn open(wallet_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !is_initialized(wallet_dir) {
            return Err(PopError::wallet_not_initialized(format!(
                "no wallet at {} — run `pop init` first",
                wallet_dir.display()
            ))
            .into());
        }
        let config = Config::load(wallet_dir)?;
        let db = Db::open(wallet_dir)?;
        Ok(Wallet {
            dir: wallet_dir.to_path_buf(),
            config,
            db,
        })
    }

    /// The network this wallet is pinned to.
    pub fn network(&self) -> Network {
        self.config.network
    }

    /// Loads the plaintext seed from disk, returning the raw (zeroizing) bytes.
    ///
    /// # Errors
    ///
    /// Errors on a missing or malformed seed file.
    pub fn load_seed(&self) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
        seed::load_seed(&self.dir)
    }

    /// Derives the funder key at `index` for this wallet's network using the
    /// loaded seed.
    ///
    /// # Errors
    ///
    /// Propagates derivation errors.
    pub fn funder_key(
        &self,
        seed: &[u8],
        index: u32,
    ) -> Result<FunderKey, Box<dyn std::error::Error>> {
        derive_funder_key(seed, self.config.network, index)
    }
}
