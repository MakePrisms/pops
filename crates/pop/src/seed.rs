//! `seed` — the BIP-39 seed, stored as plaintext, the wallet's ONLY secret.
//!
//! The 64-byte BIP-39 seed is written verbatim (hex) to a `seed` file inside
//! the wallet dir, created with `0600` perms so only the owner can read it.
//! There is deliberately NO at-rest encryption: the BIP-39 mnemonic shown once
//! at `init` is the real backup. An encrypted seed behind a separate passphrase
//! is redundant friction and a footgun — lose that passphrase and the encrypted
//! seed is bricked with no import path. Protect the wallet directory (perms +
//! disk) and keep the mnemonic offline instead.
//!
//! The seed is the master from which every funder key derives (see `derive`).
//! Losing it loses every deposit's recovery key — the recovery files alone are
//! not enough.

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// File name of the plaintext seed inside the wallet dir.
pub const SEED_FILE: &str = "seed";

/// Length of the BIP-39 seed, bytes.
const SEED_LEN: usize = 64;

/// Owner-only file permissions for the seed file.
const SEED_PERMS: u32 = 0o600;

/// Path of the seed file inside `wallet_dir`.
pub fn seed_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(SEED_FILE)
}

/// Writes the 64-byte seed as hex to `wallet_dir/seed` with `0600` perms.
///
/// The file is (re)created with owner-only permissions atomically via
/// `OpenOptions::mode`, so the secret is never briefly world-readable.
///
/// # Errors
///
/// Errors if `seed` is not 64 bytes, or on any filesystem error.
pub fn write_seed(wallet_dir: &Path, seed: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if seed.len() != SEED_LEN {
        return Err(format!("seed must be {SEED_LEN} bytes (got {})", seed.len()).into());
    }
    let path = seed_path(wallet_dir);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(SEED_PERMS)
        .open(&path)
        .map_err(|e| format!("failed to open seed file at {}: {e}", path.display()))?;
    // Defense-in-depth: if the file pre-existed with looser perms, `mode` on an
    // existing file is ignored, so tighten explicitly.
    let perms = std::fs::Permissions::from_mode(SEED_PERMS);
    std::fs::set_permissions(&path, perms)
        .map_err(|e| format!("failed to set seed file perms: {e}"))?;
    let encoded = Zeroizing::new(hex::encode(seed));
    file.write_all(encoded.as_bytes())
        .map_err(|e| format!("failed to write seed file: {e}"))?;
    Ok(())
}

/// Loads the 64-byte seed from `wallet_dir/seed`, decoding the stored hex.
///
/// The caller owns zeroizing the returned bytes once finished.
///
/// # Errors
///
/// Errors if the file is missing, unreadable, not valid hex, or not 64 bytes.
pub fn load_seed(wallet_dir: &Path) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let path = seed_path(wallet_dir);
    let mut contents = Zeroizing::new(String::new());
    std::fs::File::open(&path)
        .map_err(|e| format!("failed to read seed file at {}: {e}", path.display()))?
        .read_to_string(&mut contents)
        .map_err(|e| format!("failed to read seed file at {}: {e}", path.display()))?;
    let seed = hex::decode(contents.trim())
        .map_err(|e| format!("seed file is not valid hex: {e}"))?;
    if seed.len() != SEED_LEN {
        return Err(format!(
            "seed file must decode to {SEED_LEN} bytes (got {})",
            seed.len()
        )
        .into());
    }
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    // `super::*` does not re-export the parent's private `use`, so import the
    // trait the perm-bit assertions need directly.
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [0x44u8; SEED_LEN];
        write_seed(dir.path(), &seed).unwrap();
        let loaded = load_seed(dir.path()).unwrap();
        assert_eq!(loaded.as_slice(), seed.as_slice());
    }

    #[test]
    fn seed_file_is_owner_only_0600() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [0xABu8; SEED_LEN];
        write_seed(dir.path(), &seed).unwrap();
        let meta = std::fs::metadata(seed_path(dir.path())).unwrap();
        // Mask to the permission bits; expect exactly rw-------.
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn write_overwrites_and_retightens_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = seed_path(dir.path());
        // Pre-create a loose-perms file at the seed path.
        std::fs::write(&path, "deadbeef").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let seed = [0x11u8; SEED_LEN];
        write_seed(dir.path(), &seed).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(load_seed(dir.path()).unwrap().as_slice(), seed.as_slice());
    }

    #[test]
    fn rejects_wrong_length_seed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write_seed(dir.path(), &[0u8; 32]).is_err());
    }

    #[test]
    fn load_rejects_bad_hex() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(seed_path(dir.path()), "nothex!!").unwrap();
        assert!(load_seed(dir.path()).is_err());
    }
}
