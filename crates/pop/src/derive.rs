//! Funder-key derivation from the wallet seed.
//!
//! Funder keys are BIP-32 children of the BIP-39 seed at a **frozen** PoP
//! derivation path. One non-hardened child index is consumed per deposit
//! (the index is a monotonic counter in `wallet.db`); a fresh index per
//! deposit keeps on-chain recovery spends from correlating funder keys.
//!
//! ## The path (FROZEN — do not change)
//!
//! ```text
//! m / 5271376' / coin_type' / 0' / 0 / index
//! ```
//!
//! - **purpose = `5271376'`** = `0x506F50` = the ASCII bytes `"PoP"`
//!   (`P`=0x50, `o`=0x6F, `P`=0x50). Hardened, fixed forever — it reproduces
//!   the funder key everywhere (this wallet, and Bitcoin Core recovery).
//! - **coin_type'** — SLIP-44 per network: `0'` mainnet, `1'` for
//!   test / signet / regtest. Hardened.
//! - **account = `0'`**, **change = `0`** — fixed.
//! - **index** — the per-deposit non-hardened child, monotonic, never reused.
//!
//! The single derived child secret serves **both** funder roles: its
//! **compressed** public form is the NUT-20 quote-lock pubkey (issuance auth),
//! its **x-only** form is the `funder_pubkey` baked into `cm` and the CLTV
//! recovery leaf (on-chain reclaim). This matches `pop_test_tool`, which
//! derives both encodings from one secret.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::Network;

/// The frozen PoP BIP-32 purpose: `0x506F50` = ASCII `"PoP"`, hardened.
pub const POP_PURPOSE: u32 = 0x0050_6F50;

/// Current derivation-scheme version recorded in `config.toml`. Bumped only
/// if the path layout ever changes (it must not, for v1).
pub const DERIVATION_VERSION: u32 = 1;

/// SLIP-44 coin type for a network's PoP derivation path.
///
/// Mainnet uses `0'`; every test network (testnet / signet / regtest) uses
/// `1'`, per SLIP-44's "Testnet (all coins)" convention.
pub fn coin_type_for_network(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

/// Builds the full funder derivation path for `(network, index)`:
/// `m/5271376'/coin_type'/0'/0/index`.
///
/// # Panics
///
/// Never for in-range inputs. `POP_PURPOSE`, the coin type, and `0` are all
/// valid child numbers by construction; `index` is a `u32` and any value
/// `< 2^31` is a valid non-hardened child (callers always pass small
/// monotonic counters).
pub fn funder_path(network: Network, index: u32) -> DerivationPath {
    let coin = coin_type_for_network(network);
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(POP_PURPOSE).expect("purpose < 2^31"),
        ChildNumber::from_hardened_idx(coin).expect("coin type < 2^31"),
        ChildNumber::from_hardened_idx(0).expect("account 0 < 2^31"),
        ChildNumber::Normal { index: 0 },
        ChildNumber::from_normal_idx(index)
            .expect("derivation index must be < 2^31 (non-hardened child)"),
    ])
}

/// Renders the funder path as the canonical string
/// `m/5271376'/<coin>'/0'/0/<index>` for the recovery file's
/// `funder_derivation_path` field. The purpose is taken from `POP_PURPOSE` so
/// the string can never drift from the actual derived path.
pub fn funder_path_string(network: Network, index: u32) -> String {
    format!(
        "m/{}'/{}'/0'/0/{}",
        POP_PURPOSE,
        coin_type_for_network(network),
        index
    )
}

/// A derived funder key in the two encodings the PoP flow needs.
#[derive(Clone)]
pub struct FunderKey {
    /// The secret scalar (NUT-20 signing key; CLTV recovery key).
    pub secret_key: SecretKey,
    /// x-only public key — the `funder_pubkey` baked into `cm` + the leaf.
    pub xonly: XOnlyPublicKey,
}

impl std::fmt::Debug for FunderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("FunderKey")
            .field("xonly", &self.xonly)
            .finish_non_exhaustive()
    }
}

/// Derives the funder key for `(network, index)` from the 64-byte BIP-39 seed.
///
/// The same secret is the NUT-20 quote-lock key (compressed pubkey) and the
/// on-chain recovery key (x-only pubkey).
///
/// # Errors
///
/// Returns an error if the master key cannot be built from the seed or the
/// path cannot be derived (both indicate a malformed seed and are effectively
/// impossible for a valid BIP-39 seed).
pub fn derive_funder_key(
    seed: &[u8],
    network: Network,
    index: u32,
) -> Result<FunderKey, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, seed)
        .map_err(|e| format!("failed to build BIP-32 master key from seed: {e}"))?;
    let path = funder_path(network, index);
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| format!("failed to derive funder key at {path}: {e}"))?;
    let secret_key = child.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _parity) = keypair.x_only_public_key();
    Ok(FunderKey { secret_key, xonly })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    /// A fixed 64-byte seed (BIP-39 "abandon ... about" 12-word mnemonic seed
    /// with empty passphrase). Used so derivation is reproducible across runs.
    const TEST_SEED: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    #[test]
    fn pop_purpose_is_ascii_pop() {
        // 0x50 'P', 0x6F 'o', 0x50 'P'.
        assert_eq!(POP_PURPOSE, 0x0050_6F50);
        // 0x506F50 == decimal 5_271_376 (NOT 5_271_888 — see the module note).
        assert_eq!(POP_PURPOSE, 5_271_376);
        let bytes = POP_PURPOSE.to_be_bytes();
        assert_eq!(&bytes[1..], b"PoP");
    }

    #[test]
    fn coin_type_follows_slip44() {
        assert_eq!(coin_type_for_network(Network::Bitcoin), 0);
        assert_eq!(coin_type_for_network(Network::Testnet), 1);
        assert_eq!(coin_type_for_network(Network::Signet), 1);
        assert_eq!(coin_type_for_network(Network::Regtest), 1);
    }

    #[test]
    fn path_string_matches_path() {
        assert_eq!(
            funder_path_string(Network::Bitcoin, 7),
            "m/5271376'/0'/0'/0/7"
        );
        assert_eq!(
            funder_path_string(Network::Signet, 3),
            "m/5271376'/1'/0'/0/3"
        );
    }

    /// Determinism: the same (seed, network, index) yields the same key on
    /// every call. This is the property the whole recovery story depends on —
    /// a funder reproduces the recovery key from the seed alone.
    #[test]
    fn derivation_is_deterministic() {
        let a = derive_funder_key(&TEST_SEED, Network::Bitcoin, 0).unwrap();
        let b = derive_funder_key(&TEST_SEED, Network::Bitcoin, 0).unwrap();
        assert_eq!(a.secret_key.secret_bytes(), b.secret_key.secret_bytes());
        assert_eq!(a.xonly, b.xonly);
    }

    /// Distinct indices give distinct keys (so recovery spends don't correlate).
    #[test]
    fn distinct_indices_give_distinct_keys() {
        let k0 = derive_funder_key(&TEST_SEED, Network::Bitcoin, 0).unwrap();
        let k1 = derive_funder_key(&TEST_SEED, Network::Bitcoin, 1).unwrap();
        assert_ne!(k0.secret_key.secret_bytes(), k1.secret_key.secret_bytes());
        assert_ne!(k0.xonly, k1.xonly);
    }

    /// Different networks (different coin_type') give different keys for the
    /// same index — mainnet and signet deposits never share a key.
    #[test]
    fn network_changes_the_key() {
        let main = derive_funder_key(&TEST_SEED, Network::Bitcoin, 0).unwrap();
        let signet = derive_funder_key(&TEST_SEED, Network::Signet, 0).unwrap();
        assert_ne!(main.secret_key.secret_bytes(), signet.secret_key.secret_bytes());
    }

    /// The x-only pubkey we derive equals the x-only of the secret's full
    /// public key — i.e. the two roles really are one key.
    #[test]
    fn xonly_matches_secret_pubkey() {
        let secp = Secp256k1::new();
        let k = derive_funder_key(&TEST_SEED, Network::Bitcoin, 5).unwrap();
        let full = k.secret_key.public_key(&secp);
        let (xonly_from_secret, _) = full.x_only_public_key();
        assert_eq!(k.xonly, xonly_from_secret);
    }

    /// Pin the derived key for a fixed (seed, mainnet, index 0) so any future
    /// change to the path or derivation logic breaks loudly. Real-money
    /// critical: a silent change here would make old deposits unrecoverable.
    /// The pinned value is captured from this code's own first run; it is the
    /// canary that the frozen path stays frozen.
    #[test]
    fn mainnet_index0_key_is_pinned() {
        let k = derive_funder_key(&TEST_SEED, Network::Bitcoin, 0).unwrap();
        assert_eq!(
            hex::encode(k.xonly.serialize()),
            PINNED_MAINNET_IDX0_XONLY,
            "funder x-only pubkey drifted for (test seed, mainnet, idx 0); \
             a change here makes existing deposits unrecoverable"
        );
    }

    /// Captured from the first green run (see `mainnet_index0_key_is_pinned`).
    /// Derived from TEST_SEED at m/5271376'/0'/0'/0/0.
    const PINNED_MAINNET_IDX0_XONLY: &str =
        "875851f8d6c12eaa9eb74393b69c7c6225156ff69bad896b490dbdf8a6aa5d8d";
}
