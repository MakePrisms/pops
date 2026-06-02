//! The pluggable funder **Signer** seam.
//!
//! The `pops-core-funder` kernel is custody-free: it builds an unsigned
//! recovery spend and hands back a [`bitcoin::TapSighash`], expecting a
//! [`schnorr::Signature`] in return. This module defines the [`Signer`] trait
//! that supplies that signature (and the two pubkey encodings + the NUT-20
//! issuance signature), and a [`HotKeySigner`] that derives the funder key
//! from the wallet seed in-process.
//!
//! Splitting signing behind a trait is what keeps the door open for hardware /
//! remote / air-gapped signers later: the kernel never sees a secret, and a
//! non-hot signer just returns the 64 bytes that parse into a
//! [`schnorr::Signature`]. The kernel stays SYNC; any async lives here.

use std::error::Error;
use std::fmt;

use bitcoin::secp256k1::{schnorr, Keypair, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::hashes::Hash;
use bitcoin::{Network, TapSighash};
use cdk_common::nuts::MintRequest;
use zeroize::Zeroizing;

use crate::derive::derive_funder_key;

/// A funder public key in the two encodings the PoP flow needs.
///
/// The **x-only** form is the `funder_pubkey` baked into `cm` + the CLTV
/// recovery leaf (on-chain reclaim, what [`pops_core_funder::RecoverInputs`]
/// takes); the **compressed** form is the NUT-20 quote-lock pubkey (issuance
/// auth). Both derive from one secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunderPubkey {
    /// x-only pubkey — the on-chain recovery commitment key.
    pub xonly: XOnlyPublicKey,
    /// 33-byte compressed pubkey — the NUT-20 issuance-lock key.
    pub compressed: PublicKey,
}

/// An error from a [`Signer`] operation.
#[derive(Debug)]
pub enum SignerError {
    /// Funder-key derivation failed (malformed seed / un-derivable path).
    Derivation(String),
    /// Signing or signing-key construction failed.
    Signing(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::Derivation(m) => write!(f, "funder key derivation failed: {m}"),
            SignerError::Signing(m) => write!(f, "funder signing failed: {m}"),
        }
    }
}

impl Error for SignerError {}

/// The funder signing seam consumed by the recovery + issuance flows.
///
/// `index` is the per-deposit BIP-32 funder index. Recovery signing
/// ([`Signer::sign`]) does not take an index — the kernel's
/// [`pops_core_funder::build_unsigned`] already produced the sighash for a
/// specific deposit, and a [`HotKeySigner`] is constructed bound to that
/// deposit's key. **SYNC v1**: hardware/remote async signing would live in a
/// different impl, never in the kernel.
pub trait Signer {
    /// Returns the funder pubkey (both encodings) for the deposit at `index`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Derivation`] if the key cannot be derived.
    fn funder_pubkey(&self, index: u32) -> Result<FunderPubkey, SignerError>;

    /// Signs a BIP-341 taproot script-path `sighash` for the recovery spend,
    /// returning a bare 64-byte BIP-340 schnorr signature.
    ///
    /// # Errors
    ///
    /// [`SignerError::Signing`] / [`SignerError::Derivation`] on failure.
    fn sign(&self, sighash: TapSighash) -> Result<schnorr::Signature, SignerError>;

    /// NUT-20: signs (and self-verifies) a `MintRequest` in place with the
    /// funder key for the deposit at `index`.
    ///
    /// # Errors
    ///
    /// [`SignerError::Derivation`] if the key cannot be derived, or
    /// [`SignerError::Signing`] if signing / self-verification fails.
    fn sign_mint_request(
        &self,
        index: u32,
        req: &mut MintRequest<String>,
    ) -> Result<(), SignerError>;
}

/// A hot-key [`Signer`] backed by the wallet's in-process seed.
///
/// Holds the (zeroizing) seed + network so it can derive ANY funder index for
/// [`Signer::funder_pubkey`] / [`Signer::sign_mint_request`]. For
/// [`Signer::sign`] (which carries no index) it is bound at construction to a
/// single deposit's `index` — the recovery flow builds one per deposit. The
/// signing logic is byte-for-byte the former `recover_tx::build_and_sign`:
/// `sign_schnorr_no_aux_rand` over the derived secret (deterministic, no aux
/// randomness — sufficient for a one-shot recovery).
pub struct HotKeySigner {
    seed: Zeroizing<Vec<u8>>,
    network: Network,
    /// The deposit index [`Signer::sign`] derives + signs with.
    index: u32,
}

impl HotKeySigner {
    /// Builds a hot-key signer bound to the deposit at `index`, deriving from
    /// `seed` on `network`.
    #[must_use]
    pub fn new(seed: &[u8], network: Network, index: u32) -> Self {
        HotKeySigner {
            seed: Zeroizing::new(seed.to_vec()),
            network,
            index,
        }
    }
}

impl Signer for HotKeySigner {
    fn funder_pubkey(&self, index: u32) -> Result<FunderPubkey, SignerError> {
        let secp = Secp256k1::new();
        let fk = derive_funder_key(&self.seed, self.network, index)
            .map_err(|e| SignerError::Derivation(e.to_string()))?;
        let compressed = fk.secret_key.public_key(&secp);
        Ok(FunderPubkey {
            xonly: fk.xonly,
            compressed,
        })
    }

    fn sign(&self, sighash: TapSighash) -> Result<schnorr::Signature, SignerError> {
        let secp = Secp256k1::new();
        // Derive the bound deposit's funder secret and schnorr-sign the sighash
        // deterministically — exactly the former recover_tx::build_and_sign.
        let fk = derive_funder_key(&self.seed, self.network, self.index)
            .map_err(|e| SignerError::Derivation(e.to_string()))?;
        let keypair = Keypair::from_secret_key(&secp, &fk.secret_key);
        let msg = Message::from_digest(sighash.to_byte_array());
        Ok(secp.sign_schnorr_no_aux_rand(&msg, &keypair))
    }

    fn sign_mint_request(
        &self,
        index: u32,
        req: &mut MintRequest<String>,
    ) -> Result<(), SignerError> {
        // Re-derive the funder secret and bridge it into cdk-common's secret-key
        // type (hex round-trip — the same path the wallet used pre-fold), then
        // NUT-20-sign + self-verify in place.
        let fk = derive_funder_key(&self.seed, self.network, index)
            .map_err(|e| SignerError::Derivation(e.to_string()))?;
        let funder_secret_hex = Zeroizing::new(hex::encode(fk.secret_key.secret_bytes()));
        let cdk_secret = cdk_common::SecretKey::from_hex(funder_secret_hex.as_str())
            .map_err(|e| SignerError::Signing(format!("funder secret -> cdk secret: {e}")))?;
        req.sign(cdk_secret.clone())
            .map_err(|e| SignerError::Signing(format!("NUT-20 sign: {e}")))?;
        // Defense-in-depth self-verify (mirrors the former mint_client pre-flight).
        req.verify_signature(cdk_secret.public_key())
            .map_err(|e| SignerError::Signing(format!("NUT-20 self-verify: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed 64-byte seed (BIP-39 "abandon ... about", empty passphrase) so
    /// derivation is reproducible — matches `derive::tests::TEST_SEED`.
    const TEST_SEED: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    /// `funder_pubkey` returns the SAME x-only the direct derivation does, and a
    /// compressed pubkey whose x-only equals it (the two roles are one key).
    #[test]
    fn funder_pubkey_xonly_matches_derived_key() {
        let signer = HotKeySigner::new(&TEST_SEED, Network::Bitcoin, 7);
        let direct = derive_funder_key(&TEST_SEED, Network::Bitcoin, 7).unwrap();
        let fp = signer.funder_pubkey(7).unwrap();
        assert_eq!(fp.xonly, direct.xonly, "signer xonly must match the derived key");
        // The compressed key's x-only is the same point.
        let (compressed_xonly, _) = fp.compressed.x_only_public_key();
        assert_eq!(compressed_xonly, fp.xonly);
    }

    /// `sign` over a sighash yields a schnorr signature that VERIFIES against the
    /// bound deposit's derived x-only key — the core "the signer signs the
    /// kernel's sighash" property.
    #[test]
    fn sign_yields_valid_schnorr_over_sighash() {
        let index = 3u32;
        let signer = HotKeySigner::new(&TEST_SEED, Network::Bitcoin, index);

        // A deterministic, non-trivial 32-byte digest to stand in for a real
        // BIP-341 sighash (the signer treats it as opaque bytes to sign).
        let sighash = TapSighash::from_byte_array([0x9au8; 32]);
        let sig = signer.sign(sighash).unwrap();

        // Verify against the funder x-only the signer reports for this deposit.
        let secp = Secp256k1::new();
        let xonly = signer.funder_pubkey(index).unwrap().xonly;
        let msg = Message::from_digest(sighash.to_byte_array());
        assert!(
            secp.verify_schnorr(&sig, &msg, &xonly).is_ok(),
            "signer.sign must produce a schnorr sig valid under the derived funder key"
        );
    }

    /// Determinism: signing the same sighash twice with the same bound key
    /// yields the same signature (no-aux-rand schnorr).
    #[test]
    fn sign_is_deterministic() {
        let signer = HotKeySigner::new(&TEST_SEED, Network::Bitcoin, 1);
        let sighash = TapSighash::from_byte_array([0x42u8; 32]);
        let a = signer.sign(sighash).unwrap();
        let b = signer.sign(sighash).unwrap();
        assert_eq!(a.serialize(), b.serialize());
    }
}
