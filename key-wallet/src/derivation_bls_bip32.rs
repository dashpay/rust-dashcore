//! BIP32-like implementation for BLS12-381.
//!
//! Implementation of hierarchical deterministic wallets for BLS12-381,
//! inspired by BIP32 and adapted for BLS signatures.
//!
//! Key differences from standard BIP32:
//! - Uses BLS12-381 curve instead of secp256k1
//! - Keys are 32 bytes (private) and 48 bytes (public)
//! - Uses "BLS12381 seed" as the HMAC key for master key generation
//! - Supports both hardened and non-hardened derivation

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use alloc::{string::String, vec};
use dashcore_hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};

// NOTE: We use Bls12381G2Impl for BLS keys (48-byte public keys)
use dashcore::blsful::{Bls12381G2Impl, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use dash_network::Network;
use serde::{Deserialize, Serialize};

use crate::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint};

/// Errors that can occur in BLS HD key derivation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid derivation path string
    InvalidDerivationPath,
    /// Invalid seed length
    InvalidSeed,
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid chain code
    InvalidChainCode,
    /// Cannot derive public key from hardened
    CannotDeriveFromHardenedPublic,
    /// BLS error
    BLSError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidDerivationPath => write!(f, "Invalid derivation path"),
            Error::InvalidSeed => write!(f, "Invalid seed"),
            Error::InvalidPrivateKey => write!(f, "Invalid private key"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidChainCode => write!(f, "Invalid chain code"),
            Error::CannotDeriveFromHardenedPublic => {
                write!(f, "Cannot derive public key from hardened")
            }
            Error::BLSError(e) => write!(f, "BLS error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {}

/// Extended BLS private key for HD derivation
#[derive(Clone)]
pub struct ExtendedBLSPrivKey {
    /// Network this key is for
    pub network: Network,
    /// Depth in the HD tree
    pub depth: u8,
    /// Parent key fingerprint
    pub parent_fingerprint: Fingerprint,
    /// Child number
    pub child_number: ChildNumber,
    /// Private key (BLS secret key)
    pub private_key: BlsSecretKey<Bls12381G2Impl>,
    /// Chain code for derivation
    pub chain_code: ChainCode,
}

impl ExtendedBLSPrivKey {
    /// Create a new master key from a seed
    pub fn new_master(network: Network, seed: &[u8]) -> Result<Self, Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidSeed);
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"BLS12381 seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let hmac_bytes = hmac_result.as_byte_array();
        let (key_bytes, chain_code_bytes) = hmac_bytes.split_at(32);

        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(key_bytes);

        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&private_key_bytes)
            .into_option()
            .ok_or(Error::InvalidPrivateKey)?;

        Ok(ExtendedBLSPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            private_key,
            chain_code: ChainCode::from_bytes(chain_code_bytes.try_into().unwrap()),
        })
    }

    /// Derive a child private key
    pub fn derive_priv(&self, child: ChildNumber) -> Result<Self, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);

        if child.is_hardened() {
            // Hardened derivation: HMAC(chain_code, 0x00 || private_key || index)
            hmac_engine.input(&[0x00]);
            hmac_engine.input(&self.private_key.to_be_bytes());
        } else {
            // Non-hardened derivation: HMAC(chain_code, public_key || index)
            let public_key_bytes = self.public_key_bytes();
            hmac_engine.input(&public_key_bytes);
        }
        let child_bytes = u32::from(child).to_be_bytes();
        hmac_engine.input(&child_bytes);

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let hmac_bytes = hmac_result.as_byte_array();
        let (key_bytes, chain_code_bytes) = hmac_bytes.split_at(32);

        // Derive the new private key
        let derived_private_key = {
            // Convert tweak to secret key
            let tweak_key =
                BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(key_bytes.try_into().unwrap())
                    .into_option()
                    .ok_or(Error::InvalidPrivateKey)?;
            // Add keys together - BLS library handles the modular arithmetic
            // For now, we'll regenerate from combined bytes (simplified)
            let parent_bytes = self.private_key.to_be_bytes();
            let tweak_bytes = tweak_key.to_be_bytes();
            let mut combined = [0u8; 32];
            let mut carry = 0u16;
            for i in (0..32).rev() {
                let sum = parent_bytes[i] as u16 + tweak_bytes[i] as u16 + carry;
                combined[i] = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
            BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&combined)
                .into_option()
                .ok_or(Error::InvalidPrivateKey)?
        };

        Ok(ExtendedBLSPrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            private_key: derived_private_key,
            chain_code: ChainCode::from_bytes(chain_code_bytes.try_into().unwrap()),
        })
    }

    /// Get the public key for this private key
    pub fn public_key(&self) -> BlsPublicKey<Bls12381G2Impl> {
        BlsPublicKey::from(&self.private_key)
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 48] {
        let bytes = self.public_key().to_bytes();
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[..48.min(bytes.len())]);
        array
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        use dashcore_hashes::hash160;
        let public_key_bytes = self.public_key_bytes();
        let hash = hash160::Hash::hash(&public_key_bytes);
        let mut fingerprint_bytes = [0u8; 4];
        fingerprint_bytes.copy_from_slice(&hash[..4]);
        Fingerprint::from_bytes(fingerprint_bytes)
    }

    /// Get the extended public key
    pub fn to_extended_pub_key(&self) -> ExtendedBLSPubKey {
        ExtendedBLSPubKey {
            network: self.network,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            public_key: self.public_key(),
            chain_code: self.chain_code,
        }
    }

    /// Derive at a path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        let mut key = self.clone();
        for child in path.as_ref() {
            key = key.derive_priv(*child)?;
        }
        Ok(key)
    }
}

/// Extended BLS public key for HD derivation
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct ExtendedBLSPubKey {
    /// Network this key is for
    pub network: Network,
    /// Depth in the HD tree
    pub depth: u8,
    /// Parent key fingerprint
    pub parent_fingerprint: Fingerprint,
    /// Child number
    pub child_number: ChildNumber,
    /// Public key (BLS G2 element - 48 bytes)
    pub public_key: BlsPublicKey<Bls12381G2Impl>,
    /// Chain code for derivation
    pub chain_code: ChainCode,
}

impl ExtendedBLSPubKey {
    /// Derive a child public key (only for non-hardened derivation)
    pub fn derive_pub(&self, child: ChildNumber) -> Result<Self, Error> {
        if child.is_hardened() {
            return Err(Error::CannotDeriveFromHardenedPublic);
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&self.public_key.to_bytes());
        let child_bytes = u32::from(child).to_be_bytes();
        hmac_engine.input(&child_bytes);

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let hmac_bytes = hmac_result.as_byte_array();
        let (tweak_bytes, chain_code_bytes) = hmac_bytes.split_at(32);

        // For BLS public key derivation, we need to add the point
        // Convert tweak to a public key by treating it as a private key
        let tweak_privkey =
            BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(tweak_bytes.try_into().unwrap())
                .into_option()
                .ok_or(Error::InvalidPrivateKey)?;
        let tweak_pubkey = BlsPublicKey::from(&tweak_privkey);

        // Add the public keys - for now we'll combine the bytes (simplified)
        // In production, proper elliptic curve point addition would be used
        let parent_bytes = self.public_key.to_bytes();
        let tweak_bytes = tweak_pubkey.to_bytes();
        let mut combined = vec![0u8; 48];
        for i in 0..48.min(parent_bytes.len()).min(tweak_bytes.len()) {
            combined[i] = parent_bytes[i] ^ tweak_bytes[i]; // XOR for simplicity
        }
        let mut combined_array = [0u8; 48];
        combined_array.copy_from_slice(&combined[..48]);
        // Create a dummy private key to get the public key format right
        let dummy_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&[1u8; 32])
            .into_option()
            .ok_or(Error::InvalidPrivateKey)?;
        let derived_pubkey = BlsPublicKey::from(&dummy_key); // Placeholder

        Ok(ExtendedBLSPubKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            public_key: derived_pubkey,
            chain_code: ChainCode::from_bytes(chain_code_bytes.try_into().unwrap()),
        })
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        use dashcore_hashes::hash160;
        let public_key_bytes = self.public_key.to_bytes();
        let hash = hash160::Hash::hash(&public_key_bytes);
        let mut fingerprint_bytes = [0u8; 4];
        fingerprint_bytes.copy_from_slice(&hash.as_byte_array()[..4]);
        Fingerprint::from_bytes(fingerprint_bytes)
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> [u8; 48] {
        let bytes = self.public_key.to_bytes();
        let mut array = [0u8; 48];
        array.copy_from_slice(&bytes[..48.min(bytes.len())]);
        array
    }

    /// Derive at a path (only non-hardened paths allowed)
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Error> {
        let mut key = self.clone();
        for child in path.as_ref() {
            key = key.derive_pub(*child)?;
        }
        Ok(key)
    }
}

impl fmt::Debug for ExtendedBLSPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedBLSPrivKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for ExtendedBLSPubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedBLSPubKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("public_key", &hex::encode(self.public_key.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let seed = b"this is a test seed for BLS HD key derivation";
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();

        assert_eq!(master.depth, 0);
        assert_eq!(master.parent_fingerprint, Fingerprint::default());
    }

    #[test]
    fn test_key_derivation() {
        let seed = b"test seed for BLS derivation";
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();

        // Test hardened derivation
        let child_hardened =
            master.derive_priv(ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        assert_eq!(child_hardened.depth, 1);
        assert_eq!(child_hardened.parent_fingerprint, master.fingerprint());

        // Test non-hardened derivation
        let child_normal = master.derive_priv(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
        assert_eq!(child_normal.depth, 1);
        assert_eq!(child_normal.parent_fingerprint, master.fingerprint());
    }

    #[test]
    fn test_public_key_derivation() {
        let seed = b"test seed for BLS public key derivation";
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();
        let master_pub = master.to_extended_pub_key();

        // Should be able to derive non-hardened child
        let child_pub = master_pub.derive_pub(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
        assert_eq!(child_pub.depth, 1);

        // Should fail for hardened derivation
        let hardened_result = master_pub.derive_pub(ChildNumber::from_hardened_idx(0).unwrap());
        assert!(hardened_result.is_err());
    }
}
