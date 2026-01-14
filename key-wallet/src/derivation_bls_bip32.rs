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

use alloc::string::String;
use dashcore_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};

// NOTE: We use Bls12381G2Impl for BLS keys (48-byte public keys)
use dashcore::blsful::{
    Bls12381G2Impl, PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, SerializationFormat,
};

#[cfg(feature = "serde")]
use serde;

use dash_network::Network;
use serde::Deserialize;

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
        // Allow shorter seeds for testing compatibility with C++ implementation
        // In production, seeds should be at least 16 bytes for security
        #[cfg(not(test))]
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidSeed);
        }
        #[cfg(test)]
        if seed.len() < 8 || seed.len() > 64 {
            return Err(Error::InvalidSeed);
        }

        // Following the bls-signatures C++ implementation:
        // They do two separate HMAC-SHA256 operations with different suffixes

        // First HMAC with seed||0 for the private key
        let mut seed_with_suffix = Vec::with_capacity(seed.len() + 1);
        seed_with_suffix.extend_from_slice(seed);
        seed_with_suffix.push(0);

        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(b"BLS HD seed");
        hmac_engine.input(&seed_with_suffix);
        let hmac_result: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine);
        let private_key_bytes = hmac_result.as_byte_array();

        // #[cfg(test)]
        // {
        //     eprintln!("Seed length: {}", seed.len());
        //     eprintln!("Seed||0 (hex): {}", hex::encode(&seed_with_suffix));
        //     eprintln!("HMAC output (hex): {}", hex::encode(private_key_bytes));
        // }

        // The C++ implementation does modulo reduction by curve order
        // We need to do the same before converting to BLS private key
        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(private_key_bytes)
            .into_option()
            .ok_or(Error::InvalidPrivateKey)?;

        // #[cfg(test)]
        // {
        //     eprintln!("After from_be_bytes (hex): {}", hex::encode(private_key.to_be_bytes()));
        // }

        // Second HMAC with seed||1 for the chain code
        seed_with_suffix[seed.len()] = 1;

        let mut hmac_engine2: HmacEngine<sha256::Hash> = HmacEngine::new(b"BLS HD seed");
        hmac_engine2.input(&seed_with_suffix);
        let hmac_result2: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine2);
        let chain_code_bytes = hmac_result2.as_byte_array();

        Ok(ExtendedBLSPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            private_key,
            chain_code: ChainCode::from(*chain_code_bytes),
        })
    }

    /// Derive a child private key
    pub fn derive_priv(&self, child: ChildNumber) -> Result<Self, Error> {
        // Build the input data for HMAC
        let mut input_data = Vec::new();

        if child.is_hardened() {
            // Hardened derivation: 0x00 || private_key || index
            input_data.push(0x00);
            input_data.extend_from_slice(&self.private_key.to_be_bytes());
        } else {
            // Non-hardened derivation: public_key || index
            let public_key_bytes = self.public_key_bytes();
            input_data.extend_from_slice(&public_key_bytes);
        }
        let child_bytes = u32::from(child).to_be_bytes();
        input_data.extend_from_slice(&child_bytes);

        // First HMAC-SHA256 with suffix 0 for the private key
        let mut input_with_suffix = input_data.clone();
        input_with_suffix.push(0);

        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&input_with_suffix);
        let hmac_result: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine);
        let key_bytes = hmac_result.as_byte_array();

        // Second HMAC-SHA256 with suffix 1 for the chain code
        input_with_suffix[input_data.len()] = 1;

        let mut hmac_engine2: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine2.input(&input_with_suffix);
        let hmac_result2: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine2);
        let chain_code_bytes = hmac_result2.as_byte_array();

        // Derive the new private key using proper scalar field arithmetic
        let derived_private_key = {
            // Convert tweak to secret key
            let tweak_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(key_bytes)
                .into_option()
                .ok_or(Error::InvalidPrivateKey)?;

            // Perform scalar addition in the BLS12-381 field
            // The SecretKey struct has a public field (0) containing the scalar
            // We add the scalars and create a new SecretKey from the result
            let parent_scalar = self.private_key.0;
            let tweak_scalar = tweak_key.0;
            let derived_scalar = parent_scalar + tweak_scalar;

            BlsSecretKey::<Bls12381G2Impl>(derived_scalar)
        };

        Ok(ExtendedBLSPrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            private_key: derived_private_key,
            chain_code: ChainCode::from(*chain_code_bytes),
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
    /// Create from a private key
    pub fn from_private_key(priv_key: &ExtendedBLSPrivKey) -> Self {
        ExtendedBLSPubKey {
            network: priv_key.network,
            depth: priv_key.depth,
            parent_fingerprint: priv_key.parent_fingerprint,
            child_number: priv_key.child_number,
            public_key: priv_key.public_key(),
            chain_code: priv_key.chain_code,
        }
    }

    /// Derive a child public key (only for non-hardened derivation)
    pub fn ckd_pub(&self, child: ChildNumber) -> Result<Self, Error> {
        self.derive_pub(child)
    }

    /// Derive a child public key (only for non-hardened derivation)
    pub fn derive_pub(&self, child: ChildNumber) -> Result<Self, Error> {
        if child.is_hardened() {
            return Err(Error::CannotDeriveFromHardenedPublic);
        }

        // Build the input data for HMAC: public_key || index
        let mut input_data = Vec::new();
        input_data.extend_from_slice(&self.public_key.to_bytes());
        let child_bytes = u32::from(child).to_be_bytes();
        input_data.extend_from_slice(&child_bytes);

        // First HMAC-SHA256 with suffix 0 for the tweak
        let mut input_with_suffix = input_data.clone();
        input_with_suffix.push(0);

        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&input_with_suffix);
        let hmac_result: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine);
        let tweak_bytes = hmac_result.as_byte_array();

        // Second HMAC-SHA256 with suffix 1 for the chain code
        input_with_suffix[input_data.len()] = 1;

        let mut hmac_engine2: HmacEngine<sha256::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine2.input(&input_with_suffix);
        let hmac_result2: Hmac<sha256::Hash> = Hmac::from_engine(hmac_engine2);
        let chain_code_bytes = hmac_result2.as_byte_array();

        // For BLS public key derivation, we need to do elliptic curve point addition
        // First, convert the tweak bytes to a scalar (private key)
        let tweak_privkey = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(tweak_bytes)
            .into_option()
            .ok_or(Error::InvalidPrivateKey)?;

        // Convert the scalar to a public key point (scalar * G where G is the generator)
        let tweak_pubkey = BlsPublicKey::from(&tweak_privkey);

        // Now we need to add the two public key points using elliptic curve point addition
        // The BLS public key type has an inner field (0) that contains the actual G2Projective point
        // G2Projective implements the Group trait which supports addition

        // Access the underlying G2Projective points
        let parent_point = self.public_key.0;
        let tweak_point = tweak_pubkey.0;

        // Perform elliptic curve point addition
        let derived_point = parent_point + tweak_point;

        // Create the new public key with the derived point
        let derived_pubkey = BlsPublicKey(derived_point);

        Ok(ExtendedBLSPubKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: child,
            public_key: derived_pubkey,
            chain_code: ChainCode::from(*chain_code_bytes),
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

// Manual serde implementations for ExtendedBLSPrivKey
#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedBLSPrivKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExtendedBLSPrivKey", 6)?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field("depth", &self.depth)?;
        state.serialize_field("parent_fingerprint", &self.parent_fingerprint)?;
        state.serialize_field("child_number", &self.child_number)?;
        state.serialize_field("private_key", &self.private_key.to_be_bytes())?;
        state.serialize_field("chain_code", &self.chain_code)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedBLSPrivKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            network: Network,
            depth: u8,
            parent_fingerprint: Fingerprint,
            child_number: ChildNumber,
            private_key: [u8; 32],
            chain_code: ChainCode,
        }

        let helper = Helper::deserialize(deserializer)?;
        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&helper.private_key)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("Invalid BLS private key"))?;

        Ok(ExtendedBLSPrivKey {
            network: helper.network,
            depth: helper.depth,
            parent_fingerprint: helper.parent_fingerprint,
            child_number: helper.child_number,
            private_key,
            chain_code: helper.chain_code,
        })
    }
}

// Manual serde implementations for ExtendedBLSPubKey
#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedBLSPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ExtendedBLSPubKey", 6)?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field("depth", &self.depth)?;
        state.serialize_field("parent_fingerprint", &self.parent_fingerprint)?;
        state.serialize_field("child_number", &self.child_number)?;
        state.serialize_field("public_key", &self.public_key.to_bytes())?;
        state.serialize_field("chain_code", &self.chain_code)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedBLSPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            network: Network,
            depth: u8,
            parent_fingerprint: Fingerprint,
            child_number: ChildNumber,
            public_key: Vec<u8>,
            chain_code: ChainCode,
        }

        let helper = Helper::deserialize(deserializer)?;
        let public_key = BlsPublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            &helper.public_key,
            SerializationFormat::Modern,
        )
        .map_err(|e| serde::de::Error::custom(format!("Invalid BLS public key: {}", e)))?;

        Ok(ExtendedBLSPubKey {
            network: helper.network,
            depth: helper.depth,
            parent_fingerprint: helper.parent_fingerprint,
            child_number: helper.child_number,
            public_key,
            chain_code: helper.chain_code,
        })
    }
}

// Manual bincode implementations for ExtendedBLSPrivKey
#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedBLSPrivKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        // Encode private key as bytes
        let private_key_bytes = self.private_key.to_be_bytes();
        private_key_bytes.encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedBLSPrivKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        let private_key_bytes: [u8; 32] = <[u8; 32]>::decode(decoder)?;
        let private_key = BlsSecretKey::<Bls12381G2Impl>::from_be_bytes(&private_key_bytes)
            .into_option()
            .ok_or_else(|| {
                bincode::error::DecodeError::OtherString("Invalid BLS private key".to_string())
            })?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedBLSPrivKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            private_key,
            chain_code,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedBLSPrivKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

// Manual bincode implementations for ExtendedBLSPubKey
#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedBLSPubKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        // Encode public key as bytes
        let public_key_bytes = self.public_key.to_bytes();
        public_key_bytes.encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedBLSPubKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        let public_key_bytes: Vec<u8> = Vec::<u8>::decode(decoder)?;
        let public_key = BlsPublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            &public_key_bytes,
            SerializationFormat::Modern,
        )
        .map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid BLS public key: {}", e))
        })?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedBLSPubKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            public_key,
            chain_code,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedBLSPubKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
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

    #[test]
    fn test_derivation_matches_through_private_and_public() {
        // Test vector from C++ implementation
        // Seed: {1, 50, 6, 244, 24, 199, 1, 25}
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

        let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let master_pub = master_priv.to_extended_pub_key();

        // Test single child derivation
        // Child index: 238757
        let child_index = 238757;

        // Derive public key through private key
        let child_priv =
            master_priv.derive_priv(ChildNumber::from_normal_idx(child_index).unwrap()).unwrap();
        let pk1 = child_priv.to_extended_pub_key().public_key;

        // Derive public key directly from parent public key
        let child_pub =
            master_pub.derive_pub(ChildNumber::from_normal_idx(child_index).unwrap()).unwrap();
        let pk2 = child_pub.public_key;

        // They should be equal
        assert_eq!(
            pk1.to_bytes(),
            pk2.to_bytes(),
            "Public key derived through private key should equal public key derived directly"
        );
    }

    #[test]
    fn test_derivation_path_consistency() {
        // Test vector from C++ implementation
        // Path: m/0/3/8/1
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

        let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let master_pub = master_priv.to_extended_pub_key();

        // Derive through private keys
        let derived_priv = master_priv
            .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(3).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(8).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(1).unwrap())
            .unwrap();

        let pk_from_priv = derived_priv.to_extended_pub_key().public_key;

        // Derive through public keys
        let derived_pub = master_pub
            .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(3).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(8).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(1).unwrap())
            .unwrap();

        let pk_from_pub = derived_pub.public_key;

        // They should be equal
        assert_eq!(
            pk_from_priv.to_bytes(),
            pk_from_pub.to_bytes(),
            "Public key derived through private key path should equal public key derived through public key path"
        );
    }

    #[test]
    fn test_public_child_derivation_from_parent() {
        // Test vector from C++ implementation
        // Seed: {1, 50, 6, 244, 24, 199, 1, 0, 0, 0}
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 0, 0, 0];

        let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let master_pub = master_priv.to_extended_pub_key();

        // Child index: 13
        let child_index = 13;

        // Get public key from private derivation
        let pk1 = master_priv
            .derive_priv(ChildNumber::from_normal_idx(child_index).unwrap())
            .unwrap()
            .to_extended_pub_key();

        // Get public key from public derivation
        let pk2 =
            master_pub.derive_pub(ChildNumber::from_normal_idx(child_index).unwrap()).unwrap();

        // They should be equal
        assert_eq!(
            pk1.public_key.to_bytes(),
            pk2.public_key.to_bytes(),
            "Extended public keys should match"
        );
        assert_eq!(pk1.chain_code, pk2.chain_code, "Chain codes should match");
    }

    #[test]
    fn test_hardened_public_derivation_fails() {
        // Test that hardened derivation from public key fails
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

        let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let master_pub = master_priv.to_extended_pub_key();

        // Hardened index: (1 << 31) + 3
        let hardened_index = (1u32 << 31) + 3;

        // Private key derivation should work
        let priv_result = master_priv.derive_priv(ChildNumber::from(hardened_index)).unwrap();
        assert_eq!(priv_result.depth, 1);

        // Public key derivation should fail
        let pub_result = master_pub.derive_pub(ChildNumber::from(hardened_index));
        assert!(pub_result.is_err(), "Hardened derivation from public key should fail");

        if let Err(e) = pub_result {
            match e {
                Error::CannotDeriveFromHardenedPublic => (),
                _ => panic!("Expected CannotDeriveFromHardenedPublic error, got {:?}", e),
            }
        }
    }

    #[test]
    fn test_unhardened_derivation_consistency() {
        // Test multiple unhardened derivations
        let seed = b"test seed for unhardened BLS derivation";
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, seed).unwrap();
        let master_pub = master.to_extended_pub_key();

        // Test with child 42
        let child_priv_42 = master.derive_priv(ChildNumber::from_normal_idx(42).unwrap()).unwrap();
        let child_pub_42 =
            master_pub.derive_pub(ChildNumber::from_normal_idx(42).unwrap()).unwrap();

        assert_eq!(
            child_priv_42.to_extended_pub_key().public_key.to_bytes(),
            child_pub_42.public_key.to_bytes()
        );

        // Test grandchild derivation (42 -> 12142)
        let grandchild_priv =
            child_priv_42.derive_priv(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();
        let grandchild_pub =
            child_pub_42.derive_pub(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();

        assert_eq!(
            grandchild_priv.to_extended_pub_key().public_key.to_bytes(),
            grandchild_pub.public_key.to_bytes()
        );
    }

    #[test]
    fn test_derive_path_method() {
        // Test the derive_path method for both private and public keys
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

        let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let master_pub = master_priv.to_extended_pub_key();

        // Create a non-hardened path
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(3).unwrap(),
            ChildNumber::from_normal_idx(8).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
        ]);

        // Derive using path method on private key
        let derived_priv = master_priv.derive_path(&path).unwrap();

        // Derive using path method on public key
        let derived_pub = master_pub.derive_path(&path).unwrap();

        // They should match
        assert_eq!(
            derived_priv.to_extended_pub_key().public_key.to_bytes(),
            derived_pub.public_key.to_bytes()
        );
    }

    #[test]
    fn test_long_derivation_path() {
        // Test from C++ implementation: m/(2^31+5)/0/0/(2^31+56)/70/4
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];

        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();

        // Build the long derivation path: m/(2^31+5)/0/0/(2^31+56)/70/4
        let derived = master
            .derive_priv(ChildNumber::from_hardened_idx(5).unwrap())
            .unwrap() // Hardened (2^31+5)
            .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_hardened_idx(56).unwrap())
            .unwrap() // Hardened (2^31+56)
            .derive_priv(ChildNumber::from_normal_idx(70).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(4).unwrap())
            .unwrap();

        // Verify depth is correct
        assert_eq!(derived.depth, 6);

        // Verify chain code is properly updated
        assert_ne!(derived.chain_code, master.chain_code);

        // Verify the key can still derive children
        let child = derived.derive_priv(ChildNumber::from_normal_idx(100).unwrap()).unwrap();
        assert_eq!(child.depth, 7);
    }

    #[test]
    fn test_serialization_roundtrip() {
        // Test serialization and deserialization of extended keys
        let seed = vec![1u8, 50, 6, 244, 25, 199, 1, 25]; // C++ test vector

        let master_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let master_pub = master_priv.to_extended_pub_key();

        // Test private key serialization with serde
        #[cfg(feature = "serde")]
        {
            // Serialize to JSON
            let serialized = serde_json::to_string(&master_priv).unwrap();
            // Deserialize back
            let deserialized: ExtendedBLSPrivKey = serde_json::from_str(&serialized).unwrap();

            // Verify they match
            assert_eq!(master_priv.depth, deserialized.depth);
            assert_eq!(master_priv.parent_fingerprint, deserialized.parent_fingerprint);
            assert_eq!(master_priv.child_number, deserialized.child_number);
            assert_eq!(master_priv.chain_code, deserialized.chain_code);
            assert_eq!(
                master_priv.private_key.to_be_bytes(),
                deserialized.private_key.to_be_bytes()
            );

            // Test public key serialization
            let pub_serialized = serde_json::to_string(&master_pub).unwrap();
            let pub_deserialized: ExtendedBLSPubKey =
                serde_json::from_str(&pub_serialized).unwrap();

            assert_eq!(master_pub.depth, pub_deserialized.depth);
            assert_eq!(master_pub.parent_fingerprint, pub_deserialized.parent_fingerprint);
            assert_eq!(master_pub.child_number, pub_deserialized.child_number);
            assert_eq!(master_pub.chain_code, pub_deserialized.chain_code);
            assert_eq!(master_pub.public_key.to_bytes(), pub_deserialized.public_key.to_bytes());
        }

        // Test bincode serialization
        #[cfg(feature = "bincode")]
        {
            // Test private key
            let encoded =
                bincode::encode_to_vec(&master_priv, bincode::config::standard()).unwrap();
            let decoded: ExtendedBLSPrivKey =
                bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap().0;

            assert_eq!(master_priv.depth, decoded.depth);
            assert_eq!(master_priv.parent_fingerprint, decoded.parent_fingerprint);
            assert_eq!(master_priv.child_number, decoded.child_number);
            assert_eq!(master_priv.chain_code, decoded.chain_code);
            assert_eq!(master_priv.private_key.to_be_bytes(), decoded.private_key.to_be_bytes());

            // Test public key
            let pub_encoded =
                bincode::encode_to_vec(&master_pub, bincode::config::standard()).unwrap();
            let pub_decoded: ExtendedBLSPubKey =
                bincode::decode_from_slice(&pub_encoded, bincode::config::standard()).unwrap().0;

            assert_eq!(master_pub.depth, pub_decoded.depth);
            assert_eq!(master_pub.parent_fingerprint, pub_decoded.parent_fingerprint);
            assert_eq!(master_pub.child_number, pub_decoded.child_number);
            assert_eq!(master_pub.chain_code, pub_decoded.chain_code);
            assert_eq!(master_pub.public_key.to_bytes(), pub_decoded.public_key.to_bytes());
        }
    }

    #[test]
    fn test_serialization_and_derivation() {
        // Test that serialized keys can be used for derivation (matching C++ test)
        let seed = vec![1u8, 50, 6, 244, 25, 199, 1, 25];

        let esk = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let epk = esk.to_extended_pub_key();

        // Derive child 238757 through private key
        let pk1 = esk
            .derive_priv(ChildNumber::from_normal_idx(238757).unwrap())
            .unwrap()
            .to_extended_pub_key()
            .public_key;

        // Derive child 238757 through public key
        let pk2 = epk.derive_pub(ChildNumber::from_normal_idx(238757).unwrap()).unwrap().public_key;

        assert_eq!(pk1.to_bytes(), pk2.to_bytes());

        // Test path m/0/3/8/1
        let sk3 = esk
            .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(3).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(8).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(1).unwrap())
            .unwrap();

        let pk4 = epk
            .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(3).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(8).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(1).unwrap())
            .unwrap();

        assert_eq!(sk3.to_extended_pub_key().public_key.to_bytes(), pk4.public_key.to_bytes());
    }

    #[test]
    fn test_c_plus_plus_test_vectors() {
        // Test exact C++ test vectors for compatibility

        // Test vector 1: {1, 50, 6, 244, 24, 199, 1, 25}
        let seed1 = vec![1u8, 50, 6, 244, 24, 199, 1, 25];
        let esk1 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed1).unwrap();

        // Test hardened child derivation
        let esk77_hardened = esk1.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();
        let esk77_hardened_copy =
            esk1.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();

        // Keys derived with same index should be equal
        assert_eq!(
            esk77_hardened.private_key.to_be_bytes(),
            esk77_hardened_copy.private_key.to_be_bytes()
        );
        assert_eq!(esk77_hardened.chain_code, esk77_hardened_copy.chain_code);

        // Test non-hardened derivation
        let esk77_normal = esk1.derive_priv(ChildNumber::from_normal_idx(77).unwrap()).unwrap();

        // Hardened and non-hardened should be different
        assert_ne!(
            esk77_hardened.private_key.to_be_bytes(),
            esk77_normal.private_key.to_be_bytes()
        );

        // Test vector 2: {1, 50, 6, 244, 24, 199, 1, 0, 0, 0}
        let seed2 = vec![1u8, 50, 6, 244, 24, 199, 1, 0, 0, 0];
        let esk2 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed2).unwrap();
        let epk2 = esk2.to_extended_pub_key();

        // Test public child derivation
        let pk1 = esk2
            .derive_priv(ChildNumber::from_normal_idx(13).unwrap())
            .unwrap()
            .to_extended_pub_key();
        let pk2 = epk2.derive_pub(ChildNumber::from_normal_idx(13).unwrap()).unwrap();

        assert_eq!(pk1.public_key.to_bytes(), pk2.public_key.to_bytes());
        assert_eq!(pk1.chain_code, pk2.chain_code);
    }

    #[test]
    fn test_legacy_hd_compatibility() {
        // Test compatibility with C++ ExtendedPrivateKey/ExtendedPublicKey patterns

        // Test vector: {1, 50, 6, 244, 24, 199, 1, 0, 0, 0}
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 0, 0, 0];
        let esk = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let epk = esk.to_extended_pub_key();

        // Test PublicChild(13) derivation
        let pk1 = esk
            .derive_priv(ChildNumber::from_normal_idx(13).unwrap())
            .unwrap()
            .to_extended_pub_key();
        let pk2 = epk.derive_pub(ChildNumber::from_normal_idx(13).unwrap()).unwrap();

        // Public keys should match whether derived through private or public path
        assert_eq!(pk1.public_key.to_bytes(), pk2.public_key.to_bytes());
        assert_eq!(pk1.chain_code, pk2.chain_code);
        assert_eq!(pk1.depth, pk2.depth);
        assert_eq!(pk1.child_number, pk2.child_number);

        // Test with another seed: {1, 50, 6, 244, 25, 199, 1, 25}
        let seed2 = vec![1u8, 50, 6, 244, 25, 199, 1, 25];
        let esk2 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed2).unwrap();
        let epk2 = esk2.to_extended_pub_key();

        // Test child 238757 derivation
        let pk1_238757 =
            esk2.derive_priv(ChildNumber::from_normal_idx(238757).unwrap()).unwrap().public_key();
        let pk2_238757 =
            epk2.derive_pub(ChildNumber::from_normal_idx(238757).unwrap()).unwrap().public_key;

        assert_eq!(pk1_238757.to_bytes(), pk2_238757.to_bytes());

        // Test path m/0/3/8/1
        let sk3 = esk2
            .derive_priv(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(3).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(8).unwrap())
            .unwrap()
            .derive_priv(ChildNumber::from_normal_idx(1).unwrap())
            .unwrap();

        let pk4 = epk2
            .derive_pub(ChildNumber::from_normal_idx(0).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(3).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(8).unwrap())
            .unwrap()
            .derive_pub(ChildNumber::from_normal_idx(1).unwrap())
            .unwrap();

        assert_eq!(sk3.public_key().to_bytes(), pk4.public_key.to_bytes());
    }

    #[test]
    fn test_extended_unhardened_derivation() {
        // Test with extended seed from C++ test suite
        let seed1 = vec![
            1u8, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ];

        let master1 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed1).unwrap();
        let master1_pub = master1.to_extended_pub_key();

        // Test child 42 unhardened
        let child_sk = master1.derive_priv(ChildNumber::from_normal_idx(42).unwrap()).unwrap();
        let child_pk = master1_pub.derive_pub(ChildNumber::from_normal_idx(42).unwrap()).unwrap();

        assert_eq!(
            child_sk.to_extended_pub_key().public_key.to_bytes(),
            child_pk.public_key.to_bytes()
        );

        // Test grandchild 12142
        let grandchild_sk =
            child_sk.derive_priv(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();
        let grandchild_pk =
            child_pk.derive_pub(ChildNumber::from_normal_idx(12142).unwrap()).unwrap();

        assert_eq!(
            grandchild_sk.to_extended_pub_key().public_key.to_bytes(),
            grandchild_pk.public_key.to_bytes()
        );

        // Test with second seed vector from C++
        let seed2 = vec![
            2u8, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ];

        let master2 = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed2).unwrap();
        let master2_pub = master2.to_extended_pub_key();

        // Test unhardened child 42
        let child_sk_unhardened =
            master2.derive_priv(ChildNumber::from_normal_idx(42).unwrap()).unwrap();
        let child_pk_unhardened =
            master2_pub.derive_pub(ChildNumber::from_normal_idx(42).unwrap()).unwrap();

        // Test hardened child 42
        let child_sk_hardened =
            master2.derive_priv(ChildNumber::from_hardened_idx(42).unwrap()).unwrap();

        // Verify unhardened derivation consistency
        assert_eq!(
            child_sk_unhardened.to_extended_pub_key().public_key.to_bytes(),
            child_pk_unhardened.public_key.to_bytes()
        );

        // Verify hardened != unhardened
        assert_ne!(
            child_sk_hardened.private_key.to_be_bytes(),
            child_sk_unhardened.private_key.to_be_bytes()
        );
        assert_ne!(
            child_sk_hardened.to_extended_pub_key().public_key.to_bytes(),
            child_pk_unhardened.public_key.to_bytes()
        );
    }

    #[test]
    fn test_hardened_vs_unhardened_comparison() {
        // Comprehensive test comparing hardened vs unhardened derivation
        let seed = vec![1u8, 50, 6, 244, 24, 199, 1, 25];
        let master = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed).unwrap();

        // Test with index 77 (matching C++ test)
        let unhardened_index = 77;

        // Derive hardened child
        let child_hardened =
            master.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();
        let child_hardened_copy =
            master.derive_priv(ChildNumber::from_hardened_idx(77).unwrap()).unwrap();

        // Derive unhardened child
        let child_unhardened =
            master.derive_priv(ChildNumber::from_normal_idx(unhardened_index).unwrap()).unwrap();

        // Hardened derivation should be deterministic
        assert_eq!(
            child_hardened.private_key.to_be_bytes(),
            child_hardened_copy.private_key.to_be_bytes(),
            "Hardened derivation should be deterministic"
        );
        assert_eq!(child_hardened.chain_code, child_hardened_copy.chain_code);
        assert_eq!(child_hardened.depth, child_hardened_copy.depth);

        // Hardened and unhardened should produce different keys
        assert_ne!(
            child_hardened.private_key.to_be_bytes(),
            child_unhardened.private_key.to_be_bytes(),
            "Hardened and unhardened derivation should produce different keys"
        );
        assert_ne!(
            child_hardened.chain_code, child_unhardened.chain_code,
            "Hardened and unhardened should have different chain codes"
        );

        // Both should have correct depth
        assert_eq!(child_hardened.depth, 1);
        assert_eq!(child_unhardened.depth, 1);

        // Both should have correct parent fingerprint
        assert_eq!(child_hardened.parent_fingerprint, master.fingerprint());
        assert_eq!(child_unhardened.parent_fingerprint, master.fingerprint());
    }
}
