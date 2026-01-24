//! SLIP-0010 implementation for Ed25519.
//!
//! Implementation of SLIP-0010 hierarchical deterministic wallets for Ed25519,
//! as defined at <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>.
//!
//! Key differences from BIP32:
//! - Ed25519 only supports hardened derivation (no public key derivation)
//! - Uses "ed25519 seed" as the HMAC key for master key generation
//! - Different serialization format (no xpub/xprv, custom encoding)

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use alloc::{string::String, vec::Vec};
use dash_network::Network;
pub use dashcore::ed25519_dalek::{SigningKey, VerifyingKey};
use dashcore_hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
#[cfg(feature = "serde")]
use serde;
// Re-export ChainCode, Fingerprint and ChildNumber from bip32
use crate::bip32::{ChainCode, ChildNumber, Fingerprint};

// Re-export ed25519-dalek types as our public API
pub use dashcore::ed25519_dalek::SigningKey as Ed25519PrivateKey;
pub use dashcore::ed25519_dalek::VerifyingKey as Ed25519PublicKey;

// Use DerivationPath from bip32
pub use crate::bip32::DerivationPath;

/// Extended Ed25519 private key for SLIP-0010
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedEd25519PrivKey {
    /// Network this key is for
    pub network: Network,
    /// Depth in the derivation tree
    pub depth: u8,
    /// Parent fingerprint
    pub parent_fingerprint: Fingerprint,
    /// Child number used to derive this key
    pub child_number: ChildNumber,
    /// The Ed25519 private key (seed bytes, not the SigningKey itself)
    pub private_key: [u8; 32],
    /// Chain code for derivation
    pub chain_code: ChainCode,
}

impl ExtendedEd25519PrivKey {
    /// Create a new master key from seed
    pub fn new_master(network: Network, seed: &[u8]) -> Result<Self, Error> {
        if seed.len() < 16 {
            return Err(Error::InvalidSeedLength(seed.len()));
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"ed25519 seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let hmac_bytes = hmac_result.as_byte_array();

        // First 32 bytes are the private key seed
        let private_key: [u8; 32] = hmac_bytes[..32].try_into().expect("HMAC output is 64 bytes");

        // Last 32 bytes are the chain code
        let chain_code =
            ChainCode::from_bytes(hmac_bytes[32..].try_into().expect("HMAC output is 64 bytes"));

        Ok(ExtendedEd25519PrivKey {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_hardened_idx(0)?,
            private_key,
            chain_code,
        })
    }

    /// Derive a child private key
    pub fn derive_priv<P: AsRef<[ChildNumber]>>(
        &self,
        path: &P,
    ) -> Result<ExtendedEd25519PrivKey, Error> {
        let mut key = self.clone();
        for &child in path.as_ref() {
            key = key.ckd_priv(child)?;
        }
        Ok(key)
    }

    /// Child key derivation (always hardened for Ed25519)
    pub fn ckd_priv(&self, child: ChildNumber) -> Result<ExtendedEd25519PrivKey, Error> {
        // Ed25519 only supports hardened derivation
        if !child.is_hardened() {
            return Err(Error::NonHardenedNotSupported);
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(self.chain_code.as_ref());

        // For Ed25519: data = 0x00 || private_key || index
        hmac_engine.input(&[0x00]);
        hmac_engine.input(self.private_key.as_ref());
        hmac_engine.input(&u32::from(child).to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let hmac_bytes = hmac_result.as_byte_array();

        // First 32 bytes become the new private key seed
        let private_key: [u8; 32] = hmac_bytes[..32].try_into().expect("HMAC output is 64 bytes");

        // Last 32 bytes become the new chain code
        let chain_code =
            ChainCode::from_bytes(hmac_bytes[32..].try_into().expect("HMAC output is 64 bytes"));

        // Calculate parent fingerprint from public key
        let parent_fingerprint = self.fingerprint()?;

        Ok(ExtendedEd25519PrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number: child,
            private_key,
            chain_code,
        })
    }

    /// Get the public key for this private key
    pub fn public_key(&self) -> Result<VerifyingKey, Error> {
        let signing_key = SigningKey::from_bytes(&self.private_key);
        Ok(signing_key.verifying_key())
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Result<Fingerprint, Error> {
        use dashcore_hashes::{hash160, Hash};

        let pubkey = self.public_key()?;
        let hash = hash160::Hash::hash(&pubkey.to_bytes());
        Ok(Fingerprint::from_bytes(hash[..4].try_into().expect("hash160 has enough bytes")))
    }

    /// Get identifier (hash160 of public key)
    pub fn identifier(&self) -> Result<[u8; 20], Error> {
        use dashcore_hashes::{hash160, Hash};

        let pubkey = self.public_key()?;
        let hash = hash160::Hash::hash(&pubkey.to_bytes());
        Ok(hash.to_byte_array())
    }

    /// Encode the extended private key
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(78);

        // Version bytes (4 bytes) - Custom for Ed25519
        match self.network {
            Network::Dash => result.extend_from_slice(&[0x03, 0xB8, 0xC0, 0x0C]), // Custom version
            _ => result.extend_from_slice(&[0x03, 0xB8, 0xC0, 0x0D]),             // Testnet version
        }

        // Depth (1 byte)
        result.push(self.depth);

        // Parent fingerprint (4 bytes)
        result.extend_from_slice(self.parent_fingerprint.as_ref());

        // Child number (4 bytes)
        result.extend_from_slice(&u32::from(self.child_number).to_be_bytes());

        // Chain code (32 bytes)
        result.extend_from_slice(self.chain_code.as_ref());

        // Private key with 0x00 prefix (33 bytes)
        result.push(0x00);
        result.extend_from_slice(self.private_key.as_ref());

        result
    }

    /// Decode an extended private key
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        // Check version and determine network
        let network = match &data[0..4] {
            [0x03, 0xB8, 0xC0, 0x0C] => Network::Dash,
            [0x03, 0xB8, 0xC0, 0x0D] => Network::Testnet,
            version => {
                let mut v = [0u8; 4];
                v.copy_from_slice(version);
                return Err(Error::UnknownVersion(v));
            }
        };

        let depth = data[4];

        let parent_fingerprint = Fingerprint::from_bytes(
            data[5..9].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?,
        );

        let child_number_u32 = u32::from_be_bytes(
            data[9..13].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?,
        );

        // Ed25519 only uses hardened keys
        if child_number_u32 & (1 << 31) == 0 && depth > 0 {
            return Err(Error::NonHardenedNotSupported);
        }

        let child_number = if depth == 0 {
            ChildNumber::from_hardened_idx(0)?
        } else {
            ChildNumber::from_hardened_idx(child_number_u32 & !(1 << 31))?
        };

        let chain_code = ChainCode::from_bytes(
            data[13..45].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?,
        );

        // Check for 0x00 prefix on private key
        if data[45] != 0x00 {
            return Err(Error::InvalidPrivateKeyPrefix);
        }

        let private_key: [u8; 32] =
            data[46..78].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?;

        Ok(ExtendedEd25519PrivKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            private_key,
            chain_code,
        })
    }
}

impl fmt::Debug for ExtendedEd25519PrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedEd25519PrivKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .finish()
    }
}

/// Extended Ed25519 public key for SLIP-0010
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtendedEd25519PubKey {
    /// Network this key is for
    pub network: Network,
    /// Depth in the derivation tree
    pub depth: u8,
    /// Parent fingerprint
    pub parent_fingerprint: Fingerprint,
    /// Child number used to derive this key
    pub child_number: ChildNumber,
    /// The Ed25519 public key
    pub public_key: VerifyingKey,
    /// Chain code for derivation
    pub chain_code: ChainCode,
}

impl ExtendedEd25519PubKey {
    /// Create from a private key
    pub fn from_priv(priv_key: &ExtendedEd25519PrivKey) -> Result<Self, Error> {
        Ok(ExtendedEd25519PubKey {
            network: priv_key.network,
            depth: priv_key.depth,
            parent_fingerprint: priv_key.parent_fingerprint,
            child_number: priv_key.child_number,
            public_key: priv_key.public_key()?,
            chain_code: priv_key.chain_code,
        })
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        use dashcore_hashes::{hash160, Hash};

        let hash = hash160::Hash::hash(self.public_key.as_ref());
        Fingerprint::from_bytes(hash[..4].try_into().expect("hash160 has enough bytes"))
    }

    /// Get identifier (hash160 of public key)
    pub fn identifier(&self) -> [u8; 20] {
        use dashcore_hashes::{hash160, Hash};

        let hash = hash160::Hash::hash(self.public_key.as_ref());
        hash.to_byte_array()
    }

    /// Encode the extended public key
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(78);

        // Version bytes (4 bytes) - Custom for Ed25519 public
        match self.network {
            Network::Dash => result.extend_from_slice(&[0x03, 0xB8, 0xC4, 0x3E]), // Custom public version
            _ => result.extend_from_slice(&[0x03, 0xB8, 0xC4, 0x3F]), // Testnet public version
        }

        // Depth (1 byte)
        result.push(self.depth);

        // Parent fingerprint (4 bytes)
        result.extend_from_slice(self.parent_fingerprint.as_ref());

        // Child number (4 bytes)
        result.extend_from_slice(&u32::from(self.child_number).to_be_bytes());

        // Chain code (32 bytes)
        result.extend_from_slice(self.chain_code.as_ref());

        // Public key with 0x00 prefix for consistency (33 bytes)
        result.push(0x00);
        result.extend_from_slice(self.public_key.as_ref());

        result
    }

    /// Decode an extended public key
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        // Check version and determine network
        let network = match &data[0..4] {
            [0x03, 0xB8, 0xC4, 0x3E] => Network::Dash,
            [0x03, 0xB8, 0xC4, 0x3F] => Network::Testnet,
            version => {
                let mut v = [0u8; 4];
                v.copy_from_slice(version);
                return Err(Error::UnknownVersion(v));
            }
        };

        let depth = data[4];

        let parent_fingerprint = Fingerprint::from_bytes(
            data[5..9].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?,
        );

        let child_number_u32 = u32::from_be_bytes(
            data[9..13].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?,
        );

        let child_number = if depth == 0 {
            ChildNumber::from_hardened_idx(0)?
        } else {
            ChildNumber::from_hardened_idx(child_number_u32 & !(1 << 31))?
        };

        let chain_code = ChainCode::from_bytes(
            data[13..45].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?,
        );

        // Check for 0x00 prefix on public key (for consistency)
        if data[45] != 0x00 {
            return Err(Error::InvalidPublicKeyPrefix);
        }

        let public_key_bytes: [u8; 32] =
            data[46..78].try_into().map_err(|_| Error::WrongExtendedKeyLength(data.len()))?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| Error::Ed25519Error(e.to_string()))?;

        Ok(ExtendedEd25519PubKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            public_key,
            chain_code,
        })
    }
}

/// SLIP-0010 Ed25519 error type
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid seed length (must be at least 16 bytes)
    InvalidSeedLength(usize),
    /// Invalid child number
    InvalidChildNumber(u32),
    /// Invalid child number format
    InvalidChildNumberFormat,
    /// Invalid derivation path format
    InvalidDerivationPathFormat,
    /// Non-hardened derivation not supported for Ed25519
    NonHardenedNotSupported,
    /// Unknown version bytes
    UnknownVersion([u8; 4]),
    /// Wrong extended key length
    WrongExtendedKeyLength(usize),
    /// Invalid private key prefix (expected 0x00)
    InvalidPrivateKeyPrefix,
    /// Invalid public key prefix (expected 0x00)
    InvalidPublicKeyPrefix,
    /// Ed25519 cryptographic error
    Ed25519Error(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidSeedLength(len) => {
                write!(f, "Invalid seed length: {} (must be at least 16 bytes)", len)
            }
            Error::InvalidChildNumber(n) => {
                write!(f, "Invalid child number: {} (must be less than 2^31)", n)
            }
            Error::InvalidChildNumberFormat => {
                write!(f, "Invalid child number format")
            }
            Error::InvalidDerivationPathFormat => {
                write!(f, "Invalid derivation path format")
            }
            Error::NonHardenedNotSupported => {
                write!(f, "Ed25519 only supports hardened derivation")
            }
            Error::UnknownVersion(v) => {
                write!(f, "Unknown version bytes: {:?}", v)
            }
            Error::WrongExtendedKeyLength(len) => {
                write!(f, "Wrong extended key length: {} (expected 78)", len)
            }
            Error::InvalidPrivateKeyPrefix => {
                write!(f, "Invalid private key prefix (expected 0x00)")
            }
            Error::InvalidPublicKeyPrefix => {
                write!(f, "Invalid public key prefix (expected 0x00)")
            }
            Error::Ed25519Error(msg) => {
                write!(f, "Ed25519 error: {}", msg)
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {}

impl From<crate::bip32::Error> for Error {
    fn from(e: crate::bip32::Error) -> Self {
        match e {
            crate::bip32::Error::InvalidChildNumber(n) => Error::InvalidChildNumber(n),
            crate::bip32::Error::InvalidChildNumberFormat => Error::InvalidChildNumberFormat,
            crate::bip32::Error::InvalidDerivationPathFormat => Error::InvalidDerivationPathFormat,
            _ => Error::Ed25519Error(format!("BIP32 error: {}", e)),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedEd25519PrivKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.encode())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedEd25519PrivKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = Vec::<u8>::deserialize(deserializer)?;
        ExtendedEd25519PrivKey::decode(&bytes)
            .map_err(|e| D::Error::custom(format!("Failed to decode Ed25519 private key: {}", e)))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedEd25519PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.encode())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedEd25519PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = Vec::<u8>::deserialize(deserializer)?;
        ExtendedEd25519PubKey::decode(&bytes)
            .map_err(|e| D::Error::custom(format!("Failed to decode Ed25519 public key: {}", e)))
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedEd25519PrivKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        self.private_key.encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedEd25519PrivKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(ExtendedEd25519PrivKey {
            network: Network::decode(decoder)?,
            depth: u8::decode(decoder)?,
            parent_fingerprint: Fingerprint::decode(decoder)?,
            child_number: ChildNumber::decode(decoder)?,
            private_key: <[u8; 32]>::decode(decoder)?,
            chain_code: ChainCode::decode(decoder)?,
        })
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedEd25519PubKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        self.public_key.as_bytes().encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedEd25519PubKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        let public_key_bytes = <[u8; 32]>::decode(decoder)?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| bincode::error::DecodeError::OtherString(e.to_string()))?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedEd25519PubKey {
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
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedEd25519PrivKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedEd25519PubKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

/// Test cases from SLIP-0010 https://github.com/satoshilabs/slips/blob/master/slip-0010.md
/// Just relevant cases, Ed25519, private key
#[cfg(test)]
mod test {
    use super::*;

    const CASE_1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn case1_m() {
        assert_eq!(
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            derive_ed25519_private_key_hex(CASE_1_SEED, &[])
        );
    }

    #[test]
    fn case1_m_0h() {
        assert_eq!(
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0])
        );
    }

    #[test]
    fn case1_m_0h_1h() {
        assert_eq!(
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0, 1])
        );
    }

    #[test]
    fn case1_m_0h_1h_2h() {
        assert_eq!(
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0, 1, 2])
        );
    }

    #[test]
    fn case1_m_0h_1h_2h_2h() {
        assert_eq!(
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0, 1, 2, 2])
        );
    }

    #[test]
    fn case1_m_0h_1h_2h_1000000000h() {
        assert_eq!(
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0, 1, 2, 2, 1000000000])
        );
    }

    #[test]
    fn case1_m_0h_already_hardened() {
        assert_eq!(
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0]),
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0x80000000])
        );
    }

    #[test]
    fn case1_m_0h_1h_already_hardened() {
        assert_eq!(
            derive_ed25519_private_key_hex(CASE_1_SEED, &[1]),
            derive_ed25519_private_key_hex(CASE_1_SEED, &[0x80000001])
        );
    }

    const CASE_2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    #[test]
    fn case2_m() {
        assert_eq!(
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            derive_ed25519_private_key_hex(CASE_2_SEED, &[])
        );
    }

    #[test]
    fn case2_m_0h() {
        assert_eq!(
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            derive_ed25519_private_key_hex(CASE_2_SEED, &[0])
        );
    }

    #[test]
    fn case2_m_0h_2147483647h() {
        assert_eq!(
            "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            derive_ed25519_private_key_hex(CASE_2_SEED, &[0, 2147483647])
        );
    }

    #[test]
    fn case2_m_0h_2147483647h_1h() {
        assert_eq!(
            "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            derive_ed25519_private_key_hex(CASE_2_SEED, &[0, 2147483647, 1])
        );
    }

    #[test]
    fn case2_m_0h_2147483647h_1h_2147483646h() {
        assert_eq!(
            "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            derive_ed25519_private_key_hex(CASE_2_SEED, &[0, 2147483647, 1, 2147483646])
        );
    }

    #[test]
    fn case2_m_0h_2147483647h_1h_2147483646h_2h() {
        assert_eq!(
            "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            derive_ed25519_private_key_hex(CASE_2_SEED, &[0, 2147483647, 1, 2147483646, 2])
        );
    }

    fn derive_ed25519_private_key(seed: &[u8], indexes: &[u32]) -> [u8; 32] {
        let master = ExtendedEd25519PrivKey::new_master(Network::Dash, seed).unwrap();

        let mut current = master;
        for &index in indexes {
            // Handle both hardened (0x80000000+) and non-hardened indices
            let child_number = if index & 0x80000000 != 0 {
                // Already has hardening bit set, remove it for from_hardened_idx
                ChildNumber::from_hardened_idx(index & !0x80000000).unwrap()
            } else {
                // Normal index, add hardening
                ChildNumber::from_hardened_idx(index).unwrap()
            };
            current = current.ckd_priv(child_number).unwrap();
        }

        current.private_key
    }

    fn derive_ed25519_private_key_hex(seed_hex: &str, indexes: &[u32]) -> String {
        let seed = hex::decode(seed_hex).unwrap();

        let private_key = derive_ed25519_private_key(&seed, indexes);

        hex::encode(private_key)
    }
}
