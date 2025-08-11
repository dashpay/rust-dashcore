use crate::bip32::{ChainCode, ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use crate::Network;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};

#[cfg(feature = "bincode")]
use bincode::{BorrowDecode, Decode, Encode};
use dashcore_hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RootExtendedPrivKey {
    pub root_private_key: secp256k1::SecretKey,
    pub root_chain_code: ChainCode,
}

impl RootExtendedPrivKey {
    /// Create a new RootExtendedPrivKey
    pub fn new(root_private_key: secp256k1::SecretKey, root_chain_code: ChainCode) -> Self {
        Self {
            root_private_key,
            root_chain_code,
        }
    }

    /// Create a new master key from seed
    pub fn new_master(seed: &[u8]) -> Result<Self, crate::error::Error> {
        // Seed should be between 128 and 512 bits (16 to 64 bytes)
        if seed.len() < 16 || seed.len() > 64 {
            return Err(crate::error::Error::InvalidParameter(format!(
                "Invalid seed length: {} bytes",
                seed.len()
            )));
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        // Split the result into private key (first 32 bytes) and chain code (last 32 bytes)
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&hmac_result[..32]);
        let private_key =
            secp256k1::SecretKey::from_byte_array(&private_key_bytes).map_err(|e| {
                crate::error::Error::InvalidParameter(format!("Invalid private key: {}", e))
            })?;

        let mut chain_code_bytes = [0u8; 32];
        chain_code_bytes.copy_from_slice(&hmac_result[32..64]);
        let chain_code = ChainCode::from(chain_code_bytes);

        Ok(Self {
            root_private_key: private_key,
            root_chain_code: chain_code,
        })
    }

    /// Create from an ExtendedPrivKey (must be depth 0)
    pub fn from_extended_priv_key(key: &ExtendedPrivKey) -> Self {
        Self {
            root_private_key: key.private_key,
            root_chain_code: key.chain_code,
        }
    }

    /// Convert to ExtendedPrivKey for a specific network
    pub fn to_extended_priv_key(&self, network: Network) -> ExtendedPrivKey {
        ExtendedPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from(0),
            private_key: self.root_private_key,
            chain_code: self.root_chain_code,
        }
    }

    /// Get the corresponding public key
    pub fn to_root_extended_pub_key(&self) -> RootExtendedPubKey {
        let secp = Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &self.root_private_key);
        RootExtendedPubKey {
            root_public_key: public_key,
            root_chain_code: self.root_chain_code,
        }
    }
}

#[cfg(feature = "bincode")]
impl Encode for RootExtendedPrivKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        // Encode the private key as 32 bytes
        let private_key_bytes = self.root_private_key.secret_bytes();
        bincode::Encode::encode(&private_key_bytes, encoder)?;

        // Encode the chain code
        bincode::Encode::encode(&self.root_chain_code, encoder)?;

        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl Decode for RootExtendedPrivKey {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // Decode the private key bytes
        let private_key_bytes: [u8; 32] = bincode::Decode::decode(decoder)?;
        let root_private_key =
            secp256k1::SecretKey::from_byte_array(&private_key_bytes).map_err(|e| {
                bincode::error::DecodeError::OtherString(format!("Invalid private key: {}", e))
            })?;

        // Decode the chain code
        let root_chain_code: ChainCode = bincode::Decode::decode(decoder)?;

        Ok(Self {
            root_private_key,
            root_chain_code,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de> BorrowDecode<'de> for RootExtendedPrivKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // For borrowed decode, we still need to copy the data since secp256k1::SecretKey
        // doesn't support borrowing from the decoder
        Self::decode(decoder)
    }
}

pub trait FromOnNetwork<T>: Sized {
    /// Converts to this type from the input type.
    fn from_on_network(value: T, network: Network) -> Self;
}

pub trait IntoOnNetwork<T>: Sized {
    /// Converts this type into the (usually inferred) input type.
    fn into_on_network(self, network: Network) -> T;
}

impl<T, U> IntoOnNetwork<U> for T
where
    U: FromOnNetwork<T>,
{
    /// Calls `U::from_on_network(self)`.
    fn into_on_network(self, network: Network) -> U {
        U::from_on_network(self, network)
    }
}

impl FromOnNetwork<RootExtendedPrivKey> for ExtendedPrivKey {
    fn from_on_network(value: RootExtendedPrivKey, network: Network) -> Self {
        ExtendedPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from(0),
            private_key: value.root_private_key,
            chain_code: value.root_chain_code,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RootExtendedPubKey {
    pub root_public_key: secp256k1::PublicKey,
    pub root_chain_code: ChainCode,
}

impl RootExtendedPubKey {
    /// Create a new RootExtendedPubKey
    pub fn new(root_public_key: secp256k1::PublicKey, root_chain_code: ChainCode) -> Self {
        Self {
            root_public_key,
            root_chain_code,
        }
    }

    /// Create from an ExtendedPubKey (must be depth 0)
    pub fn from_extended_pub_key(key: &ExtendedPubKey) -> Self {
        Self {
            root_public_key: key.public_key,
            root_chain_code: key.chain_code,
        }
    }

    /// Convert to ExtendedPubKey for a specific network
    pub fn to_extended_pub_key(&self, network: Network) -> ExtendedPubKey {
        ExtendedPubKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from(0),
            public_key: self.root_public_key,
            chain_code: self.root_chain_code,
        }
    }
}

#[cfg(feature = "bincode")]
impl Encode for RootExtendedPubKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        // Encode the public key as serialized bytes (33 bytes compressed)
        let public_key_bytes = self.root_public_key.serialize();
        bincode::Encode::encode(&public_key_bytes, encoder)?;

        // Encode the chain code
        bincode::Encode::encode(&self.root_chain_code, encoder)?;

        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl Decode for RootExtendedPubKey {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // Decode the public key bytes
        let public_key_bytes: [u8; 33] = bincode::Decode::decode(decoder)?;
        let root_public_key = secp256k1::PublicKey::from_slice(&public_key_bytes).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid public key: {}", e))
        })?;

        // Decode the chain code
        let root_chain_code: ChainCode = bincode::Decode::decode(decoder)?;

        Ok(Self {
            root_public_key,
            root_chain_code,
        })
    }
}

#[cfg(feature = "bincode")]
impl<'de> BorrowDecode<'de> for RootExtendedPubKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // For borrowed decode, we still need to copy the data since secp256k1::PublicKey
        // doesn't support borrowing from the decoder
        Self::decode(decoder)
    }
}

impl FromOnNetwork<RootExtendedPubKey> for ExtendedPubKey {
    fn from_on_network(value: RootExtendedPubKey, network: Network) -> Self {
        ExtendedPubKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from(0),
            public_key: value.root_public_key,
            chain_code: value.root_chain_code,
        }
    }
}
