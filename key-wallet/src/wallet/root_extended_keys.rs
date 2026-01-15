use crate::bip32::{ChainCode, ChildNumber, ExtendedPrivKey, ExtendedPubKey};
#[cfg(feature = "bls")]
use crate::derivation_bls_bip32::ExtendedBLSPrivKey;
use crate::wallet::WalletType;
use crate::{Error, Network, Wallet};
use alloc::borrow::Cow;
#[cfg(feature = "bincode")]
use bincode::{BorrowDecode, Decode, Encode};
#[cfg(feature = "bls")]
use dashcore::blsful::Bls12381G2Impl;
use dashcore_hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::Secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RootExtendedPrivKey {
    pub root_private_key: secp256k1::SecretKey,
    pub root_chain_code: ChainCode,
}

impl zeroize::Zeroize for RootExtendedPrivKey {
    fn zeroize(&mut self) {
        self.root_private_key.non_secure_erase();
        self.root_chain_code.zeroize();
    }
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

    /// Convert to BLS extended private key for a specific network
    /// This converts the secp256k1 private key to a BLS12-381 private key
    /// Note: This is a cross-curve conversion and should be used carefully
    #[cfg(feature = "bls")]
    pub fn to_bls_extended_priv_key(&self, network: Network) -> Result<ExtendedBLSPrivKey, Error> {
        // Convert secp256k1 private key bytes to BLS private key
        // Using from_le_bytes for little-endian byte order
        // Note: from_le_bytes returns a CtOption (constant-time option) for security
        let bls_private_key_option = dashcore::blsful::SecretKey::<Bls12381G2Impl>::from_le_bytes(
            &self.root_private_key.secret_bytes(),
        );

        // Convert CtOption to Result
        let bls_private_key = if bls_private_key_option.is_some().into() {
            bls_private_key_option.unwrap()
        } else {
            return Err(Error::InvalidParameter(
                "Failed to convert to BLS key: invalid key bytes".to_string(),
            ));
        };

        Ok(ExtendedBLSPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from(0),
            private_key: bls_private_key,
            chain_code: self.root_chain_code,
        })
    }

    /// Convert to EdDSA/Ed25519 extended private key for a specific network
    /// This converts the secp256k1 private key to an Ed25519 private key
    /// Note: This is a cross-curve conversion and should be used carefully
    #[cfg(feature = "eddsa")]
    pub fn to_eddsa_extended_priv_key(
        &self,
        network: Network,
    ) -> Result<crate::derivation_slip10::ExtendedEd25519PrivKey, Error> {
        use crate::derivation_slip10::ExtendedEd25519PrivKey;

        // Convert secp256k1 private key bytes to Ed25519 seed
        // Ed25519 uses 32-byte seeds to generate keys
        let seed_bytes = self.root_private_key.secret_bytes();

        // Create Ed25519 extended private key from seed using new_master
        let eddsa_key = ExtendedEd25519PrivKey::new_master(network, &seed_bytes).map_err(|e| {
            Error::InvalidParameter(format!("Failed to convert to EdDSA key: {:?}", e))
        })?;

        Ok(eddsa_key)
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
impl<C> Decode<C> for RootExtendedPrivKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
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
impl<'de, C> BorrowDecode<'de, C> for RootExtendedPrivKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // For borrowed decode, we still need to copy the data since secp256k1::SecretKey
        // doesn't support borrowing from the decoder
        <Self as Decode<C>>::decode(decoder)
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

impl zeroize::Zeroize for RootExtendedPubKey {
    fn zeroize(&mut self) {
        // Replace the public key with a dummy value (generator point G)
        // This is a best-effort zeroization since PublicKey doesn't implement Zeroize
        self.root_public_key = secp256k1::PublicKey::from_slice(&[
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .expect("hardcoded generator point should be valid");

        // Zeroize the chain code
        self.root_chain_code.zeroize();
    }
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
impl<C> Decode<C> for RootExtendedPubKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
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
impl<'de, C> BorrowDecode<'de, C> for RootExtendedPubKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // For borrowed decode, we still need to copy the data since secp256k1::PublicKey
        // doesn't support borrowing from the decoder
        <Self as Decode<C>>::decode(decoder)
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

impl Wallet {
    /// Get the root extended public key from the wallet type
    pub fn root_extended_pub_key(&self) -> RootExtendedPubKey {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.to_root_extended_pub_key(),
            WalletType::MnemonicWithPassphrase {
                root_extended_public_key,
                ..
            } => root_extended_public_key.clone(),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => root_extended_private_key.to_root_extended_pub_key(),
            WalletType::ExtendedPrivKey(key) => key.to_root_extended_pub_key(),
            WalletType::ExternalSignable(key) => key.clone(),
            WalletType::WatchOnly(key) => key.clone(),
        }
    }

    /// Get the root extended public key from the wallet type as Cow
    pub fn root_extended_pub_key_cow(&self) -> Cow<'_, RootExtendedPubKey> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Cow::Owned(root_extended_private_key.to_root_extended_pub_key()),
            WalletType::MnemonicWithPassphrase {
                root_extended_public_key,
                ..
            } => Cow::Borrowed(root_extended_public_key),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Cow::Owned(root_extended_private_key.to_root_extended_pub_key()),
            WalletType::ExtendedPrivKey(root_extended_priv_key) => {
                Cow::Owned(root_extended_priv_key.to_root_extended_pub_key())
            }
            WalletType::ExternalSignable(root_extended_public_key) => {
                Cow::Borrowed(root_extended_public_key)
            }
            WalletType::WatchOnly(root_extended_public_key) => {
                Cow::Borrowed(root_extended_public_key)
            }
        }
    }

    /// Get the root extended private key from the wallet type
    pub(crate) fn root_extended_priv_key(&self) -> crate::Result<&RootExtendedPrivKey> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key),
            WalletType::MnemonicWithPassphrase {
                ..
            } => Err(Error::InvalidParameter(
                "Mnemonic with passphrase requires passphrase to derive private key".into(),
            )),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key),
            WalletType::ExtendedPrivKey(key) => Ok(key),
            WalletType::ExternalSignable(_) => {
                Err(Error::InvalidParameter("External signable wallet has no private key".into()))
            }
            WalletType::WatchOnly(_) => {
                Err(Error::InvalidParameter("Watch-only wallet has no private key".into()))
            }
        }
    }

    /// Get the root extended private key with passphrase callback for MnemonicWithPassphrase
    pub fn root_extended_priv_key_with_callback<F>(
        &self,
        passphrase_callback: F,
    ) -> crate::Result<RootExtendedPrivKey>
    where
        F: FnOnce() -> Result<String, Error>,
    {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key.clone()),
            WalletType::MnemonicWithPassphrase {
                mnemonic,
                ..
            } => {
                // Request passphrase via callback
                let passphrase = passphrase_callback()?;
                let seed = mnemonic.to_seed(&passphrase);
                Ok(RootExtendedPrivKey::new_master(&seed)?)
            }
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key.clone()),
            WalletType::ExtendedPrivKey(key) => Ok(key.clone()),
            WalletType::ExternalSignable(_) => {
                Err(Error::InvalidParameter("External signable wallet has no private key".into()))
            }
            WalletType::WatchOnly(_) => {
                Err(Error::InvalidParameter("Watch-only wallet has no private key".into()))
            }
        }
    }
}
