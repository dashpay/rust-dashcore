use std::borrow::Cow;

use crate::bip32::{ChainCode, ChildNumber, ExtendedPrivKey, ExtendedPubKey};
#[cfg(feature = "bls")]
use crate::derivation_bls_bip32::ExtendedBLSPrivKey;
use crate::wallet::WalletType;
use crate::{Error, Network, Wallet};
#[cfg(feature = "bincode")]
use bincode::{BorrowDecode, Decode, Encode};
#[cfg(feature = "bls")]
use dashcore::bls_sig_utils::BlsSkBytes;
use dashcore::ecdsa::{EcdsaPublicKey, EcdsaSecretKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RootExtendedPrivKey {
    pub root_private_key: EcdsaSecretKey,
    pub root_chain_code: ChainCode,
}

impl Zeroize for RootExtendedPrivKey {
    fn zeroize(&mut self) {
        self.root_private_key.zeroize();
        self.root_chain_code.zeroize();
    }
}

impl Drop for RootExtendedPrivKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RootExtendedPrivKey {
    /// Create a new RootExtendedPrivKey
    pub fn new(root_private_key: secp256k1::SecretKey, root_chain_code: ChainCode) -> Self {
        Self {
            root_private_key: root_private_key.into(),
            root_chain_code,
        }
    }

    /// Create a new master key from seed
    pub fn new_master(seed: &[u8]) -> Result<Self, crate::error::Error> {
        // The network only picks the serialization version, which is dropped.
        let master = ExtendedPrivKey::new_master(Network::Mainnet, seed)?;
        Ok(Self::from_extended_priv_key(&master))
    }

    /// Create from an ExtendedPrivKey (must be depth 0)
    pub fn from_extended_priv_key(key: &ExtendedPrivKey) -> Self {
        Self {
            root_private_key: key.private_key.into(),
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
            private_key: self.root_private_key.into(),
            chain_code: self.root_chain_code,
        }
    }

    /// Convert to BLS extended private key for a specific network
    /// This converts the secp256k1 private key to a BLS12-381 private key
    /// Note: This is a cross-curve conversion and should be used carefully
    #[cfg(feature = "bls")]
    pub fn to_bls_extended_priv_key(&self, network: Network) -> Result<ExtendedBLSPrivKey, Error> {
        // Convert secp256k1 private key bytes to BLS private key
        // The scalar is read little-endian from the secp secret, the bag holds
        // big-endian, so the bytes are reversed going in.
        let mut scalar_bytes = secp256k1::SecretKey::from(self.root_private_key).to_secret_bytes();
        scalar_bytes.reverse();

        ExtendedBLSPrivKey::from_parts(
            network,
            0,
            Default::default(),
            ChildNumber::from(0),
            BlsSkBytes::from_bytes(scalar_bytes),
            self.root_chain_code,
        )
        .map_err(|_| {
            Error::InvalidParameter("Failed to convert to BLS key: invalid key bytes".to_string())
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
        let seed_bytes = secp256k1::SecretKey::from(self.root_private_key).to_secret_bytes();

        // Create Ed25519 extended private key from seed using new_master
        let eddsa_key = ExtendedEd25519PrivKey::new_master(network, &seed_bytes).map_err(|e| {
            Error::InvalidParameter(format!("Failed to convert to EdDSA key: {:?}", e))
        })?;

        Ok(eddsa_key)
    }

    /// Get the corresponding public key
    pub fn to_root_extended_pub_key(&self) -> RootExtendedPubKey {
        let public_key = secp256k1::PublicKey::from_secret_key(&self.root_private_key.into());
        RootExtendedPubKey {
            root_public_key: public_key.into(),
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
        let private_key_bytes = secp256k1::SecretKey::from(self.root_private_key).to_secret_bytes();
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
            secp256k1::SecretKey::from_secret_bytes(private_key_bytes).map_err(|e| {
                bincode::error::DecodeError::OtherString(format!("Invalid private key: {}", e))
            })?;

        // Decode the chain code
        let root_chain_code: ChainCode = bincode::Decode::decode(decoder)?;

        Ok(Self {
            root_private_key: root_private_key.into(),
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
            private_key: value.root_private_key.into(),
            chain_code: value.root_chain_code,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RootExtendedPubKey {
    pub root_public_key: EcdsaPublicKey,
    pub root_chain_code: ChainCode,
}

impl zeroize::Zeroize for RootExtendedPubKey {
    fn zeroize(&mut self) {
        // Replace the public key with a dummy value (generator point G)
        // This is a best-effort zeroization since PublicKey doesn't implement Zeroize
        self.root_public_key = secp256k1::PublicKey::from_byte_array_compressed([
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .expect("hardcoded generator point should be valid")
        .into();

        // Zeroize the chain code
        self.root_chain_code.zeroize();
    }
}

impl RootExtendedPubKey {
    /// Create a new RootExtendedPubKey
    pub fn new(root_public_key: secp256k1::PublicKey, root_chain_code: ChainCode) -> Self {
        Self {
            root_public_key: root_public_key.into(),
            root_chain_code,
        }
    }

    /// Create from an ExtendedPubKey (must be depth 0)
    pub fn from_extended_pub_key(key: &ExtendedPubKey) -> Self {
        Self {
            root_public_key: key.public_key.into(),
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
            public_key: self.root_public_key.into(),
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
        let public_key_bytes = secp256k1::PublicKey::from(self.root_public_key).serialize();
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
        let root_public_key = secp256k1::PublicKey::from_byte_array_compressed(public_key_bytes)
            .map_err(|e| {
                bincode::error::DecodeError::OtherString(format!("Invalid public key: {}", e))
            })?;

        // Decode the chain code
        let root_chain_code: ChainCode = bincode::Decode::decode(decoder)?;

        Ok(Self {
            root_public_key: root_public_key.into(),
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
            public_key: value.root_public_key.into(),
            chain_code: value.root_chain_code,
        }
    }
}

impl Wallet {
    /// Get the root extended public key from the wallet type.
    ///
    /// The [`WalletType::WatchOnly`] and [`WalletType::ExternalSignable`] unit
    /// variants carry no key material — they return an error here because there
    /// is nothing to return. The wallet's identity is available via
    /// [`Wallet::wallet_id`] for those cases.
    pub fn root_extended_pub_key(&self) -> crate::Result<RootExtendedPubKey> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key.to_root_extended_pub_key()),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key.to_root_extended_pub_key()),
            WalletType::ExtendedPrivKey(key) => Ok(key.to_root_extended_pub_key()),
            WalletType::ExternalSignable | WalletType::WatchOnly => Err(Error::InvalidParameter(
                "Root extended public key is not available for watch-only or \
                     external-signable wallets; use wallet.wallet_id for identity and \
                     per-account xpubs for derivation"
                    .into(),
            )),
        }
    }

    /// Get the root extended public key from the wallet type as Cow.
    ///
    /// See [`Wallet::root_extended_pub_key`] for the unit-variant behavior.
    pub fn root_extended_pub_key_cow(&self) -> crate::Result<Cow<'_, RootExtendedPubKey>> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(Cow::Owned(root_extended_private_key.to_root_extended_pub_key())),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(Cow::Owned(root_extended_private_key.to_root_extended_pub_key())),
            WalletType::ExtendedPrivKey(root_extended_priv_key) => {
                Ok(Cow::Owned(root_extended_priv_key.to_root_extended_pub_key()))
            }
            WalletType::ExternalSignable | WalletType::WatchOnly => Err(Error::InvalidParameter(
                "Root extended public key is not available for watch-only or \
                     external-signable wallets; use wallet.wallet_id for identity and \
                     per-account xpubs for derivation"
                    .into(),
            )),
        }
    }

    /// Get the root extended private key from the wallet type
    pub(crate) fn root_extended_priv_key(&self) -> crate::Result<&RootExtendedPrivKey> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key),
            WalletType::ExtendedPrivKey(key) => Ok(key),
            WalletType::ExternalSignable => {
                Err(Error::InvalidParameter("External signable wallet has no private key".into()))
            }
            WalletType::WatchOnly => {
                Err(Error::InvalidParameter("Watch-only wallet has no private key".into()))
            }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use hex_conservative::{hex, DisplayHex};

    /// BIP32 test vector 1.
    const SEED: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
    const SK_HEX: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    const PK_HEX: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
    const PK_UNCOMPRESSED_HEX: &str = "0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2\
                                       3cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281";
    const CHAIN_CODE_HEX: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

    /// Both root keys serialize as hex in human-readable formats and as bare
    /// fixed-size tuples otherwise. The public key is in compressed form.
    #[test]
    fn serde_layout_of_root_keys() {
        let sk = RootExtendedPrivKey::new_master(&SEED).expect("master key");
        let pk = sk.to_root_extended_pub_key();

        let sk_json = serde_json::to_string(&sk).expect("serialize private key");
        assert_eq!(
            sk_json,
            format!(
                "{{\"root_private_key\":\"{}\",\"root_chain_code\":\"{}\"}}",
                SK_HEX, CHAIN_CODE_HEX
            )
        );
        let pk_json = serde_json::to_string(&pk).expect("serialize public key");
        assert_eq!(
            pk_json,
            format!(
                "{{\"root_public_key\":\"{}\",\"root_chain_code\":\"{}\"}}",
                PK_HEX, CHAIN_CODE_HEX
            )
        );

        let config = bincode::config::standard();
        let chain_code = format!("40{}", CHAIN_CODE_HEX.as_bytes().to_lower_hex_string());
        let sk_bin = bincode::serde::encode_to_vec(&sk, config).expect("encode private key");
        assert_eq!(sk_bin.to_lower_hex_string(), format!("{}{}", SK_HEX, chain_code));
        let pk_bin = bincode::serde::encode_to_vec(&pk, config).expect("encode public key");
        assert_eq!(pk_bin.to_lower_hex_string(), format!("{}{}", PK_HEX, chain_code));

        let sk_back: RootExtendedPrivKey =
            serde_json::from_str(&sk_json).expect("parse private key");
        assert_eq!(sk_back.root_private_key, sk.root_private_key);
        let (sk_back, _): (RootExtendedPrivKey, _) =
            bincode::serde::decode_from_slice(&sk_bin, config).expect("decode private key");
        assert_eq!(sk_back.root_private_key, sk.root_private_key);
        let pk_back: RootExtendedPubKey = serde_json::from_str(&pk_json).expect("parse public key");
        assert_eq!(pk_back.root_public_key, pk.root_public_key);
        let (pk_back, _): (RootExtendedPubKey, _) =
            bincode::serde::decode_from_slice(&pk_bin, config).expect("decode public key");
        assert_eq!(pk_back.root_public_key, pk.root_public_key);
    }

    /// Both root keys take hex in either case, and the public key also takes
    /// its uncompressed encoding. Malformed or invalid keys are rejected in
    /// both formats.
    #[test]
    fn serde_input_of_root_keys() {
        let sk = RootExtendedPrivKey::new_master(&SEED).expect("master key");
        let pk = sk.to_root_extended_pub_key();
        let pk_json = |key: &str| {
            format!(
                "{{\"root_public_key\":\"{}\",\"root_chain_code\":\"{}\"}}",
                key, CHAIN_CODE_HEX
            )
        };
        let sk_json = |key: &str| {
            format!(
                "{{\"root_private_key\":\"{}\",\"root_chain_code\":\"{}\"}}",
                key, CHAIN_CODE_HEX
            )
        };

        for key in [PK_UNCOMPRESSED_HEX.to_string(), PK_HEX.to_uppercase()] {
            let back: RootExtendedPubKey = serde_json::from_str(&pk_json(&key)).expect("parse");
            assert_eq!(back.root_public_key, pk.root_public_key);
            assert_eq!(serde_json::to_string(&back).expect("serialize"), pk_json(PK_HEX));
        }
        let bad_point = format!("05{}", &PK_HEX[2..]);
        let prefixed = format!("0x{}", PK_HEX);
        for key in [&PK_HEX[..64], &bad_point, &prefixed] {
            assert!(serde_json::from_str::<RootExtendedPubKey>(&pk_json(key)).is_err(), "{}", key);
        }

        let back: RootExtendedPrivKey =
            serde_json::from_str(&sk_json(&SK_HEX.to_uppercase())).expect("parse");
        assert_eq!(back.root_private_key, sk.root_private_key);
        let long = format!("{}00", SK_HEX);
        let zero = "00".repeat(32);
        let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        for key in [&SK_HEX[..62], &long, &zero, order] {
            assert!(serde_json::from_str::<RootExtendedPrivKey>(&sk_json(key)).is_err(), "{}", key);
        }

        let config = bincode::config::standard();
        let chain_code = format!("40{}", CHAIN_CODE_HEX.as_bytes().to_lower_hex_string());
        let decode = |hex: &str| hex_conservative::decode_to_vec(hex).expect("decode hex");
        let wrong_prefix = decode(&format!("04{}{}", &PK_HEX[2..], chain_code));
        assert!(bincode::serde::decode_from_slice::<RootExtendedPubKey, _>(&wrong_prefix, config)
            .is_err());
        assert!(bincode::serde::decode_from_slice::<RootExtendedPubKey, _>(
            &decode(&PK_HEX[..64]),
            config
        )
        .is_err());
        let zero = decode(&format!("{}{}", zero, chain_code));
        assert!(bincode::serde::decode_from_slice::<RootExtendedPrivKey, _>(&zero, config).is_err());
        assert!(bincode::serde::decode_from_slice::<RootExtendedPrivKey, _>(
            &decode(&SK_HEX[..62]),
            config
        )
        .is_err());
    }
}
