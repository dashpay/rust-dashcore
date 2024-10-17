#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
#[cfg(feature = "rand")]
use secp256k1::rand::rngs::StdRng as EcdsaRng;
#[cfg(feature = "rand")]
use secp256k1::rand::SeedableRng;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::HashMap;
use std::convert::TryFrom;
use lazy_static::lazy_static;
use secp256k1::rand::Rng;
#[cfg(feature = "rand")]
use secp256k1::rand::rngs::StdRng;
use secp256k1::Secp256k1;
use crate::{Network, PrivateKey};
use crate::key::Error;
use crate::signer::ripemd160_sha256;

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Serialize_repr,
    Deserialize_repr,
    Hash,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    Default,
    strum::EnumIter,
)]
pub enum KeyType {
    #[default]
    ECDSA_SECP256K1 = 0,
    BLS12_381 = 1,
    ECDSA_HASH160 = 2,
    BIP13_SCRIPT_HASH = 3,
    EDDSA_25519_HASH160 = 4,
}

lazy_static! {
    static ref KEY_TYPE_SIZES: HashMap<KeyType, usize> = [
        (KeyType::ECDSA_SECP256K1, 33),
        (KeyType::BLS12_381, 48),
        (KeyType::ECDSA_HASH160, 20),
        (KeyType::BIP13_SCRIPT_HASH, 20),
        (KeyType::EDDSA_25519_HASH160, 20)
    ]
    .iter()
    .copied()
    .collect();
    pub static ref KEY_TYPE_MAX_SIZE_TYPE: KeyType = KEY_TYPE_SIZES
        .iter()
        .sorted_by(|a, b| Ord::cmp(&b.1, &a.1))
        .last()
        .map(|(key_type, _)| *key_type)
        .unwrap();
}

impl KeyType {
    /// Gets the default size of the public key
    pub fn default_size(&self) -> usize {
        KEY_TYPE_SIZES[self]
    }

    /// All key types
    pub fn all_key_types() -> [KeyType; 5] {
        [
            Self::ECDSA_SECP256K1,
            Self::BLS12_381,
            Self::ECDSA_HASH160,
            Self::BIP13_SCRIPT_HASH,
            Self::EDDSA_25519_HASH160,
        ]
    }

    /// Are keys of this type unique?
    pub fn is_unique_key_type(&self) -> bool {
        match self {
            KeyType::ECDSA_SECP256K1 => true,
            KeyType::BLS12_381 => true,
            KeyType::ECDSA_HASH160 => false,
            KeyType::BIP13_SCRIPT_HASH => false,
            KeyType::EDDSA_25519_HASH160 => false,
        }
    }

    /// Can this key type be understood as an address on the Core chain?
    pub fn is_core_address_key_type(&self) -> bool {
        match self {
            KeyType::ECDSA_SECP256K1 => false,
            KeyType::BLS12_381 => false,
            KeyType::ECDSA_HASH160 => true,
            KeyType::BIP13_SCRIPT_HASH => true,
            KeyType::EDDSA_25519_HASH160 => false,
        }
    }

    #[cfg(feature = "rand")]
    /// Gets the default size of the public key
    pub fn random_public_key_data(
        &self,
        rng: &mut StdRng,
    ) -> Vec<u8> {
        match self {
            KeyType::ECDSA_SECP256K1 => {
                let secp = Secp256k1::new();
                let mut rng = EcdsaRng::from_rng(rng).unwrap();
                let secret_key = secp256k1::SecretKey::new(&mut rng);
                let private_key = PrivateKey::new(secret_key, Network::Dash);
                private_key.public_key(&secp).to_bytes()
            }
            KeyType::BLS12_381 => {
                let private_key = bls_signatures::PrivateKey::generate_dash(rng)
                    .expect("expected to generate a bls private key"); // we assume this will never error
                private_key
                    .g1_element()
                    .expect("expected to get a public key from a bls private key")
                    .to_bytes()
                    .to_vec()
            }
            KeyType::ECDSA_HASH160 | KeyType::BIP13_SCRIPT_HASH | KeyType::EDDSA_25519_HASH160 => {
                (0..self.default_size()).map(|_| rng.gen::<u8>()).collect()
            }
        }
    }

    /// Gets the public key data for a private key depending on the key type
    pub fn public_key_data_from_private_key_data(
        &self,
        private_key_bytes: &[u8],
        network: Network,
    ) -> Result<Vec<u8>, Error> {
        match self {
            KeyType::ECDSA_SECP256K1 => {
                let secp = Secp256k1::new();
                let secret_key = secp256k1::SecretKey::from_slice(private_key_bytes)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                let private_key = PrivateKey::new(secret_key, network);

                Ok(private_key.public_key(&secp).to_bytes())
            }
            KeyType::BLS12_381 => {
                #[cfg(feature = "bls-signatures")]
                {
                    let private_key =
                        bls_signatures::PrivateKey::from_bytes(private_key_bytes, false)
                            .map_err(|e| ProtocolError::Generic(e.to_string()))?;
                    let public_key_bytes = private_key
                        .g1_element()
                        .expect("expected to get a public key from a bls private key")
                        .to_bytes()
                        .to_vec();
                    Ok(public_key_bytes)
                }
                #[cfg(not(feature = "bls-signatures"))]
                return Err(Error::NotSupported(
                    "Converting a private key to a bls public key is not supported without the bls-signatures feature".to_string(),
                ));
            }
            KeyType::ECDSA_HASH160 => {
                let secp = Secp256k1::new();
                let secret_key = secp256k1::SecretKey::from_slice(private_key_bytes)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                let private_key = PrivateKey::new(secret_key, network);

                Ok(ripemd160_sha256(private_key.public_key(&secp).to_bytes().as_slice()).to_vec())
            }
            KeyType::EDDSA_25519_HASH160 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let key_pair = ed25519_dalek::SigningKey::from_bytes(
                        &private_key_bytes.try_into().map_err(|_| {
                            Error::InvalidVectorSizeError(InvalidVectorSizeError::new(
                                32,
                                private_key_bytes.len(),
                            ))
                        })?,
                    );
                    Ok(ripemd160_sha256(key_pair.verifying_key().to_bytes().as_slice()).to_vec())
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                return Err(ProtocolError::NotSupported(
                    "Converting a private key to a eddsa hash 160 is not supported without the ed25519-dalek feature".to_string(),
                ));
            }
            KeyType::BIP13_SCRIPT_HASH => {
                return Err(Error::NotSupported(
                    "Converting a private key to a script hash is not supported".to_string(),
                ));
            }
        }
    }

    #[cfg(feature = "rand")]
    /// Gets the default size of the public key
    pub fn random_public_and_private_key_data(&self, rng: &mut StdRng) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match self {
            KeyType::ECDSA_SECP256K1 => {
                let secp = Secp256k1::new();
                let mut rng = EcdsaRng::from_rng(rng).unwrap();
                let secret_key = secp256k1::SecretKey::new(&mut rng);
                let private_key = PrivateKey::new(secret_key, Network::Dash);
                Ok((
                    private_key.public_key(&secp).to_bytes(),
                    private_key.to_bytes(),
                ))
            }
            KeyType::BLS12_381 => {
                #[cfg(feature = "bls_signatures")]
                {
                    let private_key = bls_signatures::PrivateKey::generate_dash(rng)
                        .expect("expected to generate a bls private key"); // we assume this will never error
                    let public_key_bytes = private_key
                        .g1_element()
                        .expect("expected to get a public key from a bls private key")
                        .to_bytes()
                        .to_vec();
                    Ok((public_key_bytes, private_key.to_bytes().to_vec()))
                }
                #[cfg(not(feature = "bls_signatures"))]
                return Err(Error::NotSupported(
                    "Action not supported without the bls_signatures feature".to_string(),
                ));
            }
            KeyType::ECDSA_HASH160 => {
                let secp = Secp256k1::new();
                let mut rng = EcdsaRng::from_rng(rng).unwrap();
                let secret_key = secp256k1::SecretKey::new(&mut rng);
                let private_key = PrivateKey::new(secret_key, Network::Dash);
                Ok((
                    ripemd160_sha256(private_key.public_key(&secp).to_bytes().as_slice()).to_vec(),
                    private_key.to_bytes(),
                ))
            }
            KeyType::EDDSA_25519_HASH160 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let key_pair = ed25519_dalek::SigningKey::generate(rng);
                    Ok((
                        ripemd160_sha256(key_pair.verifying_key().to_bytes().as_slice()).to_vec(),
                        key_pair.to_bytes().to_vec(),
                    ))
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                return Err(Error::NotSupported(
                    "Action not supported without the ed25519-dalek feature".to_string(),
                ));
            }
            KeyType::BIP13_SCRIPT_HASH => {
                //todo (using ECDSA_HASH160 for now)
                let secp = Secp256k1::new();
                let mut rng = EcdsaRng::from_rng(rng).unwrap();
                let secret_key = secp256k1::SecretKey::new(&mut rng);
                let private_key = PrivateKey::new(secret_key, Network::Dash);
                Ok((
                    ripemd160_sha256(private_key.public_key(&secp).to_bytes().as_slice()).to_vec(),
                    private_key.to_bytes(),
                ))
            }
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TryFrom<u8> for KeyType {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ECDSA_SECP256K1),
            1 => Ok(Self::BLS12_381),
            2 => Ok(Self::ECDSA_HASH160),
            3 => Ok(Self::BIP13_SCRIPT_HASH),
            4 => Ok(Self::EDDSA_25519_HASH160),
            value => Err(Error::NotSupported(format!("Unsupported key type {}", value))),
        }
    }
}
