//
// This file is a part of rust-dashcore.
// Portions written by Andrew Poelstra <apoelstra@wpsoftware.net> for rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Dash keys.
//!
//! This module provides keys used in Dash that can be roundtrip
//! (de)serialized.

use core::fmt::{self, Write};
use core::str::FromStr;
use std::io;

#[cfg(feature = "rand")]
pub use bitcoin_crypto::key::rand;
pub use bitcoin_crypto::key::{
    constants, Keypair, Parity, ParseXOnlyPublicKeyError, XOnlyPublicKey,
};
pub use bitcoin_crypto::secp256k1::Scalar;
use dash_network::Network;
#[cfg(feature = "serde")]
use dash_types::serialize::hex as serde_hex;
use hashes::{hash160, hash_newtype, Hash as _};
use hex_conservative::DisplayHex;
use thiserror::Error as ThisError;
use zeroize::Zeroizing;

use crate::base58;
use crate::ecdsa::{
    EcdsaError, EcdsaPublicKey, EcdsaSecretKey, ECDSA_PK_LEN, ECDSA_PK_UNCOMPRESSED_LEN,
    ECDSA_SK_LEN,
};

/// A key-related error.
#[derive(Clone, PartialEq, Eq, Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    #[error("key base58 error")]
    Base58(#[from] base58::DecodeCheckError),
    /// ECDSA key error
    #[error("key ECDSA error")]
    Ecdsa(#[from] EcdsaError),
    /// Invalid key prefix error
    #[error("key prefix invalid: {0}")]
    InvalidKeyPrefix(u8),
    /// The WIF or extended key version byte was not one we recognise.
    #[error("address version {0} is invalid for this base58 type")]
    InvalidAddressVersion(u8),
    /// The base58 decoded correctly but the payload was the wrong length.
    #[error("length {0} invalid for this base58 type")]
    InvalidBase58PayloadLength(usize),
    /// A 34-byte WIF payload ended in something other than the `0x01`
    /// compression flag.
    #[error("WIF compression flag must be 0x01, got: {0:#04x}")]
    InvalidWifCompressionFlag(u8),
    /// Hex decoding error
    #[error("key hex decoding error")]
    Hex(#[from] hex_conservative::DecodeFixedLengthBytesError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    #[error("PublicKey hex should be 66 or 130 digits long, got: {0}")]
    InvalidHexLength(usize),
}

/// A Dash ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub inner: EcdsaPublicKey,
}

impl PublicKey {
    /// Constructs compressed ECDSA public key from the provided generic Secp256k1 public key
    pub fn new(key: impl Into<EcdsaPublicKey>) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: key.into(),
        }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key
    pub fn new_uncompressed(key: impl Into<EcdsaPublicKey>) -> PublicKey {
        PublicKey {
            compressed: false,
            inner: key.into(),
        }
    }

    /// Calls `f` with the key's SEC1 encoding, compressed or not as
    /// `compressed` says, without allocating.
    pub fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.inner.to_compressed())
        } else {
            f(&self.inner.to_uncompressed())
        }
    }

    /// Write the public key into a writer
    pub fn write_into<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.with_serialized(|bytes| writer.write_all(bytes))
    }

    /// Serialize the public key to bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        let compressed = match (data.len(), data.first()) {
            (ECDSA_PK_LEN, _) => true,
            (ECDSA_PK_UNCOMPRESSED_LEN, Some(&0x04)) => false,
            (ECDSA_PK_UNCOMPRESSED_LEN, Some(&prefix)) => {
                return Err(Error::InvalidKeyPrefix(prefix));
            }
            (len, _) => return Err(Error::InvalidBase58PayloadLength(len)),
        };

        Ok(PublicKey {
            compressed,
            inner: EcdsaPublicKey::from_bytes(data)?,
        })
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key(sk: &PrivateKey) -> PublicKey {
        sk.public_key()
    }

    /// Returns dash 160-bit hash of the public key
    pub fn pubkey_hash(&self) -> PubkeyHash {
        self.with_serialized(PubkeyHash::hash)
    }

    /// Returns dash 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> Option<WPubkeyHash> {
        self.compressed.then(|| WPubkeyHash::hash(&self.inner.to_compressed()))
    }
}

hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}

impl From<PublicKey> for PubkeyHash {
    fn from(key: PublicKey) -> PubkeyHash {
        key.pubkey_hash()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_serialized(|bytes| write!(f, "{:x}", bytes.as_hex()))
    }
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        match s.len() {
            66 => PublicKey::from_slice(&hex_conservative::decode_to_array::<33>(s)?),
            130 => PublicKey::from_slice(&hex_conservative::decode_to_array::<65>(s)?),
            len => Err(Error::InvalidHexLength(len)),
        }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<PublicKey, Error> {
        PublicKey::from_slice(data)
    }
}

/// A Dash ECDSA private key
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub inner: EcdsaSecretKey,
}

impl PrivateKey {
    /// Constructs compressed ECDSA private key from the provided generic Secp256k1 private key
    /// and the specified network
    pub fn new(key: impl Into<EcdsaSecretKey>, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: true,
            network,
            inner: key.into(),
        }
    }

    /// Constructs uncompressed (legacy) ECDSA private key from the provided generic Secp256k1
    /// private key and the specified network
    pub fn new_uncompressed(key: impl Into<EcdsaSecretKey>, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: false,
            network,
            inner: key.into(),
        }
    }

    /// Creates a public key from this private key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            inner: self.inner.public_key(),
        }
    }

    /// Serialize the private key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Deserialize a private key from a slice
    #[deprecated(since = "0.40.0", note = "Use `from_byte_array` instead.")]
    pub fn from_slice(data: &[u8], network: Network) -> Result<PrivateKey, Error> {
        let data = <[u8; ECDSA_SK_LEN]>::try_from(data)
            .map_err(|_| Error::Ecdsa(EcdsaError::InvalidSecretKey))?;
        PrivateKey::from_byte_array(&data, network)
    }

    pub fn from_byte_array(data: &[u8; 32], network: Network) -> Result<PrivateKey, Error> {
        Ok(PrivateKey::new(EcdsaSecretKey::from_bytes(data)?, network))
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut dyn Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = self.network.addr_params().secret_key;
        ret[1..33].copy_from_slice(&*self.inner.to_bytes());
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::Base58CkString::encode_unbounded(&ret[..])
        } else {
            base58::Base58CkString::encode_unbounded(&ret[..33])
        };
        fmt.write_str(privkey.as_str())
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(&self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<PrivateKey, Error> {
        // The payload holds the secret key; wipe it on every return path.
        let data = Zeroizing::new(base58::decode_check(wif)?);

        // Core's `DecodeSecret` takes a 34th byte as the compression flag
        // only when it is exactly 0x01.
        let compressed = match data.len() {
            33 => false,
            34 if data[33] == 1 => true,
            34 => return Err(Error::InvalidWifCompressionFlag(data[33])),
            _ => {
                return Err(Error::InvalidBase58PayloadLength(data.len()));
            }
        };

        let network = match data[0] {
            204 => Network::Mainnet,
            239 => Network::Testnet,
            x => {
                return Err(Error::InvalidAddressVersion(x));
            }
        };

        let secret = data[1..]
            .first_chunk::<ECDSA_SK_LEN>()
            .ok_or(Error::InvalidBase58PayloadLength(data.len()))?;

        Ok(PrivateKey {
            compressed,
            network,
            inner: EcdsaSecretKey::from_bytes(secret)?,
        })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_wif(f)
    }
}

impl FromStr for PrivateKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PrivateKey, Error> {
        PrivateKey::from_wif(s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PrivateKey, D::Error> {
        struct WifVisitor;

        impl<'de> serde::de::Visitor<'de> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PrivateKey::from_str(v).map_err(E::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    PrivateKey::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self))
                }
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
#[allow(clippy::collapsible_else_if)] // Aids readability.
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.with_serialized(|bytes| serde_hex::serialize_as(bytes, self, s))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        serde_hex::deserialize_as(d, PublicKey::from_str)
    }
}
