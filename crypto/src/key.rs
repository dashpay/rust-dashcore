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
use core::ops;
use core::str::FromStr;
use std::io;

use dash_network::Network;
use hashes::{hash160, hash_newtype, Hash as _};
use hex_conservative::DisplayHex;
use internals::write_err;
pub use secp256k1::{self, constants, Keypair, Parity, Secp256k1, Verification, XOnlyPublicKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::base58;

/// A key-related error.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::DecodeCheckError),
    /// secp256k1-related error
    Secp256k1(secp256k1::Error),
    /// Invalid key prefix error
    InvalidKeyPrefix(u8),
    /// The WIF or extended key version byte was not one we recognise.
    InvalidAddressVersion(u8),
    /// The base58 decoded correctly but the payload was the wrong length.
    InvalidBase58PayloadLength(usize),
    /// A 34-byte WIF payload ended in something other than the `0x01`
    /// compression flag.
    InvalidWifCompressionFlag(u8),
    /// Hex decoding error
    Hex(hex_conservative::DecodeFixedLengthBytesError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Base58(e) => write_err!(f, "key base58 error"; e),
            Error::Secp256k1(e) => write_err!(f, "key secp256k1 error"; e),
            Error::InvalidAddressVersion(v) => {
                write!(f, "address version {} is invalid for this base58 type", v)
            }
            Error::InvalidBase58PayloadLength(l) => {
                write!(f, "length {} invalid for this base58 type", l)
            }
            Error::InvalidKeyPrefix(b) => write!(f, "key prefix invalid: {}", b),
            Error::InvalidWifCompressionFlag(b) => {
                write!(f, "WIF compression flag must be 0x01, got: {:#04x}", b)
            }
            Error::Hex(e) => write_err!(f, "key hex decoding error"; e),
            Error::InvalidHexLength(got) => {
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Base58(e) => Some(e),
            Secp256k1(e) => Some(e),
            Hex(e) => Some(e),
            InvalidAddressVersion(_)
            | InvalidBase58PayloadLength(_)
            | InvalidKeyPrefix(_)
            | InvalidWifCompressionFlag(_)
            | InvalidHexLength(_) => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::DecodeCheckError> for Error {
    fn from(e: base58::DecodeCheckError) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

#[doc(hidden)]
impl From<hex_conservative::DecodeFixedLengthBytesError> for Error {
    fn from(e: hex_conservative::DecodeFixedLengthBytesError) -> Self {
        Error::Hex(e)
    }
}

/// A Dash ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub inner: secp256k1::PublicKey,
}

impl PublicKey {
    /// Constructs compressed ECDSA public key from the provided generic Secp256k1 public key
    pub fn new(key: impl Into<secp256k1::PublicKey>) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: key.into(),
        }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key
    pub fn new_uncompressed(key: impl Into<secp256k1::PublicKey>) -> PublicKey {
        PublicKey {
            compressed: false,
            inner: key.into(),
        }
    }

    fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.inner.serialize())
        } else {
            f(&self.inner.serialize_uncompressed())
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
        let (compressed, inner) = match data.len() {
            constants::PUBLIC_KEY_SIZE => {
                let data = <[u8; constants::PUBLIC_KEY_SIZE]>::try_from(data)
                    .map_err(|_| Error::Secp256k1(secp256k1::Error::InvalidPublicKey))?;
                (true, secp256k1::PublicKey::from_byte_array_compressed(data)?)
            }
            constants::UNCOMPRESSED_PUBLIC_KEY_SIZE => {
                if data[0] != 0x04 {
                    return Err(Error::InvalidKeyPrefix(data[0]));
                }
                let data = <[u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]>::try_from(data)
                    .map_err(|_| Error::Secp256k1(secp256k1::Error::InvalidPublicKey))?;
                (false, secp256k1::PublicKey::from_byte_array_uncompressed(data)?)
            }
            len => {
                return Err(Error::InvalidBase58PayloadLength(len));
            }
        };

        Ok(PublicKey {
            compressed,
            inner,
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
        if self.compressed {
            Some(WPubkeyHash::from_byte_array(
                hash160::Hash::hash(&self.inner.serialize()).to_byte_array(),
            ))
        } else {
            // We can't create witness pubkey hashes for an uncompressed
            // public keys
            None
        }
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

/// A Dash ECDSA private key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network on which this key should be used
    pub network: Network,
    /// The actual ECDSA key
    pub inner: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Constructs compressed ECDSA private key from the provided generic Secp256k1 private key
    /// and the specified network
    pub fn new(key: secp256k1::SecretKey, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: true,
            network,
            inner: key,
        }
    }

    /// Constructs uncompressed (legacy) ECDSA private key from the provided generic Secp256k1
    /// private key and the specified network
    pub fn new_uncompressed(key: secp256k1::SecretKey, network: Network) -> PrivateKey {
        PrivateKey {
            compressed: false,
            network,
            inner: key,
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
    pub fn to_bytes(self) -> Vec<u8> {
        self.inner[..].to_vec()
    }

    /// Deserialize a private key from a slice
    #[deprecated(since = "0.40.0", note = "Use `from_byte_array` instead.")]
    pub fn from_slice(data: &[u8], network: Network) -> Result<PrivateKey, Error> {
        let data = <[u8; constants::SECRET_KEY_SIZE]>::try_from(data)
            .map_err(|_| Error::Secp256k1(secp256k1::Error::InvalidSecretKey))?;
        PrivateKey::from_byte_array(&data, network)
    }

    pub fn from_byte_array(data: &[u8; 32], network: Network) -> Result<PrivateKey, Error> {
        Ok(PrivateKey::new(secp256k1::SecretKey::from_secret_bytes(*data)?, network))
    }

    /// Format the private key to WIF format.
    pub fn fmt_wif(&self, fmt: &mut dyn Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = match self.network {
            Network::Mainnet => 204,
            Network::Testnet | Network::Devnet | Network::Regtest => 239,
        };
        ret[1..33].copy_from_slice(&self.inner[..]);
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::Base58CkString::encode_unbounded(&ret[..])
        } else {
            base58::Base58CkString::encode_unbounded(&ret[..33])
        };
        fmt.write_str(privkey.as_str())
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<PrivateKey, Error> {
        let data = base58::decode_check(wif)?;

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
            .first_chunk::<{ constants::SECRET_KEY_SIZE }>()
            .ok_or(Error::InvalidBase58PayloadLength(data.len()))?;

        Ok(PrivateKey {
            compressed,
            network,
            inner: secp256k1::SecretKey::from_secret_bytes(*secret)?,
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

impl ops::Index<ops::RangeFull> for PrivateKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.inner[..]
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
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            self.with_serialized(|bytes| s.serialize_bytes(bytes))
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_str(v).map_err(E::custom)
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        PublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self))
                    }
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

/// Untweaked BIP-340 X-coord-only public key
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked BIP-340 X-coord-only public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedPublicKey(XOnlyPublicKey);

impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Untweaked BIP-340 key pair
pub type UntweakedKeyPair = Keypair;

/// Tweaked BIP-340 key pair
///
/// # Examples
/// ```
/// # #[cfg(feature = "rand-std")] {
/// # use dashcore::key::{Keypair, TweakedKeyPair, TweakedPublicKey};
/// # use dashcore::secp256k1::rand;
/// # let keypair = TweakedKeyPair::dangerous_assume_tweaked(Keypair::new(&mut rand::rng()));
/// // There are various conversion methods available to get a tweaked pubkey from a tweaked keypair.
/// let (_pk, _parity) = keypair.public_parts();
/// let _pk  = TweakedPublicKey::from_keypair(keypair);
/// let _pk = TweakedPublicKey::from(keypair);
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedKeyPair(Keypair);

impl TweakedPublicKey {
    /// Returns the [`TweakedPublicKey`] for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: TweakedKeyPair) -> Self {
        let (xonly, _parity) = keypair.0.x_only_public_key();
        TweakedPublicKey(xonly)
    }

    /// Creates a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn to_inner(self) -> XOnlyPublicKey {
        self.0
    }

    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] {
        self.0.to_byte_array()
    }
}

impl TweakedKeyPair {
    /// Creates a new [`TweakedKeyPair`] from a `KeyPair`. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedKeyPair`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(pair: Keypair) -> TweakedKeyPair {
        TweakedKeyPair(pair)
    }

    /// Returns the underlying key pair.
    #[inline]
    pub fn to_inner(self) -> Keypair {
        self.0
    }

    /// Returns the [`TweakedPublicKey`] and its [`Parity`] for this [`TweakedKeyPair`].
    #[inline]
    pub fn public_parts(&self) -> (TweakedPublicKey, Parity) {
        let (xonly, parity) = self.0.x_only_public_key();
        (TweakedPublicKey(xonly), parity)
    }
}

impl From<TweakedPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pair: TweakedPublicKey) -> Self {
        pair.0
    }
}

impl From<TweakedKeyPair> for Keypair {
    #[inline]
    fn from(pair: TweakedKeyPair) -> Self {
        pair.0
    }
}

impl From<TweakedKeyPair> for TweakedPublicKey {
    #[inline]
    fn from(pair: TweakedKeyPair) -> Self {
        TweakedPublicKey::from_keypair(pair)
    }
}
