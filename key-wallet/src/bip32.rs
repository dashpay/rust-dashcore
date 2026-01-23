// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Dash
// Updated for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP32 implementation.
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at <https://github.com/Dash/bips/blob/master/bip-0032.mediawiki>.
//!

use core::default::Default;
use core::fmt;
use core::ops::Index;
use core::str::FromStr;
#[cfg(feature = "std")]
use std::error;

use dashcore_hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::{self, Secp256k1, XOnlyPublicKey};
#[cfg(feature = "serde")]
use serde;

use crate::dip9::{
    COINJOIN_PATH_MAINNET, COINJOIN_PATH_TESTNET, DASH_BIP44_PATH_MAINNET, DASH_BIP44_PATH_TESTNET,
    IDENTITY_AUTHENTICATION_PATH_MAINNET, IDENTITY_AUTHENTICATION_PATH_TESTNET,
    IDENTITY_INVITATION_PATH_MAINNET, IDENTITY_INVITATION_PATH_TESTNET,
    IDENTITY_REGISTRATION_PATH_MAINNET, IDENTITY_REGISTRATION_PATH_TESTNET,
    IDENTITY_TOPUP_PATH_MAINNET, IDENTITY_TOPUP_PATH_TESTNET,
};
use alloc::{string::String, vec::Vec};
use base58ck;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use dash_network::Network;

/// XpubIdentifier as a hash160 result
type XpubIdentifier = hash160::Hash;

pub use secp256k1::Keypair;
pub use secp256k1::PublicKey;
/// Re-export key types from secp256k1
pub use secp256k1::SecretKey as PrivateKey;

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct ChainCode([u8; 32]);

impl ChainCode {
    /// Create a new ChainCode from a byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ChainCode(bytes)
    }

    /// Get the inner byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for ChainCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ChainCode {
    fn from(bytes: [u8; 32]) -> Self {
        ChainCode(bytes)
    }
}

impl TryFrom<&[u8]> for ChainCode {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != 32 {
            return Err(Error::InvalidChildNumberFormat);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(ChainCode(bytes))
    }
}

impl fmt::Display for ChainCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ChainCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ChainCode({}))", self)
    }
}

// Manual implementation of Zeroize for ChainCode
// Note: ChainCode is Copy, so this won't prevent copies in registers/stack
impl zeroize::Zeroize for ChainCode {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl fmt::LowerHex for ChainCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl core::ops::Index<usize> for ChainCode {
    type Output = u8;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for ChainCode {
    type Output = [u8];

    fn index(&self, idx: core::ops::Range<usize>) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for ChainCode {
    type Output = [u8];

    fn index(&self, idx: core::ops::RangeTo<usize>) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::RangeFrom<usize>> for ChainCode {
    type Output = [u8];

    fn index(&self, idx: core::ops::RangeFrom<usize>) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::RangeFull> for ChainCode {
    type Output = [u8];

    fn index(&self, _: core::ops::RangeFull) -> &Self::Output {
        &self.0[..]
    }
}

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac[32..].try_into().expect("half of hmac is guaranteed to be 32 bytes")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChainCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChainCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        let mut bytes = [0u8; 32];
        crate::utils::parse_hex_bytes(&s, &mut bytes).map_err(D::Error::custom)?;
        Ok(ChainCode(bytes))
    }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Fingerprint([u8; 4]);

impl Fingerprint {
    /// Create a new Fingerprint from a byte array
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Fingerprint(bytes)
    }

    /// Get the inner byte array
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0
    }
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 4]> for Fingerprint {
    fn from(bytes: [u8; 4]) -> Self {
        Fingerprint(bytes)
    }
}

impl TryFrom<&[u8]> for Fingerprint {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != 4 {
            return Err(Error::InvalidChildNumberFormat);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(slice);
        Ok(Fingerprint(bytes))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fingerprint({}))", self)
    }
}

impl core::str::FromStr for Fingerprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 4];
        crate::utils::parse_hex_bytes(s, &mut bytes)
            .map_err(|_| Error::InvalidPublicKeyHexLength(s.len()))?;
        Ok(Fingerprint(bytes))
    }
}

impl fmt::LowerHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl core::ops::Index<usize> for Fingerprint {
    type Output = u8;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for Fingerprint {
    type Output = [u8];

    fn index(&self, idx: core::ops::Range<usize>) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for Fingerprint {
    type Output = [u8];

    fn index(&self, idx: core::ops::RangeTo<usize>) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::RangeFrom<usize>> for Fingerprint {
    type Output = [u8];

    fn index(&self, idx: core::ops::RangeFrom<usize>) -> &Self::Output {
        &self.0[idx]
    }
}

impl core::ops::Index<core::ops::RangeFull> for Fingerprint {
    type Output = [u8];

    fn index(&self, _: core::ops::RangeFull) -> &Self::Output {
        &self.0[..]
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Fingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{:x}", self))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|_| D::Error::custom("invalid fingerprint"))
    }
}

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct ExtendedPrivKey {
    /// The network this key is to be used on
    pub network: Network,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: secp256k1::SecretKey,
    /// Chain code
    pub chain_code: ChainCode,
}

#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedPrivKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        // Encode the private key as bytes
        self.private_key.secret_bytes().encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedPrivKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        // Decode the private key from bytes
        let private_key_bytes: [u8; 32] = <[u8; 32]>::decode(decoder)?;
        let private_key = secp256k1::SecretKey::from_slice(&private_key_bytes).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid private key: {}", e))
        })?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedPrivKey {
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
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedPrivKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::borrow_decode(decoder)?;
        let depth = u8::borrow_decode(decoder)?;
        let parent_fingerprint = Fingerprint::borrow_decode(decoder)?;
        let child_number = ChildNumber::borrow_decode(decoder)?;
        // Decode the private key from bytes
        let private_key_bytes: [u8; 32] = <[u8; 32]>::borrow_decode(decoder)?;
        let private_key = secp256k1::SecretKey::from_slice(&private_key_bytes).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid private key: {}", e))
        })?;
        let chain_code = ChainCode::borrow_decode(decoder)?;

        Ok(ExtendedPrivKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            private_key,
            chain_code,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedPrivKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedPrivKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer)?.parse().map_err(D::Error::custom)
    }
}

#[cfg(not(feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "std"))))]
impl fmt::Debug for ExtendedPrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedPrivKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .finish_non_exhaustive()
    }
}

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct ExtendedPubKey {
    /// The network this key is to be used on
    pub network: Network,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}

#[cfg(feature = "bincode")]
impl bincode::Encode for ExtendedPubKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.network.encode(encoder)?;
        self.depth.encode(encoder)?;
        self.parent_fingerprint.encode(encoder)?;
        self.child_number.encode(encoder)?;
        // Encode the public key as bytes (33 bytes for compressed)
        self.public_key.serialize().encode(encoder)?;
        self.chain_code.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ExtendedPubKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::decode(decoder)?;
        let depth = u8::decode(decoder)?;
        let parent_fingerprint = Fingerprint::decode(decoder)?;
        let child_number = ChildNumber::decode(decoder)?;
        // Decode the public key from bytes (33 bytes for compressed)
        let public_key_bytes: [u8; 33] = <[u8; 33]>::decode(decoder)?;
        let public_key = secp256k1::PublicKey::from_slice(&public_key_bytes).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid public key: {}", e))
        })?;
        let chain_code = ChainCode::decode(decoder)?;

        Ok(ExtendedPubKey {
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
impl<'de, C> bincode::BorrowDecode<'de, C> for ExtendedPubKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let network = Network::borrow_decode(decoder)?;
        let depth = u8::borrow_decode(decoder)?;
        let parent_fingerprint = Fingerprint::borrow_decode(decoder)?;
        let child_number = ChildNumber::borrow_decode(decoder)?;
        // Decode the public key from bytes (33 bytes for compressed)
        let public_key_bytes: [u8; 33] = <[u8; 33]>::borrow_decode(decoder)?;
        let public_key = secp256k1::PublicKey::from_slice(&public_key_bytes).map_err(|e| {
            bincode::error::DecodeError::OtherString(format!("Invalid public key: {}", e))
        })?;
        let chain_code = ChainCode::borrow_decode(decoder)?;

        Ok(ExtendedPubKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            public_key,
            chain_code,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ExtendedPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExtendedPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer)?.parse().map_err(D::Error::custom)
    }
}

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },

    /// Non-hardened key
    Normal256 {
        /// Key index, within [0, 2^256 - 1]
        index: [u8; 32],
    },

    /// Hardened key
    Hardened256 {
        /// Key index, within [0, 2^256 - 1]
        index: [u8; 32],
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal {
                index,
            })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened {
                index,
            })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Normal`] or [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    /// [`Hardened`]: #variant.Hardened
    pub fn from_idx(index: u32, hardened: bool) -> Result<Self, Error> {
        if index & (1 << 31) != 0 {
            return Err(Error::InvalidChildNumber(index));
        }

        if hardened {
            Ok(ChildNumber::Hardened {
                index,
            })
        } else {
            Ok(ChildNumber::Normal {
                index,
            })
        }
    }

    /// Create a non-hardened `ChildNumber` from a 256-bit index.
    pub fn from_normal_idx_256(index: [u8; 32]) -> ChildNumber {
        ChildNumber::Normal256 {
            index,
        }
    }

    /// Create a hardened `ChildNumber` from a 256-bit index.
    pub fn from_hardened_idx_256(index: [u8; 32]) -> ChildNumber {
        ChildNumber::Hardened256 {
            index,
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(&self) -> bool {
        !self.is_hardened()
    }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildNumber::Hardened {
                ..
            } => true,
            ChildNumber::Normal {
                ..
            } => false,
            ChildNumber::Normal256 {
                ..
            } => false,
            ChildNumber::Hardened256 {
                ..
            } => true,
        }
    }

    /// Returns `true` if the child number is a 256 bit value.
    pub fn is_256_bits(&self) -> bool {
        match self {
            ChildNumber::Hardened {
                ..
            } => false,
            ChildNumber::Normal {
                ..
            } => false,
            ChildNumber::Normal256 {
                ..
            } => true,
            ChildNumber::Hardened256 {
                ..
            } => true,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal {
                index: idx,
            } => ChildNumber::from_normal_idx(idx + 1),
            ChildNumber::Hardened {
                index: idx,
            } => ChildNumber::from_hardened_idx(idx + 1),
            ChildNumber::Normal256 {
                mut index,
            } => {
                // Increment the 256-bit big-endian number represented by index
                let mut carry = 1u8;
                for byte in index.iter_mut().rev() {
                    let (new_byte, overflow) = byte.overflowing_add(carry);
                    *byte = new_byte;
                    carry = if overflow {
                        1
                    } else {
                        0
                    };
                    if carry == 0 {
                        break;
                    }
                }
                if carry != 0 {
                    // Overflow occurred
                    return Err(Error::InvalidChildNumber(0)); // Or define a suitable error
                }
                Ok(ChildNumber::Normal256 {
                    index,
                })
            }
            ChildNumber::Hardened256 {
                mut index,
            } => {
                // Increment the 256-bit big-endian number represented by index
                let mut carry = 1u8;
                for byte in index.iter_mut().rev() {
                    let (new_byte, overflow) = byte.overflowing_add(carry);
                    *byte = new_byte;
                    carry = if overflow {
                        1
                    } else {
                        0
                    };
                    if carry == 0 {
                        break;
                    }
                }
                if carry != 0 {
                    // Overflow occurred
                    return Err(Error::InvalidChildNumber(0)); // Or define a suitable error
                }
                Ok(ChildNumber::Hardened256 {
                    index,
                })
            }
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened {
                index: number ^ (1 << 31),
            }
        } else {
            ChildNumber::Normal {
                index: number,
            }
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(cnum: ChildNumber) -> Self {
        match cnum {
            ChildNumber::Normal {
                index,
            } => index,
            ChildNumber::Hardened {
                index,
            } => index | (1 << 31),
            ChildNumber::Normal256 {
                ..
            } => u32::MAX,
            ChildNumber::Hardened256 {
                ..
            } => u32::MAX,
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildNumber::Hardened {
                index,
            } => {
                fmt::Display::fmt(&index, f)?;
                let alt = f.alternate();
                f.write_str(if alt {
                    "h"
                } else {
                    "'"
                })
            }
            ChildNumber::Normal {
                index,
            } => fmt::Display::fmt(&index, f),
            ChildNumber::Hardened256 {
                index,
            } => {
                write!(f, "0x")?;
                for byte in index {
                    write!(f, "{:02x}", byte)?;
                }
                write!(
                    f,
                    "{}",
                    if f.alternate() {
                        "h"
                    } else {
                        "'"
                    }
                )
            }
            ChildNumber::Normal256 {
                index,
            } => {
                write!(f, "0x")?;
                for byte in index {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let is_hardened = inp.ends_with('\'') || inp.ends_with('h');
        let index_str = if is_hardened {
            &inp[..inp.len() - 1]
        } else {
            inp
        };

        if index_str.starts_with("0x") || index_str.starts_with("0X") {
            // Parse as a 256-bit hex number
            let hex_str = &index_str[2..];
            // Simple hex decoder
            let hex_bytes = hex_str
                .as_bytes()
                .chunks(2)
                .map(|chunk| {
                    let high = chunk[0];
                    let low = chunk.get(1).copied().unwrap_or(b'0');
                    let h = match high {
                        b'0'..=b'9' => high - b'0',
                        b'a'..=b'f' => high - b'a' + 10,
                        b'A'..=b'F' => high - b'A' + 10,
                        _ => return Err(Error::InvalidChildNumberFormat),
                    };
                    let l = match low {
                        b'0'..=b'9' => low - b'0',
                        b'a'..=b'f' => low - b'a' + 10,
                        b'A'..=b'F' => low - b'A' + 10,
                        _ => return Err(Error::InvalidChildNumberFormat),
                    };
                    Ok((h << 4) | l)
                })
                .collect::<Result<Vec<u8>, Error>>()?;
            if hex_bytes.len() != 32 {
                return Err(Error::InvalidChildNumberFormat);
            }
            let mut index_bytes = [0u8; 32];
            index_bytes[32 - hex_bytes.len()..].copy_from_slice(&hex_bytes);
            if is_hardened {
                Ok(ChildNumber::Hardened256 {
                    index: index_bytes,
                })
            } else {
                Ok(ChildNumber::Normal256 {
                    index: index_bytes,
                })
            }
        } else {
            // Parse as a u32 number
            let index = index_str.parse::<u32>().map_err(|_| Error::InvalidChildNumberFormat)?;
            if is_hardened {
                ChildNumber::from_hardened_idx(index)
            } else {
                ChildNumber::from_normal_idx(index)
            }
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildNumber::from)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChildNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Converts a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);

#[cfg(feature = "bincode")]
impl bincode::Encode for DerivationPath {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.0.encode(encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for DerivationPath {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(DerivationPath(Vec::<ChildNumber>::decode(decoder)?))
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for DerivationPath {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(DerivationPath(Vec::<ChildNumber>::borrow_decode(decoder)?))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum KeyDerivationType {
    ECDSA = 0,
    BLS = 1,
}

impl From<KeyDerivationType> for u32 {
    fn from(val: KeyDerivationType) -> Self {
        match val {
            KeyDerivationType::ECDSA => 0,
            KeyDerivationType::BLS => 1,
        }
    }
}

impl DerivationPath {
    pub fn bip_44_account(network: Network, account: u32) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => DASH_BIP44_PATH_MAINNET,
            _ => DASH_BIP44_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[ChildNumber::Hardened {
            index: account,
        }]);
        root_derivation_path
    }
    pub fn bip_44_payment_path(
        network: Network,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => DASH_BIP44_PATH_MAINNET,
            _ => DASH_BIP44_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[
            ChildNumber::Hardened {
                index: account,
            },
            ChildNumber::Normal {
                index: change.into(),
            },
            ChildNumber::Normal {
                index: address_index,
            },
        ]);
        root_derivation_path
    }
    pub fn coinjoin_path(network: Network, account: u32) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => COINJOIN_PATH_MAINNET,
            _ => COINJOIN_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[ChildNumber::Hardened {
            index: account,
        }]);
        root_derivation_path
    }

    /// This might have been used in the past
    pub fn identity_registration_path_child_non_hardened(network: Network, index: u32) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => IDENTITY_REGISTRATION_PATH_MAINNET,
            _ => IDENTITY_REGISTRATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[ChildNumber::Normal {
            index,
        }]);
        root_derivation_path
    }

    pub fn identity_registration_path(network: Network, index: u32) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => IDENTITY_REGISTRATION_PATH_MAINNET,
            _ => IDENTITY_REGISTRATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[ChildNumber::Hardened {
            index,
        }]);
        root_derivation_path
    }

    pub fn identity_top_up_path(network: Network, identity_index: u32, top_up_index: u32) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => IDENTITY_TOPUP_PATH_MAINNET,
            _ => IDENTITY_TOPUP_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[
            ChildNumber::Hardened {
                index: identity_index,
            },
            ChildNumber::Normal {
                index: top_up_index,
            },
        ]);
        root_derivation_path
    }

    pub fn identity_invitation_path(network: Network, index: u32) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => IDENTITY_INVITATION_PATH_MAINNET,
            _ => IDENTITY_INVITATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[ChildNumber::Hardened {
            index,
        }]);
        root_derivation_path
    }

    pub fn identity_authentication_path(
        network: Network,
        key_type: KeyDerivationType,
        identity_index: u32,
        key_index: u32,
    ) -> Self {
        let mut root_derivation_path: DerivationPath = match network {
            Network::Dash => IDENTITY_AUTHENTICATION_PATH_MAINNET,
            _ => IDENTITY_AUTHENTICATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.0.extend(&[
            ChildNumber::Hardened {
                index: key_type.into(),
            },
            ChildNumber::Hardened {
                index: identity_index,
            },
            ChildNumber::Hardened {
                index: key_index,
            },
        ]);
        root_derivation_path
    }

    pub fn derive_priv_ecdsa_for_master_seed(
        &self,
        seed: &[u8],
        network: Network,
    ) -> Result<ExtendedPrivKey, Error> {
        let secp = Secp256k1::new();
        let sk = ExtendedPrivKey::new_master(network, seed)?;
        sk.derive_priv(&secp, &self)
    }

    pub fn derive_pub_ecdsa_for_master_seed(
        &self,
        seed: &[u8],
        network: Network,
    ) -> Result<ExtendedPubKey, Error> {
        let secp = Secp256k1::new();
        let sk = self.derive_priv_ecdsa_for_master_seed(seed, network)?;
        Ok(ExtendedPubKey::from_priv(&secp, &sk))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DerivationPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DerivationPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer)?.parse().map_err(D::Error::custom)
    }
}

impl<I> Index<I> for DerivationPath
where
    Vec<ChildNumber>: Index<I>,
{
    type Output = <Vec<ChildNumber> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl Default for DerivationPath {
    fn default() -> DerivationPath {
        DerivationPath::master()
    }
}

impl<T> IntoDerivationPath for T
where
    T: Into<DerivationPath>,
{
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(self.into())
    }
}

impl IntoDerivationPath for String {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        self.parse()
    }
}

impl IntoDerivationPath for &str {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        self.parse()
    }
}

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self {
        DerivationPath(numbers)
    }
}

impl From<DerivationPath> for Vec<ChildNumber> {
    fn from(val: DerivationPath) -> Self {
        val.0
    }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self {
        DerivationPath(numbers.to_vec())
    }
}

impl ::core::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> ::core::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = core::slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        let mut parts = path.split('/');
        // First parts must be `m`.
        if parts.next().unwrap() != "m" {
            return Err(Error::InvalidDerivationPathFormat);
        }

        let ret: Result<Vec<ChildNumber>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath(ret?))
    }
}

/// An iterator over children of a [DerivationPath].
///
/// It is returned by the methods [DerivationPath::children_from],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator {
            base: path,
            next_child: Some(start),
        }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl DerivationPath {
    /// Returns length of the derivation path
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the derivation path is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Push a child number to the path
    pub fn push(&mut self, child: ChildNumber) {
        self.0.push(child)
    }

    /// Returns derivation path for a master key (i.e. empty derivation path)
    pub fn master() -> DerivationPath {
        DerivationPath(Vec::new())
    }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    pub fn is_master(&self) -> bool {
        self.0.is_empty()
    }

    /// Create a new [DerivationPath] that is a child of this one.
    pub fn child(&self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0.clone();
        path.push(cn);
        DerivationPath(path)
    }

    /// Convert into a [DerivationPath] that is a child of this one.
    pub fn into_child(self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0;
        path.push(cn);
        DerivationPath(path)
    }

    /// Get an [Iterator] over the children of this [DerivationPath]
    /// starting with the given [ChildNumber].
    pub fn children_from(&self, cn: ChildNumber) -> DerivationPathIterator<'_> {
        DerivationPathIterator::start_from(self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator<'_> {
        DerivationPathIterator::start_from(
            self,
            ChildNumber::Normal {
                index: 0,
            },
        )
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator<'_> {
        DerivationPathIterator::start_from(
            self,
            ChildNumber::Hardened {
                index: 0,
            },
        )
    }

    /// Concatenate `self` with `path` and return the resulting new path.
    ///
    /// ```
    /// use key_wallet::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let base = DerivationPath::from_str("m/42").unwrap();
    ///
    /// let deriv_1 = base.extend(DerivationPath::from_str("m/0/1").unwrap());
    /// let deriv_2 = base.extend(&[
    ///     ChildNumber::from_normal_idx(0).unwrap(),
    ///     ChildNumber::from_normal_idx(1).unwrap()
    /// ]);
    ///
    /// assert_eq!(deriv_1, deriv_2);
    /// ```
    pub fn extend<T: AsRef<[ChildNumber]>>(&self, path: T) -> DerivationPath {
        let mut new_path = self.clone();
        new_path.0.extend_from_slice(path.as_ref());
        new_path
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for cn in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(cn, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP32 error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Secp256k1(secp256k1::Error),
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4]),
    /// Encoded extended key data has wrong length
    WrongExtendedKeyLength(usize),
    /// Base58 encoding error
    Base58(base58ck::Error),
    /// Hexadecimal decoding error
    Hex(dashcore_hashes::hex::Error),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidPublicKeyHexLength(usize),
    /// Something is not supported based on active features
    NotSupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CannotDeriveFromHardenedKey => {
                f.write_str("cannot derive hardened key from public key")
            }
            Error::Secp256k1(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidChildNumber(ref n) => {
                write!(f, "child number {} is invalid (not within [0, 2^31 - 1])", n)
            }
            Error::InvalidChildNumberFormat => f.write_str("invalid child number format"),
            Error::InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            Error::UnknownVersion(ref bytes) => {
                write!(f, "unknown version magic bytes: {:?}", bytes)
            }
            Error::WrongExtendedKeyLength(ref len) => {
                write!(f, "encoded extended key data has wrong length {}", len)
            }
            Error::Base58(ref err) => write!(f, "base58 encoding error: {}", err),
            Error::Hex(ref e) => write!(f, "Hexadecimal decoding error: {}", e),
            Error::InvalidPublicKeyHexLength(got) => {
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got)
            }
            Error::NotSupported(ref msg) => write!(f, "Not supported: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        if let Error::Secp256k1(ref e) = *self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

impl From<base58ck::Error> for Error {
    fn from(err: base58ck::Error) -> Self {
        Error::Base58(err)
    }
}

impl ExtendedPrivKey {
    /// Construct a new master key from a seed value
    pub fn new_master(network: Network, seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(ExtendedPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result[..32])?,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Constructs BIP340 keypair for Schnorr signatures and Taproot use matching the internal
    /// secret key representation.
    pub fn to_keypair<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Keypair {
        Keypair::from_secret_key(secp, &self.private_key)
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut sk: ExtendedPrivKey = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    pub fn ckd_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal {
                index,
            } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
                );
                hmac_engine.input(&index.to_be_bytes());
            }
            ChildNumber::Hardened {
                index,
            } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
                hmac_engine.input(&(index | (1 << 31)).to_be_bytes());
            }
            ChildNumber::Normal256 {
                index,
            } => {
                // Non-hardened key with 256-bit index
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
                );
                hmac_engine.input(&index);
            }
            ChildNumber::Hardened256 {
                index,
            } => {
                // Hardened key with 256-bit index
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
                hmac_engine.input(&index);
            }
        }
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk = secp256k1::SecretKey::from_slice(&hmac_result[..32])
            .expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.private_key.into()).expect("statistically impossible to hit");

        Ok(ExtendedPrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Extended private key binary encoding according to BIP 32
    fn encode(&self) -> Vec<u8> {
        if self.child_number.is_256_bits() {
            self.encode_256().to_vec()
        } else {
            self.encode_32().to_vec()
        }
    }

    /// Decoding extended private key from binary data according to BIP 32
    fn decode(data: &[u8]) -> Result<ExtendedPrivKey, Error> {
        match data.len() {
            78 => Self::decode_32(data),
            107 => Self::decode_256(data),
            _ => Err(Error::WrongExtendedKeyLength(data.len())),
        }
    }

    /// Decoding extended private key from binary data according to BIP 32
    fn decode_32(data: &[u8]) -> Result<ExtendedPrivKey, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = match data {
            [0x04u8, 0x88, 0xAD, 0xE4, ..] => Network::Dash,
            [0x04u8, 0x35, 0x83, 0x94, ..] => Network::Testnet,
            [b0, b1, b2, b3, ..] => return Err(Error::UnknownVersion([*b0, *b1, *b2, *b3])),
            _ => unreachable!("length checked above"),
        };

        Ok(ExtendedPrivKey {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            private_key: secp256k1::SecretKey::from_slice(&data[46..78])?,
        })
    }

    /// Extended private key binary encoding according to BIP 32
    fn encode_32(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                Network::Dash => [0x04, 0x88, 0xAD, 0xE4],
                _ => [0x04, 0x35, 0x83, 0x94], // Testnet/Devnet/Regtest/Unknown
            }[..],
        );
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }

    /// Decoding extended private key from binary data with 256-bit child numbers
    fn decode_256(data: &[u8]) -> Result<ExtendedPrivKey, Error> {
        if data.len() != 107 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let version = &data[0..4];
        let network = match version {
            [0x0Eu8, 0xEC, 0xF0, 0x2E] => Network::Dash, // Mainnet private
            [0x0Eu8, 0xED, 0x27, 0x74] => Network::Testnet, // Testnet private
            [b0, b1, b2, b3] => return Err(Error::UnknownVersion([*b0, *b1, *b2, *b3])),
            _ => unreachable!("length checked above"),
        };

        let depth = data[4];
        let parent_fingerprint = data[5..9].try_into().expect("4 bytes for fingerprint");

        let hardening_byte = data[9];
        let is_hardened = !matches!(hardening_byte, 0x00);

        let child_number_bytes = data[10..42].try_into().expect("32 bytes for child number");
        let child_number = if is_hardened {
            ChildNumber::Hardened256 {
                index: child_number_bytes,
            }
        } else {
            ChildNumber::Normal256 {
                index: child_number_bytes,
            }
        };

        let chain_code = data[42..74].try_into().expect("32 bytes for chain code");
        let private_key = secp256k1::SecretKey::from_slice(&data[75..107])?;

        Ok(ExtendedPrivKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            private_key,
            chain_code: ChainCode(chain_code),
        })
    }

    /// Encoding extended private key to binary data with 256-bit child numbers
    fn encode_256(&self) -> [u8; 107] {
        let mut ret = [0u8; 107];

        // Version bytes
        let version: [u8; 4] = match self.network {
            Network::Dash => [0x0E, 0xEC, 0xF0, 0x2E],
            _ => [0x0E, 0xED, 0x27, 0x74], // Testnet/Devnet/Regtest/Unknown
        };
        ret[0..4].copy_from_slice(&version);

        // Depth
        ret[4] = self.depth;

        // Parent fingerprint
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        // Hardening byte
        let hardening_byte = match self.child_number {
            ChildNumber::Normal256 {
                ..
            } => 0x00,
            ChildNumber::Hardened256 {
                ..
            } => 0x01,
            _ => panic!("Invalid child number for 256-bit format"),
        };
        ret[9] = hardening_byte;

        // Child number (32 bytes)
        let child_number_bytes = match self.child_number {
            ChildNumber::Normal256 {
                index,
            }
            | ChildNumber::Hardened256 {
                index,
            } => index,
            _ => panic!("Invalid child number for 256-bit format"),
        };
        ret[10..42].copy_from_slice(&child_number_bytes);

        // Chain code (32 bytes)
        ret[42..74].copy_from_slice(&self.chain_code[..]);

        // Key data (33 bytes)
        ret[74] = 0x00; // Padding for private key
        ret[75..107].copy_from_slice(&self.private_key[..]);

        ret
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XpubIdentifier {
        ExtendedPubKey::from_priv(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.identifier(secp)[0..4].try_into().expect("4 is the fingerprint length")
    }

    /// Convert to a PrivateKey for signing operations
    pub fn to_priv(&self) -> dashcore::PrivateKey {
        dashcore::PrivateKey {
            compressed: true,
            network: self.network,
            inner: self.private_key,
        }
    }
}

impl ExtendedPubKey {
    /// Derives a public key from a private key
    #[deprecated(since = "0.28.0", note = "use ExtendedPubKey::from_priv")]
    pub fn from_private<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &ExtendedPrivKey,
    ) -> ExtendedPubKey {
        ExtendedPubKey::from_priv(secp, sk)
    }

    /// Derives a public key from a private key
    pub fn from_priv<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &ExtendedPrivKey,
    ) -> ExtendedPubKey {
        ExtendedPubKey {
            network: sk.network,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &sk.private_key),
            chain_code: sk.chain_code,
        }
    }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn to_x_only_pub(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from(self.public_key)
    }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_pub<C: secp256k1::Verification, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPubKey, Error> {
        let mut pk: ExtendedPubKey = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, *cnum)?
        }
        Ok(pk)
    }

    /// Compute the scalar tweak added to this key to get a child key
    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(
        &self,
        i: ChildNumber,
    ) -> Result<(secp256k1::SecretKey, ChainCode), Error> {
        match i {
            ChildNumber::Hardened {
                ..
            }
            | ChildNumber::Hardened256 {
                ..
            } => Err(Error::CannotDeriveFromHardenedKey),
            ChildNumber::Normal {
                index: n,
            } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.serialize()[..]);
                hmac_engine.input(&n.to_be_bytes());

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
                let chain_code = ChainCode::from_hmac(hmac_result);
                Ok((private_key, chain_code))
            }
            ChildNumber::Normal256 {
                index: idx,
            } => {
                // UInt256 mode (index >= 2^32)
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);

                // HMAC Input: serP(Kpar) || ser256(i)
                hmac_engine.input(&self.public_key.serialize()[..]);
                hmac_engine.input(&idx);

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                // IL must be less than n (order of the curve)
                let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
                let chain_code = ChainCode::from_hmac(hmac_result);

                Ok((private_key, chain_code))
            }
        }
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPubKey, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let tweaked = self.public_key.add_exp_tweak(secp, &sk.into())?;

        Ok(ExtendedPubKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: tweaked,
            chain_code,
        })
    }

    /// Extended public key binary encoding according to BIP 32 and DIP-14
    pub fn encode(&self) -> Vec<u8> {
        if self.child_number.is_256_bits() {
            self.encode_256().to_vec()
        } else {
            self.encode_32().to_vec()
        }
    }

    /// Decoding extended public key from binary data according to BIP 32 and DIP-14
    pub fn decode(data: &[u8]) -> Result<ExtendedPubKey, Error> {
        match data.len() {
            78 => Self::decode_32(data),
            107 => Self::decode_256(data),
            _ => Err(Error::WrongExtendedKeyLength(data.len())),
        }
    }

    /// Decoding extended public key from binary data according to BIP 32
    pub fn decode_32(data: &[u8]) -> Result<ExtendedPubKey, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = match data {
            [0x04u8, 0x88, 0xB2, 0x1E, ..] => Network::Dash,
            [0x04u8, 0x35, 0x87, 0xCF, ..] => Network::Testnet,
            [b0, b1, b2, b3, ..] => return Err(Error::UnknownVersion([*b0, *b1, *b2, *b3])),
            _ => unreachable!("length checked above"),
        };

        Ok(ExtendedPubKey {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
        })
    }

    /// Extended public key binary encoding according to BIP 32
    pub fn encode_32(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                Network::Dash => [0x04u8, 0x88, 0xB2, 0x1E],
                _ => [0x04u8, 0x35, 0x87, 0xCF], // Testnet/Devnet/Regtest/Unknown
            }[..],
        );
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Encoding extended public key to binary data with 256-bit child numbers
    fn encode_256(&self) -> [u8; 107] {
        let mut ret = [0u8; 107];

        // Version bytes
        let version: [u8; 4] = match self.network {
            Network::Dash => [0x0E, 0xEC, 0xEF, 0xC5],
            _ => [0x0E, 0xED, 0x27, 0x0B], // Testnet/Devnet/Regtest/Unknown
        };
        ret[0..4].copy_from_slice(&version);

        // Depth
        ret[4] = self.depth;

        // Parent fingerprint
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);

        // Hardening byte
        let hardening_byte = match self.child_number {
            ChildNumber::Normal256 {
                ..
            } => 0x00,
            ChildNumber::Hardened256 {
                ..
            } => 0x01,
            _ => panic!("Invalid child number for 256-bit format"),
        };
        ret[9] = hardening_byte;

        // Child number (32 bytes)
        let child_number_bytes = match self.child_number {
            ChildNumber::Normal256 {
                index,
            }
            | ChildNumber::Hardened256 {
                index,
            } => index,
            _ => panic!("Invalid child number for 256-bit format"),
        };
        ret[10..42].copy_from_slice(&child_number_bytes);

        // Chain code (32 bytes)
        ret[42..74].copy_from_slice(&self.chain_code[..]);

        // Key data (33 bytes)
        ret[74..107].copy_from_slice(&self.public_key.serialize()[..]);

        ret
    }

    /// Decoding extended public key from binary data with 256-bit child numbers
    fn decode_256(data: &[u8]) -> Result<ExtendedPubKey, Error> {
        if data.len() != 107 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let version = &data[0..4];
        let network = match version {
            [0x0Eu8, 0xEC, 0xEF, 0xC5] => Network::Dash, // Mainnet public
            [0x0Eu8, 0xED, 0x27, 0x0B] => Network::Testnet, // Testnet public
            [b0, b1, b2, b3] => return Err(Error::UnknownVersion([*b0, *b1, *b2, *b3])),
            _ => unreachable!("length checked above"),
        };

        let depth = data[4];
        let parent_fingerprint = data[5..9].try_into().expect("4 bytes for fingerprint");

        let hardening_byte = data[9];
        let is_hardened = !matches!(hardening_byte, 0x00);

        let child_number_bytes = data[10..42].try_into().expect("32 bytes for child number");
        let child_number = if is_hardened {
            ChildNumber::Hardened256 {
                index: child_number_bytes,
            }
        } else {
            ChildNumber::Normal256 {
                index: child_number_bytes,
            }
        };

        let chain_code = data[42..74].try_into().expect("32 bytes for chain code");

        // Key data (33 bytes)
        let public_key = secp256k1::PublicKey::from_slice(&data[74..107])?;

        Ok(ExtendedPubKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            public_key,
            chain_code: ChainCode(chain_code),
        })
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XpubIdentifier {
        let mut engine = XpubIdentifier::engine();
        engine.input(&self.public_key.serialize());
        XpubIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier()[0..4].try_into().expect("4 is the fingerprint length")
    }

    /// Convert to a PublicKey for use in address generation
    pub fn to_pub(&self) -> dashcore::PublicKey {
        dashcore::PublicKey {
            compressed: true,
            inner: self.public_key,
        }
    }
}

impl fmt::Display for ExtendedPrivKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&base58ck::encode_check(&self.encode()[..]))
    }
}

impl FromStr for ExtendedPrivKey {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ExtendedPrivKey, Error> {
        let data = base58ck::decode_check(inp)?;
        ExtendedPrivKey::decode(&data)
    }
}

impl fmt::Display for ExtendedPubKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(&base58ck::encode_check(&self.encode()[..]))
    }
}

impl FromStr for ExtendedPubKey {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ExtendedPubKey, Error> {
        let data = base58ck::decode_check(inp)?;
        ExtendedPubKey::decode(&data)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use dashcore_hashes::hex::FromHex;
    use secp256k1::{self, Secp256k1};

    use super::ChildNumber::{Hardened, Normal};
    use super::*;
    use dash_network::Network::{self, Dash};

    #[test]
    fn test_parse_derivation_path() {
        assert_eq!(DerivationPath::from_str("42"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("n/0'/0"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("4/m/5"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("m//3/0'"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(DerivationPath::from_str("m/0h/0x"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(
            DerivationPath::from_str("m/2147483648"),
            Err(Error::InvalidChildNumber(2147483648))
        );

        assert_eq!(DerivationPath::master(), DerivationPath::from_str("m").unwrap());
        assert_eq!(DerivationPath::master(), DerivationPath::default());
        assert_eq!(DerivationPath::from_str("m"), Ok(Vec::new().into()));
        assert_eq!(
            DerivationPath::from_str("m/0'"),
            Ok(vec![ChildNumber::from_hardened_idx(0).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap()
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/1/2'"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2h/2"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2'/2/1000000000"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
                ChildNumber::from_normal_idx(1000000000).unwrap(),
            ]
            .into())
        );
        let s = "m/0'/50/3'/5/545456";
        assert_eq!(DerivationPath::from_str(s), s.into_derivation_path());
        assert_eq!(DerivationPath::from_str(s), s.to_string().into_derivation_path());
    }

    #[test]
    fn test_derivation_path_conversion_index() {
        let path = DerivationPath::from_str("m/0h/1/2'").unwrap();
        let numbers: Vec<ChildNumber> = path.clone().into();
        let path2: DerivationPath = numbers.into();
        assert_eq!(path, path2);
        assert_eq!(
            &path[..2],
            &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap()]
        );
        let indexed: DerivationPath = path[..2].into();
        assert_eq!(indexed, DerivationPath::from_str("m/0h/1").unwrap());
        assert_eq!(indexed.child(ChildNumber::from_hardened_idx(2).unwrap()), path);
    }

    fn test_path<C: secp256k1::Signing + secp256k1::Verification>(
        secp: &Secp256k1<C>,
        network: Network,
        seed: &[u8],
        path: DerivationPath,
        expected_sk: &str,
        expected_pk: &str,
    ) {
        let mut sk = ExtendedPrivKey::new_master(network, seed).unwrap();
        let mut pk = ExtendedPubKey::from_priv(secp, &sk);

        // Check derivation convenience method for ExtendedPrivKey
        assert_eq!(&sk.derive_priv(secp, &path).unwrap().to_string()[..], expected_sk);

        // Check derivation convenience method for ExtendedPubKey, should error
        // appropriately if any ChildNumber is hardened
        if path.0.iter().any(|cnum| cnum.is_hardened()) {
            assert_eq!(pk.derive_pub(secp, &path), Err(Error::CannotDeriveFromHardenedKey));
        } else {
            assert_eq!(&pk.derive_pub(secp, &path).unwrap().to_string()[..], expected_pk);
        }

        // Derive keys, checking hardened and non-hardened derivation one-by-one
        for &num in path.0.iter() {
            sk = sk.ckd_priv(secp, num).unwrap();
            match num {
                Normal {
                    ..
                }
                | ChildNumber::Normal256 {
                    ..
                } => {
                    let pk2 = pk.ckd_pub(secp, num).unwrap();
                    pk = ExtendedPubKey::from_priv(secp, &sk);
                    assert_eq!(pk, pk2);
                }
                Hardened {
                    ..
                }
                | ChildNumber::Hardened256 {
                    ..
                } => {
                    assert_eq!(pk.ckd_pub(secp, num), Err(Error::CannotDeriveFromHardenedKey));
                    pk = ExtendedPubKey::from_priv(secp, &sk);
                }
            }
        }

        // Check result against expected base58
        assert_eq!(&sk.to_string()[..], expected_sk);
        assert_eq!(&pk.to_string()[..], expected_pk);
        // Check decoded base58 against result
        let decoded_sk = ExtendedPrivKey::from_str(expected_sk);
        let decoded_pk = ExtendedPubKey::from_str(expected_pk);
        assert_eq!(Ok(sk), decoded_sk);
        assert_eq!(Ok(pk), decoded_pk);
    }

    #[test]
    fn test_increment() {
        let idx = 9345497; // randomly generated, I promise
        let cn = ChildNumber::from_normal_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_normal_idx(idx + 1).unwrap()));
        let cn = ChildNumber::from_hardened_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_hardened_idx(idx + 1).unwrap()));

        let max = (1 << 31) - 1;
        let cn = ChildNumber::from_normal_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1 << 31)));
        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1 << 31)));

        let cn = ChildNumber::from_normal_idx(350).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("m/42'/350".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/351".parse().unwrap()));

        let path = DerivationPath::from_str("m/42'/350'").unwrap();
        let mut iter = path.normal_children();
        assert_eq!(iter.next(), Some("m/42'/350'/0".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/350'/1".parse().unwrap()));

        let path = DerivationPath::from_str("m/42'/350'").unwrap();
        let mut iter = path.hardened_children();
        assert_eq!(iter.next(), Some("m/42'/350'/0'".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/350'/1'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(42350).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("m/42'/42350'".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/42351'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_vector_1() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();

        // m
        test_path(
            &secp,
            Dash,
            &seed,
            "m".parse().unwrap(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        );

        // m/0h
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0h".parse().unwrap(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        );

        // m/0h/1
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0h/1".parse().unwrap(),
            "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        );

        // m/0h/1/2h
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0h/1/2h".parse().unwrap(),
            "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
            "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        );

        // m/0h/1/2h/2
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0h/1/2h/2".parse().unwrap(),
            "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
            "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        );

        // m/0h/1/2h/2/1000000000
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0h/1/2h/2/1000000000".parse().unwrap(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        );
    }

    #[test]
    fn test_vector_2() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();

        // m
        test_path(
            &secp,
            Dash,
            &seed,
            "m".parse().unwrap(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        );

        // m/0
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0".parse().unwrap(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        );

        // m/0/2147483647h
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0/2147483647h".parse().unwrap(),
            "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
            "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        );

        // m/0/2147483647h/1
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0/2147483647h/1".parse().unwrap(),
            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
            "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        );

        // m/0/2147483647h/1/2147483646h
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0/2147483647h/1/2147483646h".parse().unwrap(),
            "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        );

        // m/0/2147483647h/1/2147483646h/2
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0/2147483647h/1/2147483646h/2".parse().unwrap(),
            "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        );
    }

    #[test]
    fn test_vector_3() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();

        // m
        test_path(
            &secp,
            Dash,
            &seed,
            "m".parse().unwrap(),
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        );

        // m/0h
        test_path(
            &secp,
            Dash,
            &seed,
            "m/0h".parse().unwrap(),
            "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_childnumber() {
        serde_round_trip!(ChildNumber::from_normal_idx(0).unwrap());
        serde_round_trip!(ChildNumber::from_normal_idx(1).unwrap());
        serde_round_trip!(ChildNumber::from_normal_idx((1 << 31) - 1).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx(0).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx(1).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx((1 << 31) - 1).unwrap());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_fingerprint_chaincode() {
        use serde_json;
        let fp = Fingerprint::from([1u8, 2, 3, 42]);
        let cc = ChainCode::from([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 0, 1, 2,
        ]);

        serde_round_trip!(fp);
        serde_round_trip!(cc);

        assert_eq!("\"0102032a\"", serde_json::to_string(&fp).unwrap());
        assert_eq!(
            "\"0102030405060708090001020304050607080900010203040506070809000102\"",
            serde_json::to_string(&cc).unwrap()
        );
        assert_eq!("0102032a", fp.to_string());
        assert_eq!(
            "0102030405060708090001020304050607080900010203040506070809000102",
            cc.to_string()
        );
    }

    #[test]
    fn fmt_child_number() {
        assert_eq!("000005h", &format!("{:#06}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("5h", &format!("{:#}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("000005'", &format!("{:06}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("5'", &format!("{}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("42", &format!("{}", ChildNumber::from_normal_idx(42).unwrap()));
        assert_eq!("000042", &format!("{:06}", ChildNumber::from_normal_idx(42).unwrap()));
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_zeros() {
        /* this is how we generate key:
        let mut sk = secp256k1::key::ONE_KEY;

        let zeros = [0u8; 32];
        unsafe {
            sk.as_mut_ptr().copy_from(zeros.as_ptr(), 32);
        }

        let xpriv = ExtendedPrivKey {
            network: Network::Dash,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: sk,
            chain_code: ChainCode::from(&[0u8; 32][..])
        };

        println!("{}", xpriv);
         */

        // Xpriv having secret key set to all zeros
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx";
        ExtendedPrivKey::from_str(xpriv_str).unwrap();
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_ffs() {
        // Xpriv having secret key set to all 0xFF's
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        ExtendedPrivKey::from_str(xpriv_str).unwrap();
    }

    #[test]
    fn test_dashpay_vector_1() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("b16d3782e714da7c55a397d5f19104cfed7ffa8036ac514509bbb50807f8ac598eeb26f0797bd8cc221a6cbff2168d90a5e9ee025a5bd977977b9eccd97894bb").unwrap();

        // Test Vector 1: Non-hardened / Hardened path example
        test_path(
            &secp,
            Network::Testnet,
            &seed,
            "m/0x775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b/\
         0xf537439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89a6'/\
         0x4c4592ca670c983fc43397dfd21a6f427fac9b4ac53cb4dcdc6522ec51e81e79/0"
                .parse()
                .unwrap(),
            "tprv8iNr6Z8PgAHmYSgMKGbq42kMVAAQmwmzm5iTJdUXoxLf25zG3GeRCvnEdC6HKTHkU59nZkfjvcGk9VW2YHsFQMwsZrQLyNrGx9c37kgb368",
            "tpubDF4tEyAdpXySRui9CvGRTSQU4BgLwGxuLPKEb9WqEE93raF2ffU1PRQ6oJHCgZ7dArzcMj9iKG8s8EFA1DdwgzWAXs61uFuRE1bQi8kAmLy",
        );
    }

    #[test]
    fn test_dashpay_vector_2() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("b16d3782e714da7c55a397d5f19104cfed7ffa8036ac514509bbb50807f8ac598eeb26f0797bd8cc221a6cbff2168d90a5e9ee025a5bd977977b9eccd97894bb").unwrap();

        // Test Vector 2: Multiple hardened derivations with final non-hardened index
        test_path(
            &secp,
            Network::Testnet,
            &seed,
            "m/9'/5'/15'/0'/\
         0x555d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3a'/\
         0xa137439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89b5'/0"
                .parse()
                .unwrap(),
            "tprv8p9LqE2tA2b94gc3ciRNA525WVkFvzkcC9qjpKEcGaTqjb9u2pwTXj41KkZTj3c1a6fJUpyXRfcB4dimsYsLMjQjsTJwi5Ukx6tJ5BpmYpx",
            "tpubDLqNye58JQGox9dqWN5xZUgC5XGC6KwWmTSX6qGugrGEa5QffDm3iDfsVtX7qyXuWoQsXA6YCSuckKshyjnwiGGoYWHonAv2X98HTU613UH",
        );
    }

    #[test]
    fn test_dashpay_vector_3() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("b16d3782e714da7c55a397d5f19104cfed7ffa8036ac514509bbb50807f8ac598eeb26f0797bd8cc221a6cbff2168d90a5e9ee025a5bd977977b9eccd97894bb").unwrap();

        // Test Vector 3: Non-hardened derivation
        test_path(
            &secp,
            Network::Testnet,
            &seed,
            "m/0x775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b".parse().unwrap(),
            "dpts1vgMVEs9mmv1YLwURCeoTn9CFMZ8JMVhyZuxQSKttNSETR3zydMFHMKTTNDQPf6nnupCCtcNnSu3nKZXAJhaguyoJWD4Ju5PE6PSkBqAKWci7HLz37qmFmZZU6GMkLvNLtST2iV8NmqqbX37c45",
            "dptp1C5gGd8NzvAke5WNKyRfpDRyvV2UZ3jjrZVZU77qk9yZemMGSdZpkWp7y6wt3FzvFxAHSW8VMCaC1p6Ny5EqWuRm2sjvZLUUFMMwXhmW6eS69qjX958RYBH5R8bUCGZkCfUyQ8UVWcx9katkrRr",
        );
    }

    #[test]
    fn test_dashpay_vector_4() {
        let secp = Secp256k1::new();
        let seed = Vec::from_hex("b16d3782e714da7c55a397d5f19104cfed7ffa8036ac514509bbb50807f8ac598eeb26f0797bd8cc221a6cbff2168d90a5e9ee025a5bd977977b9eccd97894bb").unwrap();

        // Test Vector 4: Hardened path with complex indices
        test_path(
            &secp,
            Network::Testnet,
            &seed,
            "m/0x775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b/\
         0xf537439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89a6'"
                .parse()
                .unwrap(),
            "dpts1vwRsaPMQfqwp59ELpx5UeuYtdaMCJyGTwiGtr8zgf6qWPMWnhPpg8R73hwR1xLibbdKVdh17zfwMxFEMxZzBKUgPwvuosUGDKW4ayZjs3AQB9EGRcVpDoFT8V6nkcc6KzksmZxvmDcd3MqiPEu",
            "dptp1CLkexeadp6guoi8Fbiwq6CLZm3hT1DJLwHsxWvwYSeAhjenFhcQ9HumZSftfZEr4dyQjFD7gkM5bSn6Aj7F1Jve8KTn4JsMEaj9dFyJkYs4Ga5HSUqeajxGVmzaY1pEioDmvUtZL3J1NCDCmzQ",
        );
    }

    const HEX_SEED: &str = "368a0691faa33e646108368dc0d9a1f9c440e0c5393ffd2def5ed2200d6019d0f7094c24503d6d1209756ac5bfd87731b0e816736de8f5f44ea636d2b830b3bf";

    #[test]
    fn test_bip_44_account_path() {
        let path = DerivationPath::bip_44_account(Network::Dash, 0);
        assert_eq!(path.to_string(), "m/44'/5'/0'");
    }

    #[test]
    fn test_bip_44_payment_path() {
        let path = DerivationPath::bip_44_payment_path(Network::Dash, 0, true, 0);
        assert_eq!(path.to_string(), "m/44'/5'/0'/1/0");

        let path = DerivationPath::bip_44_payment_path(Network::Testnet, 1, false, 42);
        assert_eq!(path.to_string(), "m/44'/1'/1'/0/42");
    }

    #[test]
    fn test_coinjoin_path() {
        let path = DerivationPath::coinjoin_path(Network::Dash, 0);
        assert_eq!(path.to_string(), "m/9'/5'/4'/0'");

        let path = DerivationPath::coinjoin_path(Network::Testnet, 1);
        assert_eq!(path.to_string(), "m/9'/1'/4'/1'");
    }

    #[test]
    fn test_identity_registration_path() {
        let path = DerivationPath::identity_registration_path(Network::Dash, 10);
        assert_eq!(path.to_string(), "m/9'/5'/5'/1'/10'");
    }

    #[test]
    fn test_identity_top_up_path() {
        let path = DerivationPath::identity_top_up_path(Network::Testnet, 2, 3);
        assert_eq!(path.to_string(), "m/9'/1'/5'/2'/2'/3");
    }

    #[test]
    fn test_identity_invitation_path() {
        let path = DerivationPath::identity_invitation_path(Network::Dash, 15);
        assert_eq!(path.to_string(), "m/9'/5'/5'/3'/15'");
    }

    #[test]
    fn test_identity_authentication_path() {
        let path = DerivationPath::identity_authentication_path(
            Network::Dash,
            KeyDerivationType::ECDSA,
            1,
            2,
        );
        assert_eq!(path.to_string(), "m/9'/5'/5'/0'/0'/1'/2'");

        let path = DerivationPath::identity_authentication_path(
            Network::Testnet,
            KeyDerivationType::BLS,
            2,
            3,
        );
        assert_eq!(path.to_string(), "m/9'/1'/5'/0'/1'/2'/3'");
    }

    #[test]
    fn test_derive_priv_ecdsa_for_master_seed() {
        let path = DerivationPath::bip_44_account(Network::Dash, 0);
        let sk = path
            .derive_priv_ecdsa_for_master_seed(
                hex::decode(HEX_SEED).unwrap().as_ref(),
                Network::Dash,
            )
            .unwrap();
        assert_eq!(
            sk.to_string(),
            "xprv9yiAr178GdLQhB7qVbi6YQ76jopjKcUB6gGFZzYjdCNSmq1fU1RG13K3f3UP1EPNPSerY4conJPozCYeKz9QGmmvZ3CFML3qet8YVCwiTrN"
        );
        // Add correct expected value
    }

    #[test]
    fn test_derive_pub_ecdsa_for_master_seed() {
        let path = DerivationPath::bip_44_account(Network::Dash, 0);
        let pk = path
            .derive_pub_ecdsa_for_master_seed(
                hex::decode(HEX_SEED).unwrap().as_ref(),
                Network::Dash,
            )
            .unwrap();
        assert_eq!(
            pk.to_string(),
            "xpub6ChXFWe26zthufCJbdF6uY3qHqfDj5C2TuBrNNxMBXuRedLp1YjWYqdXWMnn9eLzbWWZCqbi4Cdnes1SNgK9GRaBUcZPLyLEpPRi3dU3syV"
        );
        // Add correct expected value
    }

    #[test]
    fn test_derive_priv_ecdsa_payment_change_key() {
        let path = DerivationPath::bip_44_payment_path(Network::Dash, 0, true, 3);
        let sk = path
            .derive_priv_ecdsa_for_master_seed(
                hex::decode(HEX_SEED).unwrap().as_ref(),
                Network::Dash,
            )
            .unwrap();
        assert_eq!(sk.to_string(), "xprvA4FGorKLZVC4VT3Lf2UZS3hYZBpc8wGmmyyo5HPTUS8RcyX1yw2qHddBZVxn1u4NVduXDob1sKnx3d9e5wdY3VP8qibq7CgMqPhjUoV5G2K");
        // Add correct expected value
    }

    #[test]
    fn test_derive_priv_ecdsa_payment_main_key() {
        let path = DerivationPath::bip_44_payment_path(Network::Dash, 0, false, 3);
        let sk = path
            .derive_priv_ecdsa_for_master_seed(
                hex::decode(HEX_SEED).unwrap().as_ref(),
                Network::Dash,
            )
            .unwrap();
        assert_eq!(sk.to_string(), "xprvA4F8hpkJuhhk4xqnnmY44WiVwUVPMdbF9VHE8vVmAiF6NyVXNmnyg5KnZF4VibNUuycJs6Dov4YBLm6bT2qGa81B5HHgqhUvixW2Qcgg5AE");
        // Add correct expected value
    }

    #[test]
    fn test_derive_pub_ecdsa_payment_change_key() {
        let path = DerivationPath::bip_44_payment_path(Network::Dash, 0, true, 3);
        let sk = path
            .derive_pub_ecdsa_for_master_seed(
                hex::decode(HEX_SEED).unwrap().as_ref(),
                Network::Dash,
            )
            .unwrap();
        assert_eq!(
            sk.public_key.to_string(),
            "034c155580c961177c91eda529147d93ee5088b49a3d9462f8cd9943533ac2fbc8"
        ); // Add correct expected value
    }

    #[test]
    fn test_derive_pub_ecdsa_payment_external_key() {
        let path = DerivationPath::bip_44_payment_path(Network::Dash, 0, false, 3);
        let sk = path
            .derive_pub_ecdsa_for_master_seed(
                hex::decode(HEX_SEED).unwrap().as_ref(),
                Network::Dash,
            )
            .unwrap();
        assert_eq!(
            sk.public_key.to_string(),
            "0251b09b90295c4c793e9452af0e14142c3406b67e864541149de708eb2d41d104"
        ); // Add correct expected value
    }

    #[test]
    fn test_to_priv_and_to_pub() {
        let seed = [0x42u8; 32];
        let network = Network::Testnet;

        let ext_priv = ExtendedPrivKey::new_master(network, &seed).unwrap();
        let secp = Secp256k1::new();

        // Test to_priv() method
        let priv_key = ext_priv.to_priv();
        assert!(priv_key.compressed);
        assert_eq!(priv_key.network, dashcore::Network::Testnet);
        assert_eq!(priv_key.inner, ext_priv.private_key);

        // Test to_pub() method
        let ext_pub = ExtendedPubKey::from_priv(&secp, &ext_priv);
        let pub_key = ext_pub.to_pub();
        assert!(pub_key.compressed);
        assert_eq!(pub_key.inner, ext_pub.public_key);

        // Verify the keys match
        let pub_from_priv = dashcore::PublicKey::from_private_key(&secp, &priv_key);
        assert_eq!(pub_key.inner, pub_from_priv.inner);
    }
}
