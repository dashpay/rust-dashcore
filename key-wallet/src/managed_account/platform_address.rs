//! Platform P2PKH address type for DIP-17/DIP-18
//!
//! This module provides the `PlatformP2PKHAddress` type which represents
//! a 20-byte hash used in Platform Payment addresses.

use crate::error::{Error, Result};
use crate::Network;
use core::fmt;
use dashcore::address::Payload;
use dashcore::hashes::hash160::Hash as Hash160;
use dashcore::hashes::Hash as HashTrait;
use dashcore::Address;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Platform P2PKH address (DIP-17/DIP-18)
///
/// This type stores the 20-byte hash portion of a P2PKH address used in
/// Platform Payment accounts. It provides methods for:
/// - Converting to/from `dashcore::Address`
/// - Extracting the raw hash bytes
///
/// The derivation path for these addresses follows DIP-17:
/// `m/9'/coin_type'/17'/account'/key_class'/index`
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlatformP2PKHAddress([u8; 20]);

impl PlatformP2PKHAddress {
    /// Create a new PlatformP2PKHAddress from a 20-byte hash
    pub fn new(hash: [u8; 20]) -> Self {
        Self(hash)
    }

    /// Create from a byte slice
    ///
    /// Returns an error if the slice is not exactly 20 bytes
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 20 {
            return Err(Error::InvalidAddress(format!("Expected 20 bytes, got {}", slice.len())));
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the hash bytes as a reference
    pub fn hash(&self) -> &[u8; 20] {
        &self.0
    }

    /// Get the hash bytes as an owned array
    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    /// Get the hash bytes as a slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a dashcore::Address (P2PKH)
    ///
    /// This creates a standard P2PKH address from the hash.
    /// Note: This is for interoperability - Platform addresses typically
    /// use bech32m encoding rather than base58 P2PKH format.
    pub fn to_address(&self, network: Network) -> Address {
        let pubkey_hash = Hash160::from_slice(&self.0).expect("20 bytes is valid for Hash160");
        let payload = Payload::PubkeyHash(pubkey_hash.into());
        Address::new(network, payload)
    }

    /// Create from a dashcore::Address
    ///
    /// Only P2PKH addresses are supported. Returns an error for other address types.
    pub fn from_address(address: &Address) -> Result<Self> {
        match address.payload() {
            Payload::PubkeyHash(hash) => {
                let bytes: [u8; 20] = *hash.as_byte_array();
                Ok(Self(bytes))
            }
            _ => Err(Error::InvalidAddress(
                "Only P2PKH addresses can be converted to PlatformP2PKHAddress".to_string(),
            )),
        }
    }

    /// Create from an AddressInfo
    ///
    /// Extracts the P2PKH hash from the address in AddressInfo.
    pub fn from_address_info(info: &super::address_pool::AddressInfo) -> Result<Self> {
        Self::from_address(&info.address)
    }
}

impl fmt::Debug for PlatformP2PKHAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlatformP2PKHAddress({})", hex::encode(self.0))
    }
}

impl fmt::Display for PlatformP2PKHAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as hex by default
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 20]> for PlatformP2PKHAddress {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl From<PlatformP2PKHAddress> for [u8; 20] {
    fn from(addr: PlatformP2PKHAddress) -> [u8; 20] {
        addr.0
    }
}

impl AsRef<[u8]> for PlatformP2PKHAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for PlatformP2PKHAddress {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(&self.0, encoder)
    }
}

#[cfg(feature = "bincode")]
impl<Context> bincode::Decode<Context> for PlatformP2PKHAddress {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        Ok(Self(<[u8; 20]>::decode(decoder)?))
    }
}

#[cfg(feature = "bincode")]
impl<'de, Context> bincode::BorrowDecode<'de, Context> for PlatformP2PKHAddress {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        Ok(Self(<[u8; 20]>::borrow_decode(decoder)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_address_creation() {
        let hash = [0x12u8; 20];
        let addr = PlatformP2PKHAddress::new(hash);
        assert_eq!(addr.hash(), &hash);
        assert_eq!(addr.to_bytes(), hash);
    }

    #[test]
    fn test_from_slice() {
        let hash = [0x34u8; 20];
        let addr = PlatformP2PKHAddress::from_slice(&hash).unwrap();
        assert_eq!(addr.to_bytes(), hash);

        // Wrong length should fail
        let short = [0u8; 19];
        assert!(PlatformP2PKHAddress::from_slice(&short).is_err());
    }

    #[test]
    fn test_to_from_dashcore_address() {
        let hash = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3,
            0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ];
        let platform_addr = PlatformP2PKHAddress::new(hash);

        let dashcore_addr = platform_addr.to_address(Network::Testnet);
        let roundtrip = PlatformP2PKHAddress::from_address(&dashcore_addr).unwrap();

        assert_eq!(roundtrip, platform_addr);
    }

    #[test]
    fn test_display_and_debug() {
        let hash = [0xab; 20];
        let addr = PlatformP2PKHAddress::new(hash);

        let display = format!("{}", addr);
        assert_eq!(display, "abababababababababababababababababababab");

        let debug = format!("{:?}", addr);
        assert!(debug.contains("PlatformP2PKHAddress"));
        assert!(debug.contains("abababababababababababababababababababab"));
    }

    #[test]
    fn test_from_array() {
        let hash = [0x55u8; 20];
        let addr: PlatformP2PKHAddress = hash.into();
        assert_eq!(addr.to_bytes(), hash);

        let back: [u8; 20] = addr.into();
        assert_eq!(back, hash);
    }
}
