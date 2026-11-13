//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! BLS12-381 public key and signatures.

use core::fmt;
use core::str::FromStr;

pub use dashcore_crypto::bls::BlsSigBytes as BLSSignature;
pub use dashcore_crypto::bls::*;
use hex_conservative::DisplayHex;

/// A BLS public key (48 bytes) as carried in Dash payloads and masternode lists.
///
/// Its own type rather than an alias of [`BlsPkBytes`] so that serde writes it as a hex string
/// in every format, binary ones included, as it did before the BLS backend moved to
/// `dashcore-crypto`: data persisted through binary serde keeps decoding. Convert into a
/// [`BlsPkBytes`] for cryptographic operations.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct BLSPublicKey([u8; BLS_PK_LEN]);

impl Default for BLSPublicKey {
    fn default() -> Self {
        Self([0; BLS_PK_LEN])
    }
}

impl BLSPublicKey {
    /// Wraps the raw key bytes.
    pub const fn from_bytes(bytes: [u8; BLS_PK_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies out the raw key bytes.
    pub const fn to_bytes(self) -> [u8; BLS_PK_LEN] {
        self.0
    }

    /// Borrows the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; BLS_PK_LEN] {
        &self.0
    }

    /// Reads the key from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex_conservative::DecodeFixedLengthBytesError> {
        hex_conservative::decode_to_array(s).map(Self)
    }

    /// Returns `true` when every byte is zero.
    pub fn is_zeroed(&self) -> bool {
        self.0 == [0; BLS_PK_LEN]
    }

    /// Pairs the key with the scheme to read it under, see [`BlsPkBytes::as_scheme`].
    #[cfg(feature = "bls")]
    pub fn as_scheme(self, scheme: BlsScheme) -> BlsPublicKey {
        BlsPkBytes::from(self).as_scheme(scheme)
    }
}

impl From<[u8; BLS_PK_LEN]> for BLSPublicKey {
    fn from(bytes: [u8; BLS_PK_LEN]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for BLSPublicKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; BLS_PK_LEN]>::try_from(slice).map(Self)
    }
}

impl From<BlsPkBytes> for BLSPublicKey {
    fn from(key: BlsPkBytes) -> Self {
        Self(key.to_bytes())
    }
}

impl From<BLSPublicKey> for BlsPkBytes {
    fn from(key: BLSPublicKey) -> Self {
        BlsPkBytes::from_bytes(key.0)
    }
}

impl AsRef<[u8; BLS_PK_LEN]> for BLSPublicKey {
    fn as_ref(&self) -> &[u8; BLS_PK_LEN] {
        &self.0
    }
}

impl fmt::Display for BLSPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0.as_hex(), f)
    }
}

impl fmt::Debug for BLSPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BLSPublicKey({self})")
    }
}

impl FromStr for BLSPublicKey {
    type Err = hex_conservative::DecodeFixedLengthBytesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

// A hex string in every format, as before the BLS backend moved to `dashcore-crypto`.
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_serialize_impl!(BLSPublicKey, "a BLS public key");
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(BLSPublicKey, "a BLS public key");

macro_rules! impl_elementencode {
    ($element:ident, $len:expr) => {
        impl $crate::consensus::Encodable for $element {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, $crate::io::Error> {
                self.as_bytes().consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $element {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<Self, $crate::consensus::encode::Error> {
                let mut data: [u8; $len] = [0u8; $len];
                r.read_exact(&mut data)?;
                Ok($element::from_bytes(data))
            }
        }
    };
}

impl_elementencode!(BLSPublicKey, 48);
impl_elementencode!(BLSSignature, 96);

#[cfg(test)]
mod tests {
    use super::*;

    /// Binary serde (e.g. `bincode::serde`, used to persist wallet records) writes the key as
    /// its hex string. Fixed bytes so a change of the stored layout can't go unnoticed.
    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test]
    fn binary_serde_writes_the_hex_string() {
        let key = BLSPublicKey::from_bytes(core::array::from_fn(|i| i as u8));
        let config = bincode::config::standard();

        let bytes = bincode::serde::encode_to_vec(key, config).expect("serialize key");
        let mut expected = vec![96u8];
        expected.extend_from_slice(key.to_string().as_bytes());
        assert_eq!(bytes, expected);

        let (back, _): (BLSPublicKey, _) =
            bincode::serde::decode_from_slice(&bytes, config).expect("deserialize key");
        assert_eq!(back, key);
    }

    #[test]
    fn converts_to_and_from_bls_pk_bytes() {
        let key = BLSPublicKey::from_bytes([7; BLS_PK_LEN]);
        assert_eq!(BLSPublicKey::from(BlsPkBytes::from(key)), key);
        assert_eq!(key.to_string().parse::<BLSPublicKey>().unwrap(), key);
    }
}
