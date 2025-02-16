// Rust Dash Library
// Written by
//   The Rust Dash developers
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

//! Dash BLS elements
//! Convenience wrappers around fixed size arrays of 48 and 96 bytes representing the public key
//! and signature.
//!

#[cfg(feature = "bls")]
use blsful::{Bls12381G2Impl, Pairing};
use hex::{FromHexError, ToHex};
use internals::impl_array_newtype;
use crate::core::fmt;
use crate::internal_macros::impl_bytes_newtype;
use crate::prelude::String;
use crate::sml::quorum_validation_error::QuorumValidationError;

/// A BLS Public key is 48 bytes in the scheme used for Dash Core
#[rustversion::attr(since(1.48), derive(PartialEq, Eq, Ord, PartialOrd, Hash))]
#[derive(Clone, Copy, Debug)]
pub struct BLSPublicKey([u8; 48]);

impl BLSPublicKey {
    pub fn is_zeroed(&self) -> bool {
        self.0 == [0;48]
    }
}

impl_array_newtype!(BLSPublicKey, u8, 48);

#[cfg(feature = "bls")]
impl TryFrom<BLSPublicKey> for blsful::PublicKey<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: BLSPublicKey) -> Result<Self, Self::Error> {
        Self::try_from(value.0.as_slice()).map_err(|e| QuorumValidationError::InvalidBLSPublicKey(e.to_string()))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<&BLSPublicKey> for blsful::PublicKey<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: &BLSPublicKey) -> Result<Self, Self::Error> {
        Self::try_from(value.0.as_slice()).map_err(|e| QuorumValidationError::InvalidBLSPublicKey(e.to_string()))
    }
}

impl BLSPublicKey {
    /// Create a new BLS Public Key from a hex string
    pub fn from_hex(s: &str) -> Result<BLSPublicKey, FromHexError> {
        hex::decode(s).map(|v| {
            let mut payload: [u8; 48] = [0; 48];
            payload.copy_from_slice(v.as_slice());
            Self(payload)
        })
    }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(BLSPublicKey, "a BLS Public Key");

impl core::str::FromStr for BLSPublicKey {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { BLSPublicKey::from_hex(s) }
}

impl fmt::Display for BLSPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode_hex::<String>())
    }
}

/// A BLS Signature is 96 bytes in the scheme used for Dash Core
#[rustversion::attr(since(1.48), derive(PartialEq, Eq, Ord, PartialOrd, Hash))]
#[derive(Clone, Copy)]
pub struct BLSSignature([u8; 96]);

impl BLSSignature {
    pub fn is_zeroed(&self) -> bool {
        self.0 == [0;96]
    }
}

#[cfg(feature = "bls")]
impl TryFrom<BLSSignature> for blsful::Signature<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: BLSSignature) -> Result<Self, Self::Error> {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes()))); // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::Signature::Basic(g2_element))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<&BLSSignature> for blsful::Signature<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: &BLSSignature) -> Result<Self, Self::Error> {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes()))); // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::Signature::Basic(g2_element))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<BLSSignature> for blsful::MultiSignature<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: BLSSignature) -> Result<Self, Self::Error> {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes()))); // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::MultiSignature::Basic(g2_element))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<&BLSSignature> for blsful::MultiSignature<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: &BLSSignature) -> Result<Self, Self::Error> {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes()))); // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::MultiSignature::Basic(g2_element))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<BLSSignature> for blsful::AggregateSignature<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: BLSSignature) -> Result<Self, Self::Error> {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes()))); // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::AggregateSignature::Basic(g2_element))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<&BLSSignature> for blsful::AggregateSignature<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: &BLSSignature) -> Result<Self, Self::Error> {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes()))); // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::AggregateSignature::Basic(g2_element))
    }
}

impl_array_newtype!(BLSSignature, u8, 96);
impl_bytes_newtype!(BLSSignature, 96);

macro_rules! impl_elementencode {
    ($element:ident, $len:expr) => {
        impl $crate::consensus::Encodable for $element {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, $crate::io::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $element {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<Self, $crate::consensus::encode::Error> {
                let mut data: [u8; $len] = [0u8; $len];
                r.read_exact(&mut data)?;
                Ok($element(data))
            }
        }
    };
}

#[rustversion::before(1.48)]
macro_rules! impl_eq_ord_hash {
    ($element:ident, $len:expr) => {
        #[rustversion::before(1.48)]
        impl core::hash::Hash for $element {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) { self.0.to_vec().hash(state) }
        }

        #[rustversion::before(1.48)]
        impl core::cmp::PartialEq<$element> for $element {
            fn eq(&self, other: &$element) -> bool {
                for i in 0..$len {
                    if self[i] != other[i] {
                        return false;
                    }
                }
                true
            }
        }

        #[rustversion::before(1.48)]
        impl core::cmp::Eq for $element {}

        #[rustversion::before(1.48)]
        impl core::cmp::PartialOrd for $element {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                self.0.to_vec().partial_cmp(&other.0.to_vec())
            }
        }

        #[rustversion::before(1.48)]
        impl core::cmp::Ord for $element {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.0.to_vec().cmp(&other.0.to_vec())
            }
        }
    };
}

#[rustversion::before(1.48)]
impl_eq_ord_hash!(BLSPublicKey, 48);
#[rustversion::before(1.48)]
impl_eq_ord_hash!(BLSSignature, 96);

impl_elementencode!(BLSPublicKey, 48);
impl_elementencode!(BLSSignature, 96);
