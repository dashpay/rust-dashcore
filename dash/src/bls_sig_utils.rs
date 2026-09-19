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

use core::str::FromStr;

#[cfg(feature = "bls")]
use blsful::{Bls12381G2Impl, Pairing};
use dash_types::make_bytes;
use hex::FromHexError;

#[cfg(feature = "bls")]
use crate::sml::quorum_validation_error::QuorumValidationError;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Raw BLS signature length (G2 compressed).
pub const BLS_SIG_LEN: usize = 96;

make_bytes! {
    /// BLS public key (48 bytes, unvalidated).
    BLSPublicKey, BLS_PK_LEN
}

impl BLSPublicKey {
    /// Reads these bytes from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, FromHexError> {
        let mut bytes = [0u8; BLS_PK_LEN];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Returns `true` when every byte is zero.
    pub fn is_zeroed(&self) -> bool {
        self.is_null()
    }
}

impl FromStr for BLSPublicKey {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for BLSPublicKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(self.as_bytes(), encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for BLSPublicKey {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <[u8; BLS_PK_LEN] as bincode::Decode<C>>::decode(decoder).map(Self::from_bytes)
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for BLSPublicKey {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

impl TryFrom<&[u8]> for BLSPublicKey {
    type Error = core::array::TryFromSliceError;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(<[u8; BLS_PK_LEN]>::try_from(v)?))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<BLSPublicKey> for blsful::PublicKey<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: BLSPublicKey) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().as_slice())
            .map_err(|e| QuorumValidationError::InvalidBLSPublicKey(e.to_string()))
    }
}

#[cfg(feature = "bls")]
impl TryFrom<&BLSPublicKey> for blsful::PublicKey<Bls12381G2Impl> {
    type Error = QuorumValidationError;

    fn try_from(value: &BLSPublicKey) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().as_slice())
            .map_err(|e| QuorumValidationError::InvalidBLSPublicKey(e.to_string()))
    }
}

make_bytes! {
    /// BLS signature (96 bytes, unvalidated).
    BLSSignature, BLS_SIG_LEN
}

impl BLSSignature {
    /// Reads these bytes from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, FromHexError> {
        let mut bytes = [0u8; BLS_SIG_LEN];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Returns `true` when every byte is zero.
    pub fn is_zeroed(&self) -> bool {
        self.is_null()
    }
}

impl FromStr for BLSSignature {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for BLSSignature {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(self.as_bytes(), encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for BLSSignature {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <[u8; BLS_SIG_LEN] as bincode::Decode<C>>::decode(decoder).map(Self::from_bytes)
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for BLSSignature {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

impl TryFrom<&[u8]> for BLSSignature {
    type Error = core::array::TryFromSliceError;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(<[u8; BLS_SIG_LEN]>::try_from(v)?))
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
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes())));
            // We should not error because the signature could be given by an invalid source
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
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes())));
            // We should not error because the signature could be given by an invalid source
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
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes())));
            // We should not error because the signature could be given by an invalid source
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
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes())));
            // We should not error because the signature could be given by an invalid source
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
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes())));
            // We should not error because the signature could be given by an invalid source
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
            return Err(QuorumValidationError::InvalidBLSSignature(hex::encode(value.to_bytes())));
            // We should not error because the signature could be given by an invalid source
        };

        Ok(blsful::AggregateSignature::Basic(g2_element))
    }
}

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
