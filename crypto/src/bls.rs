//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! BLS12-381 public key and signatures.

use core::str::FromStr;

#[cfg(feature = "bls")]
use blsful::{Bls12381G2Impl, Pairing};
use dash_types::{make_bytes, type_cvrt};
use hex::FromHexError;
#[cfg(feature = "bls")]
use thiserror::Error as ThisError;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Raw BLS signature length (G2 compressed).
pub const BLS_SIG_LEN: usize = 96;

/// Errors produced by BLS operations.
#[cfg(feature = "bls")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ThisError)]
pub enum BlsError {
    /// Public key bytes are not a valid G1 point.
    #[error("Invalid BLS public key: {0}")]
    InvalidPublicKey(String),

    /// Signature bytes are not a valid G2 point.
    #[error("Invalid BLS signature: {0}")]
    InvalidSignature(String),
}

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

type_cvrt!(
    for[] TryFrom<&[u8]> for BLSPublicKey,
    core::array::TryFromSliceError,
    |v| Ok(Self::from_bytes(<[u8; BLS_PK_LEN]>::try_from(*v)?))
);

#[cfg(feature = "bls")]
type_cvrt!(
    for[] TryFrom<BLSPublicKey> for blsful::PublicKey<Bls12381G2Impl>,
    BlsError,
    |value| {
        Self::try_from(value.as_bytes().as_slice())
            .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))
    }
);

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

type_cvrt!(
    for[] TryFrom<&[u8]> for BLSSignature,
    core::array::TryFromSliceError,
    |v| Ok(Self::from_bytes(<[u8; BLS_SIG_LEN]>::try_from(*v)?))
);

#[cfg(feature = "bls")]
type_cvrt!(
    for[] TryFrom<BLSSignature> for blsful::Signature<Bls12381G2Impl>,
    BlsError,
    |value| {
        let Some(g2_element) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(&value.to_bytes())
                .into_option()
        else {
            // not an error the source can be trusted not to produce
            return Err(BlsError::InvalidSignature(hex::encode(value.to_bytes())));
        };

        Ok(blsful::Signature::Basic(g2_element))
    }
);
