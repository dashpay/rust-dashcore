//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! BLS12-381 public key and signatures.

use core::str::FromStr;

#[cfg(feature = "bls")]
use blsful::{Bls12381G2Impl, Pairing, PublicKey, SerializationFormat};
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

    /// Tweak is not a valid scalar.
    #[error("Invalid BLS tweak")]
    InvalidTweak,
}

/// Which BLS scheme a 48- or 96-byte blob was written under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BlsScheme {
    /// The pre-V19 legacy scheme.
    Legacy,
    /// The post-V19 basic scheme.
    Modern,
}

#[cfg(feature = "bls")]
impl BlsScheme {
    /// The backing library's serialisation mode for this scheme.
    pub fn serialization_format(self) -> SerializationFormat {
        match self {
            Self::Legacy => SerializationFormat::Legacy,
            Self::Modern => SerializationFormat::Modern,
        }
    }
}

#[cfg(feature = "bls")]
fn encode_point(point: PublicKey<Bls12381G2Impl>, scheme: BlsScheme) -> BlsPkBytes {
    BlsPkBytes::from_bytes(
        point
            .to_bytes_with_mode(scheme.serialization_format())
            .try_into()
            .expect("a G1 point is 48 bytes"),
    )
}

make_bytes! {
    /// BLS public key (48 bytes, unvalidated).
    BlsPkBytes, BLS_PK_LEN
}

impl BlsPkBytes {
    /// Pairs these bytes with `scheme`.
    #[cfg(feature = "bls")]
    pub fn as_scheme(self, scheme: BlsScheme) -> BlsPublicKey {
        BlsPublicKey {
            bytes: self,
            scheme,
        }
    }

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

impl FromStr for BlsPkBytes {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for BlsPkBytes {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(self.as_bytes(), encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for BlsPkBytes {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <[u8; BLS_PK_LEN] as bincode::Decode<C>>::decode(decoder).map(Self::from_bytes)
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for BlsPkBytes {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

type_cvrt!(
    for[] TryFrom<&[u8]> for BlsPkBytes,
    core::array::TryFromSliceError,
    |v| Ok(Self::from_bytes(<[u8; BLS_PK_LEN]>::try_from(*v)?))
);

#[cfg(feature = "bls")]
type_cvrt!(
    for[] TryFrom<BlsPkBytes> for blsful::PublicKey<Bls12381G2Impl>,
    BlsError,
    |value| {
        Self::try_from(value.as_bytes().as_slice())
            .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))
    }
);

/// A [`BlsPkBytes`] paired with the scheme to read it under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsPublicKey {
    bytes: BlsPkBytes,
    scheme: BlsScheme,
}

#[cfg(feature = "bls")]
impl BlsPublicKey {
    /// Adds `tweak * G` to the point, written back under the same scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a G1 point, or
    /// `InvalidTweak` when the tweak is not a valid scalar.
    pub fn add_tweak(self, tweak: &[u8; 32]) -> Result<BlsPkBytes, BlsError> {
        let tweak_key = blsful::SecretKey::<Bls12381G2Impl>::from_be_bytes(tweak)
            .into_option()
            .ok_or(BlsError::InvalidTweak)?;
        let sum = self.point()?.0 + PublicKey::from(&tweak_key).0;

        Ok(encode_point(PublicKey(sum), self.scheme))
    }

    /// Checks the bytes are a point and writes it back under the same scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a G1 point.
    pub fn canonicalize(self) -> Result<BlsPkBytes, BlsError> {
        self.reencode(self.scheme)
    }

    /// Re-encodes the same point under `to`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not a G1 point under the
    /// scheme they were read with.
    pub fn reencode(self, to: BlsScheme) -> Result<BlsPkBytes, BlsError> {
        Ok(encode_point(self.point()?, to))
    }

    fn point(self) -> Result<PublicKey<Bls12381G2Impl>, BlsError> {
        PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            self.bytes.as_bytes(),
            self.scheme.serialization_format(),
        )
        .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))
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
