//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! BLS12-381 public key and signatures.

use core::str::FromStr;

#[cfg(feature = "bls")]
use blsful::{Bls12381G2Impl, Pairing, PublicKey, SerializationFormat};
use dash_types::{make_bytes, make_sbytes, type_cvrt};
use hex::FromHexError;
#[cfg(feature = "bls")]
use thiserror::Error as ThisError;
#[cfg(feature = "bls")]
use tracing::error;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Raw BLS secret key length (big-endian scalar).
pub const BLS_SK_LEN: usize = 32;

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

    /// Signature verification failed.
    #[error("BLS verification failed: {0}")]
    VerificationFailed(String),

    /// Secret key bytes are not a valid scalar.
    #[error("Invalid BLS secret key")]
    InvalidSecretKey,

    /// Tweak is not a valid scalar.
    #[error("Invalid BLS tweak")]
    InvalidTweak,
}

/// Which BLS scheme a 48- or 96-byte blob was written under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BlsScheme {
    /// The pre-V19 scheme, as Dash Core's `LegacySchemeMPL` implements it.
    Legacy,
    /// The post-V19 IETF basic scheme.
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

    /// Verifies `signature` over a 32-byte message digest.
    ///
    /// The signature is read under this same scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` or `InvalidSignature` when either side is
    /// not a curve point, or `VerificationFailed` when it does not verify.
    pub fn verify(self, digest: &[u8; 32], signature: &BlsSigBytes) -> Result<(), BlsError> {
        signature
            .as_scheme(self.scheme)
            .g2()?
            .verify(&self.point()?, digest)
            .map_err(|e| BlsError::VerificationFailed(e.to_string()))
    }

    fn point(self) -> Result<PublicKey<Bls12381G2Impl>, BlsError> {
        PublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            self.bytes.as_bytes(),
            self.scheme.serialization_format(),
        )
        .map_err(|e| BlsError::InvalidPublicKey(e.to_string()))
    }
}

make_sbytes! {
    /// BLS secret key bytes (32 big-endian bytes, unvalidated).
    BlsSkBytes, BLS_SK_LEN
}

#[cfg(feature = "bls")]
impl BlsSkBytes {
    /// Pairs these bytes with `scheme`.
    pub fn as_scheme(&self, scheme: BlsScheme) -> BlsSecretKey<'_> {
        BlsSecretKey {
            bytes: self,
            scheme,
        }
    }
}

/// A [`BlsSkBytes`] paired with the scheme to operate under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug)]
pub struct BlsSecretKey<'a> {
    bytes: &'a BlsSkBytes,
    scheme: BlsScheme,
}

#[cfg(feature = "bls")]
impl BlsSecretKey<'_> {
    /// Adds `tweak` to the scalar, for hardened derivation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSecretKey` when the bytes are not a valid scalar, or
    /// `InvalidTweak` when the tweak or the sum is not one.
    pub fn add_tweak(self, tweak: &[u8; 32]) -> Result<BlsSkBytes, BlsError> {
        let tweak = blsful::SecretKey::<Bls12381G2Impl>::from_be_bytes(tweak)
            .into_option()
            .ok_or(BlsError::InvalidTweak)?;
        let sum = blsful::SecretKey::<Bls12381G2Impl>(self.scalar()?.0 + tweak.0);

        Ok(BlsSkBytes::from_bytes(sum.to_be_bytes()))
    }

    /// The scalar these bytes denote, written back canonically.
    ///
    /// Reading reduces modulo the group order, as Dash Core does, so bytes
    /// that came from a hash are not necessarily the scalar's own encoding.
    /// Storing the result keeps the two the same.
    pub fn canonicalize(self) -> Result<BlsSkBytes, BlsError> {
        Ok(BlsSkBytes::from_bytes(self.scalar()?.to_be_bytes()))
    }

    /// Derives the public key, written under the scheme.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSecretKey` when the bytes are not a valid scalar.
    pub fn public_key(self) -> Result<BlsPkBytes, BlsError> {
        Ok(encode_point(PublicKey::from(&self.scalar()?), self.scheme))
    }

    fn scalar(self) -> Result<blsful::SecretKey<Bls12381G2Impl>, BlsError> {
        blsful::SecretKey::<Bls12381G2Impl>::from_be_bytes(self.bytes.as_bytes())
            .into_option()
            .ok_or(BlsError::InvalidSecretKey)
    }
}

make_bytes! {
    /// BLS signature (96 bytes, unvalidated).
    BlsSigBytes, BLS_SIG_LEN
}

impl BlsSigBytes {
    /// Pairs these bytes with `scheme`.
    #[cfg(feature = "bls")]
    pub fn as_scheme(self, scheme: BlsScheme) -> BlsSignature {
        BlsSignature {
            bytes: self,
            scheme,
        }
    }

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

impl FromStr for BlsSigBytes {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for BlsSigBytes {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(self.as_bytes(), encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for BlsSigBytes {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <[u8; BLS_SIG_LEN] as bincode::Decode<C>>::decode(decoder).map(Self::from_bytes)
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for BlsSigBytes {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <Self as bincode::Decode<C>>::decode(decoder)
    }
}

type_cvrt!(
    for[] TryFrom<&[u8]> for BlsSigBytes,
    core::array::TryFromSliceError,
    |v| Ok(Self::from_bytes(<[u8; BLS_SIG_LEN]>::try_from(*v)?))
);

#[cfg(feature = "bls")]
type_cvrt!(
    for[] TryFrom<BlsSigBytes> for blsful::Signature<Bls12381G2Impl>,
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

/// A [`BlsSigBytes`] paired with the scheme to read it under.
#[cfg(feature = "bls")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsSignature {
    bytes: BlsSigBytes,
    scheme: BlsScheme,
}

#[cfg(feature = "bls")]
impl BlsSignature {
    /// Verifies this aggregate against `keys`, with the rogue-key binding
    /// Dash Core's `VerifySecure` applies.
    ///
    /// Each key carries the scheme its own encoding was written under, which
    /// for a masternode list entry follows that entry's version; the scheme
    /// the aggregate verifies in is one value for the quorum.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSignature` when the signature bytes are not a G2
    /// point, or `VerificationFailed` when the aggregate does not verify. A
    /// key that will not decode is dropped rather than reported, though the
    /// failure is logged.
    pub fn verify_secure_aggregate<'a, I>(self, digest: &[u8; 32], keys: I) -> Result<(), BlsError>
    where
        I: IntoIterator<Item = (BlsScheme, &'a BlsPkBytes)>,
    {
        let points: Vec<PublicKey<Bls12381G2Impl>> = keys
            .into_iter()
            .filter_map(|(encoding, key)| {
                key.as_scheme(encoding)
                    .point()
                    .inspect_err(|e| error!("Failed to deserialize operator key: {}", e))
                    .ok()
            })
            .collect();

        self.g2()?
            .verify_secure(&points, digest.as_slice())
            .map_err(|e| BlsError::VerificationFailed(e.to_string()))
    }

    fn g2(self) -> Result<blsful::Signature<Bls12381G2Impl>, BlsError> {
        let Some(point) =
            <Bls12381G2Impl as Pairing>::Signature::from_compressed(self.bytes.as_bytes())
                .into_option()
        else {
            return Err(BlsError::InvalidSignature(hex::encode(self.bytes.as_bytes())));
        };

        Ok(blsful::Signature::Basic(point))
    }
}
