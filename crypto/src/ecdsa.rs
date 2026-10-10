//
// This file is a part of rust-dashcore.
// Portions written by Andrew Poelstra <apoelstra@wpsoftware.net> for rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

use core::fmt;
use core::str::FromStr;

#[cfg(feature = "rand")]
use bitcoin_crypto::key::rand;
use bitcoin_crypto::key::Keypair;
use dash_pkc::ecdsa::{
    Compression, EcdsaPublicKey as PkcPublicKey, EcdsaRecSigBytes as PkcRecSigBytes,
    EcdsaRecSignature as PkcRecSignature, EcdsaSecretKey as PkcSecretKey,
    EcdsaSignature as PkcSignature,
};
use dash_types::type_cvrt;
use hex_conservative::DisplayHex;
use internals::{debug_from_display, impl_array_newtype, impl_bytes_newtype};
use thiserror::Error as ThisError;
use zeroize::{Zeroize, Zeroizing};

pub use bitcoin_crypto::ecdsa::{DecodeError, ParseSignatureError, SerializedSignature, Signature};

/// Compressed SEC1 public key length.
pub const ECDSA_PK_LEN: usize = 33;

/// Uncompressed SEC1 public key length.
pub const ECDSA_PK_UNCOMPRESSED_LEN: usize = 65;

/// Scalar (secret key or tweak) length.
pub const ECDSA_SK_LEN: usize = 32;

/// Compact (`r || s`) signature length.
pub const ECDSA_SIG_LEN: usize = 64;

/// Compact recoverable signature length (a header byte, then `r || s`).
pub const ECDSA_REC_SIG_LEN: usize = ECDSA_SIG_LEN + 1;

/// Errors produced by secp256k1 operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ThisError)]
#[non_exhaustive]
pub enum EcdsaError {
    /// Public key bytes are not a usable curve point.
    #[error("invalid secp256k1 public key")]
    InvalidPublicKey,
    /// Secret key bytes are zero or not below the curve order.
    #[error("invalid secp256k1 secret key")]
    InvalidSecretKey,
    /// Recovery id is outside `0..=3`.
    #[error("invalid secp256k1 recovery id")]
    InvalidRecoveryId,
    /// Signature bytes are not a valid encoding.
    #[error("invalid secp256k1 signature")]
    InvalidSignature,
    /// No public key could be recovered from the signature and message.
    #[error("secp256k1 public key recovery failed")]
    RecoveryFailed,
    /// Tweak is out of range or produced the point at infinity.
    #[error("invalid secp256k1 tweak")]
    InvalidTweak,
    /// Signature does not verify against the key and message.
    #[error("signature failed verification")]
    VerifyFailed,
}

/// A secp256k1 public key.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "secp256k1::PublicKey"))]
#[cfg_attr(feature = "serde", serde(into = "secp256k1::PublicKey"))]
pub struct EcdsaPublicKey(PkcPublicKey);

impl EcdsaPublicKey {
    /// Parses a compressed (33-byte) or uncompressed (65-byte) SEC1 encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
        if bytes.len() != ECDSA_PK_LEN && bytes.len() != ECDSA_PK_UNCOMPRESSED_LEN {
            return Err(EcdsaError::InvalidPublicKey);
        }
        PkcPublicKey::from_bytes(bytes).map(Self).map_err(|_| EcdsaError::InvalidPublicKey)
    }

    /// The compressed SEC1 encoding.
    pub fn to_compressed(&self) -> [u8; ECDSA_PK_LEN] {
        self.0.to_compressed()
    }

    /// The uncompressed SEC1 encoding.
    pub fn to_uncompressed(&self) -> [u8; ECDSA_PK_UNCOMPRESSED_LEN] {
        self.0.to_uncompressed()
    }

    /// Adds `tweak * G` to the point.
    pub fn add_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        self.0.add_tweak(tweak).map(Self).map_err(|_| EcdsaError::InvalidTweak)
    }

    /// Checks `sig` over the 32-byte prehashed message.
    pub fn verify(
        &self,
        msg_hash: &[u8; 32],
        sig: impl AsRef<EcdsaSignature>,
    ) -> Result<(), EcdsaError> {
        self.0.verify(msg_hash, sig.as_ref().0).map_err(|_| EcdsaError::VerifyFailed)
    }

    /// Recovers the signing key from a recoverable signature over the 32-byte
    /// prehashed message.
    pub fn recover(msg_hash: &[u8; 32], sig: &EcdsaRecSignature) -> Result<Self, EcdsaError> {
        PkcPublicKey::recover(msg_hash, &sig.parse()?)
            .map(Self)
            .map_err(|_| EcdsaError::RecoveryFailed)
    }
}

/// Compared as curve points, whichever encoding the key was parsed from.
impl PartialEq for EcdsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed() == other.to_compressed()
    }
}

impl Eq for EcdsaPublicKey {}

impl core::hash::Hash for EcdsaPublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_compressed().hash(state)
    }
}

debug_from_display!(EcdsaPublicKey);

/// Hex of the compressed encoding.
impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.to_compressed().as_hex())
    }
}

/// Hex of either SEC1 encoding.
impl FromStr for EcdsaPublicKey {
    type Err = EcdsaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(
            &hex_conservative::decode_to_vec(s).map_err(|_| EcdsaError::InvalidPublicKey)?,
        )
    }
}

type_cvrt!(From<secp256k1::PublicKey> for EcdsaPublicKey, |pk| Self(PkcPublicKey::from(*pk)));
type_cvrt!(From<EcdsaPublicKey> for secp256k1::PublicKey, |pk| Self::from(pk.0));

/// A secp256k1 secret key.
#[derive(Clone, Eq, PartialEq, Zeroize)]
pub struct EcdsaSecretKey(PkcSecretKey);

impl EcdsaSecretKey {
    /// Wraps a big-endian scalar.
    pub fn from_bytes(bytes: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        PkcSecretKey::from_bytes(bytes, Compression::Compressed)
            .map(Self)
            .map_err(|_| EcdsaError::InvalidSecretKey)
    }

    /// Copies out the big-endian scalar.
    pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
        self.0.to_bytes()
    }

    /// Derives the corresponding public key.
    pub fn public_key(&self) -> EcdsaPublicKey {
        EcdsaPublicKey(self.0.public_key())
    }

    /// Adds `tweak` to the scalar.
    pub fn add_tweak(&self, tweak: &[u8; ECDSA_SK_LEN]) -> Result<Self, EcdsaError> {
        self.0.add_tweak(tweak).map(Self).map_err(|_| EcdsaError::InvalidTweak)
    }

    /// Signs a 32-byte prehashed message (RFC 6979, low-S, low-R ground).
    pub fn sign(&self, msg_hash: &[u8; 32]) -> EcdsaSignature {
        EcdsaSignature(self.0.sign(msg_hash))
    }

    /// Signs a 32-byte prehashed message recoverably (RFC 6979, low-S).
    pub fn sign_recoverable(&self, msg_hash: &[u8; 32]) -> EcdsaRecSignature {
        EcdsaRecSignature::from_pkc(self.0.sign_recoverable(msg_hash))
    }

    /// Draws a random scalar from the thread RNG.
    #[cfg(feature = "rand")]
    pub fn generate() -> Self {
        Self(secp256k1::SecretKey::new(&mut rand::rng()).into())
    }
}

impl fmt::Debug for EcdsaSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaSecretKey(..)")
    }
}

type_cvrt!(From<secp256k1::SecretKey> for EcdsaSecretKey, |sk| Self(PkcSecretKey::from(*sk)));
type_cvrt!(From<EcdsaSecretKey> for secp256k1::SecretKey, |sk| Self::from(&sk.0));
type_cvrt!(From<EcdsaSecretKey> for Keypair, |sk| {
    Self::from(secp256k1::Keypair::from_secret_key(&(&sk.0).into()))
});

#[cfg(feature = "serde")]
impl serde::Serialize for EcdsaSecretKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&secp256k1::SecretKey::from(&self.0), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EcdsaSecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <secp256k1::SecretKey as serde::Deserialize>::deserialize(d).map(|sk| Self(sk.into()))
    }
}

/// A secp256k1 ECDSA signature (the `r` and `s` scalars, without a sighash
/// type).
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "secp256k1::ecdsa::Signature"))]
#[cfg_attr(feature = "serde", serde(into = "secp256k1::ecdsa::Signature"))]
pub struct EcdsaSignature(PkcSignature);

impl EcdsaSignature {
    /// Parses the compact (`r || s`) encoding.
    pub fn from_bytes(bytes: &[u8; ECDSA_SIG_LEN]) -> Result<Self, EcdsaError> {
        PkcSignature::from_bytes(bytes).map(Self).map_err(|_| EcdsaError::InvalidSignature)
    }

    /// Parses a DER encoding.
    pub fn from_der(bytes: &[u8]) -> Result<Self, EcdsaError> {
        PkcSignature::from_der(bytes).map(Self).map_err(|_| EcdsaError::InvalidSignature)
    }

    /// The compact (`r || s`) encoding.
    pub fn to_bytes(&self) -> [u8; ECDSA_SIG_LEN] {
        self.0.to_bytes()
    }

    /// Calls `f` with the DER encoding, without allocating.
    pub fn with_der<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(self.0.to_der().as_bytes())
    }
}

impl AsRef<EcdsaSignature> for EcdsaSignature {
    fn as_ref(&self) -> &EcdsaSignature {
        self
    }
}

debug_from_display!(EcdsaSignature);

/// Hex of the DER encoding.
impl fmt::Display for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.with_der(|der| write!(f, "{:x}", der.as_hex()))
    }
}

/// Hex of the DER encoding.
impl FromStr for EcdsaSignature {
    type Err = EcdsaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_der(
            &hex_conservative::decode_to_vec(s).map_err(|_| EcdsaError::InvalidSignature)?,
        )
    }
}

type_cvrt!(From<secp256k1::ecdsa::Signature> for EcdsaSignature, |sig| Self(PkcSignature::from(*sig)));
type_cvrt!(From<EcdsaSignature> for secp256k1::ecdsa::Signature, |sig| Self::from(sig.0));

/// A compact recoverable signature as Dash Core writes it, a header byte
/// carrying the recovery id and key compression, then `r || s`. Checked by
/// the operations that read it.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "bincode", derive(bincode_derive::Encode, bincode_derive::Decode))]
pub struct EcdsaRecSignature([u8; ECDSA_REC_SIG_LEN]);

impl_array_newtype!(EcdsaRecSignature, u8, ECDSA_REC_SIG_LEN);
impl_bytes_newtype!(EcdsaRecSignature, ECDSA_REC_SIG_LEN);

impl EcdsaRecSignature {
    /// Pairs a signature with its recovery id and key compression.
    pub fn from_parts(
        sig: EcdsaSignature,
        recovery_id: u8,
        compressed: bool,
    ) -> Result<Self, EcdsaError> {
        PkcRecSignature::from_parts(sig.0, recovery_id, compressed.into())
            .map(Self::from_pkc)
            .map_err(|_| EcdsaError::InvalidRecoveryId)
    }

    fn from_pkc(sig: PkcRecSignature) -> Self {
        Self(PkcRecSigBytes::from(sig).to_bytes())
    }

    fn parse(&self) -> Result<PkcRecSignature, EcdsaError> {
        PkcRecSigBytes::from_raw(self.0)
            .ok_or(EcdsaError::InvalidRecoveryId)?
            .try_into()
            .map_err(|_| EcdsaError::InvalidSignature)
    }

    /// Whether the signing key serializes compressed.
    pub fn is_compressed(&self) -> Result<bool, EcdsaError> {
        self.parse().map(|sig| sig.is_compressed())
    }

    /// The recovery id, in `0..=3`.
    pub fn recovery_id(&self) -> Result<u8, EcdsaError> {
        self.parse().map(|sig| sig.recovery_id())
    }

    /// The signature without its recovery id.
    pub fn signature(&self) -> Result<EcdsaSignature, EcdsaError> {
        self.parse().map(|sig| EcdsaSignature(*sig.signature()))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    // A DER signature with `SIGHASH_ALL` appended.
    const SIG_HEX: &str = "3045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c01";

    /// Formatting flags apply to the whole encoding, as for a string.
    #[test]
    fn display_applies_format_flags() {
        let sig = Signature::from_str(SIG_HEX).unwrap();
        assert_eq!(format!("{}", sig), SIG_HEX);
        assert_eq!(format!("{:#}", sig), format!("0x{}", SIG_HEX));
        assert_eq!(format!("{:>200}", sig), format!("{:>200}", SIG_HEX));
        assert_eq!(format!("{:.4}", sig), SIG_HEX[..4]);

        let serialized = sig.serialize();
        assert_eq!(format!("{:x}", serialized), SIG_HEX);
        assert_eq!(format!("{:#x}", serialized), format!("0x{}", SIG_HEX));
        assert_eq!(format!("{:X}", serialized), SIG_HEX.to_uppercase());
    }

    /// Signing grinds a low R, as Dash Core does, so DER signatures fit in 70
    /// bytes; the result verifies and survives both encodings.
    #[test]
    fn sign_is_low_r_and_round_trips() {
        let sk = EcdsaSecretKey::from_bytes(&[0x42; ECDSA_SK_LEN]).expect("valid secret key");
        let pk = sk.public_key();
        for i in 0..32u8 {
            let msg = [i; 32];
            let sig = sk.sign(&msg);
            assert!(sig.to_bytes()[0] < 0x80, "R must be low");
            assert!(sig.with_der(<[u8]>::len) <= 70);
            assert_eq!(sig, sk.sign(&msg), "signing is deterministic");
            pk.verify(&msg, sig).expect("signature verifies");
            assert_eq!(pk.verify(&[i ^ 1; 32], sig), Err(EcdsaError::VerifyFailed));
            assert_eq!(EcdsaSignature::from_bytes(&sig.to_bytes()), Ok(sig));
            assert_eq!(sig.with_der(EcdsaSignature::from_der), Ok(sig));
        }
    }

    #[test]
    fn rec_signature_keeps_compression() {
        let sk = EcdsaSecretKey::from_bytes(&[0x42; ECDSA_SK_LEN]).expect("valid secret key");
        let rec = sk.sign_recoverable(&[0x07; 32]);
        assert_eq!(rec.is_compressed(), Ok(true));

        let sig = rec.signature().unwrap();
        let id = rec.recovery_id().unwrap();
        assert_eq!(EcdsaRecSignature::from_parts(sig, id, true), Ok(rec));
        let legacy = EcdsaRecSignature::from_parts(sig, id, false).unwrap();
        assert_eq!(legacy.is_compressed(), Ok(false));
        assert_ne!(legacy, rec);
        assert_eq!(EcdsaRecSignature::from_parts(sig, 4, true), Err(EcdsaError::InvalidRecoveryId));
    }

    #[test]
    fn rec_signature_carries_the_core_header() {
        let sk = EcdsaSecretKey::from_bytes(&[0x42; ECDSA_SK_LEN]).expect("valid secret key");
        let rec = sk.sign_recoverable(&[0x07; 32]);
        let id = rec.recovery_id().unwrap();
        assert_eq!(rec[0], 31 + id);
        assert_eq!(rec[1..], rec.signature().unwrap().to_bytes());

        let legacy = EcdsaRecSignature::from_parts(rec.signature().unwrap(), id, false);
        assert_eq!(legacy.unwrap()[0], 27 + id);
        assert_eq!(rec.to_string().parse::<EcdsaRecSignature>(), Ok(rec));
    }

    #[test]
    fn rec_signature_is_checked_when_read() {
        let pk = EcdsaSecretKey::from_bytes(&[0x42; ECDSA_SK_LEN]).unwrap().public_key();
        for header in [26, 35] {
            let mut raw = [0x01; ECDSA_REC_SIG_LEN];
            raw[0] = header;
            let rec = EcdsaRecSignature::from(raw);
            assert_eq!(rec.to_bytes(), raw, "raw bytes stay unchecked");
            assert_eq!(rec.recovery_id(), Err(EcdsaError::InvalidRecoveryId));
            assert_eq!(
                EcdsaPublicKey::recover(&[0x07; 32], &rec),
                Err(EcdsaError::InvalidRecoveryId)
            );
        }
        let mut raw = [0xff; ECDSA_REC_SIG_LEN];
        raw[0] = 31;
        let rec = EcdsaRecSignature::from(raw);
        assert_eq!(rec.signature(), Err(EcdsaError::InvalidSignature));
        assert_ne!(EcdsaPublicKey::recover(&[0x07; 32], &rec), Ok(pk));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn rec_signature_serde_layout_is_hex_or_bytes() {
        let bytes = EcdsaRecSignature::from([0x22; ECDSA_REC_SIG_LEN]);
        let hex = "22".repeat(ECDSA_REC_SIG_LEN);

        let json = serde_json::to_string(&bytes).expect("serialize signature");
        assert_eq!(json, format!("\"{}\"", hex));
        assert_eq!(serde_json::from_str::<EcdsaRecSignature>(&json).expect("deserialize"), bytes);

        #[cfg(feature = "bincode")]
        {
            let config = bincode::config::standard();
            let raw = bincode::encode_to_vec(bytes, config).expect("encode signature");
            assert_eq!(raw, [0x22; ECDSA_REC_SIG_LEN]);

            let encoded = bincode::serde::encode_to_vec(bytes, config).expect("encode signature");
            assert_eq!(encoded, [&[65u8][..], &[0x22; ECDSA_REC_SIG_LEN]].concat());
            let (decoded, _): (EcdsaRecSignature, _) =
                bincode::serde::decode_from_slice(&encoded, config).expect("decode signature");
            assert_eq!(decoded, bytes);
        }
    }

    #[cfg(feature = "serde")]
    const DER_HEX: &str =
        "3045022100d2e84c0a1a8e0d31d1b0f8b3cde37ab19ef8e6bff4f72c5ac6f0a4b8a8d1ec2d\
                           02204c7b8e3f2a5d6c1b0e9f8a7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39";
    #[cfg(feature = "serde")]
    const COMPACT_HEX: &str = "d2e84c0a1a8e0d31d1b0f8b3cde37ab19ef8e6bff4f72c5ac6f0a4b8a8d1ec2d\
                               4c7b8e3f2a5d6c1b0e9f8a7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39";

    /// The signature serializes as DER, a hex string in human-readable formats
    /// and a byte string otherwise.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_layout_is_der() {
        let sig = Signature::from_str(&format!("{}01", DER_HEX)).expect("parse signature");

        let json = serde_json::to_string(&sig).expect("serialize signature");
        assert_eq!(
            json,
            format!("{{\"signature\":\"{}\",\"sighash_type\":\"SIGHASH_ALL\"}}", DER_HEX)
        );
        assert_eq!(serde_json::from_str::<Signature>(&json).expect("deserialize signature"), sig);

        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(sig, config).expect("encode signature");
        let mut expected = vec![0x47];
        expected.extend(hex_conservative::decode_to_vec(DER_HEX).expect("decode hex"));
        expected.push(0x0b);
        expected.extend(b"SIGHASH_ALL");
        assert_eq!(bytes, expected);
        let (decoded, _): (Signature, _) =
            bincode::serde::decode_from_slice(&bytes, config).expect("decode signature");
        assert_eq!(decoded, sig);
    }

    /// The signature takes hex in either case. Anything other than one DER
    /// encoding is rejected in both formats.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_input_is_der_only() {
        let json =
            |sig: &str| format!("{{\"signature\":\"{}\",\"sighash_type\":\"SIGHASH_ALL\"}}", sig);
        let sig = Signature::from_str(&format!("{}01", DER_HEX)).expect("parse signature");

        let upper = serde_json::from_str::<Signature>(&json(&DER_HEX.to_uppercase()));
        assert_eq!(upper.expect("uppercase hex"), sig);
        let trailing = format!("{}00", DER_HEX);
        for bad in [COMPACT_HEX, &trailing, &DER_HEX[..DER_HEX.len() - 1]] {
            assert!(serde_json::from_str::<Signature>(&json(bad)).is_err(), "{}", bad);
        }

        let mut bytes = vec![0x40];
        bytes.extend(hex_conservative::decode_to_vec(COMPACT_HEX).expect("decode hex"));
        bytes.push(0x0b);
        bytes.extend(b"SIGHASH_ALL");
        let config = bincode::config::standard();
        assert!(bincode::serde::decode_from_slice::<Signature, _>(&bytes, config).is_err());
    }
}
