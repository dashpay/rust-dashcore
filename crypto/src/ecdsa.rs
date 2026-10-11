//
// This file is a part of rust-dashcore.
// Portions written by Andrew Poelstra <apoelstra@wpsoftware.net> for rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

#[cfg(feature = "rand")]
use bitcoin_crypto::key::rand;
#[cfg(feature = "rand")]
use bitcoin_crypto::secp256k1::SecretKey;
use dash_types::type_cvrt;
use zeroize::Zeroize;

pub use bitcoin_crypto::ecdsa::{DecodeError, ParseSignatureError, SerializedSignature, Signature};

/// Compressed SEC1 public key length.
pub const ECDSA_PK_LEN: usize = 33;

/// Uncompressed SEC1 public key length.
pub const ECDSA_PK_UNCOMPRESSED_LEN: usize = 65;

/// Scalar (secret key or tweak) length.
pub const ECDSA_SK_LEN: usize = 32;

/// Draws a random secret key from the thread RNG.
#[cfg(feature = "rand")]
pub fn generate() -> SecretKey {
    SecretKey::new(&mut rand::rng())
}

/// A secp256k1 public key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct EcdsaPublicKey(secp256k1::PublicKey);

type_cvrt!(From<secp256k1::PublicKey> for EcdsaPublicKey, |pk| Self(*pk));
type_cvrt!(From<EcdsaPublicKey> for secp256k1::PublicKey, |pk| pk.0);

/// A secp256k1 secret key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct EcdsaSecretKey(secp256k1::SecretKey);

type_cvrt!(From<secp256k1::SecretKey> for EcdsaSecretKey, |sk| Self(*sk));
type_cvrt!(From<EcdsaSecretKey> for secp256k1::SecretKey, |sk| sk.0);

impl Zeroize for EcdsaSecretKey {
    fn zeroize(&mut self) {
        self.0.non_secure_erase();
    }
}

/// A secp256k1 ECDSA signature, without a sighash type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct EcdsaSignature(secp256k1::ecdsa::Signature);

type_cvrt!(From<secp256k1::ecdsa::Signature> for EcdsaSignature, |sig| Self(*sig));
type_cvrt!(From<EcdsaSignature> for secp256k1::ecdsa::Signature, |sig| sig.0);

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
