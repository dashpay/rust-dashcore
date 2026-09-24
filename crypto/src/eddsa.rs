//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Ed25519 keys for Platform node identity.

use core::str::FromStr;

use dash_types::{make_bytes, make_sbytes};
#[cfg(feature = "eddsa")]
use dashcore_hashes::{sha256, Hash as _};
#[cfg(feature = "eddsa")]
use ed25519_dalek::{SigningKey, VerifyingKey};
#[cfg(feature = "eddsa")]
use thiserror::Error as ThisError;

/// Raw Ed25519 public key length.
pub const EDDSA_PK_LEN: usize = 32;

/// Ed25519 public key hash length.
pub const EDDSA_PK_HASH_LEN: usize = 20;

/// Raw Ed25519 secret key (seed) length.
pub const EDDSA_SK_LEN: usize = 32;

/// Errors produced by Ed25519 operations.
#[cfg(feature = "eddsa")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ThisError)]
pub enum EddsaError {
    /// Public key bytes are not a usable curve point.
    #[error("Invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),
}

make_bytes! {
    /// Ed25519 public key hash (20 bytes).
    EddsaPkHash, EDDSA_PK_HASH_LEN, rev
}

impl EddsaPkHash {
    /// Wraps the canonical (i.e. Tenderdash) order bytes.
    pub fn from_canonical_bytes(mut bytes: [u8; EDDSA_PK_HASH_LEN]) -> Self {
        bytes.reverse();
        Self::from_bytes(bytes)
    }

    /// Copies out the canonical (i.e. Tenderdash) order bytes.
    pub fn to_canonical_bytes(self) -> [u8; EDDSA_PK_HASH_LEN] {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes
    }
}

impl FromStr for EddsaPkHash {
    type Err = hex::FromHexError;

    /// Parses the canonical hex rendering.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; EDDSA_PK_HASH_LEN];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self::from_canonical_bytes(bytes))
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for EddsaPkHash {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.as_bytes().encode(encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for EddsaPkHash {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self::from_bytes(<[u8; EDDSA_PK_HASH_LEN]>::decode(decoder)?))
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for EddsaPkHash {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self::from_bytes(<[u8; EDDSA_PK_HASH_LEN]>::borrow_decode(decoder)?))
    }
}

make_bytes! {
    /// Ed25519 public key (32 bytes, unvalidated).
    EddsaPkBytes, EDDSA_PK_LEN
}

#[cfg(feature = "eddsa")]
impl EddsaPkBytes {
    /// Checks these bytes are a usable curve point.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not on the curve.
    pub fn validate(&self) -> Result<(), EddsaError> {
        VerifyingKey::from_bytes(self.as_bytes())
            .map(|_| ())
            .map_err(|e| EddsaError::InvalidPublicKey(e.to_string()))
    }

    /// The CometBFT hash of the public key.
    pub fn hash(&self) -> EddsaPkHash {
        let digest = sha256::Hash::hash(self.as_bytes()).to_byte_array();
        let mut id = [0u8; 20];
        for (out, byte) in id.iter_mut().zip(digest[..20].iter().rev()) {
            *out = *byte;
        }
        EddsaPkHash::from_bytes(id)
    }
}

make_sbytes! {
    /// Ed25519 secret key seed (32 bytes).
    EddsaSkBytes, EDDSA_SK_LEN
}

#[cfg(feature = "eddsa")]
impl EddsaSkBytes {
    /// Derives the corresponding public key.
    pub fn public_key(&self) -> EddsaPkBytes {
        EddsaPkBytes::from_bytes(SigningKey::from_bytes(self.as_bytes()).verifying_key().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Persisted masternode-list snapshots were written while the platform
    /// node id was typed as `PubkeyHash`; the bincode layout must stay
    /// identical so old snapshots keep decoding.
    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_layout_matches_pubkey_hash() {
        let bytes = [0xCD; 20];
        let config = bincode::config::standard();
        let hash_bytes =
            bincode::encode_to_vec(EddsaPkHash::from_bytes(bytes), config).expect("encode hash");
        let pubkey_hash_bytes =
            bincode::encode_to_vec(crate::key::PubkeyHash::from_byte_array(bytes), config)
                .expect("encode pubkey hash");
        assert_eq!(hash_bytes, pubkey_hash_bytes);
    }

    #[test]
    fn hex_display_and_parse_round_trip() {
        let hex = "4cd2ca50b36e0a2bb1b6b29da140448b47eeb7a1";
        let hash: EddsaPkHash = hex.parse().expect("parse hash hex");
        assert_eq!(hash.to_string(), hex);
        assert_eq!(format!("{:?}", hash), format!("EddsaPkHash({})", hex));
        assert!("abcd".parse::<EddsaPkHash>().is_err(), "wrong-length hex must fail");
        assert!("zz".repeat(20).parse::<EddsaPkHash>().is_err(), "non-hex input must fail");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_round_trip_as_hex_string() {
        let hash = EddsaPkHash::from_bytes([0x11; 20]);
        let json = serde_json::to_string(&hash).expect("serialize hash");
        assert_eq!(json, format!("\"{}\"", "11".repeat(20)));
        let back: EddsaPkHash = serde_json::from_str(&json).expect("deserialize hash");
        assert_eq!(back, hash);
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn hash_is_truncated_sha256() {
        let public_key = [7u8; 32];
        let digest = sha256::Hash::hash(&public_key);
        // `EddsaPkHash` holds the wire order, which is the byte-reversal of
        // the canonical form the digest is read in.
        let mut canonical = *EddsaPkBytes::from_bytes(public_key).hash().as_bytes();
        canonical.reverse();

        assert_eq!(canonical[..], digest.to_byte_array()[..20]);
    }
}
