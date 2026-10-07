//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Ed25519 keys for Platform node identity.

#[cfg(feature = "eddsa")]
pub use dash_pkc::eddsa::{EddsaError, EddsaPublicKey, EddsaSecretKey};
pub use dash_pkc::eddsa::{EddsaPkBytes, EddsaSkBytes, EDDSA_PK_LEN, EDDSA_SK_LEN};
use dash_types::{make_bytes, Hashable};

/// Ed25519 public key hash length.
pub const EDDSA_PK_HASH_LEN: usize = 20;

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

#[cfg(feature = "bincode")]
impl bincode::Encode for EddsaPkHash {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.to_canonical_bytes().encode(encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for EddsaPkHash {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self::from_canonical_bytes(<[u8; EDDSA_PK_HASH_LEN]>::decode(decoder)?))
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for EddsaPkHash {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        Ok(Self::from_canonical_bytes(<[u8; EDDSA_PK_HASH_LEN]>::borrow_decode(decoder)?))
    }
}

/// The CometBFT hash of the public key.
impl From<EddsaPkBytes> for EddsaPkHash {
    fn from(public_key: EddsaPkBytes) -> Self {
        Self::from_bytes(*Hashable::hash(&public_key).as_bytes())
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
        use dashcore_hashes::Hash as _;

        let bytes = [
            0x8b, 0xaa, 0xdf, 0xf0, 0x0d, 0x8b, 0xaa, 0xdf, 0xf0, 0x0d, 0x8b, 0xaa, 0xdf, 0xf0,
            0x0d, 0x8b, 0xaa, 0xdf, 0xf0, 0x0d,
        ];
        let config = bincode::config::standard();
        let hash_bytes = bincode::encode_to_vec(EddsaPkHash::from_canonical_bytes(bytes), config)
            .expect("encode hash");
        let pubkey_hash_bytes =
            bincode::encode_to_vec(crate::key::PubkeyHash::from_byte_array(bytes), config)
                .expect("encode pubkey hash");
        assert_eq!(hash_bytes, pubkey_hash_bytes);
        assert_eq!(hash_bytes, bytes, "the canonical order is the persisted order");

        let (decoded, _): (EddsaPkHash, _) =
            bincode::decode_from_slice(&hash_bytes, config).expect("decode hash");
        assert_eq!(decoded.to_canonical_bytes(), bytes);
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

    #[test]
    fn hash_is_truncated_sha256() {
        use dashcore_hashes::{sha256, Hash};

        let public_key = [7u8; 32];
        let digest = sha256::Hash::hash(&public_key);
        // `EddsaPkHash` holds the wire order, which is the byte-reversal of
        // the canonical form the digest is read in.
        let mut canonical = *EddsaPkHash::from(EddsaPkBytes::from_bytes(public_key)).as_bytes();
        canonical.reverse();

        assert_eq!(canonical[..], digest.to_byte_array()[..20]);
    }
}
