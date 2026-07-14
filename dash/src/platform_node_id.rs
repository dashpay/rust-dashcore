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

//! Dash Platform (Tenderdash/CometBFT) node ID.
//!
//! A platform node ID is the first 20 bytes of `SHA256(ed25519_public_key)`,
//! following the CometBFT node-ID convention. Although it is 20 bytes on the
//! wire like a [`PubkeyHash`](crate::PubkeyHash), it is *not* a `hash160`
//! public key hash, so it gets its own type to keep the two conventions from
//! being conflated.
//!
//! # Byte order
//!
//! The newtype always holds **canonical forward** bytes — the same order
//! dashmate / Tenderdash display and `from_ed25519_public_key` produce.
//! Dash Core serializes `platformNodeID` as a `uint160`, whose on-wire
//! `m_data` is the reverse of that canonical form (`GetHex` / `SetHex`
//! reverse for human hex). Consensus encode/decode therefore reverse at the
//! boundary so Display, FromHex, and derived ids stay comparable.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::{Hash, sha256};
use internals::impl_array_newtype;

use crate::consensus::{Decodable, Encodable, encode};
use crate::internal_macros::impl_bytes_newtype;
use crate::io;

/// A Dash Platform (Tenderdash/CometBFT) node ID.
///
/// This is `SHA256(ed25519_public_key)` truncated to 20 bytes, not a `hash160`
/// public key hash. The inner bytes are always the **canonical** (dashmate /
/// Tenderdash) forward form. Consensus encoding reverses them to match Dash
/// Core's `uint160` wire blob order.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct PlatformNodeId([u8; 20]);

impl_array_newtype!(PlatformNodeId, u8, 20);
impl_bytes_newtype!(PlatformNodeId, 20);

impl PlatformNodeId {
    /// Constructs a platform node ID from its raw **canonical** 20 bytes.
    pub const fn from_byte_array(bytes: [u8; 20]) -> Self {
        PlatformNodeId(bytes)
    }

    /// Returns the raw **canonical** 20 bytes of the node ID.
    pub const fn to_byte_array(self) -> [u8; 20] {
        self.0
    }

    /// Returns a reference to the raw **canonical** 20 bytes of the node ID.
    pub const fn as_byte_array(&self) -> &[u8; 20] {
        &self.0
    }

    /// Derives the node ID from an Ed25519 public key per the CometBFT
    /// convention: `SHA256(public_key)[0..20]`.
    pub fn from_ed25519_public_key(public_key_bytes: &[u8; 32]) -> Self {
        let digest = sha256::Hash::hash(public_key_bytes);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&digest.to_byte_array()[..20]);
        PlatformNodeId(bytes)
    }
}

impl Encodable for PlatformNodeId {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut wire = self.0;
        wire.reverse();
        wire.consensus_encode(w)
    }
}

impl Decodable for PlatformNodeId {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut wire = <[u8; 20]>::consensus_decode(r)?;
        wire.reverse();
        Ok(PlatformNodeId(wire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};
    use hashes::hex::FromHex;

    #[test]
    fn consensus_round_trip() {
        let node_id = PlatformNodeId::from_byte_array([0xAB; 20]);
        let encoded = serialize(&node_id);
        assert_eq!(encoded.len(), 20);
        assert_eq!(encoded, [0xAB; 20]);
        let decoded: PlatformNodeId = deserialize(&encoded).expect("decode node id");
        assert_eq!(decoded, node_id);
    }

    #[test]
    fn consensus_encode_reverses_asymmetric_bytes() {
        let mut canonical = [0u8; 20];
        for (i, b) in canonical.iter_mut().enumerate() {
            *b = i as u8;
        }
        let node_id = PlatformNodeId::from_byte_array(canonical);
        let encoded = serialize(&node_id);
        let mut expected_wire = canonical;
        expected_wire.reverse();
        assert_eq!(encoded, expected_wire);

        let decoded: PlatformNodeId = deserialize(&encoded).expect("decode node id");
        assert_eq!(decoded, node_id);
        assert_eq!(decoded.to_byte_array(), canonical);
    }

    /// Issue #887 mainnet-verified wire ↔ canonical pair.
    #[test]
    fn consensus_wire_matches_dash_core_uint160_order() {
        let wire_hex = "8cb97997a418f4814a63d3564b9574a393437968";
        let canonical_hex = "68794393a374954b56d3634a81f418a49779b98c";

        let wire = <[u8; 20]>::from_hex(wire_hex).expect("wire hex");
        let decoded: PlatformNodeId = deserialize(&wire).expect("decode wire");
        assert_eq!(decoded.to_string(), canonical_hex);
        assert_eq!(serialize(&decoded), wire);
    }

    /// #884 golden pubkey → canonical id; wire is the byte-reversal.
    #[test]
    fn from_ed25519_public_key_consensus_wire_is_reversed() {
        let pubkey = <[u8; 32]>::from_hex(
            "3130c14339391cf26a68d86879e180ee9a16b660f5aa91f560f67c0abe8cf789",
        )
        .expect("pubkey hex");
        let node_id = PlatformNodeId::from_ed25519_public_key(&pubkey);
        assert_eq!(node_id.to_string(), "302f2615e6955cce8ed3cff81e8011bfd3a2991f");

        let encoded = serialize(&node_id);
        let mut expected_wire = node_id.to_byte_array();
        expected_wire.reverse();
        assert_eq!(encoded, expected_wire);

        let decoded: PlatformNodeId = deserialize(&encoded).expect("decode");
        assert_eq!(decoded, node_id);
    }

    /// Persisted masternode-list snapshots were written while
    /// `platform_node_id` was typed as `PubkeyHash`; the bincode layout must
    /// stay identical so old snapshots keep decoding.
    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_layout_matches_pubkey_hash() {
        use hashes::Hash;

        let bytes = [0xCD; 20];
        let config = bincode::config::standard();
        let node_id_bytes = bincode::encode_to_vec(PlatformNodeId::from_byte_array(bytes), config)
            .expect("encode node id");
        let pubkey_hash_bytes =
            bincode::encode_to_vec(crate::PubkeyHash::from_byte_array(bytes), config)
                .expect("encode pubkey hash");
        assert_eq!(node_id_bytes, pubkey_hash_bytes);
    }

    #[test]
    fn hex_display_and_parse_round_trip() {
        let hex = "4cd2ca50b36e0a2bb1b6b29da140448b47eeb7a1";
        let node_id: PlatformNodeId = hex.parse().expect("parse node id hex");
        assert_eq!(node_id.to_string(), hex);
        assert_eq!(format!("{:?}", node_id), hex);
        assert!("abcd".parse::<PlatformNodeId>().is_err(), "wrong-length hex must fail");
        assert!("zz".repeat(20).parse::<PlatformNodeId>().is_err(), "non-hex input must fail");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_round_trip_as_hex_string() {
        let node_id = PlatformNodeId::from_byte_array([0x11; 20]);
        let json = serde_json::to_string(&node_id).expect("serialize node id");
        assert_eq!(json, format!("\"{}\"", "11".repeat(20)));
        let back: PlatformNodeId = serde_json::from_str(&json).expect("deserialize node id");
        assert_eq!(back, node_id);
    }

    #[test]
    fn from_ed25519_public_key_is_truncated_sha256() {
        let public_key = [7u8; 32];
        let digest = sha256::Hash::hash(&public_key);
        let node_id = PlatformNodeId::from_ed25519_public_key(&public_key);
        assert_eq!(node_id.as_byte_array()[..], digest.to_byte_array()[..20]);
    }
}
