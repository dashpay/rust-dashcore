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
/// public key hash. The consensus encoding is the raw 20 bytes, identical to
/// the encoding of a 20-byte key hash.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct PlatformNodeId([u8; 20]);

impl_array_newtype!(PlatformNodeId, u8, 20);
impl_bytes_newtype!(PlatformNodeId, 20);

impl PlatformNodeId {
    /// Constructs a platform node ID from its raw 20 bytes.
    pub const fn from_byte_array(bytes: [u8; 20]) -> Self {
        PlatformNodeId(bytes)
    }

    /// Returns the raw 20 bytes of the node ID.
    pub const fn to_byte_array(self) -> [u8; 20] {
        self.0
    }

    /// Returns a reference to the raw 20 bytes of the node ID.
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
        self.0.consensus_encode(w)
    }
}

impl Decodable for PlatformNodeId {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(PlatformNodeId(<[u8; 20]>::consensus_decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};

    #[test]
    fn consensus_round_trip() {
        let node_id = PlatformNodeId::from_byte_array([0xAB; 20]);
        let encoded = serialize(&node_id);
        assert_eq!(encoded.len(), 20);
        assert_eq!(encoded, [0xAB; 20]);
        let decoded: PlatformNodeId = deserialize(&encoded).expect("decode node id");
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
    fn from_ed25519_public_key_is_truncated_sha256() {
        let public_key = [7u8; 32];
        let digest = sha256::Hash::hash(&public_key);
        let node_id = PlatformNodeId::from_ed25519_public_key(&public_key);
        assert_eq!(node_id.as_byte_array()[..], digest.to_byte_array()[..20]);
    }
}
