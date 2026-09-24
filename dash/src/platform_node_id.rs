//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Dash Platform (Tenderdash/CometBFT) node ID.

pub use dashcore_crypto::eddsa::EddsaPkHash as PlatformNodeId;

use crate::consensus::{Decodable, Encodable, encode};
use crate::io;

impl Encodable for PlatformNodeId {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_bytes().consensus_encode(w)
    }
}

impl Decodable for PlatformNodeId {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(PlatformNodeId::from_bytes(<[u8; 20]>::consensus_decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};

    #[test]
    fn consensus_round_trip() {
        let mut wire = [0u8; 20];
        for (i, byte) in wire.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let node_id = PlatformNodeId::from_bytes(wire);
        let encoded = serialize(&node_id);
        assert_eq!(encoded.len(), 20);
        assert_eq!(encoded, wire, "the stored order is the wire order");
        let decoded: PlatformNodeId = deserialize(&encoded).expect("decode node id");
        assert_eq!(decoded, node_id);
    }

    /// Mainnet evonode example from issue #887: the ProRegTx wire bytes carry
    /// the `uint160` internal (reversed) order, while the canonical id — as
    /// dashmate/Tenderdash derive and display it — is the byte-reversal.
    #[test]
    fn consensus_decode_yields_canonical_order() {
        let wire_bytes = crate::internal_macros::hex!("8cb97997a418f4814a63d3564b9574a393437968");
        let node_id: PlatformNodeId = deserialize(&wire_bytes).expect("decode node id");
        assert_eq!(node_id.to_string(), "68794393a374954b56d3634a81f418a49779b98c");
        assert_eq!(serialize(&node_id), wire_bytes, "re-encoding restores wire order");
    }

    /// A node id decoded from the wire must compare equal to one derived from
    /// the matching Ed25519 public key — the mismatch reported in issue #887.
    #[cfg(feature = "eddsa")]
    #[test]
    fn decoded_wire_id_matches_derived_id() {
        let public_key = [7u8; 32];
        let derived = dashcore_crypto::eddsa::EddsaPkBytes::from_bytes(public_key).hash();

        let decoded: PlatformNodeId = deserialize(&derived.to_bytes()).expect("decode node id");
        assert_eq!(decoded, derived);
    }
}
