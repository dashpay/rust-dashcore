//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Dash Provider Dissolve Special Transaction (ProDisTx).
//!
//! Dissolves a masternode with a shared collateral, either unilaterally (one signature, by the
//! share at `actor_index`) or unanimously (one signature per share, in share order).
//! Defined in [dip-0187](https://github.com/dashpay/dips/pull/187).
//!
//! The special transaction type used for ProDisTx Transactions is 10.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::blockdata::transaction::special_transaction::provider_registration::{
    decode_compact_signatures, encode_compact_signatures,
};
use crate::consensus::{Decodable, Encodable, encode};
use crate::crypto::ecdsa::EcdsaRecSignature;
use crate::hash_types::Txid;
use crate::io;
use crate::prelude::*;

/// A Provider Dissolve Payload used in a Provider Dissolve Special Transaction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProviderDissolvePayload {
    pub version: u16,
    pub pro_tx_hash: Txid,
    /// Index of the share dissolving the masternode.
    pub actor_index: u16,
    /// One signature for a unilateral dissolution, one per share for a unanimous one.
    pub signatures: Vec<EcdsaRecSignature>,
}

impl ProviderDissolvePayload {
    /// Latest spec version of the ProDisTx payload.
    pub const CURRENT_VERSION: u16 = 1;

    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        2 + 32 + 2 + 1 + 65 * self.signatures.len()
    }
}

impl Encodable for ProviderDissolvePayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.pro_tx_hash.consensus_encode(w)?;
        len += self.actor_index.consensus_encode(w)?;
        len += encode_compact_signatures(&self.signatures, w)?;
        Ok(len)
    }
}

impl Decodable for ProviderDissolvePayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ProviderDissolvePayload {
            version: u16::consensus_decode(r)?,
            pro_tx_hash: Txid::consensus_decode(r)?,
            actor_index: u16::consensus_decode(r)?,
            signatures: decode_compact_signatures(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use super::*;
    use crate::consensus::{deserialize, serialize};

    #[test]
    fn layout() {
        let payload = ProviderDissolvePayload {
            version: 1,
            pro_tx_hash: Txid::from_byte_array([0x11; 32]),
            actor_index: 2,
            signatures: vec![
                EcdsaRecSignature::from([0x22; 65]),
                EcdsaRecSignature::from([0x33; 65]),
            ],
        };
        let mut want = vec![0x01, 0x00];
        want.extend([0x11; 32]);
        want.extend([0x02, 0x00, 0x02]);
        want.extend([0x22; 65]);
        want.extend([0x33; 65]);

        assert_eq!(serialize(&payload), want);
        assert_eq!(payload.size(), want.len());
        assert_eq!(deserialize::<ProviderDissolvePayload>(&want).unwrap(), payload);
    }
}
