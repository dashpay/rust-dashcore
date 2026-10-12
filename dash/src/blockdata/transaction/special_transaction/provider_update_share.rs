//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Dash Provider Update Share Special Transaction (ProUpShareTx).
//!
//! Changes the reward script of one share of a masternode with a shared collateral, signed by
//! that share's owner key. Defined in [dip-0187](https://github.com/dashpay/dips/pull/187).
//!
//! The special transaction type used for ProUpShareTx Transactions is 11.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;

use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, SpecialTransactionPayloadHash, Txid};
use crate::prelude::*;
use crate::{ScriptBuf, VarInt, io};

/// A Provider Update Share Payload used in a Provider Update Share Special Transaction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProviderUpdateSharePayload {
    pub version: u16,
    pub pro_tx_hash: Txid,
    pub share_index: u16,
    /// The new reward script; the share's refund script resets it.
    pub script_reward: ScriptBuf,
    pub inputs_hash: InputsHash,
    pub payload_sig: Vec<u8>,
}

impl ProviderUpdateSharePayload {
    /// Latest spec version of the ProUpShareTx payload.
    pub const CURRENT_VERSION: u16 = 1;

    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        2 + 32
            + 2
            + VarInt(self.script_reward.len() as u64).len()
            + self.script_reward.len()
            + 32
            + VarInt(self.payload_sig.len() as u64).len()
            + self.payload_sig.len()
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateSharePayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.share_index.consensus_encode(&mut s)?;
        len += self.script_reward.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateSharePayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.payload_sig.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateSharePayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ProviderUpdateSharePayload {
            version: u16::consensus_decode(r)?,
            pro_tx_hash: Txid::consensus_decode(r)?,
            share_index: u16::consensus_decode(r)?,
            script_reward: ScriptBuf::consensus_decode(r)?,
            inputs_hash: InputsHash::consensus_decode(r)?,
            payload_sig: Vec::<u8>::consensus_decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};

    #[test]
    fn layout() {
        let payload = ProviderUpdateSharePayload {
            version: 1,
            pro_tx_hash: Txid::from_byte_array([0x11; 32]),
            share_index: 3,
            script_reward: ScriptBuf::from_bytes(vec![0x51]),
            inputs_hash: InputsHash::from_byte_array([0x22; 32]),
            payload_sig: vec![0x33; 65],
        };
        let mut want = vec![0x01, 0x00];
        want.extend([0x11; 32]);
        want.extend([0x03, 0x00, 0x01, 0x51]);
        want.extend([0x22; 32]);
        want.push(65);
        want.extend([0x33; 65]);

        assert_eq!(serialize(&payload), want);
        assert_eq!(payload.size(), want.len());
        assert_eq!(deserialize::<ProviderUpdateSharePayload>(&want).unwrap(), payload);
    }
}
