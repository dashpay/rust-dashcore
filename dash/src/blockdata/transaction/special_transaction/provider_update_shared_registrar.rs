//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Dash Provider Update Shared Registrar Special Transaction (ProUpSharedRegTx).
//!
//! Changes the operator and voting keys of a masternode with a shared collateral, signed by
//! every share in share order. Defined in [dip-0187](https://github.com/dashpay/dips/pull/187).
//!
//! The special transaction type used for ProUpSharedRegTx Transactions is 12.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;

use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::blockdata::transaction::special_transaction::provider_registration::{
    decode_compact_signatures, encode_compact_signatures,
};
use crate::bls_sig_utils::BLSPublicKey;
use crate::consensus::{Decodable, Encodable, encode};
use crate::crypto::ecdsa::EcdsaRecSignature;
use crate::hash_types::{InputsHash, PubkeyHash, SpecialTransactionPayloadHash, Txid};
use crate::io;
use crate::prelude::*;

/// A Provider Update Shared Registrar Payload used in a Provider Update Shared Registrar
/// Special Transaction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProviderUpdateSharedRegistrarPayload {
    pub version: u16,
    pub pro_tx_hash: Txid,
    /// Basic BLS scheme operator key.
    pub operator_public_key: BLSPublicKey,
    pub voting_key_hash: PubkeyHash,
    pub inputs_hash: InputsHash,
    /// One signature per share, in share order.
    pub signatures: Vec<EcdsaRecSignature>,
}

impl ProviderUpdateSharedRegistrarPayload {
    /// Latest spec version of the ProUpSharedRegTx payload.
    pub const CURRENT_VERSION: u16 = 1;

    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        2 + 32 + 48 + 20 + 32 + 1 + 65 * self.signatures.len()
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateSharedRegistrarPayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateSharedRegistrarPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += encode_compact_signatures(&self.signatures, w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateSharedRegistrarPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ProviderUpdateSharedRegistrarPayload {
            version: u16::consensus_decode(r)?,
            pro_tx_hash: Txid::consensus_decode(r)?,
            operator_public_key: BLSPublicKey::consensus_decode(r)?,
            voting_key_hash: PubkeyHash::consensus_decode(r)?,
            inputs_hash: InputsHash::consensus_decode(r)?,
            signatures: decode_compact_signatures(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};

    #[test]
    fn layout() {
        let payload = ProviderUpdateSharedRegistrarPayload {
            version: 1,
            pro_tx_hash: Txid::from_byte_array([0x11; 32]),
            operator_public_key: BLSPublicKey::from([0x22; 48]),
            voting_key_hash: PubkeyHash::from_byte_array([0x33; 20]),
            inputs_hash: InputsHash::from_byte_array([0x44; 32]),
            signatures: vec![EcdsaRecSignature::from([0x55; 65])],
        };
        let mut want = vec![0x01, 0x00];
        want.extend([0x11; 32]);
        want.extend([0x22; 48]);
        want.extend([0x33; 20]);
        want.extend([0x44; 32]);
        want.push(1);
        want.extend([0x55; 65]);

        assert_eq!(serialize(&payload), want);
        assert_eq!(payload.size(), want.len());
        assert_eq!(deserialize::<ProviderUpdateSharedRegistrarPayload>(&want).unwrap(), payload);
    }
}
