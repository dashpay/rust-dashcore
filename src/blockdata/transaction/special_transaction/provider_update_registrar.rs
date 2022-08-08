// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash Provider Update Registrar Special Transaction.
//!
//! The provider update registrar special transaction is used to update the owner controlled options
//! for a masternode.
//!
//! It is defined in DIP3 https://github.com/dashpay/dips/blob/master/dip-0003.md as follows:
//!
//! To registrar update a masternode, the masternode owner must submit another special transaction
//! (DIP2) to the network. This special transaction is called a Provider Update Registrar
//! Transaction and is abbreviated as ProUpRegTx. It can only be done by the owner.
//!
//! A ProUpRegTx is only valid for masternodes in the registered masternodes subset. When
//! processed, it updates the metadata of the masternode entry. It does not revive masternodes
//! previously marked as PoSe-banned.
//!
//! The special transaction type used for ProUpRegTx Transactions is 3.

use std::io::Error;
use std::io;
use std::io::Write;
use hashes::Hash;
use ::{Script};
use consensus::{Decodable, Encodable, encode};
use ::{ProTxHash};
use ::{InputsHash};
use blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use bls_sig_utils::BLSPublicKey;
use ::{PubkeyHash, SpecialTransactionPayloadHash};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProviderUpdateRegistrarPayload {
    version: u16,
    pro_tx_hash: ProTxHash,
    operator_public_key: BLSPublicKey,
    voting_key_hash: PubkeyHash,
    operator_reward: u16,
    script_payout: Script,
    inputs_hash: InputsHash,
    payload_sig: Vec<u8>,
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateRegistrarPayload {
    fn base_payload_data_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        len += self.operator_reward.consensus_encode(&mut s)?;
        len += self.script_payout.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateRegistrarPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut s)?;
        len += self.payload_sig.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateRegistrarPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let pro_tx_hash = ProTxHash::consensus_decode(&mut d)?;
        let operator_public_key = BLSPublicKey::consensus_decode(&mut d)?;
        let voting_key_hash = PubkeyHash::consensus_decode(&mut d)?;
        let operator_reward = u16::consensus_decode(&mut d)?;
        let script_payout = Script::consensus_decode(&mut d)?;
        let inputs_hash = InputsHash::consensus_decode(&mut d)?;
        let payload_sig = Vec::<u8>::consensus_decode(&mut d)?;

        Ok(ProviderUpdateRegistrarPayload {
            version,
            pro_tx_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            payload_sig
        })
    }
}

#[cfg(test)]
mod tests {

}