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

use std::io;
use ::{Script};
use consensus::{Decodable, encode};
use ::{ProTxHash};
use ::{InputsHash, VotingKeyHash};
use bls_sig_utils::BLSPublicKey;

#[derive(Clone)]
pub struct ProviderUpdateRegistrarPayload {
    version: u16,
    pro_tx_hash: ProTxHash,
    operator_public_key: BLSPublicKey,
    voting_key_hash: VotingKeyHash,
    operator_reward: u16,
    script_payout: Script,
    inputs_hash: InputsHash,
    payload_sig: Vec<u8>,
}

impl Decodable for ProviderUpdateRegistrarPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let pro_tx_hash = ProTxHash::consensus_decode(&mut d)?;
        let operator_public_key = BLSPublicKey::consensus_decode(&mut d)?;
        let voting_key_hash = VotingKeyHash::consensus_decode(&mut d)?;
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