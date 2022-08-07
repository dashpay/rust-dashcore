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

//! Dash Provider Update Service Special Transaction.
//!
//! The provider update service special transaction is used to update the operator controlled
//! options for a masternode.
//!
//! It is defined in DIP3 https://github.com/dashpay/dips/blob/master/dip-0003.md as follows:
//!
//! To service update a masternode, the masternode operator must submit another special
//! transaction (DIP2) to the network. This special transaction is called a Provider Update
//! Service Transaction and is abbreviated as ProUpServTx. It can only be done by the operator.
//!
//! An operator can update the IP address and port fields of a masternode entry. If a non-zero
//! operatorReward was set in the initial ProRegTx, the operator may also set the
//! scriptOperatorPayout field in the ProUpServTx. If scriptOperatorPayout is not set and
//! operatorReward is non-zero, the owner gets the full masternode reward.
//!
//! A ProUpServTx is only valid for masternodes in the registered masternodes subset. When
//! processed, it updates the metadata of the masternode entry and revives the masternode if it was
//! previously marked as PoSe-banned.
//!
//! The special transaction type used for ProUpServTx Transactions is 2.


use std::io;
use std::io::{Error, Write};
use hashes::Hash;
use ::{Script};
use ::{ProTxHash};
use blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use bls_sig_utils::BLSSignature;
use consensus::{Decodable, Encodable, encode};
use ::{InputsHash, SpecialTransactionPayloadHash};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ProviderUpdateServicePayload {
    version: u16,
    pro_tx_hash: ProTxHash,
    ip_address: u128,
    port: u16,
    script_payout: Script,
    inputs_hash: InputsHash,
    payload_sig: BLSSignature,
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateServicePayload {
    fn base_payload_data_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.ip_address.consensus_encode(&mut s)?;
        len += self.port.consensus_encode(&mut s)?;
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

impl Encodable for ProviderUpdateServicePayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut s)?;
        len += self.payload_sig.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateServicePayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let pro_tx_hash = ProTxHash::consensus_decode(&mut d)?;
        let ip_address = u128::consensus_decode(&mut d)?;
        let port = u16::consensus_decode(&mut d)?;
        let script_payout = Script::consensus_decode(&mut d)?;
        let inputs_hash = InputsHash::consensus_decode(&mut d)?;
        let payload_sig = BLSSignature::consensus_decode(&mut d)?;

        Ok(ProviderUpdateServicePayload {
            version,
            pro_tx_hash,
            ip_address,
            port,
            script_payout,
            inputs_hash,
            payload_sig,
        })
    }
}

#[cfg(test)]
mod tests {

}