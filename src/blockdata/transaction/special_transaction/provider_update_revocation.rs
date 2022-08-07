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

//! Dash Provider Update Revocation Special Transaction.
//!
//! The provider update revocation special transaction is used to signal to the owner that they
//! should choose a new operator.
//!
//! It is defined in DIP3 https://github.com/dashpay/dips/blob/master/dip-0003.md as follows:
//!
//! If an operator suspects their keys are insecure or if they wish to terminate service, they
//! can issue a special transaction to the network. This special transaction is called a Provider
//! Update Revocation Transaction and is abbreviated as ProUpRevTx. It can only be done by the
//! operator and allows them to signal the owner through the blockchain to choose a new operator
//! (or the same one with a new non-compromised key).

//! When a ProUpRevTx is processed, it updates the metadata of the masternode entry by removing
//! the operator and service information and marks the masternode as PoSe-banned. Owners must
//! later issue a ProUpRegTx Transaction to set a new operator key. After the ProUpRegTx is
//! processed, the new operator must issue a ProUpServTx Transaction to update the service-related
//! metadata and clear the PoSe-banned state (revive the masternode).

//! <https://github.com/dashpay/dips/blob/master/dip-0003.md#appendix-a-reasons-for-self-revocation-of-operators>
//! describes potential reasons for a revocation.

//! The special transaction type used for Provider Update Revoking Transactions is 4.

use std::io;
use ::{Script};
use ::{ProTxHash};
use bls_sig_utils::BLSSignature;
use consensus::{Decodable, encode};
use InputsHash;

#[derive(Clone)]
pub struct ProviderUpdateRevocationPayload {
    version: u16,
    pro_tx_hash: ProTxHash,
    reason: u16,
    inputs_hash: InputsHash,
    payload_sig: BLSSignature,
}


impl Decodable for ProviderUpdateRevocationPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let pro_tx_hash = ProTxHash::consensus_decode(&mut d)?;
        let reason = u16::consensus_decode(&mut d)?;
        let inputs_hash = InputsHash::consensus_decode(&mut d)?;
        let payload_sig = BLSSignature::consensus_decode(&mut d)?;

        Ok(ProviderUpdateRevocationPayload {
            version,
            pro_tx_hash,
            reason,
            inputs_hash,
            payload_sig
        })
    }
}

#[cfg(test)]
mod tests {

}