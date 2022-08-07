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

//! Dash Provider Registration Special Transaction.
//!
//! The provider registration special transaction is used to register a masternode.
//! It is defined in DIP3 https://github.com/dashpay/dips/blob/master/dip-0003.md.
//!
//! The ProRegTx contains 2 public key IDs and one BLS public key, which represent 3 different
//! roles in the masternode and define update and voting rights. A "public key ID" refers to the
//! hash160 of an ECDSA public key. The keys are:
//!
//! KeyIdOwner (renamed to owner_key_hash): This is the public key ID of the masternode or
//! collateral owner. It is different than the key used in the collateral output. Only the owner
//! is allowed to issue ProUpRegTx transactions.
//!
//! PubKeyOperator (renamed to operator_public_key): This is the BLS public key of the masternode
//! operator. Only the operator is allowed to issue ProUpServTx transactions. The operator key is
//! also used while operating the masternode to sign masternode related P2P messages, quorum
//! related messages and governance trigger votes. Messages signed with this key are only valid
//! while the masternode is in the valid set.
//!
//! KeyIdVoting (renamed to voting_key_hash): This is the public key ID used for proposal voting.
//! Votes signed with this key are valid while the masternode is in the registered set.

use std::io;
use ::{OutPoint, Script};
use consensus::{Decodable, encode};
use ::{VarInt, VotingKeyHash};
use ::{InputsHash, OwnerKeyHash};
use bls_sig_utils::BLSPublicKey;

#[derive(Clone)]
pub struct ProviderRegistrationPayload {
    version: u16,
    provider_type: u16,
    provider_mode: u16,
    collateral_outpoint: OutPoint,
    ip_address: u128,
    port: u16,
    owner_key_hash: OwnerKeyHash,
    operator_public_key: BLSPublicKey,
    voting_key_hash: VotingKeyHash,
    operator_reward: u16,
    script_payout: Script,
    inputs_hash: InputsHash,
    payload_sig: Vec<u8>,
}

impl Decodable for ProviderRegistrationPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let provider_type = u16::consensus_decode(&mut d)?;
        let provider_mode = u16::consensus_decode(&mut d)?;
        let collateral_outpoint =  OutPoint::consensus_decode(&mut d)?;
        let ip_address = u128::consensus_decode(&mut d)?;
        let port = u16::consensus_decode(&mut d)?;
        let owner_key_hash = OwnerKeyHash::consensus_decode(&mut d)?;
        let operator_public_key = BLSPublicKey::consensus_decode(&mut d)?;
        let voting_key_hash = VotingKeyHash::consensus_decode(&mut d)?;
        let operator_reward = u16::consensus_decode(&mut d)?;
        let script_payout = Script::consensus_decode(&mut d)?;
        let inputs_hash = InputsHash::consensus_decode(&mut d)?;
        let payload_sig = Vec::<u8>::consensus_decode(&mut d)?;

        Ok(ProviderRegistrationPayload {
            version,
            provider_type,
            provider_mode,
            collateral_outpoint,
            ip_address,
            port,
            owner_key_hash,
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