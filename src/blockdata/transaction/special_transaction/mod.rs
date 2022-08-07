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

//! Dash Special Transaction.
//!
//! A dash special transaction's purpose is to relay more data than just economic information.
//! They are defined in DIP2 https://github.com/dashpay/dips/blob/master/dip-0002.md.
//! The list of special transactions can be found here:
//! https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md
//!

use std::io;
use blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use blockdata::transaction::special_transaction::provider_registration::ProviderRegistrationPayload;
use blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use blockdata::transaction::special_transaction::quorum_commitment::QuorumCommitmentPayload;
use blockdata::transaction::special_transaction::TransactionPayload::{CoinbasePayloadType, ProviderRegistrationPayloadType, ProviderUpdateRegistrarPayloadType, ProviderUpdateRevocationPayloadType, ProviderUpdateServicePayloadType, QuorumCommitmentPayloadType};
use blockdata::transaction::special_transaction::TransactionType::{Classic, Coinbase, ProviderRegistration, ProviderUpdateRegistrar, ProviderUpdateRevocation, ProviderUpdateService, QuorumCommitment};
use consensus::{Decodable, encode};
use util::address::Payload;

pub mod provider_registration;
pub mod provider_update_service;
pub mod provider_update_registrar;
pub mod provider_update_revocation;
pub mod coinbase;
pub mod quorum_commitment;

#[derive(Clone)]
pub enum TransactionPayload {
    ProviderRegistrationPayloadType(ProviderRegistrationPayload),
    ProviderUpdateServicePayloadType(ProviderUpdateServicePayload),
    ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload),
    ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload),
    CoinbasePayloadType(CoinbasePayload),
    QuorumCommitmentPayloadType(QuorumCommitmentPayload),
}

impl TransactionPayload {
    pub fn get_type(&self) -> TransactionType {
        match self {
            ProviderRegistrationPayloadType(_) => { ProviderRegistration }
            ProviderUpdateServicePayloadType(_) => { ProviderUpdateService }
            ProviderUpdateRegistrarPayloadType(_) => { ProviderUpdateRegistrar }
            ProviderUpdateRevocationPayloadType(_) => { ProviderUpdateRevocation }
            CoinbasePayloadType(_) => { Coinbase }
            QuorumCommitmentPayloadType(_) => { QuorumCommitment }
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u16)]
pub enum TransactionType {
    Classic = 0,
    ProviderRegistration = 1,
    ProviderUpdateService = 2,
    ProviderUpdateRegistrar = 3,
    ProviderUpdateRevocation = 4,
    Coinbase = 5,
    QuorumCommitment = 6,
}

impl TransactionType {
    pub fn from_optional_payload(payload: &Option<TransactionPayload>) -> Self {
        match payload {
            None => { Classic}
            Some(payload) => { payload.get_type()}
        }
    }

    fn consensus_decode<D: io::Read>(self, d: D) -> Result<Option<TransactionPayload>, encode::Error> {
        Ok(match self {
            Classic => { None }
            ProviderRegistration => { Some(ProviderRegistrationPayloadType(ProviderRegistrationPayload::consensus_decode(d)?))}
            ProviderUpdateService => { Some(ProviderUpdateServicePayloadType(ProviderUpdateServicePayload::consensus_decode(d)?))}
            ProviderUpdateRegistrar => { Some(ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload::consensus_decode(d)?))}
            ProviderUpdateRevocation => { Some(ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload::consensus_decode(d)?))}
            Coinbase => { Some(CoinbasePayloadType(CoinbasePayload::consensus_decode(d)?))}
            QuorumCommitment => { Some(QuorumCommitmentPayloadType(QuorumCommitmentPayload::consensus_decode(d)?))}
        })
    }
}
