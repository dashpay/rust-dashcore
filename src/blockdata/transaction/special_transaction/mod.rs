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
use consensus::{Decodable, encode};

pub mod provider_registration;
pub mod provider_update_service;
pub mod provider_update_registrar;
pub mod provider_update_revocation;
pub mod coinbase;
pub mod quorum_commitment;

pub enum TransactionPayload {
    ProviderRegistrationPayloadType(ProviderRegistrationPayload),
    ProviderUpdateServicePayloadType(ProviderUpdateServicePayload),
    ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload),
    ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload),
    CoinbasePayloadType(CoinbasePayload),
    QuorumCommitmentPayloadType(QuorumCommitmentPayload),
}

impl Decodable for TransactionPayload {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {}
}

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
    fn consensus_decode<D: io::Read>(self, d: D) -> Result<Option<TransactionPayload>, encode::Error> {
        Ok(match self {
            TransactionType::Classic => { None }
            TransactionType::ProviderRegistration => { Some(ProviderRegistrationPayloadType(ProviderRegistrationPayload::consensus_decode(d)?))}
            TransactionType::ProviderUpdateService => { Some(ProviderUpdateServicePayloadType(ProviderUpdateServicePayload::consensus_decode(d)?))}
            TransactionType::ProviderUpdateRegistrar => { Some(ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload::consensus_decode(d)?))}
            TransactionType::ProviderUpdateRevocation => { Some(ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload::consensus_decode(d)?))}
            TransactionType::Coinbase => { Some(CoinbasePayloadType(CoinbasePayload::consensus_decode(d)?))}
            TransactionType::QuorumCommitment => { Some(QuorumCommitmentPayloadType(QuorumCommitmentPayload::consensus_decode(d)?))}
        })
    }
}
