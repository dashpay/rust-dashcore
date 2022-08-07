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

use core::fmt::{Debug, Display, Formatter};
use std::convert::TryFrom;
use std::io;
use std::io::{Error, Read, Write};
use blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
use blockdata::transaction::special_transaction::provider_registration::ProviderRegistrationPayload;
use blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use blockdata::transaction::special_transaction::quorum_commitment::QuorumCommitmentPayload;
use blockdata::transaction::special_transaction::TransactionPayload::{CoinbasePayloadType, ProviderRegistrationPayloadType, ProviderUpdateRegistrarPayloadType, ProviderUpdateRevocationPayloadType, ProviderUpdateServicePayloadType, QuorumCommitmentPayloadType};
use blockdata::transaction::special_transaction::TransactionType::{Classic, Coinbase, ProviderRegistration, ProviderUpdateRegistrar, ProviderUpdateRevocation, ProviderUpdateService, QuorumCommitment};
use consensus::{Decodable, Encodable, encode};
use SpecialTransactionPayloadHash;

pub mod provider_registration;
pub mod provider_update_service;
pub mod provider_update_registrar;
pub mod provider_update_revocation;
pub mod coinbase;
pub mod quorum_commitment;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum TransactionPayload {
    ProviderRegistrationPayloadType(ProviderRegistrationPayload),
    ProviderUpdateServicePayloadType(ProviderUpdateServicePayload),
    ProviderUpdateRegistrarPayloadType(ProviderUpdateRegistrarPayload),
    ProviderUpdateRevocationPayloadType(ProviderUpdateRevocationPayload),
    CoinbasePayloadType(CoinbasePayload),
    QuorumCommitmentPayloadType(QuorumCommitmentPayload),
}

impl Encodable for TransactionPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        match self {
            ProviderRegistrationPayloadType(p) => { p.consensus_encode(s)}
            ProviderUpdateServicePayloadType(p) => { p.consensus_encode(s)}
            ProviderUpdateRegistrarPayloadType(p) => {p.consensus_encode(s)}
            ProviderUpdateRevocationPayloadType(p) => {p.consensus_encode(s)}
            CoinbasePayloadType(p) => {p.consensus_encode(s)}
            QuorumCommitmentPayloadType(p) => {p.consensus_encode(s)}
        }
    }
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

    pub fn to_provider_registration_payload(self) -> Result<ProviderRegistrationPayload, encode::Error> {
        if let ProviderRegistrationPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderRegistration, actual: self.get_type() })
        }
    }

    pub fn to_update_service_payload(self) -> Result<ProviderUpdateServicePayload, encode::Error> {
        if let ProviderUpdateServicePayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderUpdateService, actual: self.get_type() })
        }
    }

    pub fn to_update_registrar_payload(self) -> Result<ProviderUpdateRegistrarPayload, encode::Error> {
        if let ProviderUpdateRegistrarPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderUpdateRegistrar, actual: self.get_type() })
        }
    }

    pub fn to_update_revocation_payload(self) -> Result<ProviderUpdateRevocationPayload, encode::Error> {
        if let ProviderUpdateRevocationPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: ProviderUpdateRevocation, actual: self.get_type() })
        }
    }

    pub fn to_coinbase_payload(self) -> Result<CoinbasePayload, encode::Error> {
        if let CoinbasePayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: Coinbase, actual: self.get_type() })
        }
    }

    pub fn to_quorum_commitment_payload(self) -> Result<QuorumCommitmentPayload, encode::Error> {
        if let QuorumCommitmentPayloadType(payload) = self {
            Ok(payload)
        } else {
            Err(encode::Error::WrongSpecialTransactionPayloadConversion { expected: QuorumCommitment, actual: self.get_type() })
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

impl Debug for TransactionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            Classic => write!(f, "Classic Transaction"),
            ProviderRegistration => write!(f, "Provider Registration Transaction"),
            ProviderUpdateService => write!(f, "Provider Update Service Transaction"),
            ProviderUpdateRegistrar => write!(f, "Provider Update Registrar Transaction"),
            ProviderUpdateRevocation => write!(f, "Provider Update Revocation Transaction"),
            Coinbase => write!(f, "Coinbase Transaction"),
            QuorumCommitment => write!(f, "Quorum Commitment Transaction"),
        }
    }
}

impl Display for TransactionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            Classic => write!(f, "Classic"),
            ProviderRegistration => write!(f, "Provider Registration"),
            ProviderUpdateService => write!(f, "Provider Update Service"),
            ProviderUpdateRegistrar => write!(f, "Provider Update Registrar"),
            ProviderUpdateRevocation => write!(f, "Provider Update Revocation"),
            Coinbase => write!(f, "Coinbase"),
            QuorumCommitment => write!(f, "Quorum Commitment"),
        }
    }
}

impl TryFrom<u16> for TransactionType {
    type Error = encode::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Classic),
            1 => Ok(ProviderRegistration),
            2 => Ok(ProviderUpdateService),
            3 => Ok(ProviderUpdateRegistrar),
            4 => Ok(ProviderUpdateRevocation),
            5 => Ok(Coinbase),
            6 => Ok(QuorumCommitment),
            _ => Err(encode::Error::UnknownSpecialTransactionType(value))
        }
    }
}

impl Decodable for TransactionType {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, encode::Error> {
        let special_transaction_number = u16::consensus_decode(d)?;
        TransactionType::try_from(special_transaction_number)
    }
}

impl TransactionType {
    pub fn from_optional_payload(payload: &Option<TransactionPayload>) -> Self {
        match payload {
            None => { Classic}
            Some(payload) => { payload.get_type()}
        }
    }

    pub fn consensus_decode<D: io::Read>(self, d: D) -> Result<Option<TransactionPayload>, encode::Error> {
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

/// Data which can be encoded in a consensus-consistent way
pub trait SpecialTransactionBasePayloadEncodable {
    /// Encode the payload with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn base_payload_data_encode<W: io::Write>(&self, writer: W) -> Result<usize, io::Error>;

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash;
}