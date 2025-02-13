// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
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

//! Bitcoin network-related network messages.
//!
//! This module defines network messages which describe peers and their
//! capabilities.
//!

#[cfg(feature = "core-block-hash-use-x11")]
use hashes::hash_x11 as hashType;
#[cfg(not(feature = "core-block-hash-use-x11"))]
use hashes::sha256d as hashType;

use crate::consensus::{Decodable, Encodable, ReadExt, encode};
use crate::internal_macros::impl_consensus_encoding;
use crate::io;
use crate::network::address::Address;
use crate::network::constants::{self, ServiceFlags};
use crate::prelude::*;

/// Some simple messages

/// The `version` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct VersionMessage {
    /// The P2P network protocol version
    pub version: u32,
    /// A bitmask describing the services supported by this node
    pub services: ServiceFlags,
    /// The time at which the `version` message was sent
    pub timestamp: i64,
    /// The network address of the peer receiving the message
    pub receiver: Address,
    /// The network address of the peer sending the message
    pub sender: Address,
    /// A random nonce used to detect loops in the network
    pub nonce: u64,
    /// A string describing the peer's software
    pub user_agent: String,
    /// The height of the maximum-work blockchain that the peer is aware of
    pub start_height: i32,
    /// Whether the receiving peer should relay messages to the sender; used
    /// if the sender is bandwidth-limited and would like to support bloom
    /// filtering. Defaults to false.
    pub relay: bool,
    /// The mn auth challenge is a set of random bytes that challenge a masternode to prove
    /// themselves. The sender sends a random auth challenge, and the masternode will send back
    /// a response in mn_auth proving they are a masternode by signing this message.
    pub mn_auth_challenge: [u8; 32],
    /// Indicates if we are doing a quorum probe. Generally this should be set to false.
    pub masternode_connection: bool,
}

impl VersionMessage {
    /// Constructs a new `version` message with `relay` set to false
    pub fn new(
        services: ServiceFlags,
        timestamp: i64,
        receiver: Address,
        sender: Address,
        nonce: u64,
        user_agent: String,
        start_height: i32,
        mn_auth_challenge: [u8; 32],
    ) -> VersionMessage {
        VersionMessage {
            version: constants::PROTOCOL_VERSION,
            services,
            timestamp,
            receiver,
            sender,
            nonce,
            user_agent,
            start_height,
            relay: false,
            mn_auth_challenge,
            masternode_connection: false,
        }
    }
}

impl Encodable for VersionMessage {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(writer)?;
        len += self.services.consensus_encode(writer)?;
        len += self.timestamp.consensus_encode(writer)?;
        len += self.receiver.consensus_encode(writer)?;
        len += self.sender.consensus_encode(writer)?;
        len += self.nonce.consensus_encode(writer)?;
        len += self.user_agent.consensus_encode(writer)?;
        len += self.start_height.consensus_encode(writer)?;
        len += self.relay.consensus_encode(writer)?;
        len += self.mn_auth_challenge.consensus_encode(writer)?;
        len += self.masternode_connection.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for VersionMessage {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        // Required fields
        let version: u32 = Decodable::consensus_decode(reader)?;
        let services: ServiceFlags = Decodable::consensus_decode(reader)?;
        let timestamp: i64 = Decodable::consensus_decode(reader)?;
        let receiver: Address = Decodable::consensus_decode(reader)?;
        let sender: Address = Decodable::consensus_decode(reader)?;
        let nonce: u64 = Decodable::consensus_decode(reader)?;
        let user_agent: String = Decodable::consensus_decode(reader)?;
        let start_height: i32 = Decodable::consensus_decode(reader)?;

        // Read optional fields only if there are bytes remaining
        let relay = if let Ok(val) = reader.read_u8() { val != 0 } else { false };

        let mut mn_auth_challenge = [0u8; 32];
        if let Ok(_) = reader.read_exact(&mut mn_auth_challenge) {
            // Successfully read challenge
        } else {
            mn_auth_challenge = [0; 32]; // Default value
        }

        let masternode_connection = if let Ok(val) = reader.read_u8() { val != 0 } else { false };

        Ok(VersionMessage {
            version,
            services,
            timestamp,
            receiver,
            sender,
            nonce,
            user_agent,
            start_height,
            relay,
            mn_auth_challenge,
            masternode_connection,
        })
    }
}

/// message rejection reason as a code
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum RejectReason {
    /// malformed message
    Malformed = 0x01,
    /// invalid message
    Invalid = 0x10,
    /// obsolete message
    Obsolete = 0x11,
    /// duplicate message
    Duplicate = 0x12,
    /// nonstandard transaction
    NonStandard = 0x40,
    /// an output is below dust limit
    Dust = 0x41,
    /// insufficient fee
    Fee = 0x42,
    /// checkpoint
    Checkpoint = 0x43,
}

impl Encodable for RejectReason {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&[*self as u8])?;
        Ok(1)
    }
}

impl Decodable for RejectReason {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(match r.read_u8()? {
            0x01 => RejectReason::Malformed,
            0x10 => RejectReason::Invalid,
            0x11 => RejectReason::Obsolete,
            0x12 => RejectReason::Duplicate,
            0x40 => RejectReason::NonStandard,
            0x41 => RejectReason::Dust,
            0x42 => RejectReason::Fee,
            0x43 => RejectReason::Checkpoint,
            _ => return Err(encode::Error::ParseFailed("unknown reject code")),
        })
    }
}

/// Reject message might be sent by peers rejecting one of our messages
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Reject {
    /// message type rejected
    pub message: Cow<'static, str>,
    /// reason of rejection as code
    pub ccode: RejectReason,
    /// reason of rejectection
    pub reason: Cow<'static, str>,
    /// reference to rejected item
    pub hash: hashType::Hash,
}

impl_consensus_encoding!(Reject, message, ccode, reason, hash);

#[cfg(test)]
mod tests {
    #[cfg(feature = "core-block-hash-use-x11")]
    use hashes::hash_x11 as hashType;
    #[cfg(not(feature = "core-block-hash-use-x11"))]
    use hashes::sha256d as hashType;

    use super::{Reject, RejectReason, VersionMessage};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::internal_macros::hex;
    use crate::network::constants::ServiceFlags;

    #[test]
    fn version_message_test() {
        // This message is from my satoshi node, morning of May 27 2014
        let from_sat = hex!(
            "721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f0400016a4bbaa5155fa3ed24b60975d2b7b9860ccd64ff39c128622184b794256a0cba00"
        );

        let message: VersionMessage = deserialize(&from_sat).expect("deserialize message");

        assert_eq!(message.version, 70002);
        assert_eq!(message.services, ServiceFlags::NETWORK);
        assert_eq!(message.timestamp, 1401217254);
        // address decodes should be covered by Address tests
        assert_eq!(message.nonce, 16735069437859780935);
        assert_eq!(message.user_agent, "/Satoshi:0.9.99/".to_string());
        assert_eq!(message.start_height, 302892);
        assert!(message.relay);
        assert_eq!(
            &message.mn_auth_challenge.to_vec(),
            &hex::decode("6a4bbaa5155fa3ed24b60975d2b7b9860ccd64ff39c128622184b794256a0cba")
                .expect("expected to get vec")
        );
        assert!(!message.masternode_connection);
        assert_eq!(serialize(&message), from_sat);
    }

    #[test]
    fn reject_message_test() {
        let reject_tx_conflict = hex!(
            "027478121474786e2d6d656d706f6f6c2d636f6e666c69637405df54d3860b3c41806a3546ab48279300affacf4b88591b229141dcf2f47004"
        );
        let reject_tx_nonfinal = hex!(
            "02747840096e6f6e2d66696e616c259bbe6c83db8bbdfca7ca303b19413dc245d9f2371b344ede5f8b1339a5460b"
        );

        let decode_result_conflict: Result<Reject, _> = deserialize(&reject_tx_conflict);
        let decode_result_nonfinal: Result<Reject, _> = deserialize(&reject_tx_nonfinal);

        assert!(decode_result_conflict.is_ok());
        assert!(decode_result_nonfinal.is_ok());

        let conflict = decode_result_conflict.unwrap();
        assert_eq!("tx", conflict.message);
        assert_eq!(RejectReason::Duplicate, conflict.ccode);
        assert_eq!("txn-mempool-conflict", conflict.reason);
        assert_eq!(
            "0470f4f2dc4191221b59884bcffaaf00932748ab46356a80413c0b86d354df05"
                .parse::<hashType::Hash>()
                .unwrap(),
            conflict.hash
        );

        let nonfinal = decode_result_nonfinal.unwrap();
        assert_eq!("tx", nonfinal.message);
        assert_eq!(RejectReason::NonStandard, nonfinal.ccode);
        assert_eq!("non-final", nonfinal.reason);
        assert_eq!(
            "0b46a539138b5fde4e341b37f2d945c23d41193b30caa7fcbd8bdb836cbe9b25"
                .parse::<hashType::Hash>()
                .unwrap(),
            nonfinal.hash
        );

        assert_eq!(serialize(&conflict), reject_tx_conflict);
        assert_eq!(serialize(&nonfinal), reject_tx_nonfinal);
    }
}
