// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Dash
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

//! Dash network constants.
//!
//! This module provides various constants relating to the Dash network
//! protocol, such as protocol versioning and magic header bytes and the
//! different network types supported by Dash.
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use dashcore::Network;
//! use dashcore::consensus::encode::serialize;
//!
//! let network = Network::Dash;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0xBF, 0x0C, 0x6B, 0xBD]);
//! ```

use core::fmt;

use hashes::Hash;

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::{BlockHash, VarInt, io};

/// Version of the protocol as appearing in network message headers
/// This constant is used to signal to other peers which features you support.
/// Increasing it implies that your software also supports every feature prior to this version.
/// Doing so without support may lead to you incorrectly banning other peers or other peers banning you.
/// These are the features required for each version:
/// 70016 - Support receiving `wtxidrelay` message between `version` and `verack` message
/// 70015 - Support receiving invalid compact blocks from a peer without banning them
/// 70014 - Support compact block messages `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn`
/// 70013 - Support `feefilter` message
/// 70012 - Support `sendheaders` message and announce new blocks via headers rather than inv
/// 70011 - Support NODE_BLOOM service flag and don't support bloom filter messages if it is not set
/// 70002 - Support `reject` message
/// 70001 - Support bloom filter messages `filterload`, `filterclear` `filteradd`, `merkleblock` and FILTERED_BLOCK inventory type
/// 60002 - Support `mempool` message
/// 60001 - Support `pong` message and nonce in `ping` message
pub const PROTOCOL_VERSION: u32 = 70237;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
#[repr(u8)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum Network {
    /// Dash mainnet, the production network for real transactions.
    Dash,
    /// Dash public test network for protocol-level testing without real funds.
    Testnet,
    /// Dash development network, an isolated environment for feature development and testing.
    Devnet,
    /// Local regression testing network for deterministic, offline testing with instant block generation.
    Regtest,
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dashcore::Network;
    ///
    /// assert_eq!(Some(Network::Dash), Network::from_magic(0xBD6B0CBF));
    /// assert_eq!(None, Network::from_magic(0xFFFFFFFF));
    /// ```
    pub fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xBD6B0CBF => Some(Network::Dash),
            0xFFCAE2CE => Some(Network::Testnet),
            0xCEFFCAE2 => Some(Network::Devnet),
            0xDCB7C1FC => Some(Network::Regtest),
            _ => None,
        }
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dashcore::Network;
    ///
    /// let network = Network::Dash;
    /// assert_eq!(network.magic(), 0xBD6B0CBF);
    /// ```
    pub fn magic(self) -> u32 {
        // Note: any new entries here must be added to `from_magic` above
        match self {
            Network::Dash => 0xBD6B0CBF,
            Network::Testnet => 0xFFCAE2CE,
            Network::Devnet => 0xCEFFCAE2,
            Network::Regtest => 0xDCB7C1FC,
        }
    }

    pub fn known_genesis_block_hash(&self) -> Option<BlockHash> {
        match self {
            Network::Dash => {
                let mut block_hash =
                    hex::decode("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6")
                        .expect("expected valid hex");
                block_hash.reverse();
                Some(BlockHash::from_byte_array(block_hash.try_into().expect("expected 32 bytes")))
            }
            Network::Testnet => {
                let mut block_hash =
                    hex::decode("00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c")
                        .expect("expected valid hex");
                block_hash.reverse();
                Some(BlockHash::from_byte_array(block_hash.try_into().expect("expected 32 bytes")))
            }
            Network::Devnet => None,
            Network::Regtest => {
                let mut block_hash =
                    hex::decode("000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e")
                        .expect("expected valid hex");
                block_hash.reverse();
                Some(BlockHash::from_byte_array(block_hash.try_into().expect("expected 32 bytes")))
            }
        }
    }

    pub fn v20_activation_height(&self) -> u32 {
        match self {
            Network::Dash => 1_987_776,
            Network::Testnet => 905_100,
            // Devnet and regtest activate V20 immediately
            _ => 0,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Network::Dash => write!(f, "dash"),
            Network::Testnet => write!(f, "testnet"),
            Network::Devnet => write!(f, "devnet"),
            Network::Regtest => write!(f, "regtest"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dash" | "mainnet" => Ok(Network::Dash),
            "testnet" | "test" => Ok(Network::Testnet),
            "devnet" | "dev" => Ok(Network::Devnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(format!("Unknown network type: {}", s)),
        }
    }
}

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: ServiceFlags = ServiceFlags(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Dash Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request.  Dash
    /// Core does not support this but a patch set called Dash XT does.
    /// See BIP 64 for details on how this is implemented.
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Dash
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);

    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP157 and BIP158 for details on how this is implemented.
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP159 for details on how this is implemented.
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    /// NODE_HEADERS_COMPRESSED means the node supports compressed block headers as defined in DIP-0025.
    /// This allows for more efficient header synchronization by compressing headers from 80 bytes
    /// to as low as 37 bytes using stateful compression techniques.
    pub const NODE_HEADERS_COMPRESSED: ServiceFlags = ServiceFlags(1 << 11);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    pub fn add(&mut self, other: ServiceFlags) {
        self.0 |= other.0;
    }

    /// Remove [ServiceFlags] from this.
    pub fn remove(&mut self, other: ServiceFlags) {
        self.0 ^= other.0;
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(&self, flags: ServiceFlags) -> bool {
        (self.0 | flags.0) == self.0
    }

    /// Get the integer representation of this [ServiceFlags].
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    // This struct is weird in the dash protocol, sometime services are encoded as u64
    // and sometimes as a VarInt. While the Encodable/Decodable encodes and decodes the u64
    // as usual, this methods use VarInt to satisfy the protocol

    #[inline]
    pub fn consensus_encode_as_var_int<W: io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }

    #[inline]
    pub fn consensus_decode_from_var_int<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let services = VarInt::consensus_decode(r)?;
        Ok(ServiceFlags(services.0))
    }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = *self;
        if flags == ServiceFlags::NONE {
            return write!(f, "ServiceFlags(NONE)");
        }
        let mut first = true;
        macro_rules! write_flag {
            ($f:ident) => {
                if flags.has(ServiceFlags::$f) {
                    if !first {
                        write!(f, "|")?;
                    }
                    first = false;
                    write!(f, stringify!($f))?;
                    flags.remove(ServiceFlags::$f);
                }
            };
        }
        write!(f, "ServiceFlags(")?;
        write_flag!(NETWORK);
        write_flag!(GETUTXO);
        write_flag!(BLOOM);
        write_flag!(WITNESS);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        write_flag!(NODE_HEADERS_COMPRESSED);
        // If there are unknown flags left, we append them in hex.
        if flags != ServiceFlags::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl Encodable for ServiceFlags {
    /// Encodes the service flags as a u64, not a VarInt. Services are usually encoded as a u64
    /// but there are some messages that encode them as a VarInt instead. For those use the
    /// specialized method `consensus_encode_as_var_int`.
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ServiceFlags {
    /// Decodes the service flags as a u64, not a VarInt. Services are usually decoded as a u64
    /// but there are some messages that decode them as a VarInt instead. For those use the
    /// specialized method `consensus_decode_as_var_int`.
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceFlags;
    use crate::Network;
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn test_network_magic() {
        assert_eq!(Network::Dash.magic(), 0xBD6B0CBF);
        assert_eq!(Network::Testnet.magic(), 0xFFCAE2CE);
        assert_eq!(Network::Devnet.magic(), 0xCEFFCAE2);
        assert_eq!(Network::Regtest.magic(), 0xDCB7C1FC);
    }

    #[test]
    fn test_network_from_magic() {
        assert_eq!(Network::from_magic(0xBD6B0CBF), Some(Network::Dash));
        assert_eq!(Network::from_magic(0xFFCAE2CE), Some(Network::Testnet));
        assert_eq!(Network::from_magic(0xCEFFCAE2), Some(Network::Devnet));
        assert_eq!(Network::from_magic(0xDCB7C1FC), Some(Network::Regtest));
        assert_eq!(Network::from_magic(0x12345678), None);
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Dash.to_string(), "dash");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Devnet.to_string(), "devnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!("dash".parse::<Network>().unwrap(), Network::Dash);
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Dash);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("test".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("devnet".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("dev".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert!("invalid".parse::<Network>().is_err());
    }

    #[test]
    fn serialize_test() {
        assert_eq!(serialize(&Network::Dash.magic()), &[0xbf, 0x0c, 0x6b, 0xbd]);
        assert_eq!(serialize(&Network::Testnet.magic()), &[0xce, 0xe2, 0xca, 0xff]);
        assert_eq!(serialize(&Network::Devnet.magic()), &[0xe2, 0xca, 0xff, 0xce]);
        assert_eq!(serialize(&Network::Regtest.magic()), &[0xfc, 0xc1, 0xb7, 0xdc]);

        assert_eq!(deserialize(&[0xbf, 0x0c, 0x6b, 0xbd]).ok(), Some(Network::Dash.magic()));
        assert_eq!(deserialize(&[0xce, 0xe2, 0xca, 0xff]).ok(), Some(Network::Testnet.magic()));
        assert_eq!(deserialize(&[0xe2, 0xca, 0xff, 0xce]).ok(), Some(Network::Devnet.magic()));
        assert_eq!(deserialize(&[0xfc, 0xc1, 0xb7, 0xdc]).ok(), Some(Network::Regtest.magic()));
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
            ServiceFlags::NODE_HEADERS_COMPRESSED,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags.add(ServiceFlags::WITNESS);
        assert_eq!(flags, ServiceFlags::WITNESS);

        flags.add(ServiceFlags::GETUTXO);
        for f in all.iter() {
            assert_eq!(flags.has(*f), *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO);
        }

        flags.remove(ServiceFlags::WITNESS);
        assert_eq!(flags, ServiceFlags::GETUTXO);

        flags.add(ServiceFlags::COMPACT_FILTERS);
        flags.remove(ServiceFlags::GETUTXO);
        assert_eq!(flags, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());

        let mut flags = ServiceFlags::WITNESS;
        flags.add(ServiceFlags::BLOOM);
        flags.add(ServiceFlags::NETWORK);
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flags.to_string());
    }
}
