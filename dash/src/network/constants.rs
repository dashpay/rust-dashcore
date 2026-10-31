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
//! protocol.

use core::convert::From;
use core::{fmt, ops};

use hashes::Hash;

pub use dash_network::{Network, ParseNetworkError};

use crate::blockdata::constants::genesis_chain_params;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::{BlockHash, io};

// Re-export NODE_HEADERS_COMPRESSED for convenience
pub const NODE_HEADERS_COMPRESSED: ServiceFlags = ServiceFlags::NODE_HEADERS_COMPRESSED;

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

/// Mainnet height from which Dash HD/BIP39 wallets could first exist on chain.
///
/// No address any HD wallet derives can appear earlier, so an SPV client scanning for HD
/// wallet activity has no reason to sync mainnet below this height. Matches the entry in
/// DashSync's `mainnet_checkpoint_array` commented "first sync time (aka BIP39 creation
/// time)", the value the official Dash mobile SPV client uses as its floor.
pub const MAINNET_HD_ACTIVATION_HEIGHT: u32 = 227121;

pub trait NetworkExt {
    /// Returns the known genesis block hash for `network`.
    fn known_genesis_block_hash(&self) -> BlockHash;

    /// Earliest block height worth syncing for HD/BIP39 wallets, or `0` when the network
    /// has no floor (sync from genesis). Mainnet is floored at
    /// [`MAINNET_HD_ACTIVATION_HEIGHT`]; other networks return `0`.
    fn hd_wallet_sync_floor(&self) -> u32;
}

impl NetworkExt for Network {
    fn known_genesis_block_hash(&self) -> BlockHash {
        let hash = genesis_chain_params(*self).consensus.hash_genesis_block;
        BlockHash::from_byte_array(*hash.as_bytes())
    }

    fn hd_wallet_sync_floor(&self) -> u32 {
        match self {
            Network::Mainnet => MAINNET_HD_ACTIVATION_HEIGHT,
            _ => 0,
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

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Dash
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

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

    /// P2P_V2 means the node supports the BIP324 v2 transport.
    pub const P2P_V2: ServiceFlags = ServiceFlags(1 << 12);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    pub fn add(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 |= other.0;
        *self
    }

    /// Remove [ServiceFlags] from this.
    ///
    /// Returns itself.
    pub fn remove(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 ^= other.0;
        *self
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(self, flags: ServiceFlags) -> bool {
        (self.0 | flags.0) == self.0
    }

    /// Get the integer representation of this [ServiceFlags].
    pub fn as_u64(self) -> u64 {
        self.0
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
        write_flag!(BLOOM);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        write_flag!(NODE_HEADERS_COMPRESSED);
        write_flag!(P2P_V2);
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

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self {
        ServiceFlags(f)
    }
}

impl From<ServiceFlags> for u64 {
    fn from(val: ServiceFlags) -> Self {
        val.0
    }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.add(rhs);
    }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self {
        self.remove(rhs)
    }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.remove(rhs);
    }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceFlags;

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::BLOOM,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
            ServiceFlags::NODE_HEADERS_COMPRESSED,
            ServiceFlags::P2P_V2,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::BLOOM;
        assert_eq!(flags, ServiceFlags::BLOOM);

        let mut flags2 = flags | ServiceFlags::P2P_V2;
        for f in all.iter() {
            assert_eq!(flags2.has(*f), *f == ServiceFlags::BLOOM || *f == ServiceFlags::P2P_V2);
        }

        flags2 ^= ServiceFlags::BLOOM;
        assert_eq!(flags2, ServiceFlags::P2P_V2);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::P2P_V2;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(BLOOM)", ServiceFlags::BLOOM.to_string());
        let flag = ServiceFlags::P2P_V2 | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|P2P_V2)", flag.to_string());
        let flag = ServiceFlags::NETWORK | 0xf0.into();
        assert_eq!("ServiceFlags(NETWORK|COMPACT_FILTERS|0xb0)", flag.to_string());
    }

    /// The flags of Dash Core's `ServiceFlags` (`src/protocol.h`): bit 12 is `NODE_P2P_V2`, and
    /// Bitcoin's `NODE_GETUTXO` (bit 1) and `NODE_WITNESS` (bit 3) are not Dash flags.
    #[test]
    fn service_flags_are_dash_cores() {
        assert_eq!(ServiceFlags::from(1 << 12).to_string(), "ServiceFlags(P2P_V2)");
        assert_eq!(ServiceFlags::from(0b1010).to_string(), "ServiceFlags(0xa)");
    }
}
