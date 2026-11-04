//! The Dash [`Network`] enum and its pure helpers, extracted from the main
//! `dashcore` crate so that lightweight consumers can depend on it without
//! pulling in the full protocol library.
//!
//! Parameters come from `dash-params`, except for devnets, which are set at
//! runtime. If you need Network::known_genesis_block_hash — which returns a
//! `BlockHash` — use the extension trait provided by `dashcore`.
//!
//! # Example
//!
//! ```rust
//! use dash_network::Network;
//!
//! assert_eq!(Network::Mainnet.magic(), 0xBD6B0CBF);
//! assert_eq!(Network::from_magic(0xBD6B0CBF), Some(Network::Mainnet));
//! assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
//! assert_eq!(Network::Mainnet.default_p2p_port(), 9999);
//! ```

use core::fmt;

use dash_params::{AddrParams, ChainParams, Network as CoreNetwork};

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};

/// The Dash network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[repr(u8)]
pub enum Network {
    /// Dash mainnet, the production network for real transactions.
    Mainnet,
    /// Dash public test network for protocol-level testing without real funds.
    Testnet,
    /// Dash development network, an isolated environment for feature development and testing.
    Devnet,
    /// Local regression testing network for deterministic, offline testing with instant block generation.
    Regtest,
}

impl Network {
    /// Every network, in declaration order.
    const ALL: [Network; 4] =
        [Network::Mainnet, Network::Testnet, Network::Devnet, Network::Regtest];

    /// The chain parameters of this network, or `None` for devnets,
    /// whose parameters are set at runtime.
    pub const fn chain_params(self) -> Option<&'static ChainParams> {
        match self {
            Network::Mainnet => Some(CoreNetwork::Main.chain()),
            Network::Testnet => Some(CoreNetwork::Testnet3.chain()),
            Network::Devnet => None,
            Network::Regtest => Some(CoreNetwork::Regtest.chain()),
        }
    }

    /// The address and key prefixes of this network. Devnets share testnet's.
    pub const fn addr_params(self) -> &'static AddrParams {
        match self {
            Network::Mainnet => CoreNetwork::Main.addr(),
            Network::Testnet | Network::Devnet => CoreNetwork::Testnet3.addr(),
            Network::Regtest => CoreNetwork::Regtest.addr(),
        }
    }

    /// Creates a `Network` from the network magic bytes.
    pub fn from_magic(magic: u32) -> Option<Network> {
        Self::ALL.into_iter().find(|network| network.magic() == magic)
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    pub const fn magic(self) -> u32 {
        match self.chain_params() {
            Some(chain) => u32::from_le_bytes(chain.message_start),
            None => 0xCEFFCAE2,
        }
    }

    /// The block height at which Dash consensus version 20 activates.
    ///
    /// 0 on devnets and regtest, which set it at runtime.
    pub const fn v20_activation_height(self) -> u32 {
        match (self, self.chain_params()) {
            (Network::Mainnet | Network::Testnet, Some(chain)) => {
                chain.consensus.v20_height.to_u32()
            }
            _ => 0,
        }
    }

    /// The default P2P port for this network.
    ///
    /// Devnets can vary and should usually take theirs from configuration.
    pub const fn default_p2p_port(self) -> u16 {
        match self.chain_params() {
            Some(chain) => chain.default_port,
            None => 19799,
        }
    }

    /// DNS seed hostnames for this network. Empty for devnets.
    pub const fn dns_seeds(self) -> &'static [&'static str] {
        match self.chain_params() {
            Some(chain) => chain.dns_seeds,
            None => &[],
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Devnet => "devnet",
            Network::Regtest => "regtest",
        })
    }
}

impl core::str::FromStr for Network {
    type Err = ParseNetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Ok(Network::Mainnet),
            "testnet" | "test" => Ok(Network::Testnet),
            "devnet" | "dev" => Ok(Network::Devnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(ParseNetworkError(s.to_string())),
        }
    }
}

/// Error returned from Network::from_str when the input doesn't name a
/// known network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseNetworkError(pub String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown network type: {}", self.0)
    }
}

impl std::error::Error for ParseNetworkError {}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test]
    fn magic_round_trip_covers_all_variants() {
        for n in Network::ALL {
            let magic = n.magic();
            assert_eq!(Network::from_magic(magic), Some(n), "round-trip failed for {:?}", n);
        }
    }

    #[test]
    fn from_magic_unknown_is_none() {
        assert_eq!(Network::from_magic(0), None);
        assert_eq!(Network::from_magic(0xFFFFFFFF), None);
    }

    #[test]
    fn from_str_accepts_aliases_and_is_case_insensitive() {
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("main".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("Testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("test".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("devnet".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("dev".parse::<Network>().unwrap(), Network::Devnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
    }

    #[test]
    fn from_str_rejects_nonsense() {
        let err = "bogus".parse::<Network>().unwrap_err();
        assert_eq!(err.0, "bogus");
    }

    #[test]
    fn display_matches_canonical_lowercase() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Devnet.to_string(), "devnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
    }

    #[test_case(Network::Mainnet, 0xBD6B0CBF, 9999, 1_987_776)]
    #[test_case(Network::Testnet, 0xFFCAE2CE, 19999, 905_100)]
    #[test_case(Network::Devnet, 0xCEFFCAE2, 19799, 0)]
    #[test_case(Network::Regtest, 0xDCB7C1FC, 19899, 0)]
    fn parameters_match_dash_core(network: Network, magic: u32, port: u16, v20_height: u32) {
        assert_eq!(network.magic(), magic);
        assert_eq!(network.default_p2p_port(), port);
        assert_eq!(network.v20_activation_height(), v20_height);
    }
}
