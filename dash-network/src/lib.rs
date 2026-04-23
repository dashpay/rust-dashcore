//! The Dash [`Network`] enum and its pure helpers, extracted from the main
//! `dashcore` crate so that lightweight consumers can depend on it without
//! pulling in the full protocol library.
//!
//! This crate carries **no** dependencies beyond its optional `serde` /
//! `bincode` impls. If you need Network::known_genesis_block_hash — which
//! returns a `BlockHash` — use the extension trait provided by `dashcore`.
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

#[cfg(feature = "ffi")]
pub mod ffi;

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
    /// Creates a `Network` from the network magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dash_network::Network;
    ///
    /// assert_eq!(Some(Network::Mainnet), Network::from_magic(0xBD6B0CBF));
    /// assert_eq!(None, Network::from_magic(0xFFFFFFFF));
    /// ```
    pub const fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below.
        match magic {
            0xBD6B0CBF => Some(Network::Mainnet),
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
    /// use dash_network::Network;
    ///
    /// let network = Network::Mainnet;
    /// assert_eq!(network.magic(), 0xBD6B0CBF);
    /// ```
    pub const fn magic(self) -> u32 {
        // Note: any new entries here must be added to `from_magic` above.
        match self {
            Network::Mainnet => 0xBD6B0CBF,
            Network::Testnet => 0xFFCAE2CE,
            Network::Devnet => 0xCEFFCAE2,
            Network::Regtest => 0xDCB7C1FC,
        }
    }

    /// The block height at which Dash consensus version 20 activates.
    ///
    /// Devnet and regtest activate V20 immediately (height 0).
    pub const fn v20_activation_height(self) -> u32 {
        match self {
            Network::Mainnet => 1_987_776,
            Network::Testnet => 905_100,
            // Devnet and regtest activate V20 immediately.
            Network::Devnet | Network::Regtest => 0,
        }
    }

    /// The default P2P port for this network.
    ///
    /// Regtest's default is the typical Dash Core regtest value; devnets can
    /// vary and should usually come from configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dash_network::Network;
    ///
    /// assert_eq!(Network::Mainnet.default_p2p_port(), 9999);
    /// assert_eq!(Network::Testnet.default_p2p_port(), 19999);
    /// ```
    pub const fn default_p2p_port(self) -> u16 {
        match self {
            Network::Mainnet => 9999,
            Network::Testnet => 19999,
            Network::Devnet => 19799,
            Network::Regtest => 19899,
        }
    }

    pub const fn dns_seeds(self) -> &'static [&'static str] {
        match self {
            Network::Mainnet => &["dnsseed.dash.org"],
            Network::Testnet => &["testnet-seed.dashdot.io"],
            Network::Devnet | Network::Regtest => &[""],
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
    use super::*;

    #[test]
    fn magic_round_trip_covers_all_variants() {
        for n in [Network::Mainnet, Network::Testnet, Network::Devnet, Network::Regtest] {
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

    #[test]
    fn activation_heights_are_stable() {
        assert_eq!(Network::Mainnet.v20_activation_height(), 1_987_776);
        assert_eq!(Network::Testnet.v20_activation_height(), 905_100);
        assert_eq!(Network::Devnet.v20_activation_height(), 0);
        assert_eq!(Network::Regtest.v20_activation_height(), 0);
    }

    #[test]
    fn default_p2p_ports_match_conventions() {
        assert_eq!(Network::Mainnet.default_p2p_port(), 9999);
        assert_eq!(Network::Testnet.default_p2p_port(), 19999);
    }
}
