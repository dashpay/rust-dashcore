//! Dash network types shared across Dash crates

use std::fmt;

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub enum Network {
    /// Classic Dash Core Payment Chain
    Dash,
    /// Dash's testnet network.
    Testnet,
    /// Dash's devnet network.
    Devnet,
    /// Bitcoin's regtest network.
    Regtest,
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dash_network::Network;
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
            0xDAB5BFFA => Some(Network::Regtest),
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

    /// The known activation height of core v20
    pub fn core_v20_activation_height(&self) -> u32 {
        match self {
            Network::Dash => 1987776,
            Network::Testnet => 905100,
            Network::Devnet => 1,  // v20 active from genesis on devnet
            Network::Regtest => 1, // v20 active from genesis on regtest
            #[allow(unreachable_patterns)]
            other => panic!("Unknown activation height for network {:?}", other),
        }
    }

    /// Helper method to know if core v20 was active
    pub fn core_v20_is_active_at(&self, core_block_height: u32) -> bool {
        core_block_height >= self.core_v20_activation_height()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_magic() {
        assert_eq!(Network::Dash.magic(), 0xBD6B0CBF);
        assert_eq!(Network::Testnet.magic(), 0xFFCAE2CE);
        assert_eq!(Network::Devnet.magic(), 0xCEFFCAE2);
        assert_eq!(Network::Regtest.magic(), 0xDAB5BFFA);
    }

    #[test]
    fn test_network_from_magic() {
        assert_eq!(Network::from_magic(0xBD6B0CBF), Some(Network::Dash));
        assert_eq!(Network::from_magic(0xFFCAE2CE), Some(Network::Testnet));
        assert_eq!(Network::from_magic(0xCEFFCAE2), Some(Network::Devnet));
        assert_eq!(Network::from_magic(0xDAB5BFFA), Some(Network::Regtest));
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
}
