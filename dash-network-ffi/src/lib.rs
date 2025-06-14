//! FFI bindings for dash-network library

use dash_network::Network as DashNetwork;

// Include the UniFFI scaffolding
uniffi::include_scaffolding!("dash_network");

// Initialize function
pub fn initialize() {
    // Any global initialization if needed
}

// Re-export Network enum for UniFFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Dash,
    Testnet,
    Devnet,
    Regtest,
}

impl From<Network> for DashNetwork {
    fn from(n: Network) -> Self {
        match n {
            Network::Dash => DashNetwork::Dash,
            Network::Testnet => DashNetwork::Testnet,
            Network::Devnet => DashNetwork::Devnet,
            Network::Regtest => DashNetwork::Regtest,
        }
    }
}

impl From<DashNetwork> for Network {
    fn from(n: DashNetwork) -> Self {
        match n {
            DashNetwork::Dash => Network::Dash,
            DashNetwork::Testnet => Network::Testnet,
            DashNetwork::Devnet => Network::Devnet,
            DashNetwork::Regtest => Network::Regtest,
            _ => Network::Testnet, // Default for unknown networks
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkError {
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Invalid network")]
    InvalidNetwork,
}

pub struct NetworkInfo {
    network: DashNetwork,
}

impl NetworkInfo {
    pub fn new(network: Network) -> Self {
        Self {
            network: network.into(),
        }
    }

    pub fn from_magic(magic: u32) -> Result<Self, NetworkError> {
        DashNetwork::from_magic(magic)
            .map(|network| Self {
                network,
            })
            .ok_or(NetworkError::InvalidMagic)
    }

    pub fn magic(&self) -> u32 {
        self.network.magic()
    }

    pub fn to_string(&self) -> String {
        self.network.to_string()
    }

    pub fn is_core_v20_active(&self, block_height: u32) -> bool {
        self.network.core_v20_is_active_at(block_height)
    }

    pub fn core_v20_activation_height(&self) -> u32 {
        self.network.core_v20_activation_height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_conversion() {
        // Test FFI to Dash Network conversion
        assert_eq!(DashNetwork::from(Network::Dash), DashNetwork::Dash);
        assert_eq!(DashNetwork::from(Network::Testnet), DashNetwork::Testnet);
        assert_eq!(DashNetwork::from(Network::Devnet), DashNetwork::Devnet);
        assert_eq!(DashNetwork::from(Network::Regtest), DashNetwork::Regtest);

        // Test Dash Network to FFI conversion
        assert_eq!(Network::from(DashNetwork::Dash), Network::Dash);
        assert_eq!(Network::from(DashNetwork::Testnet), Network::Testnet);
        assert_eq!(Network::from(DashNetwork::Devnet), Network::Devnet);
        assert_eq!(Network::from(DashNetwork::Regtest), Network::Regtest);
    }

    #[test]
    fn test_network_info_creation() {
        let info = NetworkInfo::new(Network::Dash);
        assert_eq!(info.network, DashNetwork::Dash);
    }

    #[test]
    fn test_magic_bytes() {
        let dash_info = NetworkInfo::new(Network::Dash);
        assert_eq!(dash_info.magic(), 0xBD6B0CBF);

        let testnet_info = NetworkInfo::new(Network::Testnet);
        assert_eq!(testnet_info.magic(), 0xFFCAE2CE);

        let devnet_info = NetworkInfo::new(Network::Devnet);
        assert_eq!(devnet_info.magic(), 0xCEFFCAE2);

        let regtest_info = NetworkInfo::new(Network::Regtest);
        assert_eq!(regtest_info.magic(), 0xDAB5BFFA);
    }

    #[test]
    fn test_from_magic() {
        // Valid magic bytes
        assert!(NetworkInfo::from_magic(0xBD6B0CBF).is_ok());
        assert!(NetworkInfo::from_magic(0xFFCAE2CE).is_ok());
        assert!(NetworkInfo::from_magic(0xCEFFCAE2).is_ok());
        assert!(NetworkInfo::from_magic(0xDAB5BFFA).is_ok());

        // Invalid magic bytes
        assert!(matches!(NetworkInfo::from_magic(0x12345678), Err(NetworkError::InvalidMagic)));
    }

    #[test]
    fn test_network_to_string() {
        assert_eq!(NetworkInfo::new(Network::Dash).to_string(), "dash");
        assert_eq!(NetworkInfo::new(Network::Testnet).to_string(), "testnet");
        assert_eq!(NetworkInfo::new(Network::Devnet).to_string(), "devnet");
        assert_eq!(NetworkInfo::new(Network::Regtest).to_string(), "regtest");
    }

    #[test]
    fn test_core_v20_activation() {
        let dash_info = NetworkInfo::new(Network::Dash);
        assert_eq!(dash_info.core_v20_activation_height(), 1987776);
        assert!(!dash_info.is_core_v20_active(1987775));
        assert!(dash_info.is_core_v20_active(1987776));
        assert!(dash_info.is_core_v20_active(2000000));

        let testnet_info = NetworkInfo::new(Network::Testnet);
        assert_eq!(testnet_info.core_v20_activation_height(), 905100);
        assert!(!testnet_info.is_core_v20_active(905099));
        assert!(testnet_info.is_core_v20_active(905100));
    }

    #[test]
    fn test_round_trip_conversions() {
        let networks = vec![Network::Dash, Network::Testnet, Network::Devnet, Network::Regtest];

        for network in networks {
            let dash_network: DashNetwork = network.into();
            let back_to_ffi: Network = dash_network.into();
            assert_eq!(network, back_to_ffi);
        }
    }
}
