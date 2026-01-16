//! Configuration management for the Dash SPV client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use dashcore::Network;
use derive_builder::Builder;
use getset::{CopyGetters, Getters};
// Serialization removed due to complex Address types

use crate::types::ValidationMode;

/// Strategy for handling mempool (unconfirmed) transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolStrategy {
    /// Fetch all announced transactions (high bandwidth, sees all transactions).
    FetchAll,
    /// Use BIP37 bloom filters (moderate privacy, good efficiency).
    BloomFilter,
}

/// Configuration for the Dash SPV client.
#[derive(Debug, Clone, Builder, Getters, CopyGetters)]
#[builder(setter(strip_option))]
#[builder(field(private))]
#[builder(default)]
#[builder(build_fn(validate = "Self::validate", error = "String"))]
pub struct Config {
    /// Network to connect to.
    #[getset(get_copy = "pub")]
    network: Network,

    /// List of peer addresses to connect to.
    #[getset(get = "pub")]
    peers: Vec<SocketAddr>,

    /// Restrict connections strictly to the configured peers.
    ///
    /// When true, the client will not use DNS discovery or peer persistence and
    /// will only attempt to connect to addresses provided in `peers`.
    /// If no peers are configured, no outbound connections will be made.
    #[getset(get_copy = "pub")]
    restrict_to_configured_peers: bool,

    /// Path for persistent storage. Defaults to ./dash-spv-storage
    #[getset(get = "pub")]
    #[builder(setter(into))]
    storage_path: PathBuf,

    /// Validation mode.
    #[getset(get_copy = "pub")]
    validation_mode: ValidationMode,

    /// Whether to enable filter syncing.
    #[getset(get_copy = "pub")]
    enable_filters: bool,

    /// Whether to enable masternode syncing.
    #[getset(get_copy = "pub")]
    enable_masternodes: bool,

    /// Maximum number of peers to connect to.
    #[getset(get_copy = "pub")]
    max_peers: u32,

    /// Optional user agent string to advertise in the P2P version message.
    /// If not set, a sensible default is used (includes crate version).
    #[getset(get = "pub")]
    user_agent: Option<String>,

    // Mempool configuration
    /// Enable tracking of unconfirmed (mempool) transactions.
    #[getset(get_copy = "pub")]
    enable_mempool_tracking: bool,

    /// Strategy for handling mempool transactions.
    #[getset(get_copy = "pub")]
    mempool_strategy: MempoolStrategy,

    /// Maximum number of unconfirmed transactions to track.
    #[getset(get_copy = "pub")]
    max_mempool_transactions: usize,

    /// Whether to fetch transactions from INV messages immediately.
    #[getset(get_copy = "pub")]
    fetch_mempool_transactions: bool,

    /// Whether to persist mempool transactions.
    #[getset(get_copy = "pub")]
    persist_mempool: bool,

    /// Start syncing from a specific block height.
    /// The client will use the nearest checkpoint at or before this height.
    #[getset(get_copy = "pub")]
    start_from_height: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Dash,
            peers: vec![],
            restrict_to_configured_peers: false,
            storage_path: PathBuf::from("./dash-spv-storage"),
            validation_mode: ValidationMode::Full,
            enable_filters: true,
            enable_masternodes: true,
            max_peers: 8,
            user_agent: None,
            enable_mempool_tracking: true,
            mempool_strategy: MempoolStrategy::FetchAll,
            max_mempool_transactions: 1000,
            fetch_mempool_transactions: true,
            persist_mempool: false,
            start_from_height: None,
        }
    }
}

impl ConfigBuilder {
    pub fn mainnet() -> ConfigBuilder {
        let mut builder = Self::default();
        builder.network(Network::Dash);
        builder
    }

    pub fn testnet() -> ConfigBuilder {
        let mut builder = Self::default();
        builder.network(Network::Testnet);
        builder
    }

    pub fn devnet() -> ConfigBuilder {
        let mut builder = Self::default();
        builder.network(Network::Devnet);
        builder
    }

    pub fn regtest() -> ConfigBuilder {
        let peers = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19899)];

        let mut builder = Self::default();
        builder.network(Network::Regtest).peers(peers);
        builder
    }

    fn validate(&self) -> Result<(), String> {
        match self.max_peers {
            Some(max_peers) if max_peers == 0 => {
                return Err("max_peers must be > 0".to_string());
            }
            _ => {}
        }

        // Validación de mempool
        match (self.enable_mempool_tracking, self.max_mempool_transactions) {
            (Some(true), Some(0)) => {
                return Err(
                    "max_mempool_transactions must be > 0 when mempool tracking is enabled"
                        .to_string(),
                );
            }
            _ => {}
        }

        match &self.storage_path {
            Some(path) => {
                std::fs::create_dir_all(path).map_err(|e| {
                    format!("A valid storage path must be provided: {:?}: {e}", path)
                })?;
            }
            None => {}
        }

        match (&self.peers, self.restrict_to_configured_peers) {
            (Some(peers), Some(true)) if peers.is_empty() => {
                return Err(
                    "restrict_to_configured_peers is true but no peers were provided".to_string()
                );
            }
            _ => {}
        }

        Ok(())
    }
}

impl Config {
    pub fn add_peer(&mut self, address: SocketAddr) -> &mut Self {
        self.peers.push(address);
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::client::config::{Config, ConfigBuilder, MempoolStrategy};
    use crate::types::ValidationMode;
    use dashcore::Network;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert_eq!(config.network(), Network::Dash);
        assert!(config.peers().is_empty());
        assert_eq!(config.validation_mode(), ValidationMode::Full);
        assert!(config.enable_filters());
        assert!(config.enable_masternodes());
        assert_eq!(config.max_peers(), 8);

        // Mempool defaults
        assert!(config.enable_mempool_tracking());
        assert_eq!(config.mempool_strategy(), MempoolStrategy::FetchAll);
        assert_eq!(config.max_mempool_transactions(), 1000);
        assert!(config.fetch_mempool_transactions());
        assert!(!config.persist_mempool());
    }

    #[test]
    fn test_network_specific_configs() {
        let mainnet = ConfigBuilder::mainnet().build().expect("Valid configuration");
        assert_eq!(mainnet.network(), Network::Dash);
        assert!(mainnet.peers().is_empty()); // Should use DNS discovery

        let testnet = ConfigBuilder::testnet().build().expect("Valid configuration");
        assert_eq!(testnet.network(), Network::Testnet);
        assert!(testnet.peers().is_empty()); // Should use DNS discovery

        let regtest = ConfigBuilder::regtest().build().expect("Valid configuration");
        assert_eq!(regtest.network(), Network::Regtest);
        assert_eq!(regtest.peers().len(), 1);
        assert_eq!(regtest.peers()[0].to_string(), "127.0.0.1:19899");
    }

    #[test]
    fn test_builder_pattern() {
        let path = PathBuf::from("/test/storage");

        let config = ConfigBuilder::default()
            .storage_path(path.clone())
            .validation_mode(ValidationMode::Basic)
            .enable_mempool_tracking(true)
            .mempool_strategy(MempoolStrategy::BloomFilter)
            .max_mempool_transactions(500)
            .persist_mempool(true)
            .start_from_height(100000)
            .build()
            .expect("Valid configuration");

        assert_eq!(*config.storage_path(), path);
        assert_eq!(config.validation_mode(), ValidationMode::Basic);

        // Mempool settings
        assert!(config.enable_mempool_tracking());
        assert_eq!(config.mempool_strategy(), MempoolStrategy::BloomFilter);
        assert_eq!(config.max_mempool_transactions(), 500);
        assert!(config.persist_mempool());
        assert_eq!(config.start_from_height(), Some(100000));
    }

    #[test]
    fn test_add_peer() {
        let mut config = ConfigBuilder::default().build().expect("Valid configuration");
        let addr1: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:9999".parse().unwrap();

        config.add_peer(addr1);
        config.add_peer(addr2);

        assert_eq!(config.peers().len(), 2);
        assert_eq!(config.peers()[0], addr1);
        assert_eq!(config.peers()[1], addr2);
    }

    #[test]
    fn test_disable_features() {
        let config = ConfigBuilder::testnet()
            .enable_filters(false)
            .enable_masternodes(false)
            .build()
            .expect("Valid configuration");

        assert!(!config.enable_filters());
        assert!(!config.enable_masternodes());
    }

    #[test]
    fn test_validation_invalid_max_peers() {
        let result = ConfigBuilder::testnet().max_peers(0).build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_peers must be > 0");
    }

    #[test]
    fn test_validation_invalid_mempool_config() {
        let result = ConfigBuilder::testnet()
            .enable_mempool_tracking(true)
            .max_mempool_transactions(0)
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_mempool_transactions must be > 0"));
    }
}
