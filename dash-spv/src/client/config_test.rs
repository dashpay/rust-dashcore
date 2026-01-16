//! Unit tests for client configuration

#[cfg(test)]
mod tests {
    use crate::client::config::{Config, MempoolStrategy};
    use crate::types::ValidationMode;
    use dashcore::Network;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert_eq!(config.network, Network::Dash);
        assert!(config.peers.is_empty());
        assert_eq!(config.validation_mode, ValidationMode::Full);
        assert!(config.enable_filters);
        assert!(config.enable_masternodes);
        assert_eq!(config.max_peers, 8);

        // Mempool defaults
        assert!(config.enable_mempool_tracking);
        assert_eq!(config.mempool_strategy, MempoolStrategy::FetchAll);
        assert_eq!(config.max_mempool_transactions, 1000);
        assert!(config.fetch_mempool_transactions);
        assert!(!config.persist_mempool);
    }

    #[test]
    fn test_network_specific_configs() {
        let mainnet = Config::mainnet();
        assert_eq!(mainnet.network, Network::Dash);
        assert!(mainnet.peers.is_empty()); // Should use DNS discovery

        let testnet = Config::testnet();
        assert_eq!(testnet.network, Network::Testnet);
        assert!(testnet.peers.is_empty()); // Should use DNS discovery

        let regtest = Config::regtest();
        assert_eq!(regtest.network, Network::Regtest);
        assert_eq!(regtest.peers.len(), 1);
        assert_eq!(regtest.peers[0].to_string(), "127.0.0.1:19899");
    }

    #[test]
    fn test_builder_pattern() {
        let path = PathBuf::from("/test/storage");

        let config = Config::mainnet()
            .with_storage_path(path.clone())
            .with_validation_mode(ValidationMode::Basic)
            .with_mempool_tracking(MempoolStrategy::BloomFilter)
            .with_max_mempool_transactions(500)
            .with_mempool_persistence(true)
            .with_start_height(100000);

        assert_eq!(config.storage_path, path);
        assert_eq!(config.validation_mode, ValidationMode::Basic);

        // Mempool settings
        assert!(config.enable_mempool_tracking);
        assert_eq!(config.mempool_strategy, MempoolStrategy::BloomFilter);
        assert_eq!(config.max_mempool_transactions, 500);
        assert!(config.persist_mempool);
        assert_eq!(config.start_from_height, Some(100000));
    }

    #[test]
    fn test_add_peer() {
        let mut config = Config::default();
        let addr1: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:9999".parse().unwrap();

        config.add_peer(addr1);
        config.add_peer(addr2);

        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0], addr1);
        assert_eq!(config.peers[1], addr2);
    }

    #[test]
    fn test_disable_features() {
        let config = Config::default().without_filters().without_masternodes();

        assert!(!config.enable_filters);
        assert!(!config.enable_masternodes);
    }

    #[test]
    fn test_validation_invalid_max_peers() {
        let config = Config {
            max_peers: 0,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_peers must be > 0");
    }

    #[test]
    fn test_validation_invalid_mempool_config() {
        let config = Config {
            enable_mempool_tracking: true,
            max_mempool_transactions: 0,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_mempool_transactions must be > 0"));
    }

    // Removed selective strategy validation test; Selective variant no longer exists
}
