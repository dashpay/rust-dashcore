//! Unit tests for client configuration

#[cfg(test)]
mod tests {
    use crate::client::config::{ClientConfig, MempoolStrategy};
    use crate::types::ValidationMode;
    use dashcore::{Address, Network};
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();

        assert_eq!(config.network, Network::Dash);
        assert!(config.peers.is_empty());
        assert_eq!(config.validation_mode, ValidationMode::Full);
        assert_eq!(config.filter_checkpoint_interval, 1000);
        assert_eq!(config.max_headers_per_message, 2000);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.message_timeout, Duration::from_secs(60));
        assert_eq!(config.sync_timeout, Duration::from_secs(300));
        assert_eq!(config.read_timeout, Duration::from_millis(100));
        assert!(config.watch_items.is_empty());
        assert!(config.enable_filters);
        assert!(config.enable_masternodes);
        assert_eq!(config.max_peers, 8);
        assert!(config.enable_persistence);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.max_concurrent_filter_requests, 16);
        assert!(config.enable_filter_flow_control);
        assert_eq!(config.filter_request_delay_ms, 0);

        // Mempool defaults
        assert!(!config.enable_mempool_tracking);
        assert_eq!(config.mempool_strategy, MempoolStrategy::Selective);
        assert_eq!(config.max_mempool_transactions, 1000);
        assert_eq!(config.mempool_timeout_secs, 3600);
        assert_eq!(config.recent_send_window_secs, 300);
        assert!(config.fetch_mempool_transactions);
        assert!(!config.persist_mempool);
    }

    #[test]
    fn test_network_specific_configs() {
        let mainnet = ClientConfig::mainnet();
        assert_eq!(mainnet.network, Network::Dash);
        assert!(mainnet.peers.is_empty()); // Should use DNS discovery

        let testnet = ClientConfig::testnet();
        assert_eq!(testnet.network, Network::Testnet);
        assert!(testnet.peers.is_empty()); // Should use DNS discovery

        let regtest = ClientConfig::regtest();
        assert_eq!(regtest.network, Network::Regtest);
        assert_eq!(regtest.peers.len(), 1);
        assert_eq!(regtest.peers[0].to_string(), "127.0.0.1:19899");
    }

    #[test]
    fn test_builder_pattern() {
        let path = PathBuf::from("/test/storage");
        let addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();

        let config = ClientConfig::mainnet()
            .with_storage_path(path.clone())
            .with_validation_mode(ValidationMode::CheckpointsOnly)
            .with_connection_timeout(Duration::from_secs(10))
            .with_read_timeout(Duration::from_secs(5))
            .with_log_level("debug")
            .with_max_concurrent_filter_requests(32)
            .with_filter_flow_control(false)
            .with_filter_request_delay(100)
            .with_mempool_tracking(MempoolStrategy::BloomFilter)
            .with_max_mempool_transactions(500)
            .with_mempool_timeout(7200)
            .with_recent_send_window(600)
            .with_mempool_persistence(true)
            .with_start_height(100000);

        assert_eq!(config.storage_path, Some(path));
        assert!(config.enable_persistence);
        assert_eq!(config.validation_mode, ValidationMode::CheckpointsOnly);
        assert_eq!(config.connection_timeout, Duration::from_secs(10));
        assert_eq!(config.read_timeout, Duration::from_secs(5));
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.max_concurrent_filter_requests, 32);
        assert!(!config.enable_filter_flow_control);
        assert_eq!(config.filter_request_delay_ms, 100);

        // Mempool settings
        assert!(config.enable_mempool_tracking);
        assert_eq!(config.mempool_strategy, MempoolStrategy::BloomFilter);
        assert_eq!(config.max_mempool_transactions, 500);
        assert_eq!(config.mempool_timeout_secs, 7200);
        assert_eq!(config.recent_send_window_secs, 600);
        assert!(config.persist_mempool);
        assert_eq!(config.start_from_height, Some(100000));
    }

    #[test]
    fn test_add_peer() {
        let mut config = ClientConfig::default();
        let addr1: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:9999".parse().unwrap();

        config.add_peer(addr1);
        config.add_peer(addr2);

        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0], addr1);
        assert_eq!(config.peers[1], addr2);
    }

    #[test]
    fn test_watch_items() {
        let mut config = ClientConfig::default();

        // Note: We need a valid address string for the network
        // Using a dummy P2PKH address format for testing
        let addr_str = "XeNTGz5bVjPNZVPpwTRz6SnLbZGxLqJUg4"; // Example Dash mainnet address
        if let Ok(address) = Address::from_str(addr_str) {
            config = config.watch_address(address.assume_checked());
            assert_eq!(config.watch_items.len(), 1);
        }

        let script = dashcore::ScriptBuf::new();
        config = config.watch_script(script);
        assert_eq!(config.watch_items.len(), 2);
    }

    #[test]
    fn test_disable_features() {
        let config = ClientConfig::default().without_filters().without_masternodes();

        assert!(!config.enable_filters);
        assert!(!config.enable_masternodes);
    }

    #[test]
    fn test_validation_valid_config() {
        let config = ClientConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_invalid_max_headers() {
        let mut config = ClientConfig::default();
        config.max_headers_per_message = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_headers_per_message must be > 0");
    }

    #[test]
    fn test_validation_invalid_filter_checkpoint_interval() {
        let mut config = ClientConfig::default();
        config.filter_checkpoint_interval = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "filter_checkpoint_interval must be > 0");
    }

    #[test]
    fn test_validation_invalid_max_peers() {
        let mut config = ClientConfig::default();
        config.max_peers = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_peers must be > 0");
    }

    #[test]
    fn test_validation_invalid_max_concurrent_filter_requests() {
        let mut config = ClientConfig::default();
        config.max_concurrent_filter_requests = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_concurrent_filter_requests must be > 0");
    }

    #[test]
    fn test_validation_invalid_mempool_config() {
        let mut config = ClientConfig::default();
        config.enable_mempool_tracking = true;
        config.max_mempool_transactions = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_mempool_transactions must be > 0"));
    }

    #[test]
    fn test_validation_invalid_mempool_timeout() {
        let mut config = ClientConfig::default();
        config.enable_mempool_tracking = true;
        config.mempool_timeout_secs = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "mempool_timeout_secs must be > 0");
    }

    #[test]
    fn test_validation_invalid_selective_strategy() {
        let mut config = ClientConfig::default();
        config.enable_mempool_tracking = true;
        config.mempool_strategy = MempoolStrategy::Selective;
        config.recent_send_window_secs = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "recent_send_window_secs must be > 0 for Selective strategy"
        );
    }

    #[test]
    fn test_cfheader_gap_settings() {
        let config = ClientConfig::default();

        assert!(config.enable_cfheader_gap_restart);
        assert_eq!(config.cfheader_gap_check_interval_secs, 15);
        assert_eq!(config.cfheader_gap_restart_cooldown_secs, 30);
        assert_eq!(config.max_cfheader_gap_restart_attempts, 5);
    }

    #[test]
    fn test_filter_gap_settings() {
        let config = ClientConfig::default();

        assert!(config.enable_filter_gap_restart);
        assert_eq!(config.filter_gap_check_interval_secs, 20);
        assert_eq!(config.min_filter_gap_size, 10);
        assert_eq!(config.filter_gap_restart_cooldown_secs, 30);
        assert_eq!(config.max_filter_gap_restart_attempts, 5);
        assert_eq!(config.max_filter_gap_sync_size, 50000);
    }

    #[test]
    fn test_request_control_defaults() {
        let config = ClientConfig::default();

        assert!(config.max_concurrent_headers_requests.is_none());
        assert!(config.max_concurrent_mnlist_requests.is_none());
        assert!(config.max_concurrent_cfheaders_requests.is_none());
        assert!(config.max_concurrent_block_requests.is_none());
        assert!(config.headers_request_rate_limit.is_none());
        assert!(config.mnlist_request_rate_limit.is_none());
        assert!(config.cfheaders_request_rate_limit.is_none());
        assert!(config.filters_request_rate_limit.is_none());
        assert!(config.blocks_request_rate_limit.is_none());
    }

    #[test]
    fn test_wallet_creation_time() {
        let mut config = ClientConfig::default();
        config.wallet_creation_time = Some(1234567890);

        assert_eq!(config.wallet_creation_time, Some(1234567890));
    }

    #[test]
    fn test_clone_config() {
        let original = ClientConfig::mainnet().with_max_peers(16).with_log_level("debug");

        let cloned = original.clone();

        assert_eq!(cloned.network, original.network);
        assert_eq!(cloned.max_peers, original.max_peers);
        assert_eq!(cloned.log_level, original.log_level);
    }
}
