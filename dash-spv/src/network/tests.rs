//! Unit tests for network module

#[cfg(test)]
mod peer_network_manager_tests {
    use crate::client::ClientConfig;
    use crate::network::manager::PeerNetworkManager;
    use crate::network::NetworkManager;
    use dashcore::Network;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_config() -> ClientConfig {
        let temp_dir = TempDir::new().unwrap();
        ClientConfig {
            network: Network::Regtest,
            peers: vec!["127.0.0.1:19899".parse().unwrap()],
            restrict_to_configured_peers: false,
            storage_path: Some(temp_dir.path().to_path_buf()),
            validation_mode: crate::types::ValidationMode::Basic,
            filter_checkpoint_interval: 1000,
            max_headers_per_message: 2000,
            connection_timeout: Duration::from_secs(5),
            message_timeout: Duration::from_secs(30),
            sync_timeout: Duration::from_secs(60),
            enable_filters: false,
            enable_masternodes: false,
            max_peers: 3,
            enable_persistence: false,
            log_level: "info".to_string(),
            filter_request_delay_ms: 0,
            max_concurrent_filter_requests: 50,
            max_concurrent_cfheaders_requests_parallel: 50,
            cfheaders_request_timeout_secs: 30,
            max_cfheaders_retries: 3,
            // Mempool fields
            enable_mempool_tracking: false,
            mempool_strategy: crate::client::config::MempoolStrategy::BloomFilter,
            max_mempool_transactions: 1000,
            mempool_timeout_secs: 3600,
            fetch_mempool_transactions: true,
            persist_mempool: false,
            // Request control fields
            max_concurrent_headers_requests: None,
            max_concurrent_mnlist_requests: None,
            max_concurrent_cfheaders_requests: None,
            max_concurrent_block_requests: None,
            headers_request_rate_limit: None,
            mnlist_request_rate_limit: None,
            cfheaders_request_rate_limit: None,
            filters_request_rate_limit: None,
            blocks_request_rate_limit: None,
            start_from_height: None,
            wallet_creation_time: None,
            // QRInfo fields
            qr_info_extra_share: true,
            qr_info_timeout: Duration::from_secs(30),
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn test_as_any_downcast() {
        let config = create_test_config();
        let manager = PeerNetworkManager::new(&config).await.unwrap();

        // Test that we can downcast through the trait
        let network_manager: &dyn NetworkManager = &manager;
        let downcasted = network_manager.as_any().downcast_ref::<PeerNetworkManager>();

        assert!(downcasted.is_some());
    }
}

#[cfg(test)]
mod peer_tests {
    use crate::network::peer::Peer;
    use dashcore::Network;
    use std::time::Duration;

    #[test]
    fn test_peer_creation() {
        let addr = "127.0.0.1:9999".parse().unwrap();
        let timeout = Duration::from_secs(30);
        let peer = Peer::new(addr, timeout, Network::Dash);

        assert!(!peer.is_connected());
        assert_eq!(peer.peer_info().address, addr);
    }
}

#[cfg(test)]
mod pool_tests {
    use crate::network::pool::PeerPool;

    #[tokio::test]
    async fn test_pool_limits() {
        let pool = PeerPool::new();

        // Test needs_more_peers logic
        assert!(pool.needs_more_peers().await);

        // Can accept up to MAX_PEERS
        assert!(pool.can_accept_peers().await);

        // Test peer count
        assert_eq!(pool.peer_count().await, 0);

        // Verify pool limits indirectly through methods; avoid constant assertions
    }
}
