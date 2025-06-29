//! Unit tests for network module

#[cfg(test)]
mod multi_peer_tests {
    use crate::client::ClientConfig;
    use crate::network::multi_peer::MultiPeerNetworkManager;
    use crate::network::NetworkManager;
    use dashcore::Network;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_config() -> ClientConfig {
        let temp_dir = TempDir::new().unwrap();
        ClientConfig {
            network: Network::Regtest,
            peers: vec!["127.0.0.1:19899".parse().unwrap()],
            storage_path: Some(temp_dir.path().to_path_buf()),
            validation_mode: crate::types::ValidationMode::Basic,
            filter_checkpoint_interval: 1000,
            max_headers_per_message: 2000,
            connection_timeout: Duration::from_secs(5),
            message_timeout: Duration::from_secs(30),
            sync_timeout: Duration::from_secs(60),
            read_timeout: Duration::from_millis(15),
            watch_items: vec![],
            enable_filters: false,
            enable_masternodes: false,
            max_peers: 3,
            enable_persistence: false,
            log_level: "info".to_string(),
            enable_filter_flow_control: true,
            filter_request_delay_ms: 0,
            max_concurrent_filter_requests: 50,
            enable_cfheader_gap_restart: true,
            cfheader_gap_check_interval_secs: 15,
            cfheader_gap_restart_cooldown_secs: 30,
            max_cfheader_gap_restart_attempts: 5,
            enable_filter_gap_restart: true,
            filter_gap_check_interval_secs: 20,
            min_filter_gap_size: 10,
            filter_gap_restart_cooldown_secs: 30,
            max_filter_gap_restart_attempts: 5,
            max_filter_gap_sync_size: 50000,
            // Mempool fields
            enable_mempool_tracking: false,
            mempool_strategy: crate::client::config::MempoolStrategy::Selective,
            max_mempool_transactions: 1000,
            mempool_timeout_secs: 3600,
            recent_send_window_secs: 300,
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
        }
    }

    #[tokio::test]
    async fn test_multi_peer_manager_creation() {
        let config = create_test_config();
        let manager = MultiPeerNetworkManager::new(&config).await.unwrap();

        // Should start with zero peers
        assert_eq!(manager.peer_count_async().await, 0);
        // Note: is_connected() still uses sync approach, so we'll check async
        assert_eq!(manager.peer_count_async().await, 0);
    }

    #[tokio::test]
    async fn test_as_any_downcast() {
        let config = create_test_config();
        let manager = MultiPeerNetworkManager::new(&config).await.unwrap();

        // Test that we can downcast through the trait
        let network_manager: &dyn NetworkManager = &manager;
        let downcasted = network_manager.as_any().downcast_ref::<MultiPeerNetworkManager>();

        assert!(downcasted.is_some());
    }
}

#[cfg(test)]
mod tcp_network_manager_tests {
    use crate::client::ClientConfig;
    use crate::network::{NetworkManager, TcpNetworkManager};

    #[tokio::test]
    async fn test_dsq_preference_storage() {
        let config = ClientConfig::default();
        let mut network_manager = TcpNetworkManager::new(&config).await.unwrap();
        
        // Initial state should be false
        assert_eq!(network_manager.get_dsq_preference(), false);
        
        // Update to true
        network_manager.update_peer_dsq_preference(true).await.unwrap();
        assert_eq!(network_manager.get_dsq_preference(), true);
        
        // Update back to false
        network_manager.update_peer_dsq_preference(false).await.unwrap();
        assert_eq!(network_manager.get_dsq_preference(), false);
    }
}

#[cfg(test)]
mod connection_tests {
    use crate::network::connection::TcpConnection;
    use dashcore::Network;
    use std::time::Duration;

    #[test]
    fn test_tcp_connection_creation() {
        let addr = "127.0.0.1:9999".parse().unwrap();
        let timeout = Duration::from_secs(30);
        let conn = TcpConnection::new(addr, timeout, Network::Dash);

        assert!(!conn.is_connected());
        assert_eq!(conn.peer_info().address, addr);
    }
}

#[cfg(test)]
mod pool_tests {
    use crate::network::constants::{MAX_PEERS, MIN_PEERS};
    use crate::network::pool::ConnectionPool;

    #[tokio::test]
    async fn test_pool_limits() {
        let pool = ConnectionPool::new();

        // Test needs_more_connections logic
        assert!(pool.needs_more_connections().await);

        // Can accept up to MAX_PEERS
        assert!(pool.can_accept_connections().await);

        // Test connection count
        assert_eq!(pool.connection_count().await, 0);

        // Verify constants
        assert!(MIN_PEERS < MAX_PEERS);
        assert!(MIN_PEERS > 0);
    }
}
