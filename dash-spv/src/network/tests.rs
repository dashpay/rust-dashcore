//! Unit tests for network module

#[cfg(test)]
mod peer_tests {
    use crate::network::peer::Peer;
    use dashcore::Network;
    use std::time::Duration;

    #[test]
    fn test_peer_creation() {
        let addr = "127.0.0.1:9999".parse().unwrap();
        let timeout = Duration::from_secs(30);
        let peer = Peer::new(addr, timeout, Network::Mainnet);

        assert!(!peer.is_connected());
        assert_eq!(peer.address(), addr);
    }
}

#[cfg(test)]
mod pool_tests {
    use crate::network::manager::PeerNetworkManager;
    use crate::network::pool::PeerPool;
    use crate::test_utils::test_socket_address;
    use dashcore::network::constants::ServiceFlags;

    #[tokio::test]
    async fn test_pool_limits() {
        let pool = PeerPool::new();

        // Test needs_more_peers logic
        assert!(pool.needs_more_peers().await);

        // Can accept up to TARGET_PEERS
        assert!(pool.can_accept_peers().await);

        // Test peer count
        assert_eq!(pool.peer_count().await, 0);
    }

    // Cases are sequential in one test to avoid concurrent DnsDiscovery drops (TSAN race in hickory-resolver).
    #[tokio::test]
    async fn test_evict_mismatched_peers() {
        let cf = ServiceFlags::COMPACT_FILTERS;

        // Healthy pool: all peers match, nothing evicted
        let manager = PeerNetworkManager::new_for_test(cf).await;
        manager.insert_test_peer(test_socket_address(1), cf).await;
        manager.insert_test_peer(test_socket_address(2), cf).await;
        manager.insert_test_peer(test_socket_address(3), cf).await;
        manager.evict_mismatched_peers().await;
        assert_eq!(manager.test_peer_count().await, 3);

        // Lone mismatched peer is preserved (never drop to zero)
        let manager = PeerNetworkManager::new_for_test(cf).await;
        manager.insert_test_peer(test_socket_address(1), ServiceFlags::NETWORK).await;
        manager.evict_mismatched_peers().await;
        assert_eq!(manager.test_peer_count().await, 1);

        // All peers lack service: tick 1 drops all but 1, tick 2 preserves the lone peer
        let manager = PeerNetworkManager::new_for_test(cf).await;
        manager.insert_test_peer(test_socket_address(1), ServiceFlags::NETWORK).await;
        manager.insert_test_peer(test_socket_address(2), ServiceFlags::NETWORK).await;
        manager.insert_test_peer(test_socket_address(3), ServiceFlags::NETWORK).await;
        manager.evict_mismatched_peers().await;
        assert_eq!(manager.test_peer_count().await, 1);
        manager.evict_mismatched_peers().await;
        assert_eq!(manager.test_peer_count().await, 1);

        // Mixed pool: only mismatched peers are dropped, matching peers survive
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let p1 = test_socket_address(1);
        let p2 = test_socket_address(2);
        let p3 = test_socket_address(3);
        let p4 = test_socket_address(4);
        manager.insert_test_peer(p1, cf).await;
        manager.insert_test_peer(p2, cf).await;
        manager.insert_test_peer(p3, ServiceFlags::NETWORK).await;
        manager.insert_test_peer(p4, ServiceFlags::NETWORK).await;
        manager.evict_mismatched_peers().await;
        assert_eq!(manager.test_peer_count().await, 2);
        assert!(manager.test_is_connected(&p1).await);
        assert!(manager.test_is_connected(&p2).await);
        assert!(!manager.test_is_connected(&p3).await);
        assert!(!manager.test_is_connected(&p4).await);
    }
}
