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
    use crate::network::peer::Peer;
    use crate::network::pool::PeerPool;
    use crate::test_utils::test_socket_address;
    use dashcore::network::constants::ServiceFlags;
    use dashcore::Network;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_pool_limits() {
        let pool = PeerPool::new(8);

        // Test needs_more_peers logic
        assert!(pool.needs_more_peers().await);

        // Can accept up to 8 peers
        assert!(pool.can_accept_peers().await);

        // Test peer count
        assert_eq!(pool.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_capability_policy_for_handshake_and_eviction() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let mut incapable =
            Peer::new(test_socket_address(9), Duration::from_secs(10), Network::Testnet);
        incapable.set_services(ServiceFlags::NETWORK);

        // Handshake admission: keep fallback when no capable peer exists yet.
        let manager = PeerNetworkManager::new_for_test(cf).await;
        assert!(!manager.test_has_capable_peer().await);
        assert!(!manager.test_should_reject_after_handshake(&incapable).await);

        // Handshake admission: reject incapable peers once a capable peer exists.
        let manager = PeerNetworkManager::new_for_test(cf).await;
        manager.insert_test_peer(test_socket_address(1), cf).await;
        assert!(manager.test_has_capable_peer().await);
        assert!(manager.test_should_reject_after_handshake(&incapable).await);

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

    #[tokio::test(start_paused = true)]
    async fn test_capability_rejection_cache_expires() {
        let manager = PeerNetworkManager::new_for_test(ServiceFlags::COMPACT_FILTERS).await;
        let fresh = test_socket_address(42);
        let expired = test_socket_address(43);

        manager.insert_test_capability_rejected(expired).await;
        tokio::time::advance(Duration::from_secs(31 * 60)).await;
        manager.insert_test_capability_rejected(fresh).await;

        assert!(manager.test_is_capability_rejected(&fresh).await);
        assert!(!manager.test_is_capability_rejected(&expired).await);

        assert_eq!(manager.test_capability_rejected_count().await, 1);
    }
}

#[cfg(test)]
mod selection_tests {
    use crate::network::manager::PeerNetworkManager;
    use crate::network::reputation::ChangeReason;
    use crate::test_utils::test_socket_address;
    use dashcore::network::constants::ServiceFlags;

    async fn full_pool_with_bad_peer(bad: u8) -> (PeerNetworkManager, std::net::SocketAddr) {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        for i in 1u8..=8 {
            manager.insert_test_peer(test_socket_address(i), cf).await;
        }
        let bad_addr = test_socket_address(bad);
        // Two stalls put the peer past the eviction threshold.
        manager.test_update_reputation(bad_addr, ChangeReason::RequestTimeout).await;
        manager.test_update_reputation(bad_addr, ChangeReason::RequestTimeout).await;
        (manager, bad_addr)
    }

    #[tokio::test]
    async fn test_next_peer_excludes_low_scoring_peer() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let good1 = test_socket_address(1);
        let good2 = test_socket_address(2);
        let bad = test_socket_address(3);
        manager.insert_test_peer(good1, cf).await;
        manager.insert_test_peer(good2, cf).await;
        manager.insert_test_peer(bad, cf).await;

        // Push the bad peer well outside the good band.
        manager.test_update_reputation(bad, ChangeReason::InvalidTransactionInBlock).await;

        let mut seen_good1 = false;
        let mut seen_good2 = false;
        for _ in 0..20 {
            let picked = manager.test_next_peer().await;
            assert_ne!(picked, bad, "a low-scoring peer must not be routed to");
            seen_good1 |= picked == good1;
            seen_good2 |= picked == good2;
        }
        assert!(seen_good1 && seen_good2, "load should spread across the good band");
    }

    #[tokio::test]
    async fn test_evict_worst_stuck_peer_removes_the_stalling_peer() {
        let (manager, bad) = full_pool_with_bad_peer(3).await;
        // A replacement must be available or eviction is a no-op.
        manager.test_add_known_address(test_socket_address(99)).await;

        manager.test_evict_worst_stuck_peer().await;

        assert!(!manager.test_is_connected(&bad).await, "stalling peer should be evicted");
        assert_eq!(manager.test_peer_count().await, 7);
    }

    #[tokio::test]
    async fn test_evict_worst_stuck_peer_skips_without_replacement() {
        let (manager, _bad) = full_pool_with_bad_peer(3).await;
        // No known addresses -> no replacement candidate -> no eviction.
        manager.test_evict_worst_stuck_peer().await;
        assert_eq!(manager.test_peer_count().await, 8);
    }

    #[tokio::test]
    async fn test_evict_worst_stuck_peer_skips_when_all_peers_bad() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        for i in 1u8..=8 {
            let addr = test_socket_address(i);
            manager.insert_test_peer(addr, cf).await;
            manager.test_update_reputation(addr, ChangeReason::RequestTimeout).await;
            manager.test_update_reputation(addr, ChangeReason::RequestTimeout).await;
        }
        manager.test_add_known_address(test_socket_address(99)).await;

        manager.test_evict_worst_stuck_peer().await;

        // Every peer is equally bad, so the problem is systemic: evict none.
        assert_eq!(manager.test_peer_count().await, 8);
    }

    #[tokio::test]
    async fn test_evict_worst_stuck_peer_skips_when_pool_not_full() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        for i in 1u8..=3 {
            manager.insert_test_peer(test_socket_address(i), cf).await;
        }
        let bad = test_socket_address(2);
        manager.test_update_reputation(bad, ChangeReason::RequestTimeout).await;
        manager.test_update_reputation(bad, ChangeReason::RequestTimeout).await;
        manager.test_add_known_address(test_socket_address(99)).await;

        manager.test_evict_worst_stuck_peer().await;

        // Pool is below max_peers, so eviction would be pure loss: skip.
        assert_eq!(manager.test_peer_count().await, 3);
    }
}
