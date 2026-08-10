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
    use crate::network::manager::{
        PeerNetworkManager, REQUEST_OWED_TIMEOUT, REQUEST_STALL_TIMEOUT,
    };
    use crate::network::reputation::ChangeReason;
    use crate::test_utils::test_socket_address;
    use dashcore::blockdata::block::{Block, Header, Version};
    use dashcore::network::constants::ServiceFlags;
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_blockdata::Inventory;
    use dashcore::network::message_filter::{CFilter, GetCFHeaders, GetCFilters};
    use dashcore::{BlockHash, CompactTarget, TxMerkleNode, Txid};
    use dashcore_hashes::Hash;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn get_filter_headers() -> NetworkMessage {
        NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: BlockHash::all_zeros(),
        })
    }

    fn get_filters() -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: BlockHash::all_zeros(),
        })
    }

    fn filter_response() -> NetworkMessage {
        NetworkMessage::CFilter(CFilter {
            filter_type: 0,
            block_hash: BlockHash::all_zeros(),
            filter: vec![],
        })
    }

    fn get_blocks() -> NetworkMessage {
        NetworkMessage::GetData(vec![Inventory::Block(BlockHash::all_zeros())])
    }

    fn get_transactions() -> NetworkMessage {
        NetworkMessage::GetData(vec![Inventory::Transaction(Txid::all_zeros())])
    }

    fn block_response() -> NetworkMessage {
        NetworkMessage::Block(Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![],
        })
    }

    async fn full_pool_with_bad_peer(bad: u8) -> (PeerNetworkManager, std::net::SocketAddr) {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        for i in 1u8..=8 {
            manager.insert_test_peer(test_socket_address(i), cf).await;
        }
        let bad_addr = test_socket_address(bad);
        // Two consecutive stalls reach the eviction threshold.
        manager.test_update_reputation(bad_addr, ChangeReason::RequestTimeout).await;
        manager.test_update_reputation(bad_addr, ChangeReason::RequestTimeout).await;
        (manager, bad_addr)
    }

    /// A peer that is fast at one request kind must not be able to hide being slow
    /// at another.
    ///
    /// Seen on mainnet: a peer averaging 11.9s on filter headers, with a 32s p90,
    /// measured as 52ms and took 40% of the traffic with zero stall penalties. Its
    /// quick `cfilter` responses kept clearing the timer its slow `getcfheaders`
    /// had armed, so the slow response found nothing to clear and was never
    /// recorded, and the sweep never saw an aged entry. Only 255 of 1050 filter
    /// header timers were cleared by an actual `cfheaders` response.
    #[tokio::test(start_paused = true)]
    async fn test_fast_response_does_not_clear_another_kinds_timer() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let peer = test_socket_address(1);
        manager.insert_test_peer(peer, cf).await;

        // The peer owes us both a filter-header and a filter response.
        manager.test_arm_request(peer, &get_filter_headers()).await;
        manager.test_arm_request(peer, &get_filters()).await;

        // It answers the filter promptly. That must not count as answering the
        // filter headers, which it is still sitting on.
        tokio::time::advance(Duration::from_millis(50)).await;
        manager.test_deliver_response(peer, &filter_response()).await;

        // Past the stall timeout with the filter headers still unanswered.
        tokio::time::advance(REQUEST_STALL_TIMEOUT + Duration::from_secs(1)).await;
        manager.test_sweep_stalled_peers().await;

        assert_eq!(
            manager.test_score(peer).await,
            ChangeReason::RequestTimeout.score(),
            "the unanswered filter-header request must still be caught as a stall"
        );
    }

    /// A peer stalling on several request kinds at once is one failing peer, not
    /// several, so a single sweep must not stack strikes and evict it outright.
    #[tokio::test(start_paused = true)]
    async fn test_stalling_on_two_kinds_is_one_strike_per_sweep() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let peer = test_socket_address(1);
        manager.insert_test_peer(peer, cf).await;

        manager.test_arm_request(peer, &get_filter_headers()).await;
        manager.test_arm_request(peer, &get_filters()).await;

        tokio::time::advance(REQUEST_STALL_TIMEOUT + Duration::from_secs(1)).await;
        manager.test_sweep_stalled_peers().await;

        assert_eq!(
            manager.test_score(peer).await,
            ChangeReason::RequestTimeout.score(),
            "two stalled kinds are still one failing peer, so one strike"
        );
    }

    #[tokio::test]
    async fn test_next_peer_excludes_slow_peer() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let good1 = test_socket_address(1);
        let good2 = test_socket_address(2);
        let slow = test_socket_address(3);
        for addr in [good1, good2, slow] {
            manager.insert_test_peer(addr, cf).await;
        }

        manager.test_record_latency(good1, Duration::from_millis(40)).await;
        manager.test_record_latency(good2, Duration::from_millis(60)).await;
        manager.test_record_latency(slow, Duration::from_secs(10)).await;

        let mut seen_good1 = false;
        let mut seen_good2 = false;
        for _ in 0..20 {
            let picked = manager.test_next_peer().await;
            assert_ne!(picked, slow, "a peer that has stopped answering must not be routed to");
            seen_good1 |= picked == good1;
            seen_good2 |= picked == good2;
        }
        assert!(seen_good1 && seen_good2, "load should spread across the responsive peers");
    }

    /// The failure this guards against was seen on mainnet: one peer answered a
    /// few requests before the others had answered any, that head start was enough
    /// to rank it alone at the top, and from then on it took every request while
    /// the peers it starved got none and so could never earn their way back. Here
    /// the same head start must not stop the pool sharing the work.
    #[tokio::test]
    async fn test_next_peer_keeps_spreading_after_one_peer_gets_a_head_start() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let peers = [test_socket_address(1), test_socket_address(2), test_socket_address(3)];
        for addr in peers {
            manager.insert_test_peer(addr, cf).await;
        }

        // The head start: the first peer is measured, and fast, before the rest
        // have answered anything at all.
        for _ in 0..3 {
            manager.test_record_latency(peers[0], Duration::from_millis(20)).await;
        }

        let mut picks: HashMap<SocketAddr, u32> = HashMap::new();
        for _ in 0..300 {
            let picked = manager.test_next_peer().await;
            *picks.entry(picked).or_default() += 1;
            manager.test_record_latency(picked, Duration::from_millis(50)).await;
        }

        for addr in peers {
            assert_eq!(
                picks.get(&addr).copied().unwrap_or(0),
                100,
                "every peer should keep an equal share, got {picks:?}"
            );
        }
    }

    /// A peer sitting on a block request must not be handed the retry of that
    /// same request.
    ///
    /// Seen on mainnet: one of three peers silently dropped every `getdata` it
    /// received. Latency only ever records a response, so a peer answering
    /// nothing was never measured and kept its turn in the rotation, which it
    /// then used to win the retry of the request it had just dropped. Filter sync
    /// commits behind the missing block, so the client spent 66% of a 16 minute
    /// run frozen, in stalls of exactly one, two and four block timeouts.
    #[tokio::test(start_paused = true)]
    async fn test_peer_owing_a_block_is_skipped_until_it_answers() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let silent = test_socket_address(1);
        let good = test_socket_address(2);
        for addr in [silent, good] {
            manager.insert_test_peer(addr, cf).await;
        }

        manager.test_arm_request(silent, &get_blocks()).await;
        tokio::time::advance(REQUEST_OWED_TIMEOUT + Duration::from_secs(1)).await;

        for _ in 0..10 {
            assert_eq!(
                manager.test_route(&get_blocks()).await,
                good,
                "a peer already sitting on a block request must not be sent another"
            );
        }

        // Answering clears the debt, and the peer is a candidate again.
        manager.test_deliver_response(silent, &block_response()).await;
        let mut picks: HashMap<SocketAddr, u32> = HashMap::new();
        for _ in 0..10 {
            *picks.entry(manager.test_route(&get_blocks()).await).or_default() += 1;
        }
        assert!(picks.contains_key(&silent), "a peer that answered must be routed to again");
    }

    /// The skip is a preference, not a rule: with every peer owing a response,
    /// refusing to send is worse than sending to a busy peer.
    #[tokio::test(start_paused = true)]
    async fn test_routing_falls_back_when_every_peer_owes_a_block() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let peers = [test_socket_address(1), test_socket_address(2)];
        for addr in peers {
            manager.insert_test_peer(addr, cf).await;
            manager.test_arm_request(addr, &get_blocks()).await;
        }
        tokio::time::advance(REQUEST_OWED_TIMEOUT + Duration::from_secs(1)).await;

        assert!(peers.contains(&manager.test_route(&get_blocks()).await));
    }

    /// Blocks are routed away from, never penalized for. A block body can be
    /// megabytes and a peer sends nothing until the transfer completes, so a slow
    /// link is indistinguishable from a peer ignoring us and must not cost
    /// reputation or trigger eviction.
    #[tokio::test(start_paused = true)]
    async fn test_unanswered_block_request_does_not_penalize_the_peer() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        let peer = test_socket_address(1);
        manager.insert_test_peer(peer, cf).await;

        manager.test_arm_request(peer, &get_blocks()).await;
        tokio::time::advance(REQUEST_STALL_TIMEOUT + Duration::from_secs(1)).await;
        manager.test_sweep_stalled_peers().await;

        assert_eq!(
            manager.test_score(peer).await,
            0,
            "a slow block transfer must not be scored as a stall"
        );
    }

    /// The mempool asks for transactions with the same `getdata` message blocks
    /// use, and a `block` response would never arrive to clear that timer. Timing
    /// it would leave a peer permanently owing a response it was never asked for.
    #[tokio::test(start_paused = true)]
    async fn test_transaction_getdata_does_not_arm_the_block_timer() {
        let cf = ServiceFlags::COMPACT_FILTERS;
        let manager = PeerNetworkManager::new_for_test(cf).await;
        // Only one peer is sent the tx request, so a wrongly armed block timer
        // shows up as that peer being skipped rather than being hidden by the
        // all-peers-owing fallback.
        let mempool_peer = test_socket_address(1);
        let idle_peer = test_socket_address(2);
        for addr in [mempool_peer, idle_peer] {
            manager.insert_test_peer(addr, cf).await;
        }
        manager.test_arm_request(mempool_peer, &get_transactions()).await;
        tokio::time::advance(REQUEST_OWED_TIMEOUT + Duration::from_secs(1)).await;

        let mut picks: HashMap<SocketAddr, u32> = HashMap::new();
        for _ in 0..20 {
            *picks.entry(manager.test_route(&get_blocks()).await).or_default() += 1;
        }
        assert!(
            picks.contains_key(&mempool_peer),
            "a pending tx request must not make a peer look like it owes a block, got {picks:?}"
        );
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
