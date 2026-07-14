//! Unit tests for reputation system (in-module tests)

#[cfg(test)]
mod tests {
    use crate::storage::{PeerStorage, PersistentPeerStorage, PersistentStorage};

    use super::super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime};

    async fn score(manager: &PeerReputationManager, peer: &SocketAddr) -> i32 {
        manager.get_all_reputations().await.get(peer).map_or(0, |rep| rep.score)
    }

    #[tokio::test]
    async fn test_basic_reputation_operations() {
        let manager = PeerReputationManager::new();
        let peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        assert_eq!(score(&manager, &peer).await, 0);

        manager.update_reputation(peer, ChangeReason::HandshakeFailed).await;
        assert_eq!(score(&manager, &peer).await, 10);

        manager.update_reputation(peer, ChangeReason::ResponseDelivered).await;
        assert_eq!(score(&manager, &peer).await, 8);
    }

    #[tokio::test]
    async fn test_banning_mechanism() {
        let manager = PeerReputationManager::new();
        let peer: SocketAddr = "192.168.1.1:8333".parse().unwrap();

        // Banned on the 10th violation (10 * 10 = 100).
        for i in 0..10 {
            let banned = manager.update_reputation(peer, ChangeReason::HandshakeFailed).await;
            if i == 9 {
                assert!(banned);
            } else {
                assert!(!banned);
            }
        }

        assert!(manager.is_banned(&peer).await);
    }

    #[tokio::test]
    async fn test_reputation_persistence() {
        let manager = PeerReputationManager::new();
        let peer1: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let peer2: SocketAddr = "10.0.0.2:8333".parse().unwrap();

        manager.update_reputation(peer1, ChangeReason::ResponseDelivered).await;
        manager.update_reputation(peer1, ChangeReason::ResponseDelivered).await;
        manager.update_reputation(peer2, ChangeReason::InvalidTransactionInBlock).await;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let peer_storage = PersistentPeerStorage::open(temp_dir.path())
            .await
            .expect("Failed to open PersistentPeerStorage");
        manager.save_to_storage(&peer_storage).await.unwrap();

        let new_manager = PeerReputationManager::new();
        new_manager.load_from_storage(&peer_storage).await.unwrap();

        assert_eq!(score(&new_manager, &peer1).await, -4);
        assert_eq!(score(&new_manager, &peer2).await, 20);
    }

    #[tokio::test]
    async fn test_peer_selection() {
        let manager = PeerReputationManager::new();

        let good_peer = AddrV2Message::dummy(0, "1.1.1.1".parse().unwrap(), 8333);
        let neutral_peer = AddrV2Message::dummy(0, "2.2.2.2".parse().unwrap(), 8333);
        let bad_peer = AddrV2Message::dummy(0, "3.3.3.3".parse().unwrap(), 8333);

        manager
            .update_reputation(good_peer.socket_addr().unwrap(), ChangeReason::ResponseDelivered)
            .await;
        manager
            .update_reputation(
                bad_peer.socket_addr().unwrap(),
                ChangeReason::InvalidTransactionInBlock,
            )
            .await;

        let all_peers = vec![good_peer.clone(), neutral_peer.clone(), bad_peer.clone()];
        let selected = manager.select_best_peers(all_peers, 2).await;

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], good_peer.socket_addr().unwrap());
        assert_eq!(selected[1], neutral_peer.socket_addr().unwrap());
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let manager = PeerReputationManager::new();
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Track connection attempts
        manager.record_connection_attempt(peer).await;
        manager.record_connection_attempt(peer).await;
        manager.record_successful_connection(peer).await;

        let reputations = manager.get_all_reputations().await;
        let rep = &reputations[&peer];

        assert_eq!(rep.connection_attempts, 2);
        assert_eq!(rep.successful_connections, 1);
    }

    #[tokio::test]
    async fn test_request_timeout_penalty_and_ban() {
        let manager = PeerReputationManager::new();
        let peer: SocketAddr = "127.0.0.1:7777".parse().unwrap();

        // Ten stalls (10 * 10) reach the ban line; only the tenth bans.
        for i in 0..10 {
            let banned = manager.update_reputation(peer, ChangeReason::RequestTimeout).await;
            assert_eq!(banned, i == 9);
        }
        assert_eq!(score(&manager, &peer).await, 100);
        assert!(manager.is_banned(&peer).await);
    }

    #[tokio::test]
    async fn test_scores_for_returns_scores_and_defaults() {
        let manager = PeerReputationManager::new();
        let good: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let bad: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let unknown: SocketAddr = "127.0.0.1:3".parse().unwrap();

        manager.update_reputation(good, ChangeReason::ResponseDelivered).await;
        manager.update_reputation(bad, ChangeReason::InvalidTransactionInBlock).await;

        let scores = manager.scores_for([good, bad, unknown]).await;
        assert_eq!(scores.get(&good), Some(&-2));
        assert_eq!(scores.get(&bad), Some(&20));
        assert_eq!(scores.get(&unknown), Some(&0));
    }

    #[tokio::test]
    async fn test_load_clamps_score_and_credits_offline_decay() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = PersistentPeerStorage::open(temp_dir.path()).await.unwrap();

        // Persisted near the ban line but seen recently: clamps to the restart ceiling.
        let near_ban: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        // Persisted mid-score but offline ~2 hours: decays by two intervals on load.
        let offline: SocketAddr = "10.0.0.2:8333".parse().unwrap();

        let mut map: HashMap<SocketAddr, PeerReputation> = HashMap::new();
        map.insert(
            near_ban,
            PeerReputation {
                score: 95,
                last_seen: SystemTime::now(),
                ..Default::default()
            },
        );
        map.insert(
            offline,
            PeerReputation {
                score: 30,
                last_seen: SystemTime::now() - Duration::from_secs(2 * 60 * 60 + 60),
                ..Default::default()
            },
        );
        storage.save_peers_reputation(&map).await.unwrap();

        let manager = PeerReputationManager::new();
        manager.load_from_storage(&storage).await.unwrap();

        // Clamped to RESTART_SCORE_CEILING, so one post-restart penalty cannot ban it.
        assert_eq!(score(&manager, &near_ban).await, 40);
        // 30 - 2 intervals * 5 decay.
        assert_eq!(score(&manager, &offline).await, 20);
    }
}
