//! Unit tests for reputation system (in-module tests)

#[cfg(test)]
mod tests {
    use crate::storage::PersistentStorage;

    use super::super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_basic_reputation_operations() {
        let manager = PeerReputationManager::new();
        let peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        // Initial score should be 0
        assert_eq!(manager.get_score(&peer).await, 0);

        // Test misbehavior
        manager
            .update_reputation(peer, misbehavior_scores::INVALID_MESSAGE, "Test invalid message")
            .await;
        assert_eq!(manager.get_score(&peer).await, 10);

        // Test positive behavior
        manager.update_reputation(peer, positive_scores::VALID_HEADERS, "Test valid headers").await;
        assert_eq!(manager.get_score(&peer).await, 5);
    }

    #[tokio::test]
    async fn test_banning_mechanism() {
        let manager = PeerReputationManager::new();
        let peer: SocketAddr = "192.168.1.1:8333".parse().unwrap();

        // Accumulate misbehavior
        for i in 0..10 {
            let banned = manager
                .update_reputation(
                    peer,
                    misbehavior_scores::INVALID_MESSAGE,
                    &format!("Violation {}", i),
                )
                .await;

            // Should be banned on the 10th violation (total score = 100)
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

        // Set reputations
        manager.update_reputation(peer1, -10, "Good peer").await;
        manager.update_reputation(peer2, 50, "Bad peer").await;

        // Save and load
        let temp_dir = tempfile::TempDir::new().unwrap();
        let peer_storage = PersistentPeerStorage::open(temp_dir.path())
            .await
            .expect("Failed to open PersistentPeerStorage");
        manager.save_to_storage(&peer_storage).await.unwrap();

        let new_manager = PeerReputationManager::new();
        new_manager.load_from_storage(&peer_storage).await.unwrap();

        // Verify scores were preserved
        assert_eq!(new_manager.get_score(&peer1).await, -10);
        assert_eq!(new_manager.get_score(&peer2).await, 50);
    }

    #[tokio::test]
    async fn test_peer_selection() {
        let manager = PeerReputationManager::new();

        let good_peer: SocketAddr = "1.1.1.1:8333".parse().unwrap();
        let neutral_peer: SocketAddr = "2.2.2.2:8333".parse().unwrap();
        let bad_peer: SocketAddr = "3.3.3.3:8333".parse().unwrap();

        // Set different reputations
        manager.update_reputation(good_peer, -20, "Very good").await;
        manager.update_reputation(bad_peer, 80, "Very bad").await;
        // neutral_peer has default score of 0

        let all_peers = vec![good_peer, neutral_peer, bad_peer];
        let selected = manager.select_best_peers(all_peers, 2).await;

        // Should select good_peer first, then neutral_peer
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], good_peer);
        assert_eq!(selected[1], neutral_peer);
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
}
