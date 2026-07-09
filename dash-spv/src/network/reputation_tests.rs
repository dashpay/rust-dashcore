//! Unit tests for the peer behaviour multiplier.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::storage::{PersistentPeerStorage, PersistentStorage};
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    async fn multiplier(manager: &PeerReputationManager, peer: &SocketAddr) -> f32 {
        manager.hint(peer).await.unwrap().0
    }

    #[test]
    fn good_and_bad_actions_move_the_multiplier_within_bounds() {
        // Starts trusted.
        assert_eq!(ChangeReason::GoodResponse.apply(1.0), 1.0);
        // A bad action lowers it.
        let m = ChangeReason::Timeout.apply(1.0);
        assert!(m < 1.0 && m > 0.0);
        // Good actions raise it back, clamped at 1.
        assert_eq!(ChangeReason::GoodResponse.apply(0.98), 1.0);
        // It never goes below 0.
        assert_eq!(ChangeReason::HandshakeFailed.apply(0.1), 0.0);
    }

    #[test]
    fn security_violation_zeroes_the_multiplier() {
        assert_eq!(ChangeReason::InvalidData.apply(1.0), 0.0);
        assert!(ChangeReason::InvalidData.is_security_violation());
    }

    #[tokio::test]
    async fn penalize_accumulates_and_gates_usability() {
        let manager = PeerReputationManager::new();
        let peer = addr("127.0.0.1:8333");

        // Unknown peers are usable by default.
        assert!(manager.is_usable(&peer).await);

        manager.penalize(peer, ChangeReason::Timeout).await;
        assert!(multiplier(&manager, &peer).await < 1.0);
        assert!(manager.is_usable(&peer).await);

        manager.penalize(peer, ChangeReason::InvalidData).await;
        assert_eq!(multiplier(&manager, &peer).await, 0.0);
        assert!(!manager.is_usable(&peer).await);
    }

    #[tokio::test]
    async fn rank_orders_by_multiplier_then_latency_and_drops_zero() {
        let manager = PeerReputationManager::new();
        let best = addr("1.1.1.1:8333");
        let slower = addr("2.2.2.2:8333");
        let untrusted = addr("3.3.3.3:8333");

        manager.record(best, 1.0, Some(20)).await;
        manager.record(slower, 1.0, Some(200)).await;
        manager.record(untrusted, 0.0, Some(5)).await;

        let ranked = manager.rank(vec![slower, untrusted, best]).await;
        assert_eq!(ranked, vec![best, slower]);
    }

    #[tokio::test]
    async fn record_latency_preserves_multiplier() {
        let manager = PeerReputationManager::new();
        let peer = addr("10.0.0.1:8333");

        manager.penalize(peer, ChangeReason::Timeout).await;
        let m = multiplier(&manager, &peer).await;
        manager.record_latency(peer, 42).await;

        assert_eq!(multiplier(&manager, &peer).await, m);
        assert!(manager.is_measured(&peer).await);
        assert_eq!(manager.hint(&peer).await, Some((m, Some(42))));
    }

    #[tokio::test]
    async fn persistence_round_trips_multiplier_and_latency() {
        let manager = PeerReputationManager::new();
        let peer = addr("10.0.0.2:8333");
        manager.record(peer, 0.4, Some(120)).await;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = PersistentPeerStorage::open(temp_dir.path()).await.unwrap();
        manager.save_to_storage(&storage).await.unwrap();

        let loaded = PeerReputationManager::new();
        loaded.load_from_storage(&storage).await.unwrap();
        assert_eq!(loaded.hint(&peer).await, Some((0.4, Some(120))));
    }
}
