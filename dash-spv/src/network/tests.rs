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
        let peer = Peer::new(addr, timeout, Network::Dash);

        assert!(!peer.is_connected());
        assert_eq!(peer.address(), addr);
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

        // Can accept up to TARGET_PEERS
        assert!(pool.can_accept_peers().await);

        // Test peer count
        assert_eq!(pool.peer_count().await, 0);

        // Verify pool limits indirectly through methods; avoid constant assertions
    }
}

#[cfg(test)]
mod request_sender_tests {
    use crate::network::{NetworkRequest, RequestSender};
    use dashcore::network::message::NetworkMessage;
    use tokio::sync::mpsc;

    #[test]
    fn test_send_message_to_peer_queues_correct_variant() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sender = RequestSender::new(tx);
        let addr = "192.168.1.1:9999".parse().unwrap();
        let msg = NetworkMessage::Verack;

        sender.send_message_to_peer(addr, msg).unwrap();

        let request = rx.try_recv().unwrap();
        let NetworkRequest::SendMessageToPeer(recv_addr, recv_msg) = request else {
            panic!("Expected SendMessageToPeer variant");
        };
        assert_eq!(recv_addr, addr);
        assert!(matches!(recv_msg, NetworkMessage::Verack));
    }

    #[test]
    fn test_send_message_to_peer_returns_error_on_closed_channel() {
        let (tx, rx) = mpsc::unbounded_channel();
        let sender = RequestSender::new(tx);
        drop(rx);

        let addr = "192.168.1.1:9999".parse().unwrap();
        let result = sender.send_message_to_peer(addr, NetworkMessage::Verack);
        assert!(result.is_err());
    }
}
