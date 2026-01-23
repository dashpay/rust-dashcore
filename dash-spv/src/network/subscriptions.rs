//! Message subscription and routing for network communication.
//!
//! This module implements a publish-subscribe pattern for filtering and
//! distributing network messages to interested components:
//!
//! - [`Message`]: Wraps a `NetworkMessage` with the originating peer ID
//! - [`MessageSubscriber`]: Filters messages by type and forwards to a channel
//! - [`MessageRouter`]: Manages subscribers and routes messages to interested parties

use crate::network::MessageType;
use dashcore::network::message::NetworkMessage;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

/// A network message tagged with the peer that sent it.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    peer_address: SocketAddr,
    inner: NetworkMessage,
}

impl Message {
    /// Creates a new Message from a peer ID and network message.
    pub fn new(peer_address: SocketAddr, inner: NetworkMessage) -> Self {
        Self {
            peer_address,
            inner,
        }
    }

    /// Forwarding the cmd() of the underlying NetworkMessage
    pub fn cmd(&self) -> &'static str {
        self.inner.cmd()
    }

    /// Returns the SocketAddr of the peer that sent this message.
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    /// Returns a reference to the underlying network message.
    pub fn inner(&self) -> &NetworkMessage {
        &self.inner
    }
}

/// A subscriber that receives messages matching specific types.
#[derive(Debug)]
pub struct MessageSubscriber {
    pub types: Vec<MessageType>,
    pub sender: mpsc::UnboundedSender<Message>,
}

impl MessageSubscriber {
    pub fn new(types: &[MessageType], sender: mpsc::UnboundedSender<Message>) -> Self {
        Self {
            types: types.to_vec(),
            sender,
        }
    }

    fn interested_in(&self, message: &Message) -> bool {
        self.types.iter().any(|t| t.matches(message.inner()))
    }

    pub fn send_if_wanted(&self, message: &Message) {
        if self.interested_in(message) {
            let _ = self.sender.send(message.clone());
        }
    }
}

/// Routes incoming messages to all interested subscribers.
#[derive(Debug, Default)]
pub struct MessageRouter {
    subscribers: Vec<MessageSubscriber>,
}

impl MessageRouter {
    /// Creates a new subscription and returns a receiver that yields messages matching any of the requested types.
    pub fn new_subscriber(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message> {
        let (sender, receiver) = unbounded_channel();
        self.subscribers.push(MessageSubscriber::new(types, sender));
        log::debug!("New subscriber registered for {:?}", types);
        receiver
    }

    /// Distributes a message to all subscribers interested in its type.
    pub fn route(&self, message: &Message) {
        for subscriber in self.subscribers.iter() {
            subscriber.send_if_wanted(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_socket_address;

    fn create_headers_message() -> NetworkMessage {
        NetworkMessage::Headers(vec![])
    }

    fn create_inv_message() -> NetworkMessage {
        NetworkMessage::Inv(vec![])
    }

    #[test]
    fn test_message_creation() {
        let peer_address = test_socket_address(1);
        let inner = create_headers_message();
        let msg = Message::new(peer_address, inner.clone());

        assert_eq!(msg.peer_address(), peer_address);
        assert_eq!(*msg.inner(), inner);
    }

    #[test]
    fn test_interested_in_matching_type() {
        let (sender, _receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[MessageType::Headers], sender);
        let msg = Message::new(test_socket_address(1), create_headers_message());

        assert!(subscriber.interested_in(&msg));
    }

    #[test]
    fn test_interested_in_non_matching_type() {
        let (sender, _receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[MessageType::Headers], sender);
        let msg = Message::new(test_socket_address(1), create_inv_message());

        assert!(!subscriber.interested_in(&msg));
    }

    #[test]
    fn test_interested_in_multiple_types() {
        let (sender, _receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[MessageType::Headers, MessageType::Inv], sender);

        let headers_msg = Message::new(test_socket_address(1), create_headers_message());
        let inv_msg = Message::new(test_socket_address(1), create_inv_message());

        assert!(subscriber.interested_in(&headers_msg));
        assert!(subscriber.interested_in(&inv_msg));
    }

    #[test]
    fn test_interested_in_empty_types() {
        let (sender, _receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[], sender);
        let msg = Message::new(test_socket_address(1), create_headers_message());

        assert!(!subscriber.interested_in(&msg));
    }

    #[tokio::test]
    async fn test_send_if_wanted_sends_when_interested() {
        let (sender, mut receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[MessageType::Headers], sender);
        let msg = Message::new(test_socket_address(1), create_headers_message());

        subscriber.send_if_wanted(&msg);

        let received = receiver.recv().await;
        assert!(received.is_some());
        assert!(matches!(received.unwrap().inner(), NetworkMessage::Headers(_)));
    }

    #[tokio::test]
    async fn test_send_if_wanted_skips_when_not_interested() {
        let (sender, mut receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[MessageType::Headers], sender);
        let msg = Message::new(test_socket_address(1), create_inv_message());

        subscriber.send_if_wanted(&msg);

        // Channel should be empty
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn test_send_if_wanted_dropped_receiver() {
        let (sender, receiver) = unbounded_channel();
        let subscriber = MessageSubscriber::new(&[MessageType::Headers], sender);
        drop(receiver);

        let msg = Message::new(test_socket_address(1), create_headers_message());
        // Should not panic when receiver is dropped
        subscriber.send_if_wanted(&msg);
    }

    #[tokio::test]
    async fn test_new_subscriber_multiple() {
        let mut router = MessageRouter::default();
        let mut receiver1 = router.new_subscriber(&[MessageType::Headers]);
        let mut receiver2 = router.new_subscriber(&[MessageType::Inv]);

        let headers_msg = Message::new(test_socket_address(1), create_headers_message());
        let inv_msg = Message::new(test_socket_address(1), create_inv_message());

        router.route(&headers_msg);
        router.route(&inv_msg);

        // Each receiver gets only its subscribed type
        assert_eq!(receiver1.recv().await.unwrap(), headers_msg);
        assert_eq!(receiver2.recv().await.unwrap(), inv_msg);
    }

    #[tokio::test]
    async fn test_route_to_interested_subscriber() {
        let mut router = MessageRouter::default();
        let mut receiver = router.new_subscriber(&[MessageType::Inv]);

        let msg = Message::new(test_socket_address(1), create_inv_message());
        router.route(&msg);

        assert_eq!(receiver.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_route_skips_uninterested() {
        let mut router = MessageRouter::default();
        let mut receiver = router.new_subscriber(&[MessageType::Headers]);

        let msg = Message::new(test_socket_address(1), create_inv_message());
        router.route(&msg);

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn test_route_no_subscribers() {
        let router = MessageRouter::default();
        let msg = Message::new(test_socket_address(1), create_headers_message());

        // Should not panic with no subscribers
        router.route(&msg);
    }

    #[tokio::test]
    async fn test_route_multiple_subscribers_same_type() {
        let mut router = MessageRouter::default();
        let mut receiver1 = router.new_subscriber(&[MessageType::Headers]);
        let mut receiver2 = router.new_subscriber(&[MessageType::Headers]);

        let msg = Message::new(test_socket_address(1), create_headers_message());
        router.route(&msg);

        // Both should receive the message
        assert_eq!(receiver1.recv().await.unwrap(), msg);
        assert_eq!(receiver2.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_dropped_subscriber_does_not_affect_others() {
        let mut router = MessageRouter::default();
        let receiver1 = router.new_subscriber(&[MessageType::Headers]);
        let mut receiver2 = router.new_subscriber(&[MessageType::Headers]);

        // Drop the first receiver
        drop(receiver1);

        let msg = Message::new(test_socket_address(1), create_headers_message());
        router.route(&msg);

        // Second receiver should still work
        assert_eq!(receiver2.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_messages_received_in_order() {
        let mut router = MessageRouter::default();
        let mut receiver = router.new_subscriber(&[MessageType::Headers, MessageType::Inv]);

        let peer_1 = test_socket_address(1);
        let peer_2 = test_socket_address(2);
        let peer_3 = test_socket_address(3);

        let msg1 = Message::new(peer_1, create_headers_message());
        let msg2 = Message::new(peer_2, create_inv_message());
        let msg3 = Message::new(peer_3, create_headers_message());

        router.route(&msg1);
        router.route(&msg2);
        router.route(&msg3);

        assert_eq!(receiver.recv().await.unwrap().peer_address(), peer_1);
        assert_eq!(receiver.recv().await.unwrap().peer_address(), peer_2);
        assert_eq!(receiver.recv().await.unwrap().peer_address(), peer_3);
    }
}
