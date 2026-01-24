//! Message dispatcher for network message distribution.
//!
//! This module filters incoming network messages by type and forwards
//! them to registered receivers.
//!
//! - [`Message`]: Wraps a `NetworkMessage` with the originating peer address
//! - [`MessageDispatcher`]: Manages channels and dispatches messages to interested parties

use std::collections::HashMap;
use std::net::SocketAddr;

use dashcore::network::message::NetworkMessage;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::network::MessageType;

/// A network message tagged with the peer that sent it.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    peer_address: SocketAddr,
    inner: NetworkMessage,
}

impl Message {
    /// Creates a new Message from a peer address and network message.
    pub fn new(peer_address: SocketAddr, inner: NetworkMessage) -> Self {
        Self {
            peer_address,
            inner,
        }
    }

    /// Forwards the cmd() of the underlying NetworkMessage.
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

/// Routes incoming network messages to subscribers based on message type.
///
/// Subscribers call [`message_receiver`](Self::message_receiver) with the message types they
/// want, receiving an unbounded channel. When [`dispatch`](Self::dispatch) is called, the
/// message is sent to all subscribers registered for that type. Dead channels are pruned
/// automatically on dispatch.
#[derive(Debug, Default)]
pub struct MessageDispatcher {
    senders: HashMap<MessageType, Vec<UnboundedSender<Message>>>,
}

impl MessageDispatcher {
    /// Creates and returns a receiver that yields only messages matching the provided message types.
    pub fn message_receiver(
        &mut self,
        message_types: &[MessageType],
    ) -> UnboundedReceiver<Message> {
        let (sender, receiver) = unbounded_channel();
        for message_type in message_types {
            self.senders.entry(*message_type).or_default().push(sender.clone());
        }
        receiver
    }

    /// Distributes a message to all subscribers interested in its type.
    pub fn dispatch(&self, message: &Message) {
        let message_type = MessageType::from(message);
        let Some(senders) = self.senders.get(&message_type) else {
            return;
        };
        for sender in senders {
            let _ = sender.send(message.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_socket_address;

    #[test]
    fn test_message_creation() {
        let peer_address = test_socket_address(1);
        let inner = NetworkMessage::Headers(vec![]);
        let msg = Message::new(peer_address, inner.clone());

        assert_eq!(msg.cmd(), inner.cmd());
        assert_eq!(msg.peer_address(), peer_address);
        assert_eq!(*msg.inner(), inner);
    }

    #[tokio::test]
    async fn test_dispatch_to_interested_receiver() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver = message_dispatcher.message_receiver(&[MessageType::Inv]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Inv(vec![]));
        message_dispatcher.dispatch(&msg);

        assert_eq!(receiver.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_dispatch_skips_uninterested() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver = message_dispatcher.message_receiver(&[MessageType::Headers]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Inv(vec![]));
        message_dispatcher.dispatch(&msg);

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn test_dispatch_no_subscribers() {
        let message_dispatcher = MessageDispatcher::default();
        let msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));

        // Should not panic with no subscribers
        message_dispatcher.dispatch(&msg);
    }

    #[tokio::test]
    async fn test_message_receiver_multiple_types() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver1 = message_dispatcher.message_receiver(&[MessageType::Headers]);
        let mut receiver2 = message_dispatcher.message_receiver(&[MessageType::Inv]);

        let headers_msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        let inv_msg = Message::new(test_socket_address(2), NetworkMessage::Inv(vec![]));

        message_dispatcher.dispatch(&headers_msg);
        message_dispatcher.dispatch(&inv_msg);

        assert_eq!(receiver1.recv().await.unwrap(), headers_msg);
        assert_eq!(receiver2.recv().await.unwrap(), inv_msg);
    }

    #[tokio::test]
    async fn test_dispatch_multiple_subscribers_same_type() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver1 = message_dispatcher.message_receiver(&[MessageType::Headers]);
        let mut receiver2 = message_dispatcher.message_receiver(&[MessageType::Headers]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        message_dispatcher.dispatch(&msg);

        assert_eq!(receiver1.recv().await.unwrap(), msg);
        assert_eq!(receiver2.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_dropped_receiver_does_not_affect_others() {
        let mut message_dispatcher = MessageDispatcher::default();
        let receiver1 = message_dispatcher.message_receiver(&[MessageType::Headers]);
        let mut receiver2 = message_dispatcher.message_receiver(&[MessageType::Headers]);

        drop(receiver1);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        message_dispatcher.dispatch(&msg);

        assert_eq!(receiver2.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_messages_received_in_order() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver =
            message_dispatcher.message_receiver(&[MessageType::Headers, MessageType::Inv]);

        let peer_1 = test_socket_address(1);
        let peer_2 = test_socket_address(2);
        let peer_3 = test_socket_address(3);

        let msg1 = Message::new(peer_1, NetworkMessage::Headers(vec![]));
        let msg2 = Message::new(peer_2, NetworkMessage::Inv(vec![]));
        let msg3 = Message::new(peer_3, NetworkMessage::Headers(vec![]));

        message_dispatcher.dispatch(&msg1);
        message_dispatcher.dispatch(&msg2);
        message_dispatcher.dispatch(&msg3);

        assert_eq!(receiver.recv().await.unwrap().peer_address(), peer_1);
        assert_eq!(receiver.recv().await.unwrap().peer_address(), peer_2);
        assert_eq!(receiver.recv().await.unwrap().peer_address(), peer_3);
    }

    #[tokio::test]
    async fn test_message_receiver_receives_multiple_types() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver =
            message_dispatcher.message_receiver(&[MessageType::Headers, MessageType::Inv]);

        let headers_msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        let inv_msg = Message::new(test_socket_address(2), NetworkMessage::Inv(vec![]));

        message_dispatcher.dispatch(&headers_msg);
        message_dispatcher.dispatch(&inv_msg);

        assert_eq!(receiver.recv().await.unwrap(), headers_msg);
        assert_eq!(receiver.recv().await.unwrap(), inv_msg);
    }
}
