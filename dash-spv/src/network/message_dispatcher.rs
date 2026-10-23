//! Message dispatcher for network message distribution.
//!
//! This module filters incoming network messages by type and forwards
//! them to registered receivers.
//!
//! - [`Message`]: Wraps a `NetworkMessage` with the originating peer address
//! - [`MessageDispatcher`]: Manages channels and dispatches messages to interested parties

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::network::MessageType;

/// Capacity of each subscriber queue, one filter batch (the largest response burst a single
/// sync request triggers). A full queue makes [`MessageDispatcher::dispatch`] wait, so the peer
/// readers stop reading and TCP throttles the peers instead of memory growing.
const MESSAGE_CHANNEL_CAPACITY: usize = 1000;

/// A network message tagged with the peer that sent it.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    peer_address: SocketAddr,
    inner: NetworkMessage,
    header_hashes: Option<Vec<BlockHash>>,
}

impl Message {
    /// Creates a new Message from a peer address and network message.
    pub fn new(peer_address: SocketAddr, inner: NetworkMessage) -> Self {
        Self {
            peer_address,
            inner,
            header_hashes: None,
        }
    }

    /// Creates a headers message carrying hashes already computed during decompression.
    pub(crate) fn new_headers(
        peer_address: SocketAddr,
        headers_with_hashes: Vec<(dashcore::Header, BlockHash)>,
    ) -> Self {
        let (headers, hashes) = headers_with_hashes.into_iter().unzip();
        Self {
            peer_address,
            inner: NetworkMessage::Headers(headers),
            header_hashes: Some(hashes),
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

    /// Consumes the wrapper and returns its network message.
    pub(crate) fn into_inner(self) -> NetworkMessage {
        self.inner
    }

    /// Returns cached hashes for a decompressed headers2 message.
    pub(crate) fn header_hashes(&self) -> Option<&[BlockHash]> {
        self.header_hashes.as_deref()
    }
}

/// Routes incoming network messages to subscribers based on message type.
///
/// Subscribers call [`message_receiver`](Self::message_receiver) with the message types they
/// want, receiving a bounded channel. When [`dispatch`](Self::dispatch) is called, the
/// message is sent to all subscribers registered for that type. Dead channels are pruned
/// automatically on dispatch.
#[derive(Debug, Default)]
pub struct MessageDispatcher {
    senders: HashMap<MessageType, Vec<Sender<Message>>>,
}

impl MessageDispatcher {
    /// Creates and returns a receiver that yields only messages matching the provided message types.
    pub fn message_receiver(&mut self, message_types: &[MessageType]) -> Receiver<Message> {
        let (sender, receiver) = channel(MESSAGE_CHANNEL_CAPACITY);
        let unique_types: HashSet<MessageType> = message_types.iter().copied().collect();
        for message_type in unique_types {
            self.senders.entry(message_type).or_default().push(sender.clone());
        }
        receiver
    }

    /// Distributes a message to all subscribers interested in its type, waiting for queue
    /// capacity. Prunes dead senders automatically.
    pub async fn dispatch(&mut self, message: &Message) {
        let message_type = MessageType::from(message);
        if let Some(senders) = self.senders.get_mut(&message_type) {
            for sender in senders.iter() {
                let _ = sender.send(message.clone()).await;
            }
            senders.retain(|sender| !sender.is_closed());
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_socket_address;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_message_creation() {
        let peer_address = test_socket_address(1);
        let inner = NetworkMessage::Headers(vec![]);
        let msg = Message::new(peer_address, inner.clone());

        assert_eq!(msg.cmd(), inner.cmd());
        assert_eq!(msg.peer_address(), peer_address);
        assert_eq!(*msg.inner(), inner);
    }

    #[test]
    fn test_headers_message_carries_precomputed_hashes() {
        let peer_address = test_socket_address(1);
        let header = dashcore::Header::dummy(1);
        let hash = header.block_hash();
        let msg = Message::new_headers(peer_address, vec![(header, hash)]);

        assert_eq!(msg.header_hashes(), Some([hash].as_slice()));
        assert_eq!(msg.inner(), &NetworkMessage::Headers(vec![header]));
    }

    #[tokio::test]
    async fn test_dispatch_to_interested_receiver() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver = message_dispatcher.message_receiver(&[MessageType::Inv]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Inv(vec![]));
        message_dispatcher.dispatch(&msg).await;

        assert_eq!(receiver.recv().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn test_dispatch_skips_uninterested() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver = message_dispatcher.message_receiver(&[MessageType::Headers]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Inv(vec![]));
        message_dispatcher.dispatch(&msg).await;

        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_dispatch_no_subscribers() {
        let mut message_dispatcher = MessageDispatcher::default();
        let msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));

        // Should not panic with no subscribers
        message_dispatcher.dispatch(&msg).await;
    }

    #[tokio::test]
    async fn test_message_receiver_multiple_types() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver1 = message_dispatcher.message_receiver(&[MessageType::Headers]);
        let mut receiver2 = message_dispatcher.message_receiver(&[MessageType::Inv]);

        let headers_msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        let inv_msg = Message::new(test_socket_address(2), NetworkMessage::Inv(vec![]));

        message_dispatcher.dispatch(&headers_msg).await;
        message_dispatcher.dispatch(&inv_msg).await;

        assert_eq!(receiver1.recv().await.unwrap(), headers_msg);
        assert_eq!(receiver2.recv().await.unwrap(), inv_msg);
    }

    #[tokio::test]
    async fn test_dispatch_multiple_subscribers_same_type() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver1 = message_dispatcher.message_receiver(&[MessageType::Headers]);
        let mut receiver2 = message_dispatcher.message_receiver(&[MessageType::Headers]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        message_dispatcher.dispatch(&msg).await;

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
        message_dispatcher.dispatch(&msg).await;

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

        message_dispatcher.dispatch(&msg1).await;
        message_dispatcher.dispatch(&msg2).await;
        message_dispatcher.dispatch(&msg3).await;

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

        message_dispatcher.dispatch(&headers_msg).await;
        message_dispatcher.dispatch(&inv_msg).await;

        assert_eq!(receiver.recv().await.unwrap(), headers_msg);
        assert_eq!(receiver.recv().await.unwrap(), inv_msg);
    }

    #[tokio::test]
    async fn test_dispatch_waits_for_queue_capacity() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver = message_dispatcher.message_receiver(&[MessageType::Inv]);
        let msg = Message::new(test_socket_address(1), NetworkMessage::Inv(vec![]));
        for _ in 0..MESSAGE_CHANNEL_CAPACITY {
            message_dispatcher.dispatch(&msg).await;
        }

        let wait = Duration::from_millis(100);
        assert!(timeout(wait, message_dispatcher.dispatch(&msg)).await.is_err());

        receiver.recv().await.unwrap();
        timeout(wait, message_dispatcher.dispatch(&msg)).await.unwrap();
    }

    #[tokio::test]
    async fn test_duplicate_message_types_no_duplicate_delivery() {
        let mut message_dispatcher = MessageDispatcher::default();
        let mut receiver = message_dispatcher.message_receiver(&[
            MessageType::Headers,
            MessageType::Headers,
            MessageType::Headers,
        ]);

        let msg = Message::new(test_socket_address(1), NetworkMessage::Headers(vec![]));
        message_dispatcher.dispatch(&msg).await;

        assert_eq!(receiver.recv().await.unwrap(), msg);
        assert!(receiver.try_recv().is_err());
    }
}
