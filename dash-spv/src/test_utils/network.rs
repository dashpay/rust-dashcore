use std::collections::VecDeque;

use crate::error::{NetworkError, NetworkResult};
use crate::event_bus::{EventBus, EventReceiver};
use crate::network::{
    Message, MessageDispatcher, MessageType, NetworkEvent, NetworkManager, NetworkRequest,
    RequestSender,
};
use async_trait::async_trait;
use dashcore::network::constants::ServiceFlags;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{
    block::Header as BlockHeader, network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage, BlockHash,
};
use dashcore_hashes::Hash;
use std::any::Any;
use std::net::SocketAddr;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub fn test_socket_address(id: u8) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, id], id as u16))
}

/// Mock network manager for testing
pub struct MockNetworkManager {
    connected: bool,
    connected_peer: SocketAddr,
    sent_messages: VecDeque<NetworkMessage>,
    headers_chain: Vec<BlockHeader>,
    peer_best_height: Option<u32>,
    supports_compact_filters: bool,
    message_dispatcher: MessageDispatcher,
    /// Request sender for outgoing messages.
    request_tx: UnboundedSender<NetworkRequest>,
    /// Keep receiver alive so sends don't fail. Use Option to allow taking for tests.
    #[allow(dead_code)]
    request_rx: Option<UnboundedReceiver<NetworkRequest>>,
    /// Event bus for network events.
    network_event_bus: EventBus<NetworkEvent>,
}

impl MockNetworkManager {
    /// Create a new mock network manager.
    pub fn new() -> Self {
        let (request_tx, request_rx) = unbounded_channel();
        Self {
            connected: false,
            connected_peer: test_socket_address(1),
            sent_messages: VecDeque::new(),
            headers_chain: Vec::new(),
            peer_best_height: None,
            supports_compact_filters: true,
            message_dispatcher: MessageDispatcher::default(),
            request_tx,
            request_rx: Some(request_rx),
            network_event_bus: EventBus::default(),
        }
    }

    /// Create a mock network manager with a specific request sender.
    ///
    /// The caller owns the receiver and can inspect messages sent via `request_sender()`.
    pub fn with_request_sender(request_tx: UnboundedSender<NetworkRequest>) -> Self {
        Self {
            connected: true,
            connected_peer: SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9999),
            sent_messages: VecDeque::new(),
            headers_chain: Vec::new(),
            peer_best_height: None,
            supports_compact_filters: true,
            message_dispatcher: MessageDispatcher::default(),
            request_tx,
            request_rx: None, // Caller owns the receiver
            network_event_bus: EventBus::default(),
        }
    }

    /// Get reference to sent messages for test verification
    pub fn sent_messages(&self) -> &VecDeque<NetworkMessage> {
        &self.sent_messages
    }

    /// Get count of sent messages
    pub fn sent_message_count(&self) -> usize {
        self.sent_messages.len()
    }

    /// Get last sent message
    pub fn last_sent_message(&self) -> Option<&NetworkMessage> {
        self.sent_messages.back()
    }

    /// Clear sent messages
    pub fn clear_sent_messages(&mut self) {
        self.sent_messages.clear();
    }

    /// Set peer best height for testing
    pub fn set_peer_best_height(&mut self, height: u32) {
        self.peer_best_height = Some(height);
    }

    /// Set whether peers support compact filters
    pub fn set_supports_compact_filters(&mut self, supports: bool) {
        self.supports_compact_filters = supports;
    }

    /// Add a chain of headers for testing
    pub fn add_headers_chain(&mut self, genesis_hash: BlockHash, count: usize) {
        let mut headers = Vec::new();
        let mut prev_hash = genesis_hash;

        // Skip genesis (height 0) as it's already in ChainState
        for i in 1..count {
            let header = BlockHeader {
                version: dashcore::block::Version::from_consensus(1),
                prev_blockhash: prev_hash,
                merkle_root: dashcore::hashes::sha256d::Hash::all_zeros().into(),
                time: 1000000 + i as u32,
                bits: dashcore::CompactTarget::from_consensus(0x207fffff),
                nonce: i as u32,
            };

            prev_hash = header.block_hash();
            headers.push(header);
        }

        self.headers_chain = headers;
    }

    /// Process GetHeaders request and return appropriate headers
    fn process_getheaders(&self, msg: &GetHeadersMessage) -> Vec<BlockHeader> {
        // Find the starting point in our chain
        let start_idx = if msg.locator_hashes.is_empty() {
            0
        } else {
            // Find the first locator hash we recognize
            let mut found_idx = None;
            for locator in &msg.locator_hashes {
                for (idx, header) in self.headers_chain.iter().enumerate() {
                    if header.block_hash() == *locator {
                        found_idx = Some(idx + 1); // Start from next header
                        break;
                    }
                }
                if found_idx.is_some() {
                    break;
                }
            }
            found_idx.unwrap_or(0)
        };

        // Return up to 2000 headers starting from start_idx
        let end_idx = (start_idx + 2000).min(self.headers_chain.len());

        if start_idx < self.headers_chain.len() {
            self.headers_chain[start_idx..end_idx].to_vec()
        } else {
            Vec::new()
        }
    }
}

impl Default for MockNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkManager for MockNetworkManager {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn message_receiver(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message> {
        self.message_dispatcher.message_receiver(types)
    }

    fn request_sender(&self) -> RequestSender {
        RequestSender::new(self.request_tx.clone())
    }

    async fn connect(&mut self) -> NetworkResult<()> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> NetworkResult<()> {
        self.connected = false;
        self.sent_messages.clear();
        Ok(())
    }

    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        if !self.connected {
            return Err(NetworkError::NotConnected);
        }

        // Track sent message for test verification
        self.sent_messages.push_back(message.clone());

        // Process GetHeaders requests
        if let NetworkMessage::GetHeaders(ref getheaders) = message {
            let headers = self.process_getheaders(getheaders);
            if !headers.is_empty() {
                let message = Message::new(self.connected_peer, NetworkMessage::Headers(headers));
                self.message_dispatcher.dispatch(&message);
            }
        }

        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn peer_count(&self) -> usize {
        if self.connected {
            1
        } else {
            0
        }
    }

    async fn get_peer_best_height(&self) -> Option<CoreBlockHeight> {
        let height = self.peer_best_height.unwrap_or(self.headers_chain.len() as u32);
        Some(height)
    }

    async fn has_peer_with_service(&self, _service_flags: ServiceFlags) -> bool {
        todo!()
    }

    fn subscribe_network_events(&self) -> EventReceiver<NetworkEvent> {
        self.network_event_bus.subscribe()
    }
}
