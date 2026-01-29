use crate::error::{NetworkError, NetworkResult};
use crate::network::{Message, MessageDispatcher, MessageType, NetworkManager};
use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{
    block::Header as BlockHeader, network::constants::ServiceFlags,
    network::message::NetworkMessage, network::message_blockdata::GetHeadersMessage, BlockHash,
};
use dashcore_hashes::Hash;
use std::any::Any;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedReceiver;

pub fn test_socket_address(id: u8) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, id], id as u16))
}

/// Mock network manager for testing
pub struct MockNetworkManager {
    connected: bool,
    connected_peer: SocketAddr,
    headers_chain: Vec<BlockHeader>,
    peer_best_height: Option<u32>,
    message_dispatcher: MessageDispatcher,
    sent_messages: Vec<NetworkMessage>,
}

impl MockNetworkManager {
    /// Create a new mock network manager
    pub fn new() -> Self {
        Self {
            connected: true,
            connected_peer: SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9999),
            headers_chain: Vec::new(),
            peer_best_height: None,
            message_dispatcher: MessageDispatcher::default(),
            sent_messages: Vec::new(),
        }
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

    pub fn sent_messages(&self) -> &Vec<NetworkMessage> {
        &self.sent_messages
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

    async fn connect(&mut self) -> NetworkResult<()> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> NetworkResult<()> {
        self.connected = false;
        Ok(())
    }

    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        if !self.connected {
            return Err(NetworkError::NotConnected);
        }

        // Process GetHeaders requests
        if let NetworkMessage::GetHeaders(ref getheaders) = message {
            let headers = self.process_getheaders(getheaders);
            if !headers.is_empty() {
                let message = Message::new(self.connected_peer, NetworkMessage::Headers(headers));
                self.message_dispatcher.dispatch(&message);
            }
        }

        self.sent_messages.push(message);

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
        self.peer_best_height
    }

    async fn has_peer_with_service(&self, _service_flags: ServiceFlags) -> bool {
        self.connected
    }
}
