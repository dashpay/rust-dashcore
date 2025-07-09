//! Mock network manager for testing

use std::any::Any;
use std::collections::VecDeque;

use async_trait::async_trait;
use dashcore::{
    block::Header as BlockHeader,
    network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage,
    network::constants::ServiceFlags,
    BlockHash,
};
use dashcore_hashes::Hash;
use tokio::sync::mpsc;

use crate::error::{NetworkError, NetworkResult};
use crate::types::PeerInfo;

use super::NetworkManager;

/// Mock network manager for testing
pub struct MockNetworkManager {
    connected: bool,
    messages: VecDeque<NetworkMessage>,
    headers_chain: Vec<BlockHeader>,
    message_sender: mpsc::Sender<NetworkMessage>,
    message_receiver: mpsc::Receiver<NetworkMessage>,
}

impl MockNetworkManager {
    /// Create a new mock network manager
    pub fn new() -> Self {
        let (message_sender, message_receiver) = mpsc::channel(1000);
        
        Self {
            connected: false,
            messages: VecDeque::new(),
            headers_chain: Vec::new(),
            message_sender,
            message_receiver,
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
}

#[async_trait]
impl NetworkManager for MockNetworkManager {
    fn as_any(&self) -> &dyn Any {
        self
    }
    
    async fn connect(&mut self) -> NetworkResult<()> {
        self.connected = true;
        Ok(())
    }
    
    async fn disconnect(&mut self) -> NetworkResult<()> {
        self.connected = false;
        self.messages.clear();
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
                self.messages.push_back(NetworkMessage::Headers(headers));
            }
        }
        
        Ok(())
    }
    
    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        if !self.connected {
            return Err(NetworkError::NotConnected);
        }
        
        // Check for messages in the receiver channel first
        if let Ok(msg) = self.message_receiver.try_recv() {
            return Ok(Some(msg));
        }
        
        // Then check our internal queue
        Ok(self.messages.pop_front())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn peer_count(&self) -> usize {
        if self.connected { 1 } else { 0 }
    }
    
    fn peer_info(&self) -> Vec<PeerInfo> {
        if self.connected {
            vec![PeerInfo {
                address: "127.0.0.1:9999".parse().unwrap(),
                connected: true,
                last_seen: std::time::SystemTime::now(),
                version: Some(70015),
                services: Some(1),
                user_agent: Some("/MockPeer:1.0.0/".to_string()),
                best_height: Some(self.headers_chain.len() as u32),
            }]
        } else {
            vec![]
        }
    }
    
    async fn send_ping(&mut self) -> NetworkResult<u64> {
        Ok(1234567890)
    }
    
    async fn handle_ping(&mut self, _nonce: u64) -> NetworkResult<()> {
        Ok(())
    }
    
    fn handle_pong(&mut self, _nonce: u64) -> NetworkResult<()> {
        Ok(())
    }
    
    fn should_ping(&self) -> bool {
        false
    }
    
    fn cleanup_old_pings(&mut self) {}
    
    fn get_message_sender(&self) -> mpsc::Sender<NetworkMessage> {
        self.message_sender.clone()
    }
    
    async fn get_peer_best_height(&self) -> NetworkResult<Option<u32>> {
        Ok(Some(self.headers_chain.len() as u32))
    }
    
    async fn has_peer_with_service(&self, _service_flags: ServiceFlags) -> bool {
        self.connected
    }
    
    async fn get_peers_with_service(&self, _service_flags: ServiceFlags) -> Vec<PeerInfo> {
        self.peer_info()
    }
    
    async fn get_last_message_peer_id(&self) -> crate::types::PeerId {
        // For mock, always return PeerId(1) when connected
        if self.connected {
            crate::types::PeerId(1)
        } else {
            crate::types::PeerId(0)
        }
    }
}