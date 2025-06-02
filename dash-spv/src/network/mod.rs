//! Network layer for the Dash SPV client.

pub mod addrv2;
pub mod connection;
pub mod constants;
pub mod discovery;
pub mod handshake;
pub mod message_handler;
pub mod multi_peer;
pub mod peer;
pub mod persist;
pub mod pool;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use dashcore::network::message::NetworkMessage;
use crate::error::{NetworkError, NetworkResult};

pub use connection::TcpConnection;
pub use handshake::{HandshakeManager, HandshakeState};
pub use message_handler::MessageHandler;
pub use peer::PeerManager;

/// Network manager trait for abstracting network operations.
#[async_trait]
pub trait NetworkManager: Send + Sync {
    /// Convert to Any for downcasting.
    fn as_any(&self) -> &dyn std::any::Any;
    
    /// Connect to the network.
    async fn connect(&mut self) -> NetworkResult<()>;
    
    /// Disconnect from the network.
    async fn disconnect(&mut self) -> NetworkResult<()>;
    
    /// Send a message to a peer.
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()>;
    
    /// Receive a message from a peer.
    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>>;
    
    /// Check if connected to any peers.
    fn is_connected(&self) -> bool;
    
    /// Get the number of connected peers.
    fn peer_count(&self) -> usize;
    
    /// Get peer information.
    fn peer_info(&self) -> Vec<crate::types::PeerInfo>;
    
    /// Send a ping message.
    async fn send_ping(&mut self) -> NetworkResult<u64>;
    
    /// Handle a received ping message by sending a pong.
    async fn handle_ping(&mut self, nonce: u64) -> NetworkResult<()>;
    
    /// Handle a received pong message.
    fn handle_pong(&mut self, nonce: u64) -> NetworkResult<()>;
    
    /// Check if we should send a ping (2 minute timeout).
    fn should_ping(&self) -> bool;
    
    /// Clean up old pending pings.
    fn cleanup_old_pings(&mut self);
}

/// TCP-based network manager implementation.
pub struct TcpNetworkManager {
    config: crate::client::ClientConfig,
    connection: Option<TcpConnection>,
    handshake: HandshakeManager,
    _message_handler: MessageHandler,
}

impl TcpNetworkManager {
    /// Create a new TCP network manager.
    pub async fn new(config: &crate::client::ClientConfig) -> NetworkResult<Self> {
        Ok(Self {
            config: config.clone(),
            connection: None,
            handshake: HandshakeManager::new(config.network),
            _message_handler: MessageHandler::new(),
        })
    }
}

#[async_trait]
impl NetworkManager for TcpNetworkManager {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    async fn connect(&mut self) -> NetworkResult<()> {
        if self.config.peers.is_empty() {
            return Err(NetworkError::ConnectionFailed("No peers configured".to_string()));
        }
        
        // Try to connect to the first peer for now
        let peer_addr = self.config.peers[0];
        
        let mut connection = TcpConnection::new(peer_addr, self.config.connection_timeout, self.config.network);
        connection.connect_instance().await?;
        
        // Perform handshake
        self.handshake.perform_handshake(&mut connection).await?;
        
        self.connection = Some(connection);
        
        Ok(())
    }
    
    async fn disconnect(&mut self) -> NetworkResult<()> {
        if let Some(mut connection) = self.connection.take() {
            connection.disconnect().await?;
        }
        self.handshake.reset();
        Ok(())
    }
    
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        let connection = self.connection.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        connection.send_message(message).await
    }
    
    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        let connection = self.connection.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        connection.receive_message().await
    }
    
    fn is_connected(&self) -> bool {
        self.connection.as_ref().map_or(false, |c| c.is_connected())
    }
    
    fn peer_count(&self) -> usize {
        if self.is_connected() { 1 } else { 0 }
    }
    
    fn peer_info(&self) -> Vec<crate::types::PeerInfo> {
        if let Some(connection) = &self.connection {
            vec![connection.peer_info()]
        } else {
            vec![]
        }
    }
    
    async fn send_ping(&mut self) -> NetworkResult<u64> {
        let connection = self.connection.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        connection.send_ping().await
    }
    
    async fn handle_ping(&mut self, nonce: u64) -> NetworkResult<()> {
        let connection = self.connection.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        connection.handle_ping(nonce).await
    }
    
    fn handle_pong(&mut self, nonce: u64) -> NetworkResult<()> {
        let connection = self.connection.as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;
        
        connection.handle_pong(nonce)
    }
    
    fn should_ping(&self) -> bool {
        self.connection.as_ref().map_or(false, |c| c.should_ping())
    }
    
    fn cleanup_old_pings(&mut self) {
        if let Some(connection) = self.connection.as_mut() {
            connection.cleanup_old_pings();
        }
    }
}