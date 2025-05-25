//! Network layer for the Dash SPV client.

pub mod connection;
pub mod handshake;
pub mod message_handler;
pub mod peer;

use std::net::SocketAddr;
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
}

/// TCP-based network manager implementation.
pub struct TcpNetworkManager {
    config: crate::client::ClientConfig,
    connection: Option<TcpConnection>,
    handshake: HandshakeManager,
    message_handler: MessageHandler,
}

impl TcpNetworkManager {
    /// Create a new TCP network manager.
    pub async fn new(config: &crate::client::ClientConfig) -> NetworkResult<Self> {
        Ok(Self {
            config: config.clone(),
            connection: None,
            handshake: HandshakeManager::new(config.network),
            message_handler: MessageHandler::new(),
        })
    }
}

#[async_trait]
impl NetworkManager for TcpNetworkManager {
    async fn connect(&mut self) -> NetworkResult<()> {
        if self.config.peers.is_empty() {
            return Err(NetworkError::ConnectionFailed("No peers configured".to_string()));
        }
        
        // Try to connect to the first peer for now
        let peer_addr = self.config.peers[0];
        
        let mut connection = TcpConnection::new(peer_addr, self.config.connection_timeout);
        connection.connect().await?;
        
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
}