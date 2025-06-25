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
pub mod reputation;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub mod mock;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::{NetworkError, NetworkResult};
use dashcore::network::message::NetworkMessage;

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

    /// Get a message sender channel for sending messages from other components.
    fn get_message_sender(&self) -> mpsc::Sender<NetworkMessage>;
    
    /// Get the best block height reported by connected peers.
    async fn get_peer_best_height(&self) -> NetworkResult<Option<u32>>;
    
    /// Check if any connected peer supports a specific service.
    async fn has_peer_with_service(&self, service_flags: dashcore::network::constants::ServiceFlags) -> bool;
    
    /// Get peers that support a specific service.
    async fn get_peers_with_service(&self, service_flags: dashcore::network::constants::ServiceFlags) -> Vec<crate::types::PeerInfo>;
    
    /// Check if any connected peer supports headers2 compression.
    async fn has_headers2_peer(&self) -> bool {
        self.has_peer_with_service(dashcore::network::constants::NODE_HEADERS_COMPRESSED).await
    }
    
    /// Get the peer ID of the last peer that sent us a message.
    /// Returns PeerId(0) if no message has been received yet.
    async fn get_last_message_peer_id(&self) -> crate::types::PeerId {
        crate::types::PeerId(0) // Default implementation
    }
}

/// TCP-based network manager implementation.
pub struct TcpNetworkManager {
    config: crate::client::ClientConfig,
    connection: Option<TcpConnection>,
    handshake: HandshakeManager,
    _message_handler: MessageHandler,
    message_sender: mpsc::Sender<NetworkMessage>,
    message_receiver: mpsc::Receiver<NetworkMessage>,
}

impl TcpNetworkManager {
    /// Create a new TCP network manager.
    pub async fn new(config: &crate::client::ClientConfig) -> NetworkResult<Self> {
        let (message_sender, message_receiver) = mpsc::channel(1000);

        Ok(Self {
            config: config.clone(),
            connection: None,
            handshake: HandshakeManager::new(config.network, config.mempool_strategy),
            _message_handler: MessageHandler::new(),
            message_sender,
            message_receiver,
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

        let mut connection =
            TcpConnection::new(peer_addr, self.config.connection_timeout, self.config.network);
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
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        connection.send_message(message).await
    }

    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        connection.receive_message().await
    }

    fn is_connected(&self) -> bool {
        self.connection.as_ref().map_or(false, |c| c.is_connected())
    }

    fn peer_count(&self) -> usize {
        if self.is_connected() {
            1
        } else {
            0
        }
    }

    fn peer_info(&self) -> Vec<crate::types::PeerInfo> {
        if let Some(connection) = &self.connection {
            vec![connection.peer_info()]
        } else {
            vec![]
        }
    }

    async fn send_ping(&mut self) -> NetworkResult<u64> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        connection.send_ping().await
    }

    async fn handle_ping(&mut self, nonce: u64) -> NetworkResult<()> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        connection.handle_ping(nonce).await
    }

    fn handle_pong(&mut self, nonce: u64) -> NetworkResult<()> {
        let connection = self
            .connection
            .as_mut()
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

    fn get_message_sender(&self) -> mpsc::Sender<NetworkMessage> {
        self.message_sender.clone()
    }
    
    async fn get_peer_best_height(&self) -> NetworkResult<Option<u32>> {
        if let Some(connection) = &self.connection {
            // For single peer connection, return the peer's best height
            match connection.peer_info().best_height {
                Some(height) if height > 0 => Ok(Some(height as u32)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
    
    async fn has_peer_with_service(&self, service_flags: dashcore::network::constants::ServiceFlags) -> bool {
        if let Some(connection) = &self.connection {
            let peer_info = connection.peer_info();
            peer_info.services
                .map(|s| dashcore::network::constants::ServiceFlags::from(s).has(service_flags))
                .unwrap_or(false)
        } else {
            false
        }
    }
    
    async fn get_peers_with_service(&self, service_flags: dashcore::network::constants::ServiceFlags) -> Vec<crate::types::PeerInfo> {
        if let Some(connection) = &self.connection {
            let peer_info = connection.peer_info();
            if peer_info.services
                .map(|s| dashcore::network::constants::ServiceFlags::from(s).has(service_flags))
                .unwrap_or(false) {
                vec![peer_info]
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }
    
    async fn get_last_message_peer_id(&self) -> crate::types::PeerId {
        // For single peer connection, always return PeerId(1) when connected
        if self.connection.is_some() {
            crate::types::PeerId(1)
        } else {
            crate::types::PeerId(0)
        }
    }
}
