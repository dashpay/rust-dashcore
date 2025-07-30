//! Network handshake management.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dashcore::network::constants;
use dashcore::network::constants::{ServiceFlags, NODE_HEADERS_COMPRESSED};
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_network::VersionMessage;
use dashcore::Network;
// Hash trait not needed in current implementation

use crate::error::{NetworkError, NetworkResult};
use crate::network::connection::TcpConnection;
use crate::client::config::MempoolStrategy;

/// Handshake state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state.
    Init,
    /// Version message sent.
    VersionSent,
    /// Version received and verack sent.
    VersionReceivedVerackSent,
    /// Verack received.
    VerackReceived,
    /// Handshake complete.
    Complete,
}

/// Manages the network handshake process.
pub struct HandshakeManager {
    _network: Network,
    state: HandshakeState,
    our_version: u32,
    peer_version: Option<u32>,
    peer_services: Option<ServiceFlags>,
    version_received: bool,
    verack_received: bool,
    version_sent: bool,
    mempool_strategy: MempoolStrategy,
}

impl HandshakeManager {
    /// Create a new handshake manager.
    pub fn new(network: Network, mempool_strategy: MempoolStrategy) -> Self {
        Self {
            _network: network,
            state: HandshakeState::Init,
            our_version: constants::PROTOCOL_VERSION,
            peer_version: None,
            peer_services: None,
            version_received: false,
            verack_received: false,
            version_sent: false,
            mempool_strategy,
        }
    }

    /// Perform the handshake with a peer.
    pub async fn perform_handshake(&mut self, connection: &mut TcpConnection) -> NetworkResult<()> {
        use tokio::time::{timeout, Duration};

        // Send version message
        self.send_version(connection).await?;
        self.version_sent = true;
        self.state = HandshakeState::VersionSent;
        tracing::info!("Handshake initiated - version message sent to peer");

        // Define timeout for the entire handshake process
        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
        const MESSAGE_POLL_INTERVAL: Duration = Duration::from_millis(100);

        let start_time = tokio::time::Instant::now();

        // Wait for responses with timeout
        loop {
            // Check if we've exceeded the overall handshake timeout
            if start_time.elapsed() > HANDSHAKE_TIMEOUT {
                tracing::error!("Handshake timeout after {}s - version_received={}, verack_received={}", 
                    HANDSHAKE_TIMEOUT.as_secs(), self.version_received, self.verack_received);
                return Err(NetworkError::Timeout);
            }

            // Try to receive a message with a short timeout
            match timeout(MESSAGE_POLL_INTERVAL, connection.receive_message()).await {
                Ok(Ok(Some(message))) => {
                    tracing::debug!("Received message during handshake: {:?}", message.cmd());
                    match self.handle_handshake_message(connection, message).await? {
                        Some(HandshakeState::Complete) => {
                            self.state = HandshakeState::Complete;
                            break;
                        }
                        _ => {
                            // Continue immediately to check for more messages in the buffer
                            // Don't add any delays here as multiple messages may be waiting
                            continue;
                        }
                    }
                }
                Ok(Ok(None)) => {
                    // No message available, continue immediately
                    // The read timeout already provides the necessary delay
                    continue;
                }
                Ok(Err(e)) => {
                    tracing::error!("Error receiving message during handshake: {}", e);
                    return Err(e);
                }
                Err(_) => {
                    // Timeout on receive_message, continue to check overall timeout
                    continue;
                }
            }
        }

        tracing::info!("Handshake completed successfully - version_received={}, verack_received={}", 
            self.version_received, self.verack_received);
        Ok(())
    }

    /// Reset the handshake state.
    pub fn reset(&mut self) {
        self.state = HandshakeState::Init;
        self.peer_version = None;
        self.version_received = false;
        self.verack_received = false;
        self.version_sent = false;
    }

    /// Handle a handshake message.
    async fn handle_handshake_message(
        &mut self,
        connection: &mut TcpConnection,
        message: NetworkMessage,
    ) -> NetworkResult<Option<HandshakeState>> {
        match message {
            NetworkMessage::Version(version_msg) => {
                tracing::debug!("Received version message: {:?}", version_msg);
                self.peer_version = Some(version_msg.version);
                self.peer_services = Some(version_msg.services);
                self.version_received = true;
                
                // Update connection's peer information
                connection.update_peer_info(&version_msg);

                // If we haven't sent our version yet (peer initiated), send it now
                if !self.version_sent {
                    tracing::debug!("Peer initiated handshake, sending our version");
                    self.send_version(connection).await?;
                    self.version_sent = true;
                }

                // Send SendAddrV2 first to signal support (must be before verack!)
                tracing::debug!("Sending sendaddrv2 to signal AddrV2 support");
                connection.send_message(NetworkMessage::SendAddrV2).await?;

                // Then send verack
                tracing::debug!("Sending verack in response to version");
                connection.send_message(NetworkMessage::Verack).await?;
                tracing::debug!("Sent verack, version_received={}, verack_received={}", 
                              self.version_received, self.verack_received);

                // Update state
                self.state = HandshakeState::VersionReceivedVerackSent;

                // Check if handshake is complete (both version and verack received)
                if self.version_received && self.verack_received {
                    tracing::info!(
                        "Handshake complete - both version and verack exchanged!"
                    );
                    
                    // Check if both peers support headers2
                    if let Some(peer_services) = self.peer_services {
                        if peer_services.has(NODE_HEADERS_COMPRESSED) {
                            tracing::info!("Peer supports headers2 - sending SendHeaders2");
                            connection.send_message(NetworkMessage::SendHeaders2).await?;
                        }
                    }
                    
                    // Also send SendHeaders to request headers be pushed to us
                    tracing::info!("Sending SendHeaders to request headers be pushed");
                    connection.send_message(NetworkMessage::SendHeaders).await?;
                    
                    return Ok(Some(HandshakeState::Complete));
                }

                Ok(None)
            }
            NetworkMessage::Verack => {
                tracing::debug!("Received verack message, current state: {:?}", self.state);
                self.verack_received = true;
                
                // Update state
                if self.state == HandshakeState::VersionSent {
                    self.state = HandshakeState::VerackReceived;
                }
                
                // Check if handshake is complete (both version and verack received)
                if self.version_received && self.verack_received {
                    tracing::info!("Handshake complete - both version and verack exchanged!");
                    
                    // Check if both peers support headers2
                    if let Some(peer_services) = self.peer_services {
                        if peer_services.has(NODE_HEADERS_COMPRESSED) {
                            tracing::info!("Peer supports headers2 - sending SendHeaders2");
                            connection.send_message(NetworkMessage::SendHeaders2).await?;
                        }
                    }
                    
                    // Also send SendHeaders to request headers be pushed to us
                    tracing::info!("Sending SendHeaders to request headers be pushed");
                    connection.send_message(NetworkMessage::SendHeaders).await?;
                    
                    return Ok(Some(HandshakeState::Complete));
                } else {
                    tracing::debug!(
                        "Verack received but handshake not complete: version_received={}, verack_received={}",
                        self.version_received, self.verack_received
                    );
                }
                Ok(None)
            }
            NetworkMessage::Ping(nonce) => {
                // Respond to ping during handshake
                tracing::debug!("Responding to ping during handshake: {}", nonce);
                connection.send_message(NetworkMessage::Pong(nonce)).await?;
                Ok(None)
            }
            NetworkMessage::SendAddrV2 => {
                // Peer supports AddrV2
                tracing::debug!("Peer signaled AddrV2 support");
                Ok(None)
            }
            _ => {
                // Ignore other messages during handshake
                tracing::debug!("Ignoring message during handshake: {:?}", message);
                Ok(None)
            }
        }
    }

    /// Send version message.
    async fn send_version(&mut self, connection: &mut TcpConnection) -> NetworkResult<()> {
        let version_message = self.build_version_message(connection.peer_info().address);
        connection.send_message(NetworkMessage::Version(version_message)).await?;
        tracing::debug!("Sent version message");
        Ok(())
    }

    /// Build version message.
    fn build_version_message(&self, address: SocketAddr) -> VersionMessage {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        // SPV client advertises headers2 support but no other services
        let services = NODE_HEADERS_COMPRESSED;

        VersionMessage {
            version: self.our_version,
            services,
            timestamp,
            receiver: dashcore::network::address::Address::new(&address, ServiceFlags::NETWORK),
            sender: dashcore::network::address::Address::new(
                &"127.0.0.1:0".parse().unwrap(),
                services,
            ),
            nonce: rand::random(),
            user_agent: "/rust-dash-spv:0.1.0/".to_string(),
            start_height: 0,              // SPV client starts at 0
            relay: match self.mempool_strategy {
                MempoolStrategy::FetchAll => true,  // Want all transactions for FetchAll strategy
                _ => false,                         // Don't want relay for other strategies
            },
            mn_auth_challenge: [0; 32],   // Not a masternode
            masternode_connection: false, // Not connecting to masternode
        }
    }

    /// Get current handshake state.
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Get peer version if available.
    pub fn peer_version(&self) -> Option<u32> {
        self.peer_version
    }
    
    /// Check if peer supports headers2 compression.
    pub fn peer_supports_headers2(&self) -> bool {
        self.peer_services
            .map(|services| services.has(NODE_HEADERS_COMPRESSED))
            .unwrap_or(false)
    }
}
