//! Network handshake management.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dashcore::network::constants;
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_network::VersionMessage;
use dashcore::Network;
// Hash trait not needed in current implementation

use crate::error::{NetworkError, NetworkResult};
use crate::network::connection::TcpConnection;

/// Handshake state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state.
    Init,
    /// Version message sent.
    VersionSent,
    /// Handshake complete.
    Complete,
}

/// Manages the network handshake process.
pub struct HandshakeManager {
    _network: Network,
    state: HandshakeState,
    our_version: u32,
    peer_version: Option<u32>,
}

impl HandshakeManager {
    /// Create a new handshake manager.
    pub fn new(network: Network) -> Self {
        Self {
            _network: network,
            state: HandshakeState::Init,
            our_version: constants::PROTOCOL_VERSION,
            peer_version: None,
        }
    }

    /// Perform the handshake with a peer.
    pub async fn perform_handshake(&mut self, connection: &mut TcpConnection) -> NetworkResult<()> {
        use tokio::time::{timeout, Duration};

        // Send version message
        self.send_version(connection).await?;
        self.state = HandshakeState::VersionSent;

        // Define timeout for the entire handshake process
        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
        const MESSAGE_POLL_INTERVAL: Duration = Duration::from_millis(100);

        let start_time = tokio::time::Instant::now();

        // Wait for responses with timeout
        loop {
            // Check if we've exceeded the overall handshake timeout
            if start_time.elapsed() > HANDSHAKE_TIMEOUT {
                return Err(NetworkError::Timeout);
            }

            // Try to receive a message with a short timeout
            match timeout(MESSAGE_POLL_INTERVAL, connection.receive_message()).await {
                Ok(Ok(Some(message))) => {
                    match self.handle_handshake_message(connection, message).await? {
                        Some(HandshakeState::Complete) => {
                            self.state = HandshakeState::Complete;
                            break;
                        }
                        _ => continue,
                    }
                }
                Ok(Ok(None)) => {
                    // No message available, yield to prevent tight loop
                    tokio::task::yield_now().await;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout on receive_message, continue to check overall timeout
                    continue;
                }
            }
        }

        tracing::info!("Handshake completed successfully");
        Ok(())
    }

    /// Reset the handshake state.
    pub fn reset(&mut self) {
        self.state = HandshakeState::Init;
        self.peer_version = None;
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

                // Send SendAddrV2 first to signal support (must be before verack!)
                tracing::debug!("Sending sendaddrv2 to signal AddrV2 support");
                connection.send_message(NetworkMessage::SendAddrV2).await?;

                // Then send verack
                tracing::debug!("Sending verack in response to version");
                connection.send_message(NetworkMessage::Verack).await?;
                tracing::debug!("Sent verack, handshake state: {:?}", self.state);

                // Check if handshake is complete (we've sent version and received version)
                if self.state == HandshakeState::VersionSent {
                    tracing::info!(
                        "Handshake complete - sent verack in response to peer's version!"
                    );
                    return Ok(Some(HandshakeState::Complete));
                }

                Ok(None)
            }
            NetworkMessage::Verack => {
                tracing::debug!("Received verack message, current state: {:?}", self.state);
                if self.state == HandshakeState::VersionSent {
                    tracing::info!("Handshake complete - received peer's verack!");
                    return Ok(Some(HandshakeState::Complete));
                } else {
                    tracing::warn!(
                        "Received verack but state is not VersionSent: {:?}",
                        self.state
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

        let services = ServiceFlags::NONE; // SPV client doesn't provide services

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
            relay: false,                 // We don't want transaction relay
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
}
