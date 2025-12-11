//! Transport layer abstraction for Dash P2P connections.
//!
//! This module provides a `Transport` trait that abstracts the underlying
//! communication protocol (V1 unencrypted or V2 BIP324 encrypted).

pub mod message_ids;
pub mod v1;
pub mod v2;
pub mod v2_handshake;

use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;

use crate::error::NetworkResult;

pub use v1::V1Transport;
pub use v2::V2Transport;
pub use v2_handshake::{V2HandshakeManager, V2HandshakeResult, V2Session};

/// Transport preference for peer connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPreference {
    /// Use V2 encrypted transport only (fail if peer doesn't support).
    V2Only,
    /// Prefer V2 encrypted transport, fallback to V1 if needed (default).
    #[default]
    V2Preferred,
    /// Use V1 unencrypted transport only (for compatibility testing).
    V1Only,
}

/// Result of establishing a transport connection.
pub enum TransportEstablishResult {
    /// Successfully established V1 transport.
    V1(V1Transport),
    /// Need to fallback to V1 (V2 handshake detected V1-only peer).
    FallbackToV1,
}

/// Abstract transport layer for P2P communication.
///
/// This trait is implemented by both V1Transport (unencrypted) and
/// V2Transport (BIP324 encrypted) to provide a unified interface
/// for message exchange.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a network message over the transport.
    ///
    /// # Arguments
    /// * `message` - The network message to send
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NetworkError)` on failure
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()>;

    /// Receive a network message from the transport.
    ///
    /// # Returns
    /// * `Ok(Some(message))` if a complete message was received
    /// * `Ok(None)` if no complete message is available yet (non-blocking)
    /// * `Err(NetworkError)` on failure or disconnection
    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>>;

    /// Check if the transport is connected.
    fn is_connected(&self) -> bool;

    /// Get the transport protocol version (1 or 2).
    fn protocol_version(&self) -> u8;

    /// Get the number of bytes sent over this transport.
    fn bytes_sent(&self) -> u64;

    /// Get the number of bytes received over this transport.
    fn bytes_received(&self) -> u64;

    /// Shutdown the transport connection.
    async fn shutdown(&mut self) -> NetworkResult<()>;
}
