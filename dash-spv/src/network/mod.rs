//! Network layer for the Dash SPV client.

pub mod addrv2;
pub mod constants;
pub mod discovery;
pub mod handshake;
pub mod manager;
pub mod peer;
pub mod pool;
pub mod reputation;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::error::NetworkResult;
use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;

pub use handshake::{HandshakeManager, HandshakeState};
pub use manager::PeerNetworkManager;
pub use peer::Peer;

/// Network manager trait for abstracting network operations.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
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

    /// Get the best block height reported by connected peers.
    async fn get_peer_best_height(&self) -> NetworkResult<Option<u32>>;

    /// Check if any connected peer supports a specific service.
    async fn has_peer_with_service(
        &self,
        service_flags: dashcore::network::constants::ServiceFlags,
    ) -> bool;

    /// Check if any connected peer supports headers2 compression.
    async fn has_headers2_peer(&self) -> bool {
        self.has_peer_with_service(dashcore::network::constants::NODE_HEADERS_COMPRESSED).await
    }

    /// Get the peer ID of the last peer that sent us a message.
    /// Returns PeerId(0) if no message has been received yet.
    async fn get_last_message_peer_id(&self) -> crate::types::PeerId {
        crate::types::PeerId(0) // Default implementation
    }

    /// Get the socket address of the last peer that sent us a message.
    /// Default implementation returns None; implementations with peer tracking can override.
    async fn get_last_message_peer_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }

    /// Mark that the current peer has sent us Headers2 messages.
    async fn mark_peer_sent_headers2(&mut self) -> NetworkResult<()> {
        Ok(()) // Default implementation
    }

    /// Check if the current peer has sent us Headers2 messages.
    async fn peer_has_sent_headers2(&self) -> bool {
        false // Default implementation
    }

    /// Request QRInfo from the network.
    ///
    /// # Arguments
    /// * `base_block_hashes` - Array of base block hashes for the masternode lists the light client already knows
    /// * `block_request_hash` - Hash of the block for which the masternode list diff is requested
    /// * `extra_share` - Optional flag to indicate if an extra share is requested
    async fn request_qr_info(
        &mut self,
        base_block_hashes: Vec<BlockHash>,
        block_request_hash: BlockHash,
        extra_share: bool,
    ) -> NetworkResult<()> {
        use dashcore::network::message_qrinfo::GetQRInfo;

        let get_qr_info = GetQRInfo {
            base_block_hashes: base_block_hashes.clone(),
            block_request_hash,
            extra_share,
        };

        let base_hashes_count = get_qr_info.base_block_hashes.len();

        self.send_message(NetworkMessage::GetQRInfo(get_qr_info)).await?;

        tracing::debug!(
            "Requested QRInfo with {} base hashes for block {}, extra_share={}",
            base_hashes_count,
            block_request_hash,
            extra_share
        );

        Ok(())
    }

    /// Penalize the last peer that sent us a message by adjusting reputation.
    /// Default implementation is a no-op for managers without reputation.
    async fn penalize_last_message_peer(
        &self,
        _score_change: i32,
        _reason: &str,
    ) -> NetworkResult<()> {
        Ok(())
    }

    /// Convenience: penalize last peer for an invalid ChainLock.
    async fn penalize_last_message_peer_invalid_chainlock(
        &self,
        reason: &str,
    ) -> NetworkResult<()> {
        self.penalize_last_message_peer(
            crate::network::reputation::misbehavior_scores::INVALID_CHAINLOCK,
            reason,
        )
        .await
    }

    /// Convenience: penalize last peer for an invalid InstantLock.
    async fn penalize_last_message_peer_invalid_instantlock(
        &self,
        reason: &str,
    ) -> NetworkResult<()> {
        self.penalize_last_message_peer(
            crate::network::reputation::misbehavior_scores::INVALID_INSTANTLOCK,
            reason,
        )
        .await
    }
}
