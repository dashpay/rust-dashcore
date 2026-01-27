//! Network layer for the Dash SPV client.

pub mod addrv2;
pub mod constants;
pub mod discovery;
pub mod handshake;
pub mod manager;
mod message_dispatcher;
pub mod peer;
pub mod pool;
mod reputation;

mod message_type;
#[cfg(test)]
mod tests;

use crate::{error::NetworkResult, network::reputation::ChangeReason};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;
pub use handshake::{HandshakeManager, HandshakeState};
pub use manager::PeerNetworkManager;
pub use message_dispatcher::{Message, MessageDispatcher};
pub use message_type::MessageType;
pub use peer::Peer;
pub(crate) use reputation::PeerReputation;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedReceiver;

/// Network manager trait for abstracting network operations.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
    /// Convert to Any for downcasting.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Creates and returns a receiver that yields only messages of the matching the provided message types.
    async fn message_receiver(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message>;

    /// Connect to the network.
    async fn connect(&mut self) -> NetworkResult<()>;

    /// Disconnect from the network.
    async fn disconnect(&mut self) -> NetworkResult<()>;

    /// Send a message to a peer.
    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()>;

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

    /// Penalize a peer by address by adjusting reputation.
    /// Default implementation is a no-op for managers without reputation.
    async fn penalize_peer(&self, _address: SocketAddr, _reason: ChangeReason) {}

    /// Penalize a peer by address for an invalid ChainLock.
    async fn penalize_peer_invalid_chainlock(&self, address: SocketAddr) {
        self.penalize_peer(address, ChangeReason::InvalidChainLock).await;
    }

    /// Penalize a peer by address for an invalid InstantLock.
    async fn penalize_peer_invalid_instantlock(&self, peer_address: SocketAddr) {
        self.penalize_peer(peer_address, ChangeReason::InvalidInstantLock).await;
    }
}
