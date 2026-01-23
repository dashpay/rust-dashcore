//! Network layer for the Dash SPV client.

pub mod addrv2;
pub mod constants;
pub mod discovery;
pub mod handshake;
pub mod manager;
pub mod peer;
pub mod pool;
pub mod reputation;
mod subscriptions;

#[cfg(test)]
mod tests;

use crate::error::NetworkResult;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;
pub use handshake::{HandshakeManager, HandshakeState};
pub use manager::PeerNetworkManager;
pub use peer::Peer;
use std::net::SocketAddr;
pub use subscriptions::{Message, MessageRouter};
use tokio::sync::mpsc::UnboundedReceiver;

/// Message types that subscribers can subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Block headers (uncompressed).
    Headers,
    /// Block headers (compressed).
    Headers2,
    /// Compact filter headers.
    CFHeaders,
    /// Compact filters.
    CFilter,
    /// Full blocks.
    Block,
    /// Masternode list diffs.
    MnListDiff,
    /// Quorum rotation info.
    QRInfo,
    /// ChainLock signatures.
    CLSig,
    /// InstantSend locks.
    ISLock,
    /// Inventory announcements.
    Inv,
}

impl MessageType {
    /// Check if a NetworkMessage matches this type.
    pub fn matches(&self, msg: &NetworkMessage) -> bool {
        matches!(
            (self, msg),
            (MessageType::Headers, NetworkMessage::Headers(_))
                | (MessageType::Headers2, NetworkMessage::Headers2(_))
                | (MessageType::CFHeaders, NetworkMessage::CFHeaders(_))
                | (MessageType::CFilter, NetworkMessage::CFilter(_))
                | (MessageType::Block, NetworkMessage::Block(_))
                | (MessageType::MnListDiff, NetworkMessage::MnListDiff(_))
                | (MessageType::QRInfo, NetworkMessage::QRInfo(_))
                | (MessageType::CLSig, NetworkMessage::CLSig(_))
                | (MessageType::ISLock, NetworkMessage::ISLock(_))
                | (MessageType::Inv, NetworkMessage::Inv(_))
        )
    }
}

/// Network manager trait for abstracting network operations.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
    /// Convert to Any for downcasting.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Subscribe to specific message types.
    /// Returns a receiver that yields only messages of the subscribed types.
    async fn subscribe(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message>;

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
    async fn penalize_peer(&self, _address: SocketAddr, _score_change: i32, _reason: &str) {}

    /// Penalize a peer by address for an invalid ChainLock.
    async fn penalize_peer_invalid_chainlock(&self, address: SocketAddr, reason: &str) {
        self.penalize_peer(
            address,
            crate::network::reputation::misbehavior_scores::INVALID_CHAINLOCK,
            reason,
        )
        .await;
    }

    /// Penalize a peer by address for an invalid InstantLock.
    async fn penalize_peer_invalid_instantlock(&self, peer_address: SocketAddr, reason: &str) {
        self.penalize_peer(
            peer_address,
            crate::network::reputation::misbehavior_scores::INVALID_INSTANTLOCK,
            reason,
        )
        .await;
    }
}
