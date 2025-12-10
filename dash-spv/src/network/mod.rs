//! Network layer for the Dash SPV client.

pub mod addrv2;
pub mod constants;
pub mod discovery;
mod event;
pub mod handshake;
pub mod manager;
mod message_dispatcher;
pub mod peer;
pub mod pool;
pub mod reputation;

mod message_type;
#[cfg(test)]
mod tests;

pub use event::NetworkEvent;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::NetworkResult;
use crate::event_bus::EventReceiver;
use crate::NetworkError;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::{GetHeadersMessage, Inventory};
use dashcore::network::message_filter::{GetCFHeaders, GetCFilters};
use dashcore::network::message_qrinfo::GetQRInfo;
use dashcore::network::message_sml::GetMnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
pub use handshake::{HandshakeManager, HandshakeState};
pub use manager::PeerNetworkManager;
pub use message_dispatcher::{Message, MessageDispatcher};
pub use message_type::MessageType;
pub use peer::Peer;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedReceiver;

/// Request to send to network.
#[derive(Debug)]
pub enum NetworkRequest {
    /// Send a message to the network.
    SendMessage(NetworkMessage),
}

/// Handle for managers to queue outgoing network requests.
#[derive(Clone)]
pub struct RequestSender {
    tx: mpsc::UnboundedSender<NetworkRequest>,
}

impl RequestSender {
    /// Create a new RequestSender.
    pub fn new(tx: mpsc::UnboundedSender<NetworkRequest>) -> Self {
        Self {
            tx,
        }
    }

    /// Queue a message to be sent to the network.
    fn send_message(&self, msg: NetworkMessage) -> NetworkResult<()> {
        self.tx
            .send(NetworkRequest::SendMessage(msg))
            .map_err(|e| NetworkError::ProtocolError(e.to_string()))
    }

    pub fn request_inventory(&self, inventory: Vec<Inventory>) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetData(inventory))
    }

    pub fn request_block_headers(&self, start_hash: BlockHash) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![start_hash],
            BlockHash::all_zeros(),
        )))
    }

    pub fn request_filter_headers(
        &self,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height,
            stop_hash,
        }))
    }

    pub fn request_filters(&self, start_height: u32, stop_hash: BlockHash) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height,
            stop_hash,
        }))
    }

    pub fn request_mnlist_diff(
        &self,
        base_block_hash: BlockHash,
        block_hash: BlockHash,
    ) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetMnListD(GetMnListDiff {
            base_block_hash,
            block_hash,
        }))
    }

    pub fn request_qr_info(
        &self,
        known_block_hashes: Vec<BlockHash>,
        target_block_hash: BlockHash,
    ) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetQRInfo(GetQRInfo {
            base_block_hashes: known_block_hashes,
            block_request_hash: target_block_hash,
            extra_share: true,
        }))
    }

    pub fn request_blocks(&self, hashes: Vec<BlockHash>) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetData(
            hashes.into_iter().map(Inventory::Block).collect(),
        ))
    }
}

/// Network manager trait for abstracting network operations.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
    /// Convert to Any for downcasting.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Creates and returns a receiver that yields only messages of the matching the provided message types.
    async fn message_receiver(&mut self, types: &[MessageType]) -> UnboundedReceiver<Message>;

    /// Get a sender for queuing outgoing network requests.
    ///
    /// Messages sent via this sender are delivered to the network asynchronously.
    fn request_sender(&self) -> RequestSender;

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
    async fn get_peer_best_height(&self) -> Option<CoreBlockHeight>;

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

    /// Subscribe to network events (peer connections, disconnections).
    ///
    /// Returns a broadcast receiver for network events.
    fn subscribe_network_events(&self) -> EventReceiver<NetworkEvent>;
}
