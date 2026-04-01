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
use tokio::sync::{broadcast, mpsc};

use crate::error::NetworkResult;
use crate::NetworkError;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::{GetHeadersMessage, Inventory};
use dashcore::network::message_bloom::FilterLoad;
use dashcore::network::message_filter::{GetCFHeaders, GetCFilters};
use dashcore::network::message_qrinfo::GetQRInfo;
use dashcore::network::message_sml::GetMnListDiff;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
pub use handshake::{HandshakeManager, HandshakeState};
pub use manager::PeerNetworkManager;
pub use message_dispatcher::{Message, MessageDispatcher};
pub use message_type::MessageType;
pub use peer::Peer;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedReceiver;

const FILTER_TYPE_DEFAULT: u8 = 0;

/// Request to send to network.
#[derive(Debug)]
pub enum NetworkRequest {
    /// Send a message to the network.
    SendMessage(NetworkMessage),
    /// Send a message to a specific peer.
    SendMessageToPeer(NetworkMessage, SocketAddr),
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

    /// Queue a message to be sent to a specific peer.
    fn send_message_to_peer(
        &self,
        msg: NetworkMessage,
        peer_address: SocketAddr,
    ) -> NetworkResult<()> {
        self.tx
            .send(NetworkRequest::SendMessageToPeer(msg, peer_address))
            .map_err(|e| NetworkError::ProtocolError(e.to_string()))
    }

    /// Request inventory from a specific peer.
    pub fn request_inventory(
        &self,
        inventory: Vec<Inventory>,
        peer_address: SocketAddr,
    ) -> NetworkResult<()> {
        self.send_message_to_peer(NetworkMessage::GetData(inventory), peer_address)
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
            filter_type: FILTER_TYPE_DEFAULT,
            start_height,
            stop_hash,
        }))
    }

    pub fn request_filters(&self, start_height: u32, stop_hash: BlockHash) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetCFilters(GetCFilters {
            filter_type: FILTER_TYPE_DEFAULT,
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
        extra_share: bool,
    ) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetQRInfo(GetQRInfo {
            base_block_hashes: known_block_hashes,
            block_request_hash: target_block_hash,
            extra_share,
        }))
    }

    pub fn request_blocks(&self, hashes: Vec<BlockHash>) -> NetworkResult<()> {
        self.send_message(NetworkMessage::GetData(
            hashes.into_iter().map(Inventory::Block).collect(),
        ))
    }

    /// Send a filterload message to a specific peer.
    pub fn send_filter_load(&self, filter_load: FilterLoad, peer: SocketAddr) -> NetworkResult<()> {
        self.send_message_to_peer(NetworkMessage::FilterLoad(filter_load), peer)
    }

    /// Send a filterclear message to a specific peer.
    pub fn send_filter_clear(&self, peer: SocketAddr) -> NetworkResult<()> {
        self.send_message_to_peer(NetworkMessage::FilterClear, peer)
    }

    /// Send a mempool message to request inventory from a specific peer.
    pub fn request_mempool(&self, peer: SocketAddr) -> NetworkResult<()> {
        self.send_message_to_peer(NetworkMessage::MemPool, peer)
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

    /// Get the number of connected peers.
    fn peer_count(&self) -> usize;

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

    /// Subscribe to network events (peer connections, disconnections).
    ///
    /// Returns a broadcast receiver for network events.
    fn subscribe_network_events(&self) -> broadcast::Receiver<NetworkEvent>;
}
