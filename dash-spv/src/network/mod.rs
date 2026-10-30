mod bans;
mod broker;
mod costs;
mod discovery;
mod manager;
mod peer;
pub mod transport;

use crate::error::NetworkResult;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::{GetHeadersMessage, Inventory};
use dashcore::network::message_filter::{GetCFHeaders, GetCFilters};
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedReceiver;

pub use broker::RequestKey;
pub use manager::NetworkEvent;
pub use manager::{Inbound, InboundMessage, MessageType, PeerNetworkManager};
pub use transport::TransportPreference;
// Used by the mock network manager to enforce the same de-duplication contract.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) use broker::request_keys;

pub trait Request: Send + 'static {
    fn height(&self) -> u32;
    fn into_message(self) -> NetworkMessage;
}

impl Request for NetworkMessage {
    fn height(&self) -> u32 {
        match self {
            NetworkMessage::GetCFilters(m) => m.start_height,
            NetworkMessage::GetCFHeaders(m) => m.start_height,
            _ => 0,
        }
    }

    fn into_message(self) -> NetworkMessage {
        self
    }
}

impl Request for GetCFilters {
    fn height(&self) -> u32 {
        self.start_height
    }

    fn into_message(self) -> NetworkMessage {
        NetworkMessage::GetCFilters(self)
    }
}

impl Request for GetCFHeaders {
    fn height(&self) -> u32 {
        self.start_height
    }

    fn into_message(self) -> NetworkMessage {
        NetworkMessage::GetCFHeaders(self)
    }
}

/// `getdata` for one block.
pub struct BlockRequest {
    pub height: u32,
    pub hash: BlockHash,
}

impl Request for BlockRequest {
    fn height(&self) -> u32 {
        self.height
    }
    fn into_message(self) -> NetworkMessage {
        NetworkMessage::GetData(vec![Inventory::Block(self.hash)])
    }
}

/// `getheaders` from the header at `height`, whose hash is `locator`.
pub struct HeadersRequest {
    pub height: u32,
    pub locator: BlockHash,
}

impl Request for HeadersRequest {
    fn height(&self) -> u32 {
        self.height
    }
    fn into_message(self) -> NetworkMessage {
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![self.locator],
            BlockHash::all_zeros(),
        ))
    }
}

/// Peer-to-peer network surface the sync layer depends on, so it can be mocked in tests.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
    /// Call after every consumer has subscribed, so the initial peer events are seen.
    async fn start(&self);

    async fn stop(&self);

    /// Fire-and-forget: keyed requests are de-duplicated, paced, timed out and retried.
    /// Within a message class, the lowest `height` is sent first. Use [`SendRequest::send`].
    async fn enqueue(&self, height: u32, msg: NetworkMessage);

    /// Returns `false` if the peer is not connected or the write failed.
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool;

    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()>;

    /// Inject a message into the local pump as if received from a peer.
    async fn dispatch_local(&self, msg: NetworkMessage);

    /// Stops timeout/retry tracking of `key`.
    async fn request_answered(&self, key: RequestKey);

    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound>;

    fn events(&self) -> broadcast::Receiver<NetworkEvent>;

    /// Best tip height advertised across connected peers.
    fn tip(&self) -> u32;

    async fn connected_count(&self) -> u32;

    /// Closes the peer and refuses to dial it again for a day.
    async fn ban_peer(&self, addr: SocketAddr);
}

/// `send` on any [`NetworkManager`], including `dyn NetworkManager`.
#[async_trait]
pub trait SendRequest {
    async fn send<R: Request>(&self, request: R);
}

#[async_trait]
impl<T: NetworkManager + ?Sized> SendRequest for T {
    async fn send<R: Request>(&self, request: R) {
        self.enqueue(request.height(), request.into_message()).await
    }
}
