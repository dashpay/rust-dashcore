mod discovery;
mod manager;
mod peer;

use crate::error::NetworkResult;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedReceiver;

pub use manager::NetworkEvent;
pub use manager::{Inbound, InboundMessage, MessageType, PeerNetworkManager, RequestKey};
// Used by the mock network manager to enforce the same de-duplication contract.
pub(crate) use manager::request_keys;

/// Peer-to-peer network surface the sync layer depends on, so it can be mocked in tests.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
    /// Call after every consumer has subscribed, so the initial peer events are seen.
    async fn start(&self);

    async fn stop(&self);

    /// Fire-and-forget: keyed requests are de-duplicated, paced, timed out and retried.
    async fn send(&self, msg: NetworkMessage);

    /// Returns `false` if the peer is not connected or the write failed.
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool;

    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()>;

    /// Inject a message into the local pump as if received from a peer.
    async fn dispatch_local(&self, msg: NetworkMessage);

    /// Stops timeout/retry tracking of `key` and returns the serving peer's in-flight unit.
    async fn request_answered(&self, key: RequestKey);

    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound>;

    fn events(&self) -> broadcast::Receiver<NetworkEvent>;

    /// Best tip height advertised across connected peers.
    fn tip(&self) -> u32;

    async fn connected_count(&self) -> u32;
}
