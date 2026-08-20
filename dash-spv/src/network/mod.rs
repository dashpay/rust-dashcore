mod discovery;
mod manager;
mod peer;

use crate::error::NetworkResult;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedReceiver;

// `NetworkEvent` is part of the public `EventHandler` API (delivered to
// `on_network_event`), so it stays exported. The peer-to-peer manager and its
// request/message plumbing are internal: the client builds and owns the manager
// itself (see `DashSpvClient::new`), so none of these are part of the public API.
pub use manager::NetworkEvent;
// These form the `NetworkManager` trait's interface, which appears in the public
// `DashSpvClient<W, N: NetworkManager, S>` bound, so they are part of the public API.
pub use manager::{Inbound, InboundMessage, MessageType, PeerNetworkManager, RequestKey};

/// Abstraction over the peer-to-peer network manager.
///
/// The sync managers and pipelines depend on this trait rather than the concrete
/// [`PeerNetworkManager`], so a lightweight mock can drive them in unit tests and
/// the client stays generic over the network implementation. It is the *minimum*
/// surface the sync layer needs: declare requests, subscribe to inbound messages
/// and peer events, correlate answered requests, and lifecycle.
///
/// Requests are fire-and-forget: the implementation de-duplicates by request key,
/// paces, times out and retries. Once a response is correlated to a request, the
/// caller reports it via [`request_answered`](Self::request_answered), the single
/// call that both stops the tracking and gives the serving peer back the
/// in-flight unit the request was holding.
#[async_trait]
pub trait NetworkManager: Send + Sync + 'static {
    /// Begin peer discovery/connection. Call *after* every consumer has
    /// subscribed, so the initial `PeersUpdated`/`PeerConnected` events are seen.
    fn start(&self);

    /// Tear down all peer connections and background tasks.
    fn stop(&self);

    /// Declare a request/message. Keyed requests are de-duplicated, paced,
    /// timed out and retried by the implementation.
    async fn send(&self, msg: NetworkMessage);

    /// Send a message to one specific peer. Returns `false` if the peer is not
    /// connected or the write failed.
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool;

    /// Broadcast a message to all connected peers.
    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()>;

    /// Inject a message into the local pump as if received from a peer.
    async fn dispatch_local(&self, msg: NetworkMessage);

    /// Report that a request key has been answered: it stops being tracked for
    /// timeout/retry, and the peer that was serving it gets its in-flight unit
    /// back.
    async fn request_answered(&self, key: RequestKey);

    /// Subscribe to inbound messages of the given types. Each inbound item is a
    /// `(peer, message)` pair.
    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound>;

    /// Subscribe to peer-set lifecycle events.
    fn events(&self) -> broadcast::Receiver<NetworkEvent>;

    /// Best tip height advertised across connected peers.
    fn tip(&self) -> u32;

    /// Number of currently connected peers.
    async fn connected_count(&self) -> u32;
}

// TODO: Inline the methods
// Thin delegation to the inherent methods of `PeerNetworkManager`. Method-call
// syntax (`self.method(..)`) resolves to the inherent method (inherent methods
// take precedence over trait methods), so this does not recurse and adds no
// behaviour of its own.
#[async_trait]
impl NetworkManager for PeerNetworkManager {
    fn start(&self) {
        self.start()
    }
    fn stop(&self) {
        self.stop()
    }
    async fn send(&self, msg: NetworkMessage) {
        self.send(msg).await
    }
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        self.send_to(addr, msg).await
    }
    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()> {
        self.broadcast(msg).await
    }
    async fn dispatch_local(&self, msg: NetworkMessage) {
        self.dispatch_local(msg).await
    }
    async fn request_answered(&self, key: RequestKey) {
        self.request_answered(key).await
    }
    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        self.subscribe(kinds).await
    }
    fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.events()
    }
    fn tip(&self) -> u32 {
        self.tip()
    }
    async fn connected_count(&self) -> u32 {
        self.connected_count().await
    }
}
