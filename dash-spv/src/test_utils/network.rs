//! A lightweight in-memory [`NetworkManager`] for unit tests.
//!
//! It records everything the sync layer sends (so a test can assert on the
//! requests a manager/pipeline issued), lets a test inject inbound messages and
//! peer events, and exposes the advertised tip / connected-peer count. No sockets,
//! no background tasks, no DNS.

// The recorders below need a *sync* mutex: `NetworkManager::broadcast` is
// non-async by design (the real implementation spawns and returns), so a
// `tokio::sync::Mutex` cannot be locked there without either making the trait
// method async or spawning — and spawning would race the assertion that follows
// `broadcast()` in a test. Every guard here is a short-lived temporary that never
// crosses an `.await`, so the crate-wide ban on `std::sync::Mutex` (which exists
// to stop guards being held across await points) does not apply to this module.
#![allow(clippy::disallowed_types)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::network::{
    request_keys, Inbound, InboundMessage, MessageType, NetworkEvent, NetworkManager, RequestKey,
};

/// Deterministic loopback socket address for tests (`127.0.0.1:<id>`).
pub fn test_socket_address(id: u8) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 40000 + id as u16)
}

struct Subscriber {
    kinds: Vec<MessageType>,
    tx: UnboundedSender<Inbound>,
}

/// In-memory mock of the peer-to-peer network manager for unit tests.
pub struct MockNetworkManager {
    sent: Mutex<Vec<NetworkMessage>>,
    sent_to: Mutex<Vec<(SocketAddr, NetworkMessage)>>,
    broadcasts: Mutex<Vec<NetworkMessage>>,
    answered: Mutex<Vec<RequestKey>>,
    /// Requests the broker would consider in play, so the mock de-duplicates the
    /// way the real one does. Without it a manager that re-declares a request it
    /// never correlated looks like it sent twice, when against a real broker the
    /// second declaration is dropped and the response it is waiting for never
    /// comes — a contract breach that only showed up in production.
    in_play: Mutex<HashSet<RequestKey>>,
    subscribers: Mutex<Vec<Subscriber>>,
    events_tx: broadcast::Sender<NetworkEvent>,
    tip: AtomicU32,
    connected: AtomicU32,
}

impl Default for MockNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MockNetworkManager {
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(1024);
        Self {
            sent: Mutex::new(Vec::new()),
            sent_to: Mutex::new(Vec::new()),
            broadcasts: Mutex::new(Vec::new()),
            answered: Mutex::new(Vec::new()),
            in_play: Mutex::new(HashSet::new()),
            subscribers: Mutex::new(Vec::new()),
            events_tx,
            tip: AtomicU32::new(0),
            connected: AtomicU32::new(1),
        }
    }

    /// Every message declared via [`NetworkManager::send`], in order.
    pub fn sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent.lock().expect("mock mutex poisoned").clone()
    }

    /// Every `(peer, message)` sent via [`NetworkManager::send_to`], in order.
    pub fn sent_to_messages(&self) -> Vec<(SocketAddr, NetworkMessage)> {
        self.sent_to.lock().expect("mock mutex poisoned").clone()
    }

    /// Every message broadcast via [`NetworkManager::broadcast`], in order.
    pub fn broadcast_messages(&self) -> Vec<NetworkMessage> {
        self.broadcasts.lock().expect("mock mutex poisoned").clone()
    }

    /// Every request key reported via [`NetworkManager::request_answered`].
    pub fn answered_keys(&self) -> Vec<RequestKey> {
        self.answered.lock().expect("mock mutex poisoned").clone()
    }

    /// Clear all recorded sends (handy between phases of a test).
    ///
    /// Deliberately does NOT release the requests still in play: forgetting what
    /// was recorded is not the same as the peers having answered, and a request
    /// the broker is still tracking stays de-duplicated. Use
    /// [`Self::forget_requests_in_play`] for a test that means to start over.
    pub fn clear_sent(&self) {
        self.sent.lock().expect("mock mutex poisoned").clear();
        self.sent_to.lock().expect("mock mutex poisoned").clear();
        self.broadcasts.lock().expect("mock mutex poisoned").clear();
    }

    /// Release every tracked request, the way the broker does when the peers
    /// carrying them are lost: their entries go back to queued and the messages
    /// are re-sent, so the keys stop de-duplicating. A test that simulates losing
    /// the peer set calls this at the point the disconnect happens.
    pub fn release_requests_in_play(&self) {
        self.in_play.lock().expect("mock mutex poisoned").clear();
    }

    /// Requests the mock currently considers in play (declared, not yet answered).
    pub fn requests_in_play(&self) -> usize {
        self.in_play.lock().expect("mock mutex poisoned").len()
    }

    /// Set the tip height reported by [`NetworkManager::tip`].
    pub fn set_tip(&self, tip: u32) {
        self.tip.store(tip, Ordering::SeqCst);
    }

    /// Set the count reported by [`NetworkManager::connected_count`].
    pub fn set_connected(&self, n: u32) {
        self.connected.store(n, Ordering::SeqCst);
    }

    /// Deliver an inbound `(peer, message)` to every subscriber interested in
    /// its message type, as the real pump would.
    pub fn inject(&self, peer: SocketAddr, msg: NetworkMessage) {
        self.inject_inbound(peer, msg.into())
    }

    /// Like [`Self::inject`], for a message carrying what the network layer worked
    /// out while decoding it — the hashes that come free with `headers2`.
    pub fn inject_inbound(&self, peer: SocketAddr, msg: InboundMessage) {
        let kind = MessageType::from_cmd(msg.cmd());
        let shared = std::sync::Arc::new(msg);
        let subs = self.subscribers.lock().expect("mock mutex poisoned");
        for sub in subs.iter() {
            if kind.map(|k| sub.kinds.contains(&k)).unwrap_or(false) {
                let _ = sub.tx.send((peer, shared.clone()));
            }
        }
    }

    /// Emit a peer-set lifecycle event to all [`NetworkManager::events`] subscribers.
    pub fn emit_event(&self, event: NetworkEvent) {
        let _ = self.events_tx.send(event);
    }
}

#[async_trait]
impl NetworkManager for MockNetworkManager {
    fn start(&self) {}

    fn stop(&self) {}

    async fn send(&self, msg: NetworkMessage) {
        // Same de-duplication the real broker applies: a keyed request already in
        // play is dropped, and stays dropped until it is reported answered.
        // Keyless traffic (mempool, tx, control `getdata`) is never de-duplicated.
        let keys = request_keys(&msg);
        if !keys.is_empty() {
            let mut in_play = self.in_play.lock().expect("mock mutex poisoned");
            if keys.iter().any(|key| in_play.contains(key)) {
                return;
            }
            in_play.extend(keys);
        }
        self.sent.lock().expect("mock mutex poisoned").push(msg);
    }

    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        self.sent_to.lock().expect("mock mutex poisoned").push((addr, msg));
        true
    }

    async fn broadcast(&self, msg: NetworkMessage) -> crate::error::NetworkResult<()> {
        self.broadcasts.lock().expect("mock mutex poisoned").push(msg);
        // No peer set here: `set_connected(0)` asks for a broadcast that reached
        // nobody.
        if self.connected.load(Ordering::SeqCst) == 0 {
            return Err(crate::NetworkError::ConnectionFailed("No connected peers".to_string()));
        }
        Ok(())
    }

    async fn dispatch_local(&self, msg: NetworkMessage) {
        self.inject(test_socket_address(0), msg);
    }

    async fn request_answered(&self, key: RequestKey) {
        self.in_play.lock().expect("mock mutex poisoned").remove(&key);
        self.answered.lock().expect("mock mutex poisoned").push(key);
    }

    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        let (tx, rx) = unbounded_channel();
        self.subscribers.lock().expect("mock mutex poisoned").push(Subscriber {
            kinds: kinds.to_vec(),
            tx,
        });
        rx
    }

    fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.events_tx.subscribe()
    }

    fn tip(&self) -> u32 {
        self.tip.load(Ordering::SeqCst)
    }

    async fn connected_count(&self) -> u32 {
        self.connected.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::network::message_filter::GetCFilters;
    use dashcore::BlockHash;

    fn get_cfilters(start: u32) -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: BlockHash::dummy(9),
        })
    }

    /// The mock must drop a request already in play, because the real broker does.
    /// A mock that recorded both would let a manager that re-declares without ever
    /// correlating look correct here and hang against a real peer, waiting on a
    /// response to a request that was never sent.
    #[tokio::test]
    async fn a_request_already_in_play_is_dropped() {
        let mock = MockNetworkManager::new();

        mock.send(get_cfilters(0)).await;
        mock.send(get_cfilters(0)).await;
        assert_eq!(mock.sent_messages().len(), 1, "the re-declaration must not reach the wire");

        mock.send(get_cfilters(1000)).await;
        assert_eq!(mock.sent_messages().len(), 2, "a different key is a different request");
    }

    /// The key is held for the whole lifecycle: only reporting the response frees
    /// it for re-declaration.
    #[tokio::test]
    async fn the_key_is_released_by_the_response() {
        let mock = MockNetworkManager::new();

        mock.send(get_cfilters(0)).await;
        mock.send(get_cfilters(0)).await;
        assert_eq!(mock.sent_messages().len(), 1);

        mock.request_answered(RequestKey::CFilters(0)).await;
        assert_eq!(mock.requests_in_play(), 0);

        mock.send(get_cfilters(0)).await;
        assert_eq!(mock.sent_messages().len(), 2, "an answered request may be declared again");
    }

    /// Traffic the broker does not track is never de-duplicated: two `mempool`
    /// messages must both go out.
    #[tokio::test]
    async fn keyless_traffic_is_never_de_duplicated() {
        let mock = MockNetworkManager::new();

        mock.send(NetworkMessage::MemPool).await;
        mock.send(NetworkMessage::MemPool).await;

        assert_eq!(mock.sent_messages().len(), 2);
        assert_eq!(mock.requests_in_play(), 0);
    }

    /// Clearing the recorders is not the peers answering: a request the broker is
    /// still tracking stays de-duplicated across a `clear_sent`.
    #[tokio::test]
    async fn clearing_the_recorders_does_not_release_the_requests() {
        let mock = MockNetworkManager::new();

        mock.send(get_cfilters(0)).await;
        mock.clear_sent();
        mock.send(get_cfilters(0)).await;
        assert!(mock.sent_messages().is_empty(), "still in play, so still de-duplicated");

        mock.release_requests_in_play();
        mock.send(get_cfilters(0)).await;
        assert_eq!(mock.sent_messages().len(), 1);
    }
}
