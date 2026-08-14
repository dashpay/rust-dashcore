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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::network::{
    Inbound, InboundMessage, MessageType, NetworkEvent, NetworkManager, RequestKey,
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
    completed: Mutex<Vec<(SocketAddr, usize)>>,
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
            completed: Mutex::new(Vec::new()),
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

    /// Every `(peer, n)` reported via [`NetworkManager::request_completed`].
    pub fn completed_requests(&self) -> Vec<(SocketAddr, usize)> {
        self.completed.lock().expect("mock mutex poisoned").clone()
    }

    /// Clear all recorded sends (handy between phases of a test).
    pub fn clear_sent(&self) {
        self.sent.lock().expect("mock mutex poisoned").clear();
        self.sent_to.lock().expect("mock mutex poisoned").clear();
        self.broadcasts.lock().expect("mock mutex poisoned").clear();
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
        self.sent.lock().expect("mock mutex poisoned").push(msg);
    }

    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        self.sent_to.lock().expect("mock mutex poisoned").push((addr, msg));
        true
    }

    fn broadcast(&self, msg: NetworkMessage) {
        self.broadcasts.lock().expect("mock mutex poisoned").push(msg);
    }

    async fn dispatch_local(&self, msg: NetworkMessage) {
        self.inject(test_socket_address(0), msg);
    }

    async fn request_answered(&self, key: RequestKey) {
        self.answered.lock().expect("mock mutex poisoned").push(key);
    }

    async fn request_completed(&self, peer: SocketAddr, n: usize) {
        self.completed.lock().expect("mock mutex poisoned").push((peer, n));
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
