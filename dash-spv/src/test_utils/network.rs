//! In-memory [`NetworkManager`] for unit tests: records sends, injects inbound
//! messages and peer events.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::network::{
    request_keys, Inbound, InboundMessage, MessageType, NetworkEvent, NetworkManager, RequestKey,
};

pub fn test_socket_address(id: u8) -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 40000 + id as u16)
}

struct Subscriber {
    kinds: Vec<MessageType>,
    tx: UnboundedSender<Inbound>,
}

pub struct MockNetworkManager {
    sent: Mutex<Vec<NetworkMessage>>,
    sent_to: Mutex<Vec<(SocketAddr, NetworkMessage)>>,
    broadcasts: Mutex<Vec<NetworkMessage>>,
    released: Mutex<Vec<RequestKey>>,
    banned: Mutex<Vec<SocketAddr>>,
    /// Mirrors the broker's de-duplication, so a manager that re-declares a request
    /// it never correlated fails here instead of hanging against a real broker.
    in_play: Mutex<HashSet<RequestKey>>,
    subscribers: Mutex<Vec<Subscriber>>,
    events_tx: RwLock<broadcast::Sender<NetworkEvent>>,
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
            released: Mutex::new(Vec::new()),
            banned: Mutex::new(Vec::new()),
            in_play: Mutex::new(HashSet::new()),
            subscribers: Mutex::new(Vec::new()),
            events_tx: RwLock::new(events_tx),
            tip: AtomicU32::new(0),
            connected: AtomicU32::new(1),
        }
    }

    /// Close the network event bus, which fails the sync loop of a client
    /// running on this network.
    pub async fn close_network_events(&self) {
        *self.events_tx.write().await = broadcast::Sender::new(1);
    }

    pub async fn sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent.lock().await.clone()
    }

    pub async fn sent_to_messages(&self) -> Vec<(SocketAddr, NetworkMessage)> {
        self.sent_to.lock().await.clone()
    }

    pub async fn broadcast_messages(&self) -> Vec<NetworkMessage> {
        self.broadcasts.lock().await.clone()
    }

    pub async fn released_keys(&self) -> Vec<RequestKey> {
        self.released.lock().await.clone()
    }

    pub async fn banned_peers(&self) -> Vec<SocketAddr> {
        self.banned.lock().await.clone()
    }

    /// Clears the recorders but not the in-play requests, which stay de-duplicated
    /// until released or [`Self::release_requests_in_play`].
    pub async fn clear_sent(&self) {
        self.sent.lock().await.clear();
        self.sent_to.lock().await.clear();
        self.broadcasts.lock().await.clear();
    }

    /// Simulates the broker re-queueing requests when their peers are lost; call it
    /// where a test's disconnect happens so the keys stop de-duplicating.
    pub async fn release_requests_in_play(&self) {
        self.in_play.lock().await.clear();
    }

    pub async fn requests_in_play(&self) -> usize {
        self.in_play.lock().await.len()
    }

    pub fn set_tip(&self, tip: u32) {
        self.tip.store(tip, Ordering::SeqCst);
    }

    pub fn set_connected(&self, n: u32) {
        self.connected.store(n, Ordering::SeqCst);
    }

    pub async fn inject(&self, peer: SocketAddr, msg: NetworkMessage) {
        self.inject_inbound(peer, msg.into()).await
    }

    /// Like [`Self::inject`], with the decode-time data (e.g. `headers2` hashes).
    pub async fn inject_inbound(&self, peer: SocketAddr, msg: InboundMessage) {
        let kind = MessageType::from_cmd(msg.cmd());
        let shared = std::sync::Arc::new(msg);
        let subs = self.subscribers.lock().await;
        for sub in subs.iter() {
            if kind.map(|k| sub.kinds.contains(&k)).unwrap_or(false) {
                let _ = sub.tx.send((peer, shared.clone()));
            }
        }
    }

    pub async fn emit_event(&self, event: NetworkEvent) {
        let _ = self.events_tx.read().await.send(event);
    }
}

#[async_trait]
impl NetworkManager for MockNetworkManager {
    async fn start(&self) {}

    async fn stop(&self) {}

    async fn enqueue(&self, _height: u32, msg: NetworkMessage) {
        // Same as the broker: a keyed request in play is dropped until released, and
        // keyless traffic is never de-duplicated.
        let keys = request_keys(&msg);
        if !keys.is_empty() {
            let mut in_play = self.in_play.lock().await;
            if keys.iter().any(|key| in_play.contains(key)) {
                return;
            }
            in_play.extend(keys);
        }
        self.sent.lock().await.push(msg);
    }

    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        self.sent_to.lock().await.push((addr, msg));
        true
    }

    async fn broadcast(&self, msg: NetworkMessage) -> crate::error::NetworkResult<()> {
        self.broadcasts.lock().await.push(msg);
        if self.connected.load(Ordering::SeqCst) == 0 {
            return Err(crate::NetworkError::ConnectionFailed("No connected peers".to_string()));
        }
        Ok(())
    }

    async fn dispatch_local(&self, msg: NetworkMessage) {
        self.inject(test_socket_address(0), msg).await;
    }

    async fn release_request(&self, key: RequestKey) {
        self.in_play.lock().await.remove(&key);
        self.released.lock().await.push(key);
    }

    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        let (tx, rx) = unbounded_channel();
        self.subscribers.lock().await.push(Subscriber {
            kinds: kinds.to_vec(),
            tx,
        });
        rx
    }

    fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        // Only `close_network_events` writes, and never while a client subscribes.
        self.events_tx.try_read().expect("event bus is being replaced").subscribe()
    }

    fn tip(&self) -> u32 {
        self.tip.load(Ordering::SeqCst)
    }

    async fn connected_count(&self) -> u32 {
        self.connected.load(Ordering::SeqCst)
    }

    async fn ban_peer(&self, addr: SocketAddr) {
        self.banned.lock().await.push(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::SendRequest;
    use dashcore::network::message_filter::GetCFilters;
    use dashcore::BlockHash;

    fn get_cfilters(start: u32) -> NetworkMessage {
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: BlockHash::dummy(9),
        })
    }

    #[tokio::test]
    async fn a_request_already_in_play_is_dropped() {
        let mock = MockNetworkManager::new();

        mock.send(get_cfilters(0)).await;
        mock.send(get_cfilters(0)).await;
        assert_eq!(
            mock.sent_messages().await.len(),
            1,
            "the re-declaration must not reach the wire"
        );

        mock.send(get_cfilters(1000)).await;
        assert_eq!(mock.sent_messages().await.len(), 2, "a different key is a different request");
    }

    #[tokio::test]
    async fn the_key_is_released_by_the_response() {
        let mock = MockNetworkManager::new();

        mock.send(get_cfilters(0)).await;
        mock.send(get_cfilters(0)).await;
        assert_eq!(mock.sent_messages().await.len(), 1);

        mock.release_request(RequestKey::CFilters(0)).await;
        assert_eq!(mock.requests_in_play().await, 0);

        mock.send(get_cfilters(0)).await;
        assert_eq!(
            mock.sent_messages().await.len(),
            2,
            "an answered request may be declared again"
        );
    }

    #[tokio::test]
    async fn keyless_traffic_is_never_de_duplicated() {
        let mock = MockNetworkManager::new();

        mock.send(NetworkMessage::MemPool).await;
        mock.send(NetworkMessage::MemPool).await;

        assert_eq!(mock.sent_messages().await.len(), 2);
        assert_eq!(mock.requests_in_play().await, 0);
    }

    #[tokio::test]
    async fn clearing_the_recorders_does_not_release_the_requests() {
        let mock = MockNetworkManager::new();

        mock.send(get_cfilters(0)).await;
        mock.clear_sent().await;
        mock.send(get_cfilters(0)).await;
        assert!(mock.sent_messages().await.is_empty(), "still in play, so still de-duplicated");

        mock.release_requests_in_play().await;
        mock.send(get_cfilters(0)).await;
        assert_eq!(mock.sent_messages().await.len(), 1);
    }
}
