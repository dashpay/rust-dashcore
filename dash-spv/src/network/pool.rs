//! Peer pool for managing multiple peer connections

use crate::error::{NetworkError, NetworkResult, SpvError as Error};
use crate::network::peer::Peer;
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::prelude::CoreBlockHeight;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Whether a message is a request that expects a response from the peer.
fn is_request(message: &NetworkMessage) -> bool {
    matches!(
        message,
        NetworkMessage::GetHeaders(_)
            | NetworkMessage::GetHeaders2(_)
            | NetworkMessage::GetCFHeaders(_)
            | NetworkMessage::GetCFilters(_)
            | NetworkMessage::GetData(_)
            | NetworkMessage::GetMnListD(_)
            | NetworkMessage::GetQRInfo(_)
            | NetworkMessage::MemPool
    )
}

/// Service flags a message requires from a peer, and whether they are mandatory.
fn required_service(message: &NetworkMessage) -> Option<(ServiceFlags, bool)> {
    match message {
        NetworkMessage::FilterLoad(_) | NetworkMessage::FilterClear | NetworkMessage::MemPool => {
            Some((ServiceFlags::BLOOM, true))
        }
        NetworkMessage::GetCFHeaders(_) | NetworkMessage::GetCFilters(_) => {
            Some((ServiceFlags::COMPACT_FILTERS, true))
        }
        NetworkMessage::GetHeaders(_) | NetworkMessage::GetHeaders2(_) => {
            Some((ServiceFlags::NODE_HEADERS_COMPRESSED, false))
        }
        _ => None,
    }
}

/// Pool for managing multiple peer instances
pub struct PeerPool {
    /// Active peers mapped by address
    peers: Arc<RwLock<HashMap<SocketAddr, Arc<RwLock<Peer>>>>>,
    /// Addresses currently being connected to
    connecting: Arc<RwLock<HashSet<SocketAddr>>>,
    /// Maximum number of simultaneous peer connections (from `ClientConfig::max_peers`).
    max_peers: usize,
}

impl PeerPool {
    /// Create a new peer pool with a connection cap.
    pub fn new(max_peers: usize) -> Self {
        // Assert peers are greater than 0. We may change this
        // so 0 means 'connect to as many peers as you can'
        debug_assert!(max_peers > 0, "max_peers must be greater than 0 for the spv client to sync");

        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            connecting: Arc::new(RwLock::new(HashSet::new())),
            max_peers,
        }
    }

    /// Mark an address as being connected to
    pub async fn mark_connecting(&self, addr: SocketAddr) -> bool {
        let mut connecting = self.connecting.write().await;
        connecting.insert(addr)
    }

    /// Add a peer to the pool
    pub async fn add_peer(&self, addr: SocketAddr, peer: Peer) -> Result<(), Error> {
        let mut peers = self.peers.write().await;
        let mut connecting = self.connecting.write().await;

        // Remove from connecting set
        connecting.remove(&addr);

        // Check if we're at capacity
        if peers.len() >= self.max_peers {
            return Err(Error::Network(NetworkError::ConnectionFailed(format!(
                "Maximum peers ({}) reached",
                self.max_peers
            ))));
        }

        // Check if already connected
        if peers.contains_key(&addr) {
            return Err(Error::Network(NetworkError::ConnectionFailed(format!(
                "Already connected to {}",
                addr
            ))));
        }

        peers.insert(addr, Arc::new(RwLock::new(peer)));
        tracing::info!("Added peer {}, total peers: {}", addr, peers.len());
        Ok(())
    }

    /// Remove a peer from the pool and clear connecting state
    pub async fn remove_peer(&self, addr: &SocketAddr) -> Option<Arc<RwLock<Peer>>> {
        self.connecting.write().await.remove(addr);
        let removed = self.peers.write().await.remove(addr);
        if removed.is_some() {
            tracing::info!("Removed peer {}", addr);
        }
        removed
    }

    /// Get all active peers
    pub async fn get_all_peers(&self) -> Vec<(SocketAddr, Arc<RwLock<Peer>>)> {
        self.peers.read().await.iter().map(|(addr, peer)| (*addr, peer.clone())).collect()
    }

    /// Get a specific peer
    pub async fn get_peer(&self, addr: &SocketAddr) -> Option<Arc<RwLock<Peer>>> {
        self.peers.read().await.get(addr).cloned()
    }

    /// Get the number of active peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Check if connected to a specific peer
    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.peers.read().await.contains_key(addr)
    }

    /// Check if currently connecting to a peer
    pub async fn is_connecting(&self, addr: &SocketAddr) -> bool {
        self.connecting.read().await.contains(addr)
    }

    /// Get all connected peer addresses
    pub async fn get_connected_addresses(&self) -> Vec<SocketAddr> {
        self.peers.read().await.keys().copied().collect()
    }

    pub async fn get_best_height(&self) -> Option<CoreBlockHeight> {
        let peers = self.get_all_peers().await;

        if peers.is_empty() {
            tracing::debug!("get_best_height: No peers available");
            return None;
        }

        let mut best_height = 0u32;
        let mut peer_count = 0;

        for (addr, peer) in peers.iter() {
            let peer_guard = peer.read().await;
            peer_count += 1;

            tracing::debug!(
                "get_best_height: Peer {} - best_height: {:?}, version: {:?}, connected: {}",
                addr,
                peer_guard.best_height(),
                peer_guard.version(),
                peer_guard.is_connected(),
            );

            if let Some(peer_height) = peer_guard.best_height() {
                if peer_height > 0 {
                    best_height = best_height.max(peer_height);
                    tracing::debug!(
                        "get_best_height: Updated best_height to {} from peer {}",
                        best_height,
                        addr
                    );
                }
            }
        }

        tracing::debug!(
            "get_best_height: Checked {} peers, best_height: {}",
            peer_count,
            best_height
        );

        if best_height > 0 {
            Some(best_height)
        } else {
            None
        }
    }

    /// Collect all connected peers that advertise the given service flags.
    pub(crate) async fn peers_with_service(
        &self,
        flags: ServiceFlags,
    ) -> Vec<(SocketAddr, Arc<RwLock<Peer>>)> {
        let peers = self.peers.read().await;
        let mut result = Vec::new();
        for (addr, peer) in peers.iter() {
            if peer.read().await.has_service(flags) {
                result.push((*addr, peer.clone()));
            }
        }
        result
    }

    /// Check whether any connected peer advertises the given service flags.
    pub(crate) async fn has_peers_with_service(&self, flags: ServiceFlags) -> bool {
        let peers = self.peers.read().await;
        for peer in peers.values() {
            if peer.read().await.has_service(flags) {
                return true;
            }
        }
        false
    }

    /// Send a message to the best-scoring peer able to serve it, returning the
    /// address it was sent to.
    ///
    /// The pool owns peer selection: callers never hold a `Peer`. It picks the
    /// probed peer with the best response-time bucket (breaking ties by lowest
    /// median RTT), so a slow, stalling or still-unprobed peer is skipped. Sync
    /// requests stay on a single fast peer, which the filter pipeline processes
    /// faster than interleaved responses from several peers.
    pub(crate) async fn send(&self, message: NetworkMessage) -> NetworkResult<SocketAddr> {
        let candidates = match required_service(&message) {
            Some((flags, must_have)) => {
                let matching = self.peers_with_service(flags).await;
                if matching.is_empty() {
                    if must_have {
                        return Err(NetworkError::ProtocolError(format!(
                            "No peers support {}",
                            flags
                        )));
                    }
                    self.get_all_peers().await
                } else {
                    matching
                }
            }
            None => self.get_all_peers().await,
        };

        let (addr, peer) = self
            .select_best(&candidates)
            .await
            .ok_or_else(|| NetworkError::ConnectionFailed("No connected peers".to_string()))?;

        Self::send_on_peer(&addr, &peer, message).await?;
        Ok(addr)
    }

    /// Send a message to a specific peer. Errors if the peer is gone so the
    /// caller can fall back to `send`.
    pub(crate) async fn send_to(
        &self,
        addr: SocketAddr,
        message: NetworkMessage,
    ) -> NetworkResult<()> {
        let peer = self.get_peer(&addr).await.ok_or_else(|| {
            NetworkError::ConnectionFailed(format!("Peer {} not connected", addr))
        })?;
        Self::send_on_peer(&addr, &peer, message).await
    }

    /// Pick the best peer: once any peer has a latency sample, only probed peers
    /// are eligible (a still-unprobed or silent peer is skipped); among those it
    /// takes the highest quality (latency score × behaviour multiplier), breaking
    /// ties by lowest median RTT.
    async fn select_best(
        &self,
        candidates: &[(SocketAddr, Arc<RwLock<Peer>>)],
    ) -> Option<(SocketAddr, Arc<RwLock<Peer>>)> {
        if candidates.is_empty() {
            return None;
        }
        let mut entries = Vec::with_capacity(candidates.len());
        for (addr, peer) in candidates {
            let (probed, stalling, quality, median) = {
                let guard = peer.read().await;
                (
                    guard.median_rtt().is_some(),
                    guard.is_stalling(),
                    guard.quality(),
                    guard.median_rtt(),
                )
            };
            entries.push((
                *addr,
                peer.clone(),
                probed,
                stalling,
                quality,
                median.unwrap_or(Duration::MAX),
            ));
        }

        // Prefer non-stalling, probed peers; fall back only if none qualify so a
        // single (even stalling) peer still gets used rather than stalling forever.
        let any_probed = entries.iter().any(|e| e.2);
        let any_live = entries.iter().any(|e| (!any_probed || e.2) && !e.3);
        entries
            .into_iter()
            .filter(|e| (!any_probed || e.2) && (!any_live || !e.3))
            .max_by(|a, b| a.4.total_cmp(&b.4).then_with(|| b.5.cmp(&a.5)))
            .map(|(addr, peer, ..)| (addr, peer))
    }

    async fn send_on_peer(
        addr: &SocketAddr,
        peer: &Arc<RwLock<Peer>>,
        message: NetworkMessage,
    ) -> NetworkResult<()> {
        let mut guard = peer.write().await;
        let message = match message {
            NetworkMessage::GetHeaders(h) if guard.can_request_headers2() => {
                NetworkMessage::GetHeaders2(h)
            }
            other => other,
        };
        if is_request(&message) {
            guard.note_request_sent();
        }
        guard
            .send_message(message)
            .await
            .map_err(|e| NetworkError::ProtocolError(format!("Failed to send to {}: {}", addr, e)))
    }

    /// Check if we need more peers
    pub async fn needs_more_peers(&self) -> bool {
        self.peer_count().await < self.max_peers
    }

    /// Check if we can accept more peers
    pub async fn can_accept_peers(&self) -> bool {
        self.peer_count().await < self.max_peers
    }

    /// Remove unhealthy peers and return their addresses so the caller can
    /// emit the appropriate network events.
    pub async fn remove_unhealthy(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let mut unhealthy = Vec::new();

        // Check each peer's health
        for (addr, peer) in peers.iter() {
            // Use blocking read to properly check health
            let peer_guard = peer.read().await;
            if !peer_guard.is_healthy() {
                unhealthy.push(*addr);
            }
        }

        // Release read lock before taking write lock
        drop(peers);

        // Remove unhealthy connections
        if !unhealthy.is_empty() {
            let mut peers = self.peers.write().await;
            unhealthy.retain(|addr| peers.remove(addr).is_some());
        }

        unhealthy
    }
}

impl Default for PeerPool {
    fn default() -> Self {
        Self::new(8)
    }
}

#[cfg(test)]
impl PeerPool {
    pub(crate) async fn insert_peer_with_services(&self, addr: SocketAddr, flags: ServiceFlags) {
        let mut peer = Peer::dummy(addr);
        peer.set_services(flags);
        self.peers.write().await.insert(addr, Arc::new(RwLock::new(peer)));
    }

    async fn insert_peer_with_rtts(&self, addr: SocketAddr, rtts: &[u64]) {
        let mut peer = Peer::dummy(addr);
        for &ms in rtts {
            peer.record_rtt(std::time::Duration::from_millis(ms));
        }
        self.peers.write().await.insert(addr, Arc::new(RwLock::new(peer)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_pool_basic() {
        let pool = PeerPool::new(8);

        // Initial state
        assert_eq!(pool.peer_count().await, 0);
        assert!(pool.needs_more_peers().await);
        assert!(pool.can_accept_peers().await);

        // Test marking as connecting
        let addr = "127.0.0.1:9999".parse().expect("Failed to parse test address");
        assert!(pool.mark_connecting(addr).await);
        assert!(!pool.mark_connecting(addr).await); // Already marked
        assert!(pool.is_connecting(&addr).await);
    }

    #[tokio::test]
    async fn test_select_skips_slow_peer() {
        let pool = PeerPool::new(8);
        let fast: SocketAddr = "127.0.0.1:2001".parse().unwrap();
        let slow: SocketAddr = "127.0.0.1:2002".parse().unwrap();
        pool.insert_peer_with_rtts(fast, &[20, 30, 40]).await;
        pool.insert_peer_with_rtts(slow, &[900, 800]).await;

        let candidates = pool.get_all_peers().await;
        let (addr, _) = pool.select_best(&candidates).await.unwrap();
        assert_eq!(addr, fast);
    }

    #[tokio::test]
    async fn test_select_breaks_ties_by_median() {
        let pool = PeerPool::new(8);
        let quick: SocketAddr = "127.0.0.1:2003".parse().unwrap();
        let quicker: SocketAddr = "127.0.0.1:2004".parse().unwrap();
        // Same worst-bucket score (4), so the lower median wins.
        pool.insert_peer_with_rtts(quick, &[40, 45]).await;
        pool.insert_peer_with_rtts(quicker, &[5, 10]).await;

        let candidates = pool.get_all_peers().await;
        let (addr, _) = pool.select_best(&candidates).await.unwrap();
        assert_eq!(addr, quicker);
    }

    #[tokio::test]
    async fn test_select_prefers_probed_over_unprobed() {
        let pool = PeerPool::new(8);
        let probed: SocketAddr = "127.0.0.1:2005".parse().unwrap();
        let unprobed: SocketAddr = "127.0.0.1:2006".parse().unwrap();
        pool.insert_peer_with_rtts(probed, &[30]).await;
        pool.insert_peer_with_rtts(unprobed, &[]).await;

        let candidates = pool.get_all_peers().await;
        let (addr, _) = pool.select_best(&candidates).await.unwrap();
        assert_eq!(addr, probed);
    }

    #[tokio::test]
    async fn test_service_lookup() {
        let pool = PeerPool::new(8);
        let compact_filters = ServiceFlags::COMPACT_FILTERS;
        let combined = compact_filters | ServiceFlags::NODE_HEADERS_COMPRESSED;

        // No matches on empty pool
        assert!(pool.peers_with_service(compact_filters).await.is_empty());

        // No matches when peers lack the requested flag
        let addr1: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        pool.insert_peer_with_services(addr1, ServiceFlags::NETWORK).await;
        assert!(pool.peers_with_service(compact_filters).await.is_empty());

        // Single-flag lookup returns matching peers
        let addr2: SocketAddr = "127.0.0.1:1002".parse().unwrap();
        let addr3: SocketAddr = "127.0.0.1:1003".parse().unwrap();
        pool.insert_peer_with_services(addr2, ServiceFlags::NETWORK | compact_filters).await;
        pool.insert_peer_with_services(addr3, ServiceFlags::NETWORK | combined).await;

        let filter_peers: HashMap<SocketAddr, _> =
            pool.peers_with_service(compact_filters).await.into_iter().collect();
        assert_eq!(filter_peers.len(), 2);
        assert!(filter_peers.contains_key(&addr2));
        assert!(filter_peers.contains_key(&addr3));

        // Combined flags require all bits present
        let combined_peers = pool.peers_with_service(combined).await;
        assert_eq!(combined_peers.len(), 1);
        assert_eq!(combined_peers[0].0, addr3);

        // NONE matches every peer in the pool
        let all = pool.peers_with_service(ServiceFlags::NONE).await;
        assert_eq!(all.len(), 3);
    }
}
