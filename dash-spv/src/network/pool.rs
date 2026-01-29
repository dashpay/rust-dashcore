//! Peer pool for managing multiple peer connections

use crate::error::{NetworkError, SpvError as Error};
use crate::network::constants::{MAX_PEERS, MIN_PEERS};
use crate::network::peer::Peer;
use dashcore::prelude::CoreBlockHeight;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Pool for managing multiple peer instances
pub struct PeerPool {
    /// Active peers mapped by address
    peers: Arc<RwLock<HashMap<SocketAddr, Arc<RwLock<Peer>>>>>,
    /// Addresses currently being connected to
    connecting: Arc<RwLock<HashSet<SocketAddr>>>,
}

impl PeerPool {
    /// Create a new peer pool
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            connecting: Arc::new(RwLock::new(HashSet::new())),
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
        if peers.len() >= MAX_PEERS {
            return Err(Error::Network(NetworkError::ConnectionFailed(format!(
                "Maximum peers ({}) reached",
                MAX_PEERS
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
        log::info!("Added peer {}, total peers: {}", addr, peers.len());
        Ok(())
    }

    /// Remove a peer from the pool
    pub async fn remove_peer(&self, addr: &SocketAddr) -> Option<Arc<RwLock<Peer>>> {
        let removed = self.peers.write().await.remove(addr);
        if removed.is_some() {
            log::info!("Removed peer {}", addr);
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
            log::debug!("get_peer_best_height: No peers available");
            return None;
        }

        let mut best_height = 0u32;
        let mut peer_count = 0;

        for (addr, peer) in peers.iter() {
            let peer_guard = peer.read().await;
            peer_count += 1;

            log::debug!(
                "get_peer_best_height: Peer {} - best_height: {:?}, version: {:?}, connected: {}",
                addr,
                peer_guard.best_height(),
                peer_guard.version(),
                peer_guard.is_connected(),
            );

            if let Some(peer_height) = peer_guard.best_height() {
                if peer_height > 0 {
                    best_height = best_height.max(peer_height);
                    log::debug!(
                        "get_peer_best_height: Updated best_height to {} from peer {}",
                        best_height,
                        addr
                    );
                }
            }
        }

        log::debug!(
            "get_peer_best_height: Checked {} peers, best_height: {}",
            peer_count,
            best_height
        );

        if best_height > 0 {
            Some(best_height)
        } else {
            None
        }
    }

    /// Check if we need more peers
    pub async fn needs_more_peers(&self) -> bool {
        self.peer_count().await < MIN_PEERS
    }

    /// Check if we can accept more peers
    pub async fn can_accept_peers(&self) -> bool {
        self.peer_count().await < MAX_PEERS
    }

    /// Clean up disconnected peers
    pub async fn cleanup_disconnected(&self) {
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
            for addr in unhealthy {
                peers.remove(&addr);
                log::warn!(
                    "Cleaned up unhealthy peer: {} (marked unhealthy by health check)",
                    addr
                );
            }
        }
    }
}

impl Default for PeerPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_pool_basic() {
        let pool = PeerPool::new();

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
}
