//! Peer management functionality.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::types::PeerInfo;

/// Manages multiple peer connections.
pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerInfo>,
    max_peers: usize,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
        }
    }
    
    /// Add a peer.
    pub fn add_peer(&mut self, address: SocketAddr) -> bool {
        if self.peers.len() >= self.max_peers {
            return false;
        }
        
        let peer_info = PeerInfo {
            address,
            connected: false,
            last_seen: SystemTime::now(),
            version: None,
            services: None,
            user_agent: None,
            best_height: None,
        };
        
        self.peers.insert(address, peer_info);
        true
    }
    
    /// Remove a peer.
    pub fn remove_peer(&mut self, address: &SocketAddr) -> Option<PeerInfo> {
        self.peers.remove(address)
    }
    
    /// Update peer information.
    pub fn update_peer(&mut self, address: SocketAddr, update: impl FnOnce(&mut PeerInfo)) {
        if let Some(peer) = self.peers.get_mut(&address) {
            update(peer);
        }
    }
    
    /// Get peer information.
    pub fn get_peer(&self, address: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(address)
    }
    
    /// Get all peer information.
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.values().cloned().collect()
    }
    
    /// Get connected peers.
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers.values()
            .filter(|p| p.connected)
            .cloned()
            .collect()
    }
    
    /// Get the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.peers.values()
            .filter(|p| p.connected)
            .count()
    }
    
    /// Get the best height among connected peers.
    pub fn best_height(&self) -> Option<i32> {
        self.peers.values()
            .filter(|p| p.connected)
            .filter_map(|p| p.best_height)
            .max()
    }
    
    /// Mark a peer as connected.
    pub fn mark_connected(&mut self, address: SocketAddr, version: u32, services: u64, user_agent: String, best_height: i32) {
        self.update_peer(address, |peer| {
            peer.connected = true;
            peer.last_seen = SystemTime::now();
            peer.version = Some(version);
            peer.services = Some(services);
            peer.user_agent = Some(user_agent);
            peer.best_height = Some(best_height);
        });
    }
    
    /// Mark a peer as disconnected.
    pub fn mark_disconnected(&mut self, address: SocketAddr) {
        self.update_peer(address, |peer| {
            peer.connected = false;
        });
    }
    
    /// Update last seen time for a peer.
    pub fn update_last_seen(&mut self, address: SocketAddr) {
        self.update_peer(address, |peer| {
            peer.last_seen = SystemTime::now();
        });
    }
    
    /// Check if we can add more peers.
    pub fn can_add_peer(&self) -> bool {
        self.peers.len() < self.max_peers
    }
    
    /// Get statistics.
    pub fn stats(&self) -> PeerStats {
        PeerStats {
            total_peers: self.peers.len(),
            connected_peers: self.connected_count(),
            max_peers: self.max_peers,
        }
    }
}

/// Peer management statistics.
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub max_peers: usize,
}