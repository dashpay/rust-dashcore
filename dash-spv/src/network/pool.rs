//! Connection pool for managing multiple peer connections

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{NetworkError, SpvError as Error};
use crate::network::connection::TcpConnection;
use crate::network::constants::{MAX_PEERS, MIN_PEERS};

/// Pool for managing multiple TCP connections
pub struct ConnectionPool {
    /// Active connections mapped by peer address
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<RwLock<TcpConnection>>>>>,
    /// Addresses currently being connected to
    connecting: Arc<RwLock<HashSet<SocketAddr>>>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            connecting: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Mark an address as being connected to
    pub async fn mark_connecting(&self, addr: SocketAddr) -> bool {
        let mut connecting = self.connecting.write().await;
        connecting.insert(addr)
    }

    /// Add a connection to the pool
    pub async fn add_connection(&self, addr: SocketAddr, conn: TcpConnection) -> Result<(), Error> {
        let mut connections = self.connections.write().await;
        let mut connecting = self.connecting.write().await;

        // Remove from connecting set
        connecting.remove(&addr);

        // Check if we're at capacity
        if connections.len() >= MAX_PEERS {
            return Err(Error::Network(NetworkError::ConnectionFailed(format!(
                "Maximum peers ({}) reached",
                MAX_PEERS
            ))));
        }

        // Check if already connected
        if connections.contains_key(&addr) {
            return Err(Error::Network(NetworkError::ConnectionFailed(format!(
                "Already connected to {}",
                addr
            ))));
        }

        connections.insert(addr, Arc::new(RwLock::new(conn)));
        log::info!("🔵 Added connection to {}, total peers: {}", addr, connections.len());
        Ok(())
    }

    /// Remove a connection from the pool
    pub async fn remove_connection(&self, addr: &SocketAddr) -> Option<Arc<RwLock<TcpConnection>>> {
        let mut connections = self.connections.write().await;
        let removed = connections.remove(addr);
        if removed.is_some() {
            let remaining = connections.len();
            log::info!(
                "🔴 Removed connection to {}, {} peers remaining",
                addr,
                remaining
            );
        }
        removed
    }

    /// Get all active connections
    pub async fn get_all_connections(&self) -> Vec<(SocketAddr, Arc<RwLock<TcpConnection>>)> {
        self.connections.read().await.iter().map(|(addr, conn)| (*addr, conn.clone())).collect()
    }

    /// Get a specific connection
    pub async fn get_connection(&self, addr: &SocketAddr) -> Option<Arc<RwLock<TcpConnection>>> {
        self.connections.read().await.get(addr).cloned()
    }

    /// Get the number of active connections
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Check if connected to a specific peer
    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.connections.read().await.contains_key(addr)
    }

    /// Check if currently connecting to a peer
    pub async fn is_connecting(&self, addr: &SocketAddr) -> bool {
        self.connecting.read().await.contains(addr)
    }

    /// Get all connected peer addresses
    pub async fn get_connected_addresses(&self) -> Vec<SocketAddr> {
        self.connections.read().await.keys().copied().collect()
    }

    /// Check if we need more connections
    pub async fn needs_more_connections(&self) -> bool {
        self.connection_count().await < MIN_PEERS
    }

    /// Check if we can accept more connections
    pub async fn can_accept_connections(&self) -> bool {
        self.connection_count().await < MAX_PEERS
    }

    /// Clean up disconnected peers
    pub async fn cleanup_disconnected(&self) {
        let connections = self.connections.read().await;
        let mut unhealthy = Vec::new();

        // Check each connection's health
        for (addr, conn) in connections.iter() {
            // Use blocking read to properly check health
            let conn_guard = conn.read().await;
            if !conn_guard.is_healthy() {
                unhealthy.push(*addr);
            }
        }

        // Release read lock before taking write lock
        drop(connections);

        // Remove unhealthy connections
        if !unhealthy.is_empty() {
            let mut connections = self.connections.write().await;
            for addr in unhealthy {
                connections.remove(&addr);
                log::warn!(
                    "Cleaned up unhealthy peer: {} (marked unhealthy by health check)",
                    addr
                );
            }
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::Network;

    #[tokio::test]
    async fn test_connection_pool_basic() {
        let pool = ConnectionPool::new();

        // Initial state
        assert_eq!(pool.connection_count().await, 0);
        assert!(pool.needs_more_connections().await);
        assert!(pool.can_accept_connections().await);

        // Test marking as connecting
        let addr = "127.0.0.1:9999".parse().expect("Failed to parse test address");
        assert!(pool.mark_connecting(addr).await);
        assert!(!pool.mark_connecting(addr).await); // Already marked
        assert!(pool.is_connecting(&addr).await);
    }
}
