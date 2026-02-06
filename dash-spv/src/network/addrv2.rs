//! AddrV2 message handling for modern peer exchange protocol

use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use dashcore::network::address::{AddrV2, AddrV2Message};
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;

use crate::network::constants::{MAX_ADDR_TO_SEND, MAX_ADDR_TO_STORE};

const ONE_WEEK: u32 = 7 * 24 * 60 * 60;
const TEN_MINUTES: u32 = 600;

/// Evict oldest entries if the map exceeds capacity, keeping the freshest addresses.
fn evict_if_needed(peers: &mut HashMap<SocketAddr, AddrV2Message>) {
    if peers.len() > MAX_ADDR_TO_STORE {
        let mut entries: Vec<_> = peers.drain().collect();
        entries.sort_by_key(|(_, msg)| std::cmp::Reverse(msg.time));
        entries.truncate(MAX_ADDR_TO_STORE);
        peers.extend(entries);
    }
}

/// Handler for AddrV2 peer exchange protocol
pub struct AddrV2Handler {
    /// Known peer addresses from AddrV2 messages
    known_peers: Arc<RwLock<HashMap<SocketAddr, AddrV2Message>>>,
    /// Peers that support AddrV2
    supports_addrv2: Arc<RwLock<HashSet<SocketAddr>>>,
}

impl AddrV2Handler {
    /// Create a new AddrV2 handler
    pub fn new() -> Self {
        Self {
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            supports_addrv2: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Handle SendAddrV2 message indicating peer support
    pub async fn handle_sendaddrv2(&self, peer_addr: SocketAddr) {
        self.supports_addrv2.write().await.insert(peer_addr);
        log::debug!("Peer {} supports AddrV2", peer_addr);
    }

    /// Handle incoming AddrV2 messages
    pub async fn handle_addrv2(&self, messages: Vec<AddrV2Message>) {
        let mut known_peers = self.known_peers.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| {
                log::error!("System time error in handle_addrv2: {}", e);
                Duration::from_secs(0)
            })
            .as_secs() as u32;

        let received = messages.len();
        let mut added = 0;
        let mut updated = 0;

        for msg in messages {
            // Accept addresses seen within the last week. Older addresses are likely stale.
            // Also, reject timestamps more than 10 minutes in the future which are invalid.
            if msg.time < now.saturating_sub(ONE_WEEK) || msg.time > now + TEN_MINUTES {
                log::trace!("Ignoring AddrV2 with invalid timestamp: {}", msg.time);
                continue;
            }

            let Ok(socket_addr) = msg.socket_addr() else {
                continue;
            };

            // Only update if new or has fresher timestamp
            match known_peers.get(&socket_addr) {
                Some(existing) if existing.time >= msg.time => continue,
                Some(_) => updated += 1,
                None => added += 1,
            }
            known_peers.insert(socket_addr, msg);
        }

        evict_if_needed(&mut known_peers);

        log::info!(
            "Processed AddrV2 messages: received {}, added {}, updated {}, total known peers: {}",
            received,
            added,
            updated,
            known_peers.len()
        );
    }

    /// Get addresses to share with a peer
    pub async fn get_addresses_for_peer(&self, count: usize) -> Vec<AddrV2Message> {
        let known_peers = self.known_peers.read().await;

        if known_peers.is_empty() {
            return vec![];
        }

        // Select random subset
        let mut rng = thread_rng();
        let count = count.min(MAX_ADDR_TO_SEND).min(known_peers.len());

        let addresses: Vec<AddrV2Message> =
            known_peers.values().choose_multiple(&mut rng, count).into_iter().cloned().collect();

        addresses
    }

    /// Check if a peer supports AddrV2
    pub async fn peer_supports_addrv2(&self, addr: &SocketAddr) -> bool {
        self.supports_addrv2.read().await.contains(addr)
    }

    /// Get all known socket addresses
    pub async fn get_known_addresses(&self) -> Vec<AddrV2Message> {
        self.known_peers.read().await.values().cloned().collect()
    }

    /// Add a known peer address
    pub async fn add_known_address(&self, addr: SocketAddr, services: ServiceFlags) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| {
                log::error!("System time error in add_known_address: {}", e);
                Duration::from_secs(0)
            })
            .as_secs() as u32;

        let addr_v2 = match addr.ip() {
            std::net::IpAddr::V4(ipv4) => AddrV2::Ipv4(ipv4),
            std::net::IpAddr::V6(ipv6) => AddrV2::Ipv6(ipv6),
        };

        let addr_msg = AddrV2Message {
            time: now,
            services,
            addr: addr_v2,
            port: addr.port(),
        };

        let mut known_peers = self.known_peers.write().await;
        known_peers.insert(addr, addr_msg);
        evict_if_needed(&mut known_peers);
    }

    /// Build a GetAddr response message
    pub async fn build_addr_response(&self) -> NetworkMessage {
        let addresses = self.get_addresses_for_peer(23).await; // Bitcoin typically sends ~23 addresses
        NetworkMessage::AddrV2(addresses)
    }
}

impl Default for AddrV2Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::network::address::AddrV2;

    #[tokio::test]
    async fn test_addrv2_handler_basic() {
        let handler = AddrV2Handler::new();

        // Test SendAddrV2 support tracking
        let peer = "127.0.0.1:9999".parse().expect("Failed to parse test peer address");
        handler.handle_sendaddrv2(peer).await;
        assert!(handler.peer_supports_addrv2(&peer).await);

        // Test adding known address
        let addr = "192.168.1.1:9999".parse().expect("Failed to parse test address");
        handler.add_known_address(addr, ServiceFlags::from(1)).await;

        let known = handler.get_known_addresses().await;
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].socket_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn test_addrv2_timestamp_validation() {
        let handler = AddrV2Handler::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get system time in test")
            .as_secs() as u32;

        // Create test messages with various timestamps
        let addr: SocketAddr =
            "127.0.0.1:9999".parse().expect("Failed to parse test socket address");
        let ipv4_addr = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("Test expects IPv4 address but got IPv6"),
        };

        let messages = vec![
            // Valid: current time
            AddrV2Message {
                time: now,
                services: ServiceFlags::from(1),
                addr: AddrV2::Ipv4(ipv4_addr),
                port: addr.port(),
            },
            // Invalid: too old (4 hours ago)
            AddrV2Message {
                time: now.saturating_sub(14400),
                services: ServiceFlags::from(1),
                addr: AddrV2::Ipv4(ipv4_addr),
                port: addr.port(),
            },
            // Invalid: too far in future (20 minutes)
            AddrV2Message {
                time: now + 1200,
                services: ServiceFlags::from(1),
                addr: AddrV2::Ipv4(ipv4_addr),
                port: addr.port(),
            },
        ];

        handler.handle_addrv2(messages).await;

        // Only the valid message should be stored
        let known = handler.get_known_addresses().await;
        assert_eq!(known.len(), 1);
    }
}
