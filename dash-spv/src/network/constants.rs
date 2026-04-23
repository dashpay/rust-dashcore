//! Network constants for peer support

use dashcore::Network;
use std::net::SocketAddr;
use std::time::Duration;

// Connection limits
pub const TARGET_PEERS: usize = 3;

// Timeouts
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(120);
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

// Reconnection
pub const RECONNECT_DELAY: Duration = Duration::from_secs(5);
pub const MAX_RECONNECT_ATTEMPTS: u32 = 3;

// DNS seeds for Dash mainnet
pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "dnsseed.dash.org",
    // Note: dnsseed.dashdot.io and dnsseed.masternode.io are currently not resolving
];

// DNS seeds for Dash testnet
pub const TESTNET_DNS_SEEDS: &[&str] = &["testnet-seed.dashdot.io"];

/// Default Dash P2P port for mainnet.
pub const MAINNET_P2P_PORT: u16 = 9999;
/// Default Dash P2P port for testnet.
pub const TESTNET_P2P_PORT: u16 = 19999;

// Peer exchange
pub const MAX_ADDR_TO_SEND: usize = 1000;
pub const MAX_ADDR_TO_STORE: usize = 2000;

// Connection maintenance
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10); // Check more frequently
pub const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(60); // Discover more frequently

// DNS and polling intervals
pub const DNS_DISCOVERY_DELAY: Duration = Duration::from_secs(10);
pub const MESSAGE_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const MESSAGE_RECEIVE_TIMEOUT: Duration = Duration::from_millis(100);

/// Hardcoded masternode peer addresses for mainnet.
///
/// Sourced from the [`dash_network_seeds`] crate, which is refreshed weekly
/// by `.github/workflows/update-masternode-seeds.yml` via the
/// `masternode-seeds-fetcher` tool. The returned list is the union of
/// regular and Evo masternodes — for a typed view (e.g. evo-only), depend
/// on `dash-network-seeds` directly.
pub fn mainnet_seed_peers() -> Vec<SocketAddr> {
    dash_network_seeds::addresses(Network::Mainnet)
}

/// Hardcoded masternode peer addresses for testnet. See [`mainnet_seed_peers`]
/// for context.
pub fn testnet_seed_peers() -> Vec<SocketAddr> {
    dash_network_seeds::addresses(Network::Testnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_seed_peers_contains_hp_mn_ips() {
        let peers = testnet_seed_peers();
        // The HP-MN range at 68.67.122.1-29 should be present; later runs may
        // extend it but never shrink below 29.
        let hp_mn = peers.iter().filter(|a| a.ip().to_string().starts_with("68.67.122.")).count();
        assert!(hp_mn >= 29, "expected >=29 HP-MN testnet seeds, got {}", hp_mn);
        assert!(peers.iter().all(|a| a.port() == TESTNET_P2P_PORT));
    }

    #[test]
    fn mainnet_seed_peers_non_empty() {
        let peers = mainnet_seed_peers();
        assert!(!peers.is_empty(), "mainnet seeds must not be empty");
        assert!(peers.iter().all(|a| a.port() == MAINNET_P2P_PORT));
    }
}
