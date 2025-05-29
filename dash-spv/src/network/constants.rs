//! Network constants for multi-peer support

use std::time::Duration;

// Connection limits
pub const MAX_PEERS: usize = 8;
pub const MIN_PEERS: usize = 3;
pub const TARGET_PEERS: usize = 5;

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
pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "testnet-seed.dashdot.io",
    "test.dnsseed.masternode.io",
];

// Peer exchange
pub const MAX_ADDR_TO_SEND: usize = 1000;
pub const MAX_ADDR_TO_STORE: usize = 2000;

// Connection maintenance
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10); // Check more frequently
pub const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(60); // Discover more frequently