//! Network constants for peer support

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

// Fixed peer IPs for Dash testnet (hp-masternodes)
pub const TESTNET_FIXED_PEERS: &[&str] = &[
    "68.67.122.1",
    "68.67.122.2",
    "68.67.122.3",
    "68.67.122.4",
    "68.67.122.5",
    "68.67.122.6",
    "68.67.122.7",
    "68.67.122.8",
    "68.67.122.9",
    "68.67.122.10",
    "68.67.122.11",
    "68.67.122.12",
    "68.67.122.13",
    "68.67.122.14",
    "68.67.122.15",
    "68.67.122.16",
    "68.67.122.17",
    "68.67.122.18",
    "68.67.122.19",
    "68.67.122.20",
    "68.67.122.21",
    "68.67.122.22",
    "68.67.122.23",
    "68.67.122.24",
    "68.67.122.25",
    "68.67.122.26",
    "68.67.122.27",
    "68.67.122.28",
    "68.67.122.29",
];

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
