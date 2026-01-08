//! Configuration management for the Dash SPV client.

use std::net::SocketAddr;
use std::path::PathBuf;

use dashcore::Network;
// Serialization removed due to complex Address types

use crate::types::ValidationMode;

/// Strategy for handling mempool (unconfirmed) transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolStrategy {
    /// Fetch all announced transactions (high bandwidth, sees all transactions).
    FetchAll,
    /// Use BIP37 bloom filters (moderate privacy, good efficiency).
    BloomFilter,
}

/// Configuration for the Dash SPV client.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ClientConfig {
    /// Network to connect to.
    pub network: Network,

    /// List of peer addresses to connect to.
    pub peers: Vec<SocketAddr>,

    /// Restrict connections strictly to the configured peers.
    ///
    /// When true, the client will not use DNS discovery or peer persistence and
    /// will only attempt to connect to addresses provided in `peers`.
    /// If no peers are configured, no outbound connections will be made.
    pub restrict_to_configured_peers: bool,

    /// Optional path for persistent storage.
    pub storage_path: Option<PathBuf>,

    /// Validation mode.
    pub validation_mode: ValidationMode,

    /// Whether to enable filter syncing.
    pub enable_filters: bool,

    /// Whether to enable masternode syncing.
    pub enable_masternodes: bool,

    /// Maximum number of peers to connect to.
    pub max_peers: u32,

    /// Log level for tracing.
    pub log_level: String,

    /// Optional user agent string to advertise in the P2P version message.
    /// If not set, a sensible default is used (includes crate version).
    pub user_agent: Option<String>,

    // Mempool configuration
    /// Enable tracking of unconfirmed (mempool) transactions.
    pub enable_mempool_tracking: bool,

    /// Strategy for handling mempool transactions.
    pub mempool_strategy: MempoolStrategy,

    /// Maximum number of unconfirmed transactions to track.
    pub max_mempool_transactions: usize,

    /// Time after which unconfirmed transactions are pruned (seconds).
    pub mempool_timeout_secs: u64,

    /// Whether to fetch transactions from INV messages immediately.
    pub fetch_mempool_transactions: bool,

    /// Whether to persist mempool transactions.
    pub persist_mempool: bool,

    /// Start syncing from a specific block height.
    /// The client will use the nearest checkpoint at or before this height.
    pub start_from_height: Option<u32>,

    /// Wallet creation time as Unix timestamp.
    /// Used to determine appropriate checkpoint for sync.
    pub wallet_creation_time: Option<u32>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            network: Network::Dash,
            peers: vec![],
            restrict_to_configured_peers: false,
            storage_path: None,
            validation_mode: ValidationMode::Full,
            enable_filters: true,
            enable_masternodes: true,
            max_peers: 8,
            log_level: "info".to_string(),
            user_agent: None,
            // Mempool defaults
            enable_mempool_tracking: true,
            mempool_strategy: MempoolStrategy::FetchAll,
            max_mempool_transactions: 1000,
            mempool_timeout_secs: 3600, // 1 hour
            fetch_mempool_transactions: true,
            persist_mempool: false,
            start_from_height: None,
            wallet_creation_time: None,
        }
    }
}

impl ClientConfig {
    /// Create a new configuration for the given network.
    pub fn new(network: Network) -> Self {
        Self {
            network,
            peers: Self::default_peers_for_network(network),
            restrict_to_configured_peers: false,
            ..Self::default()
        }
    }

    /// Create a configuration for mainnet.
    pub fn mainnet() -> Self {
        Self::new(Network::Dash)
    }

    /// Create a configuration for testnet.
    pub fn testnet() -> Self {
        Self::new(Network::Testnet)
    }

    /// Create a configuration for regtest.
    pub fn regtest() -> Self {
        Self::new(Network::Regtest)
    }

    /// Add a peer address.
    pub fn add_peer(&mut self, address: SocketAddr) -> &mut Self {
        self.peers.push(address);
        self
    }

    /// Restrict connections to the configured peers only.
    pub fn with_restrict_to_configured_peers(mut self, restrict: bool) -> Self {
        self.restrict_to_configured_peers = restrict;
        self
    }

    /// Set storage path.
    pub fn with_storage_path(mut self, path: PathBuf) -> Self {
        self.storage_path = Some(path);
        self
    }

    /// Set validation mode.
    pub fn with_validation_mode(mut self, mode: ValidationMode) -> Self {
        self.validation_mode = mode;
        self
    }

    /// Disable filters.
    pub fn without_filters(mut self) -> Self {
        self.enable_filters = false;
        self
    }

    /// Disable masternodes.
    pub fn without_masternodes(mut self) -> Self {
        self.enable_masternodes = false;
        self
    }

    /// Set log level.
    pub fn with_log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }

    /// Set custom user agent string for the P2P handshake.
    /// The library will lightly validate and normalize it during handshake.
    pub fn with_user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self
    }

    /// Enable mempool tracking with specified strategy.
    pub fn with_mempool_tracking(mut self, strategy: MempoolStrategy) -> Self {
        self.enable_mempool_tracking = true;
        self.mempool_strategy = strategy;
        self
    }

    /// Set maximum number of mempool transactions to track.
    pub fn with_max_mempool_transactions(mut self, max: usize) -> Self {
        self.max_mempool_transactions = max;
        self
    }

    /// Set mempool transaction timeout.
    pub fn with_mempool_timeout(mut self, timeout_secs: u64) -> Self {
        self.mempool_timeout_secs = timeout_secs;
        self
    }

    /// Enable or disable mempool persistence.
    pub fn with_mempool_persistence(mut self, enabled: bool) -> Self {
        self.persist_mempool = enabled;
        self
    }

    /// Set the starting height for synchronization.
    pub fn with_start_height(mut self, height: u32) -> Self {
        self.start_from_height = Some(height);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Note: Empty peers list is now valid - DNS discovery will be used automatically

        if self.max_peers == 0 {
            return Err("max_peers must be > 0".to_string());
        }

        // Mempool validation
        if self.enable_mempool_tracking {
            if self.max_mempool_transactions == 0 {
                return Err(
                    "max_mempool_transactions must be > 0 when mempool tracking is enabled"
                        .to_string(),
                );
            }
            if self.mempool_timeout_secs == 0 {
                return Err("mempool_timeout_secs must be > 0".to_string());
            }
        }

        Ok(())
    }

    /// Get default peers for a network.
    /// Returns empty vector to enable immediate DNS discovery on startup.
    /// Explicit peers can still be added via add_peer() or configuration.
    fn default_peers_for_network(network: Network) -> Vec<SocketAddr> {
        match network {
            Network::Dash | Network::Testnet => {
                // Return empty to trigger immediate DNS discovery
                // DNS seeds will be used: dnsseed.dash.org (mainnet), testnet-seed.dashdot.io (testnet)
                vec![]
            }
            Network::Regtest => {
                // Regtest typically uses local peers
                vec!["127.0.0.1:19899".parse::<SocketAddr>()]
                    .into_iter()
                    .filter_map(Result::ok)
                    .collect()
            }
            _ => vec![],
        }
    }
}
