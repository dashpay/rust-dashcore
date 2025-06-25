//! Configuration management for the Dash SPV client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use dashcore::{Address, Network, ScriptBuf};
// Serialization removed due to complex Address types

use crate::types::{ValidationMode, WatchItem};

/// Strategy for handling mempool (unconfirmed) transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolStrategy {
    /// Fetch all announced transactions (poor privacy, high bandwidth).
    FetchAll,
    /// Use BIP37 bloom filters (moderate privacy, good efficiency).
    BloomFilter,
    /// Only fetch when recently sent or from known addresses (good privacy, default).
    Selective,
}

/// Configuration for the Dash SPV client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Network to connect to.
    pub network: Network,

    /// List of peer addresses to connect to.
    pub peers: Vec<SocketAddr>,

    /// Optional path for persistent storage.
    pub storage_path: Option<PathBuf>,

    /// Validation mode.
    pub validation_mode: ValidationMode,

    /// BIP157 filter checkpoint interval.
    pub filter_checkpoint_interval: u32,

    /// Maximum headers per message.
    pub max_headers_per_message: u32,

    /// Connection timeout.
    pub connection_timeout: Duration,

    /// Message timeout.
    pub message_timeout: Duration,

    /// Sync timeout.
    pub sync_timeout: Duration,
    
    /// Read timeout for TCP socket operations.
    pub read_timeout: Duration,

    /// Items to watch on the blockchain.
    pub watch_items: Vec<WatchItem>,

    /// Whether to enable filter syncing.
    pub enable_filters: bool,

    /// Whether to enable masternode syncing.
    pub enable_masternodes: bool,

    /// Maximum number of peers to connect to.
    pub max_peers: u32,

    /// Whether to persist state to disk.
    pub enable_persistence: bool,

    /// Log level for tracing.
    pub log_level: String,

    /// Maximum concurrent filter requests (default: 8).
    pub max_concurrent_filter_requests: usize,

    /// Enable flow control for filter requests (default: true).
    pub enable_filter_flow_control: bool,

    /// Delay between filter requests in milliseconds (default: 50).
    pub filter_request_delay_ms: u64,

    /// Enable automatic CFHeader gap detection and restart
    pub enable_cfheader_gap_restart: bool,

    /// Interval for checking CFHeader gaps (seconds)
    pub cfheader_gap_check_interval_secs: u64,

    /// Cooldown between CFHeader restart attempts (seconds)  
    pub cfheader_gap_restart_cooldown_secs: u64,

    /// Maximum CFHeader gap restart attempts
    pub max_cfheader_gap_restart_attempts: u32,

    /// Enable automatic filter gap detection and restart
    pub enable_filter_gap_restart: bool,

    /// Interval for checking filter gaps (seconds)
    pub filter_gap_check_interval_secs: u64,

    /// Minimum filter gap size to trigger restart (blocks)
    pub min_filter_gap_size: u32,

    /// Cooldown between filter restart attempts (seconds)
    pub filter_gap_restart_cooldown_secs: u64,

    /// Maximum filter gap restart attempts
    pub max_filter_gap_restart_attempts: u32,

    /// Maximum number of filters to sync in a single gap sync batch
    pub max_filter_gap_sync_size: u32,

    // Mempool configuration
    /// Enable tracking of unconfirmed (mempool) transactions.
    pub enable_mempool_tracking: bool,

    /// Strategy for handling mempool transactions.
    pub mempool_strategy: MempoolStrategy,

    /// Maximum number of unconfirmed transactions to track.
    pub max_mempool_transactions: usize,

    /// Time after which unconfirmed transactions are pruned (seconds).
    pub mempool_timeout_secs: u64,

    /// Time window for recent sends in selective mode (seconds).
    pub recent_send_window_secs: u64,

    /// Whether to fetch transactions from INV messages immediately.
    pub fetch_mempool_transactions: bool,

    /// Whether to persist mempool transactions.
    pub persist_mempool: bool,

    // Request control configuration
    /// Maximum concurrent header requests (default: 1).
    pub max_concurrent_headers_requests: Option<usize>,

    /// Maximum concurrent masternode list requests (default: 1).
    pub max_concurrent_mnlist_requests: Option<usize>,

    /// Maximum concurrent CF header requests (default: 1).
    pub max_concurrent_cfheaders_requests: Option<usize>,

    /// Maximum concurrent block requests (default: 5).
    pub max_concurrent_block_requests: Option<usize>,

    /// Rate limit for header requests per second (default: 10.0).
    pub headers_request_rate_limit: Option<f64>,

    /// Rate limit for masternode list requests per second (default: 5.0).
    pub mnlist_request_rate_limit: Option<f64>,

    /// Rate limit for CF header requests per second (default: 10.0).
    pub cfheaders_request_rate_limit: Option<f64>,

    /// Rate limit for filter requests per second (default: 50.0).
    pub filters_request_rate_limit: Option<f64>,

    /// Rate limit for block requests per second (default: 10.0).
    pub blocks_request_rate_limit: Option<f64>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            network: Network::Dash,
            peers: vec![],
            storage_path: None,
            validation_mode: ValidationMode::Full,
            filter_checkpoint_interval: 1000,
            max_headers_per_message: 2000,
            connection_timeout: Duration::from_secs(30),
            message_timeout: Duration::from_secs(60),
            sync_timeout: Duration::from_secs(300),
            read_timeout: Duration::from_millis(15),
            watch_items: vec![],
            enable_filters: true,
            enable_masternodes: true,
            max_peers: 8,
            enable_persistence: true,
            log_level: "info".to_string(),
            max_concurrent_filter_requests: 16,
            enable_filter_flow_control: true,
            filter_request_delay_ms: 0,
            enable_cfheader_gap_restart: true,
            cfheader_gap_check_interval_secs: 15,
            cfheader_gap_restart_cooldown_secs: 30,
            max_cfheader_gap_restart_attempts: 5,
            enable_filter_gap_restart: true,
            filter_gap_check_interval_secs: 20,
            min_filter_gap_size: 10,
            filter_gap_restart_cooldown_secs: 30,
            max_filter_gap_restart_attempts: 5,
            max_filter_gap_sync_size: 50000,
            // Mempool defaults
            enable_mempool_tracking: false,
            mempool_strategy: MempoolStrategy::Selective,
            max_mempool_transactions: 1000,
            mempool_timeout_secs: 3600, // 1 hour
            recent_send_window_secs: 300, // 5 minutes
            fetch_mempool_transactions: true,
            persist_mempool: false,
            // Request control defaults
            max_concurrent_headers_requests: None,
            max_concurrent_mnlist_requests: None,
            max_concurrent_cfheaders_requests: None,
            max_concurrent_block_requests: None,
            headers_request_rate_limit: None,
            mnlist_request_rate_limit: None,
            cfheaders_request_rate_limit: None,
            filters_request_rate_limit: None,
            blocks_request_rate_limit: None,
        }
    }
}

impl ClientConfig {
    /// Create a new configuration for the given network.
    pub fn new(network: Network) -> Self {
        Self {
            network,
            peers: Self::default_peers_for_network(network),
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

    /// Set storage path.
    pub fn with_storage_path(mut self, path: PathBuf) -> Self {
        self.storage_path = Some(path);
        self.enable_persistence = true;
        self
    }

    /// Set validation mode.
    pub fn with_validation_mode(mut self, mode: ValidationMode) -> Self {
        self.validation_mode = mode;
        self
    }

    /// Add a watch address.
    pub fn watch_address(mut self, address: Address) -> Self {
        self.watch_items.push(WatchItem::address(address));
        self
    }

    /// Add a watch script.
    pub fn watch_script(mut self, script: ScriptBuf) -> Self {
        self.watch_items.push(WatchItem::Script(script));
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

    /// Set connection timeout.
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }
    
    /// Set read timeout for TCP socket operations.
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Set log level.
    pub fn with_log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }

    /// Set maximum concurrent filter requests.
    pub fn with_max_concurrent_filter_requests(mut self, max_requests: usize) -> Self {
        self.max_concurrent_filter_requests = max_requests;
        self
    }

    /// Enable or disable filter flow control.
    pub fn with_filter_flow_control(mut self, enabled: bool) -> Self {
        self.enable_filter_flow_control = enabled;
        self
    }

    /// Set delay between filter requests.
    pub fn with_filter_request_delay(mut self, delay_ms: u64) -> Self {
        self.filter_request_delay_ms = delay_ms;
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

    /// Set recent send window for selective strategy.
    pub fn with_recent_send_window(mut self, window_secs: u64) -> Self {
        self.recent_send_window_secs = window_secs;
        self
    }

    /// Enable or disable mempool persistence.
    pub fn with_mempool_persistence(mut self, enabled: bool) -> Self {
        self.persist_mempool = enabled;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.peers.is_empty() {
            return Err("No peers specified".to_string());
        }

        if self.max_headers_per_message == 0 {
            return Err("max_headers_per_message must be > 0".to_string());
        }

        if self.filter_checkpoint_interval == 0 {
            return Err("filter_checkpoint_interval must be > 0".to_string());
        }

        if self.max_peers == 0 {
            return Err("max_peers must be > 0".to_string());
        }

        if self.max_concurrent_filter_requests == 0 {
            return Err("max_concurrent_filter_requests must be > 0".to_string());
        }

        // Mempool validation
        if self.enable_mempool_tracking {
            if self.max_mempool_transactions == 0 {
                return Err("max_mempool_transactions must be > 0 when mempool tracking is enabled".to_string());
            }
            if self.mempool_timeout_secs == 0 {
                return Err("mempool_timeout_secs must be > 0".to_string());
            }
            if self.mempool_strategy == MempoolStrategy::Selective && self.recent_send_window_secs == 0 {
                return Err("recent_send_window_secs must be > 0 for Selective strategy".to_string());
            }
        }

        Ok(())
    }

    /// Get default peers for a network.
    fn default_peers_for_network(network: Network) -> Vec<SocketAddr> {
        match network {
            Network::Dash => vec![
                // Use well-known IP addresses instead of DNS names for reliability
                "104.248.113.204:9999".parse().unwrap(), // dashdot.io seed
                "149.28.22.65:9999".parse().unwrap(), // masternode.io seed
            ],
            Network::Testnet => vec![
                "174.138.35.118:19999".parse().unwrap(), // testnet seed
                "149.28.22.65:19999".parse().unwrap(),   // testnet masternode.io
            ],
            Network::Regtest => vec!["127.0.0.1:19899".parse().unwrap()],
            _ => vec![],
        }
    }
}
