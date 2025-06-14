//! Configuration management for the Dash SPV client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use dashcore::{Address, Network, ScriptBuf};
// Serialization removed due to complex Address types

use crate::types::{ValidationMode, WatchItem};

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
            watch_items: vec![],
            enable_filters: true,
            enable_masternodes: true,
            max_peers: 8,
            enable_persistence: true,
            log_level: "info".to_string(),
            max_concurrent_filter_requests: 16,
            enable_filter_flow_control: true,
            filter_request_delay_ms: 0,
        }
    }
}

impl ClientConfig {
    /// Create a new configuration for the given network.
    pub fn new(network: Network) -> Self {
        let mut config = Self::default();
        config.network = network;
        config.peers = Self::default_peers_for_network(network);
        config
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
        
        Ok(())
    }
    
    /// Get default peers for a network.
    fn default_peers_for_network(network: Network) -> Vec<SocketAddr> {
        match network {
            Network::Dash => vec![
                // Use well-known IP addresses instead of DNS names for reliability
                "127.0.0.1:9999".parse().unwrap(),    // seed.dash.org
                "104.248.113.204:9999".parse().unwrap(), // dashdot.io seed
                "149.28.22.65:9999".parse().unwrap(),    // masternode.io seed
                "127.0.0.1:9999".parse().unwrap(),
            ],
            Network::Testnet => vec![
                "174.138.35.118:19999".parse().unwrap(), // testnet seed
                "149.28.22.65:19999".parse().unwrap(),   // testnet masternode.io
                "127.0.0.1:19999".parse().unwrap(),
            ],
            Network::Regtest => vec![
                "127.0.0.1:19899".parse().unwrap(),
            ],
            _ => vec![],
        }
    }
}