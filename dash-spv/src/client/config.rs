//! Configuration management for the Dash SPV client.

use clap::ValueEnum;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use dashcore::Network;
// Serialization removed due to complex Address types

use crate::client::devnet::DevnetConfig;
use crate::sync::BroadcastHoldout;
use crate::types::ValidationMode;

/// Strategy for handling mempool (unconfirmed) transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
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

    /// Path for persistent storage. Defaults to ./dash-spv-storage
    pub storage_path: PathBuf,

    /// Validation mode.
    pub validation_mode: ValidationMode,

    /// Whether to enable filter syncing.
    pub enable_filters: bool,

    /// Whether to enable masternode syncing.
    pub enable_masternodes: bool,

    /// Whether wallets created from this config include a CoinJoin account.
    ///
    /// Nothing inside the client reads this. It exists so callers that build
    /// a wallet from this config, such as the CLI, can pick the account set
    /// at wallet-creation time. The CoinJoin account watches two full address
    /// pools, which roughly doubles the compact-filter watch set and with it
    /// the number of false-positive block downloads.
    pub enable_coinjoin: bool,

    /// Maximum number of peers to connect to.
    pub max_peers: u32,

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

    /// Whether to fetch transactions from INV messages immediately.
    pub fetch_mempool_transactions: bool,

    /// How many peers to withhold broadcast transactions from.
    ///
    /// Peers never re-announce a transaction to whoever sent it to them, so
    /// the withheld ("holdout") peers are the only source of the `inv` echo
    /// that proves a broadcast propagated through the network.
    pub broadcast_holdout: BroadcastHoldout,

    /// Distinct non-recipient peers that must announce a broadcast txid back
    /// before the broadcast is reported as accepted.
    pub broadcast_acceptance_threshold: usize,

    /// How long a broadcast may stay pending before its outcome is reported
    /// as uncertain.
    pub broadcast_acceptance_timeout: Duration,

    /// Start syncing from a specific block height.
    /// The client will use the nearest checkpoint at or before this height.
    pub start_from_height: Option<u32>,

    /// Time-to-live (seconds) for unfunded receive-address reservations,
    /// periodically reclaimed by the sweep so a hand-out that is never paid and
    /// never released does not pin gap-limit headroom forever. `Some(secs)`
    /// enables the sweep with that TTL; `None` disables it. Defaults to one hour.
    /// Set with [`Self::with_reservation_ttl_secs`] or clear with
    /// [`Self::without_reservation_sweep`].
    pub reservation_sweep_ttl_secs: Option<u64>,

    /// Devnet-only configuration. Must be `Some` iff `network == Network::Devnet`.
    pub devnet: Option<DevnetConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            peers: vec![],
            restrict_to_configured_peers: false,
            storage_path: PathBuf::from("./dash-spv-storage"),
            validation_mode: ValidationMode::Full,
            enable_filters: true,
            enable_masternodes: true,
            enable_coinjoin: false,
            max_peers: 3,
            user_agent: None,
            // Mempool defaults
            enable_mempool_tracking: true,
            mempool_strategy: MempoolStrategy::FetchAll,
            max_mempool_transactions: 1000,
            fetch_mempool_transactions: true,
            broadcast_holdout: BroadcastHoldout::Half,
            broadcast_acceptance_threshold: 1,
            broadcast_acceptance_timeout: Duration::from_secs(60),
            start_from_height: None,
            reservation_sweep_ttl_secs: Some(3600),
            devnet: None,
        }
    }
}

impl ClientConfig {
    /// Create a new configuration for the given network.
    pub fn new(network: Network) -> Self {
        Self {
            network,
            restrict_to_configured_peers: false,
            ..Self::default()
        }
    }

    /// Create a configuration for mainnet.
    pub fn mainnet() -> Self {
        Self::new(Network::Mainnet)
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
    pub fn with_storage_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage_path = path.into();
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

    /// Include a CoinJoin account in wallets created from this config.
    pub fn with_coinjoin(mut self, enable: bool) -> Self {
        self.enable_coinjoin = enable;
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

    /// Set the broadcast holdout policy.
    pub fn with_broadcast_holdout(mut self, holdout: BroadcastHoldout) -> Self {
        self.broadcast_holdout = holdout;
        self
    }

    /// Set how many non-recipient peer announcements mark a broadcast accepted.
    pub fn with_broadcast_acceptance_threshold(mut self, threshold: usize) -> Self {
        self.broadcast_acceptance_threshold = threshold;
        self
    }

    /// Set the timeout after which a pending broadcast is reported uncertain.
    pub fn with_broadcast_acceptance_timeout(mut self, timeout: Duration) -> Self {
        self.broadcast_acceptance_timeout = timeout;
        self
    }

    /// Bundle the broadcast acceptance settings for the mempool manager.
    pub(crate) fn broadcast_config(&self) -> crate::sync::BroadcastConfig {
        crate::sync::BroadcastConfig {
            holdout: self.broadcast_holdout,
            acceptance_threshold: self.broadcast_acceptance_threshold,
            acceptance_timeout: self.broadcast_acceptance_timeout,
        }
    }

    /// Set the starting height for synchronization.
    pub fn with_start_height(mut self, height: u32) -> Self {
        self.start_from_height = Some(height);
        self
    }

    /// Disable the periodic receive-address reservation sweep.
    pub fn without_reservation_sweep(mut self) -> Self {
        self.reservation_sweep_ttl_secs = None;
        self
    }

    /// Enable the periodic receive-address reservation sweep with the given TTL
    /// (seconds): a reservation older than `secs` is reclaimed.
    pub fn with_reservation_ttl_secs(mut self, secs: u64) -> Self {
        self.reservation_sweep_ttl_secs = Some(secs);
        self
    }

    /// Attach a [`DevnetConfig`]. The network must be `Network::Devnet`.
    /// [`validate`](Self::validate) enforces the biconditional.
    pub fn with_devnet(mut self, devnet: DevnetConfig) -> Self {
        self.devnet = Some(devnet);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Note: Empty peers list is now valid - DNS discovery will be used automatically

        if self.max_peers == 0 {
            return Err("max_peers must be > 0".to_string());
        }

        // Mempool validation
        if self.enable_mempool_tracking && self.max_mempool_transactions == 0 {
            return Err(
                "max_mempool_transactions must be > 0 when mempool tracking is enabled".to_string()
            );
        }

        if self.reservation_sweep_ttl_secs == Some(0) {
            return Err("reservation_sweep_ttl_secs must be > 0 when set; use without_reservation_sweep() to disable the sweep".to_string());
        }

        if self.broadcast_acceptance_threshold == 0 {
            return Err("broadcast_acceptance_threshold must be > 0".to_string());
        }
        if self.broadcast_acceptance_timeout.is_zero() {
            return Err("broadcast_acceptance_timeout must be > 0".to_string());
        }

        match (self.network == Network::Devnet, &self.devnet) {
            (true, Some(devnet)) => devnet.validate()?,
            (true, None) => {
                return Err("network is Devnet but no DevnetConfig was provided".to_string());
            }
            (false, Some(_)) => {
                return Err(format!(
                    "DevnetConfig is only valid on Devnet, but network is {:?}",
                    self.network
                ));
            }
            (false, None) => {}
        }

        std::fs::create_dir_all(&self.storage_path).map_err(|e| {
            format!(
                "A valid storage path must be provided to the ClientConfig {:?}: {e}",
                self.storage_path
            )
        })?;

        Ok(())
    }

    /// Apply process-wide settings derived from this config. Idempotent for the
    /// same values, returns an error if a conflicting setting was already applied.
    pub(crate) fn apply_global_overrides(&self) -> Result<(), String> {
        if let Some(devnet) = &self.devnet {
            devnet.apply_global_overrides()?;
        }
        Ok(())
    }
}
