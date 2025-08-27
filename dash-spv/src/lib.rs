//! Dash SPV (Simplified Payment Verification) client library.
//!
//! This library provides a complete implementation of a Dash SPV client that can:
//!
//! - Synchronize block headers from the Dash network
//! - Download and verify BIP157 compact block filters  
//! - Maintain an up-to-date masternode list
//! - Validate ChainLocks and InstantLocks
//! - Monitor addresses and scripts for transactions
//! - Persist state to disk for quick restarts
//!
//! # Quick Start
//!
//! ```no_run
//! use dash_spv::{DashSpvClient, ClientConfig};
//! use dash_spv::network::MultiPeerNetworkManager;
//! use dash_spv::storage::MemoryStorageManager;
//! use dashcore::Network;
//! use key_wallet_manager::spv_wallet_manager::SPVWalletManager;
//! use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
//! use key_wallet_manager::wallet_manager::WalletManager;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create configuration for mainnet
//!     let config = ClientConfig::mainnet()
//!         .with_storage_path("/path/to/data".into())
//!         .with_log_level("info");
//!
//!     // Create the required components
//!     let network = MultiPeerNetworkManager::new(&config).await?;
//!     let storage = MemoryStorageManager::new().await?;
//!     let wallet = Arc::new(RwLock::new(SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new())));
//!
//!     // Create and start the client
//!     let mut client = DashSpvClient::new(config.clone(), network, storage, wallet).await?;
//!     client.start().await?;
//!
//!     // Synchronize to the tip of the blockchain
//!     let progress = client.sync_to_tip().await?;
//!     println!("Synced to height {}", progress.header_height);
//!
//!     // Stop the client
//!     client.stop().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **Async/await support**: Built on tokio for modern async Rust
//! - **Modular architecture**: Easily swap out components like storage backends
//! - **Comprehensive validation**: Configurable validation levels from basic to full PoW
//! - **BIP157 support**: Efficient transaction filtering with compact block filters
//! - **Dash-specific features**: ChainLocks, InstantLocks, and masternode list sync
//! - **Persistent storage**: Save and restore state between runs
//! - **Extensive logging**: Built-in tracing support for debugging

pub mod bloom;
pub mod chain;
pub mod client;
pub mod error;
pub mod mempool_filter;
pub mod network;
pub mod storage;
pub mod sync;
pub mod terminal;
pub mod types;
pub mod validation;

// Re-export main types for convenience
pub use client::{ClientConfig, DashSpvClient};
pub use error::{NetworkError, SpvError, StorageError, SyncError, ValidationError};
pub use types::{ChainState, FilterMatch, PeerInfo, SpvStats, SyncProgress, ValidationMode};

// Re-export commonly used dashcore types
pub use dashcore::{Address, BlockHash, Network, OutPoint, QuorumHash, ScriptBuf};

// Re-export hash trait
pub use dashcore::hashes::Hash;

// Re-export MasternodeListEngine and related types
pub use dashcore::sml::masternode_list_engine::{
    MasternodeListEngine, MasternodeListEngineBTreeMapBlockContainer,
    MasternodeListEngineBlockContainer,
};

// Re-export LLMQ types
pub use dashcore::sml::llmq_type::LLMQType;

/// Current version of the dash-spv library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize logging with the given level.
///
/// This is a convenience function that sets up tracing-subscriber
/// with a simple format suitable for most applications.
pub fn init_logging(level: &str) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::fmt;

    let level = match level {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    };

    fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_max_level(level)
        .try_init()
        .map_err(|e| format!("Failed to initialize logging: {}", e).into())
}
