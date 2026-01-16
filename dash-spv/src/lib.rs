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
//! use dash_spv::network::PeerNetworkManager;
//! use dash_spv::storage::DiskStorageManager;
//! use dashcore::Network;
//! use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
//! use key_wallet_manager::wallet_manager::WalletManager;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use tokio_util::sync::CancellationToken;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create configuration for mainnet
//!     let config = ClientConfig::mainnet()
//!         .with_storage_path("./.tmp/example-storage");
//!
//!     // Create the required components
//!     let network = PeerNetworkManager::new(&config).await?;
//!     let storage = DiskStorageManager::new(&config).await?;
//!     let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));
//!
//!     // Create and start the client
//!     let mut client = DashSpvClient::new(config.clone(), network, storage, wallet).await?;
//!     client.start().await?;
//!
//!     let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
//!     let shutdown_token = CancellationToken::new();
//!
//!     client.run(command_receiver, shutdown_token).await?;
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

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub mod chain;
pub mod client;
pub mod error;
pub mod logging;
pub mod mempool_filter;
pub mod network;
pub mod storage;
pub mod sync;
#[cfg(feature = "terminal-ui")]
pub mod terminal;
pub mod types;
pub mod validation;

// Re-export main types for convenience
pub use client::{Config, DashSpvClient};
pub use error::{
    LoggingError, LoggingResult, NetworkError, SpvError, StorageError, SyncError, ValidationError,
};
pub use logging::{init_console_logging, init_logging, LogFileConfig, LoggingConfig, LoggingGuard};
pub use tracing::level_filters::LevelFilter;
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
