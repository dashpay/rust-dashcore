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
//! use dashcore::Network;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create configuration for mainnet
//!     let config = ClientConfig::mainnet()
//!         .with_storage_path("/path/to/data".into())
//!         .with_log_level("info");
//!
//!     // Create and start the client
//!     let mut client = DashSpvClient::new(config).await?;
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

pub mod client;
pub mod error;
pub mod network;
pub mod storage;
pub mod sync;
pub mod types;
pub mod validation;
pub mod terminal;
pub mod wallet;

// Re-export main types for convenience
pub use client::{ClientConfig, DashSpvClient};
pub use error::{SpvError, NetworkError, StorageError, ValidationError, SyncError};
pub use types::{
    ChainState, SyncProgress, ValidationMode, WatchItem, FilterMatch, 
    PeerInfo, SpvStats
};
pub use wallet::{Wallet, Balance, Utxo, TransactionProcessor, TransactionResult, BlockResult, AddressStats};

// Re-export commonly used dashcore types
pub use dashcore::{Address, Network, BlockHash, ScriptBuf, OutPoint};

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

