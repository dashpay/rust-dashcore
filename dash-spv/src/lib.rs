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
//! use key_wallet_manager::WalletManager;
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
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
//!     // Create and run the client
//!     let client = DashSpvClient::new(
//!         config.clone(),
//!         network,
//!         storage,
//!         wallet,
//!         vec![Arc::new(())],
//!     ).await?;
//!
//!     client.run().await?;
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

#![deny(clippy::disallowed_types)]

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub mod chain;
pub mod client;
pub mod error;
pub mod logging;
pub mod network;
pub mod storage;
pub mod sync;
pub mod types;
pub mod validation;

// Re-export main types for convenience
pub use client::config::MempoolStrategy;
pub use client::{ClientConfig, DashSpvClient, DevnetConfig, EventHandler};
pub use error::{
    LoggingError, LoggingResult, NetworkError, SpvError, StorageError, SyncError, ValidationError,
};
pub use logging::{init_console_logging, init_logging, LogFileConfig, LoggingConfig, LoggingGuard};
pub use tracing::level_filters::LevelFilter;
pub use types::{FilterMatch, ValidationMode};

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
pub use dashcore::sml::llmq_type::{LLMQType, LlmqDevnetParams};

/// Current version of the dash-spv library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git commit the library was built from, empty if it could not be determined.
pub const GIT_HASH: &str = env!("DASH_SPV_GIT_HASH");

/// Whether the source tree has uncommitted tracked changes.
///
/// Resolved by [`git_state::git_dirty`] while this crate is compiled, so it
/// re-evaluates whenever the crate is rebuilt. An unstaged edit that triggers
/// a rebuild is reflected without staging or committing, which a build script
/// cannot achieve for the unbounded working tree. Builds with no git context
/// (e.g. a packaged source tarball) report `false`.
pub const GIT_DIRTY: bool = git_state::git_dirty!();

/// Whether the build was made from a commit pointed at by a `v*` release tag.
pub const GIT_TAGGED: bool = const_str_eq(env!("DASH_SPV_GIT_TAGGED"), "true");

const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Human readable version.
///
/// A release build (the commit is pointed at by a `v*` tag and the tree is clean)
/// renders just `dash-spv 0.42.0`. Any development build surfaces the commit so it
/// is recognizable as non-release: `dash-spv 0.42.0 (a1b2c3d4e5f6)`, or
/// `dash-spv 0.42.0 (a1b2c3d4e5f6-dirty)` with uncommitted changes. Builds with no
/// git context (e.g. a packaged source tarball) render just `dash-spv 0.42.0`.
pub fn version_info() -> String {
    if GIT_HASH.is_empty() || (GIT_TAGGED && !GIT_DIRTY) {
        format!("dash-spv {VERSION}")
    } else if GIT_DIRTY {
        format!("dash-spv {VERSION} ({GIT_HASH}-dirty)")
    } else {
        format!("dash-spv {VERSION} ({GIT_HASH})")
    }
}

#[cfg(test)]
mod tests {
    use super::{version_info, GIT_DIRTY, GIT_HASH, GIT_TAGGED, VERSION};

    #[test]
    fn version_info_format() {
        let info = version_info();
        assert!(info.starts_with("dash-spv "));
        assert!(info.contains(VERSION));

        let is_release = GIT_HASH.is_empty() || (GIT_TAGGED && !GIT_DIRTY);
        if is_release {
            assert_eq!(info, format!("dash-spv {VERSION}"));
        } else {
            assert!(info.contains(GIT_HASH));
            assert_eq!(info.ends_with("-dirty)"), GIT_DIRTY);
        }
    }
}
