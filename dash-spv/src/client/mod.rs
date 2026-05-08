//! High-level client API for the Dash SPV client.
//!
//! Provides `DashSpvClient`, the main entry point for SPV operations including
//! sync orchestration, mempool tracking, peer/masternode queries, and transaction
//! broadcasting.
//!
//! ## Module Structure
//!
//! - `config.rs` - Client configuration
//! - `core.rs` - Core `DashSpvClient` struct definition and simple accessors
//! - `lifecycle.rs` - Client lifecycle (new, start, stop, shutdown)
//! - `events.rs` - Event emission and progress tracking receivers
//! - `queries.rs` - Peer, masternode, and balance queries
//! - `transactions.rs` - Transaction operations (e.g., broadcast)
//! - `sync_coordinator.rs` - Sync orchestration and network monitoring
//!
//! ## Lock Ordering
//!
//! When acquiring multiple locks, always use this order:
//! 1. running (`Arc<RwLock<bool>>`)
//! 2. storage (`Arc<Mutex<S>>`)
//!
//! Never acquire locks in reverse order or deadlock will occur!

pub mod config;
pub mod event_handler;

mod core;
mod events;
mod lifecycle;
mod queries;
mod sync_coordinator;
mod transactions;

// Re-export public types from extracted modules
pub use config::ClientConfig;
pub use event_handler::EventHandler;

// Re-export the main client struct
pub use core::DashSpvClient;

#[cfg(test)]
mod config_test;

#[cfg(test)]
mod tests {
    use super::{ClientConfig, DashSpvClient};
    use crate::client::config::MempoolStrategy;
    use crate::storage::DiskStorageManager;
    use crate::test_utils::MockNetworkManager;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_manager::WalletManager;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn client_exposes_shared_wallet_manager() {
        let config = ClientConfig::mainnet()
            .without_filters()
            .without_masternodes()
            .with_mempool_tracking(MempoolStrategy::FetchAll)
            .with_storage_path(TempDir::new().unwrap().path());

        let network_manager = MockNetworkManager::new();
        let storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

        let client =
            DashSpvClient::new(config, network_manager, storage, wallet, vec![Arc::new(())])
                .await
                .expect("client construction must succeed");

        // Verify the wallet is accessible
        let wallet_ref = client.wallet();
        let _wallet_guard = wallet_ref.read().await;
    }

    #[tokio::test]
    async fn client_attaches_builtin_logging_handler() {
        let config = ClientConfig::mainnet()
            .without_filters()
            .without_masternodes()
            .with_mempool_tracking(MempoolStrategy::FetchAll)
            .with_storage_path(TempDir::new().unwrap().path());

        let network_manager = MockNetworkManager::new();
        let storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

        let client = DashSpvClient::new(config, network_manager, storage, wallet, Vec::new())
            .await
            .expect("client construction must succeed");

        assert_eq!(
            client.event_handlers.len(),
            1,
            "constructor should auto-attach the built-in logging handler",
        );
    }
}
