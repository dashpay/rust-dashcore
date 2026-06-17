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

pub mod config;
pub mod devnet;
pub mod event_handler;

mod core;
mod events;
mod lifecycle;
mod queries;
mod sync_coordinator;
mod transactions;

// Re-export public types from extracted modules
pub use config::ClientConfig;
pub use devnet::DevnetConfig;
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
    use crate::Network;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_manager::WalletManager;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Construct a mainnet client with the given wallet birth height and optional
    /// explicit `start_from_height`, then return the height and hash its chain is
    /// anchored at.
    async fn anchored_tip(
        birth_height: u32,
        start_from_height: Option<u32>,
    ) -> (u32, Option<dashcore::BlockHash>) {
        let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Mainnet);
        wallet_manager
            .create_wallet_from_mnemonic(
                TEST_MNEMONIC,
                birth_height,
                WalletAccountCreationOptions::Default,
            )
            .expect("wallet creation must succeed");
        let wallet = Arc::new(RwLock::new(wallet_manager));

        let temp_dir = TempDir::new().unwrap();
        let mut config = ClientConfig::mainnet()
            .without_filters()
            .without_masternodes()
            .with_storage_path(temp_dir.path());
        config.start_from_height = start_from_height;

        let storage = DiskStorageManager::new(&config).await.expect("Failed to create storage");
        let client = DashSpvClient::new(
            config,
            MockNetworkManager::new(),
            storage,
            wallet,
            vec![Arc::new(())],
        )
        .await
        .expect("client construction must succeed");
        (client.tip_height().await, client.tip_hash().await)
    }

    #[tokio::test]
    async fn birth_height_anchors_chain_to_nearest_checkpoint() {
        // A wallet born at 120_000 anchors at the 100_000 checkpoint, not genesis, and
        // the stored tip carries the trusted checkpoint hash (what the next header's
        // `prev_blockhash` is validated against), not a hash recomputed from a header.
        let (height, hash) = anchored_tip(120_000, None).await;
        assert_eq!(height, 100_000);
        let expected: dashcore::BlockHash =
            "00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2".parse().unwrap();
        assert_eq!(hash, Some(expected));

        // Birth height 0 keeps syncing from genesis.
        assert_eq!(anchored_tip(0, None).await.0, 0);

        // Explicit `start_from_height` wins over the wallet birth height, even when
        // the birth height would resolve to a higher checkpoint.
        assert_eq!(anchored_tip(120_000, Some(60_000)).await.0, 50_000);
    }

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
}
