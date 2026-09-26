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
    use crate::storage::{BlockHeaderStorage, DiskStorageManager, MetadataStorage, StorageManager};
    use crate::test_utils::MockNetworkManager;
    use crate::Network;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_manager::WalletManager;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const SECOND_TEST_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const STORAGE_MARKER_KEY: &str = "spv_cache_reanchor_test_marker";
    const STORAGE_MARKER_VALUE: &[u8] = b"preserve-compatible-cache";

    type TestClient =
        DashSpvClient<WalletManager<ManagedWalletInfo>, MockNetworkManager, DiskStorageManager>;

    async fn client_at(
        network: Network,
        birth_height: u32,
        mnemonic: &str,
        storage_path: &Path,
    ) -> TestClient {
        let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(network);
        wallet_manager
            .create_wallet_from_mnemonic(
                mnemonic,
                birth_height,
                WalletAccountCreationOptions::Default,
            )
            .expect("wallet creation must succeed");
        let wallet = Arc::new(RwLock::new(wallet_manager));

        let config = match network {
            Network::Mainnet => ClientConfig::mainnet(),
            Network::Testnet => ClientConfig::testnet(),
            other => panic!("unsupported test network: {other:?}"),
        }
        .without_filters()
        .without_masternodes()
        .with_storage_path(storage_path);

        let storage = DiskStorageManager::new(&config).await.expect("Failed to create storage");
        DashSpvClient::new(config, MockNetworkManager::new(), storage, wallet, vec![Arc::new(())])
            .await
            .expect("client construction must succeed")
    }

    async fn storage_start(client: &TestClient) -> u32 {
        client
            .storage()
            .lock()
            .await
            .get_start_height()
            .await
            .expect("client storage must have an anchor")
    }

    async fn store_marker(client: &TestClient) {
        let metadata = client.storage().lock().await.metadata();
        metadata
            .write()
            .await
            .store_metadata(STORAGE_MARKER_KEY, STORAGE_MARKER_VALUE)
            .await
            .expect("test marker must be stored");
    }

    async fn load_marker(client: &TestClient) -> Option<Vec<u8>> {
        let metadata = client.storage().lock().await.metadata();
        let value = metadata
            .read()
            .await
            .load_metadata(STORAGE_MARKER_KEY)
            .await
            .expect("test marker read must succeed");
        value
    }

    async fn shutdown_client(client: TestClient) {
        let storage = client.storage();
        storage.lock().await.shutdown().await;
        drop(client);
    }

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
        // A wallet birth height below mainnet's HD/BIP39 activation floor is clamped up to
        // the floor, which anchors at the nearest checkpoint at or before it: the 200_000
        // checkpoint. The stored tip carries the trusted checkpoint hash (what the next
        // header's `prev_blockhash` is validated against), not a hash recomputed from a header.
        // 120_000 is below mainnet's HD/BIP39 sync floor, so it is clamped up.
        let (height, hash) = anchored_tip(120_000, None).await;
        assert_eq!(height, 200_000);
        let expected: dashcore::BlockHash =
            "000000000004d0615ff622ec78457ca211dc63fc9c62cca9d9d9af7206be721b".parse().unwrap();
        assert_eq!(hash, Some(expected));

        // Birth height 0 no longer drags mainnet sync to genesis; it floors at HD activation.
        assert_eq!(anchored_tip(0, None).await.0, 200_000);

        // A birth height above the floor is unaffected and anchors at the nearest
        // checkpoint at or below it.
        assert_eq!(anchored_tip(560_000, None).await.0, 550_000);

        // Explicit `start_from_height` wins over the wallet birth height and is honored
        // even below the floor.
        assert_eq!(anchored_tip(120_000, Some(60_000)).await.0, 50_000);
    }

    #[tokio::test]
    async fn older_testnet_wallet_reanchors_recent_shared_storage_to_genesis() {
        let temp_dir = TempDir::new().unwrap();

        let recent_wallet =
            client_at(Network::Testnet, 1_510_000, TEST_MNEMONIC, temp_dir.path()).await;
        assert_eq!(storage_start(&recent_wallet).await, 1_500_000);
        store_marker(&recent_wallet).await;
        shutdown_client(recent_wallet).await;

        let old_wallet =
            client_at(Network::Testnet, 0, SECOND_TEST_MNEMONIC, temp_dir.path()).await;
        assert_eq!(storage_start(&old_wallet).await, 0);
        assert_eq!(
            load_marker(&old_wallet).await,
            None,
            "re-anchoring must clear the complete SPV store, including metadata"
        );
        shutdown_client(old_wallet).await;
    }

    #[tokio::test]
    async fn storage_that_starts_before_wallet_requirement_is_preserved() {
        let earlier_store_dir = TempDir::new().unwrap();

        let old_wallet =
            client_at(Network::Testnet, 0, TEST_MNEMONIC, earlier_store_dir.path()).await;
        assert_eq!(storage_start(&old_wallet).await, 0);
        store_marker(&old_wallet).await;
        shutdown_client(old_wallet).await;

        let recent_wallet =
            client_at(Network::Testnet, 1_510_000, SECOND_TEST_MNEMONIC, earlier_store_dir.path())
                .await;
        assert_eq!(storage_start(&recent_wallet).await, 0);
        assert_eq!(
            load_marker(&recent_wallet).await,
            Some(STORAGE_MARKER_VALUE.to_vec()),
            "storage with sufficient historical coverage must be reused"
        );
        shutdown_client(recent_wallet).await;

        let equal_store_dir = TempDir::new().unwrap();
        let first_recent_wallet =
            client_at(Network::Testnet, 1_500_000, TEST_MNEMONIC, equal_store_dir.path()).await;
        assert_eq!(storage_start(&first_recent_wallet).await, 1_500_000);
        store_marker(&first_recent_wallet).await;
        shutdown_client(first_recent_wallet).await;

        let second_recent_wallet =
            client_at(Network::Testnet, 1_500_000, SECOND_TEST_MNEMONIC, equal_store_dir.path())
                .await;
        assert_eq!(storage_start(&second_recent_wallet).await, 1_500_000);
        assert_eq!(
            load_marker(&second_recent_wallet).await,
            Some(STORAGE_MARKER_VALUE.to_vec()),
            "storage anchored exactly at the wallet requirement must be reused"
        );
        shutdown_client(second_recent_wallet).await;
    }

    #[tokio::test]
    async fn mainnet_reanchor_respects_hd_wallet_sync_floor() {
        let temp_dir = TempDir::new().unwrap();

        let recent_wallet =
            client_at(Network::Mainnet, 560_000, TEST_MNEMONIC, temp_dir.path()).await;
        assert_eq!(storage_start(&recent_wallet).await, 550_000);
        shutdown_client(recent_wallet).await;

        let old_wallet =
            client_at(Network::Mainnet, 0, SECOND_TEST_MNEMONIC, temp_dir.path()).await;
        assert_eq!(storage_start(&old_wallet).await, 200_000);
        shutdown_client(old_wallet).await;
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
