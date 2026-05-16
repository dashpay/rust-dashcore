//! Integration tests for wallet functionality.
//!
//! These tests validate end-to-end wallet operations through the SPVWalletManager.

use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{ClientConfig, DashSpvClient};
use dashcore::Network;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
/// Create a test SPV client with memory storage for integration testing.
async fn create_test_client(
) -> DashSpvClient<WalletManager<ManagedWalletInfo>, PeerNetworkManager, DiskStorageManager> {
    let config = ClientConfig::testnet()
        .without_filters()
        .with_storage_path(TempDir::new().unwrap().path())
        .without_masternodes()
        // Ensure DNS discovery isn't used since it's causing flakiness in CI and not needed for these tests.
        .with_restrict_to_configured_peers(true);

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await.unwrap();

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await.expect("Failed to create storage");

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    DashSpvClient::new(config, network_manager, storage_manager, wallet, vec![]).await.unwrap()
}

#[tokio::test]
async fn test_spv_client_creation() {
    // Basic test to ensure client can be created
    let client = create_test_client().await;

    // Verify client is created
    assert_eq!(client.network().await, Network::Testnet);
}

#[tokio::test]
async fn test_spv_client_run_stop() {
    let client = create_test_client().await;

    // Run twice on the same instance: the watch must re-arm after stop(), so a
    // second run() succeeds.
    for _ in 0..2 {
        let run_client = client.clone();
        let handle = tokio::spawn(async move { run_client.run().await });

        tokio::time::timeout(Duration::from_secs(5), async {
            while !client.is_running() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client failed to start");

        client.stop().await.unwrap();

        // stop() wakes the run loop immediately via the watch rather than only
        // on the next 100ms coordinator tick, so the join completes far inside
        // this bound. A hang (e.g. a missed wakeup) would trip the timeout.
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("run task did not exit promptly after stop")
            .unwrap()
            .unwrap();

        assert!(!client.is_running());
    }
}

#[tokio::test]
async fn test_wallet_manager_basic_operations() {
    // Test basic wallet manager operations
    let wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Test that we can create a wallet manager
    // Check wallet count
    assert_eq!(wallet_manager.wallet_count(), 0);

    // Test adding a wallet (this would need actual wallet creation logic)
    // For now, just verify the manager is working
    let balance = wallet_manager.get_total_balance();
    assert_eq!(balance, 0);
}
