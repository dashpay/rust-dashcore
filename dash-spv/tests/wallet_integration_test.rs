//! Integration tests for wallet functionality.
//!
//! These tests validate end-to-end wallet operations through the SPVWalletManager.

use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{Config, DashSpvClient};
use dashcore::Network;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
/// Create a test SPV client with memory storage for integration testing.
async fn create_test_client(
) -> DashSpvClient<WalletManager<ManagedWalletInfo>, PeerNetworkManager, DiskStorageManager> {
    let config = Config::testnet()
        .without_filters()
        .with_storage_path(TempDir::new().unwrap().path())
        .without_masternodes();

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await.unwrap();

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await.expect("Failed to create storage");

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    DashSpvClient::new(config, network_manager, storage_manager, wallet).await.unwrap()
}

#[tokio::test]
async fn test_spv_client_creation() {
    // Basic test to ensure client can be created
    let client = create_test_client().await;

    // Verify client is created
    assert_eq!(client.network(), Network::Testnet);
}

#[tokio::test]
async fn test_spv_client_start_stop() {
    // Test starting and stopping the client
    let mut client = create_test_client().await;

    // Start the client
    client.start().await.unwrap();

    // Verify client is running
    let running = client.is_running().await;
    assert!(running);

    // Stop the client
    client.stop().await.unwrap();

    // Verify client is stopped
    let running = client.is_running().await;
    assert!(!running);
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

// Note: More comprehensive wallet tests should be in the key-wallet-manager crate
// since that's where the wallet logic now resides
