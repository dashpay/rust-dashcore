//! Simple integration test for ChainLock validation flow

use dash_spv::client::{Config, DashSpvClient};
use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::types::ValidationMode;
use dashcore::Network;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tracing::Level;

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .try_init();
}

#[tokio::test]
async fn test_chainlock_validation_flow() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();

    // Create client config with masternodes enabled
    let network = Network::Dash;
    let enable_masternodes = true;
    let config = Config {
        network,
        enable_filters: false,
        enable_masternodes,
        validation_mode: ValidationMode::Basic,
        storage_path: temp_dir.path().to_path_buf(),
        peers: vec!["127.0.0.1:9999".parse().unwrap()], // Dummy peer to satisfy config
        ..Default::default()
    };

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await.unwrap();

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await.unwrap();

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    // Create the SPV client
    let client =
        DashSpvClient::new(config, network_manager, storage_manager, wallet).await.unwrap();

    // Test that update_chainlock_validation works
    let updated = client.update_chainlock_validation().unwrap();

    // The update may succeed if masternodes are enabled and terminal block data is available
    // This is expected behavior - the client pre-loads terminal block data for mainnet
    if enable_masternodes && network == Network::Dash {
        // On mainnet with masternodes enabled, terminal block data is pre-loaded
        assert!(updated, "Should have masternode engine with terminal block data");
    } else {
        // Otherwise should be false
        assert!(!updated, "Should not have masternode engine before sync");
    }

    tracing::info!("✅ ChainLock validation flow test passed");
}

#[tokio::test]
async fn test_chainlock_manager_initialization() {
    init_logging();

    // Create temp directory for storage
    let temp_dir = TempDir::new().unwrap();

    // Create client config
    let config = Config {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        storage_path: temp_dir.path().to_path_buf(),
        peers: vec!["127.0.0.1:9999".parse().unwrap()], // Dummy peer to satisfy config
        ..Default::default()
    };

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await.unwrap();

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await.unwrap();

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    // Create the SPV client
    let client =
        DashSpvClient::new(config, network_manager, storage_manager, wallet).await.unwrap();

    // Verify chainlock manager is initialized
    // We can't directly access it from tests, but we can verify the client works
    let sync_progress = client.sync_progress().await.unwrap();
    assert_eq!(sync_progress.header_height, 0);

    tracing::info!("✅ ChainLock manager initialization test passed");
}
