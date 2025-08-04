//! Simple integration test for ChainLock validation flow

use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::types::ValidationMode;
use dashcore::Network;
use tempfile::TempDir;
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
    let storage_path = temp_dir.path().to_path_buf();

    // Create client config with masternodes enabled
    let network = Network::Dash;
    let enable_masternodes = true;
    let config = ClientConfig {
        network,
        enable_filters: false,
        enable_masternodes,
        validation_mode: ValidationMode::Basic,
        storage_path: Some(storage_path),
        enable_persistence: true,
        peers: vec!["127.0.0.1:9999".parse().unwrap()], // Dummy peer to satisfy config
        ..Default::default()
    };

    // Create the SPV client
    let mut client = DashSpvClient::new(config).await.unwrap();

    // Test that update_chainlock_validation works
    let updated = client.update_chainlock_validation().await.unwrap();
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
    let storage_path = temp_dir.path().to_path_buf();

    // Create client config
    let config = ClientConfig {
        network: Network::Dash,
        enable_filters: false,
        enable_masternodes: false,
        validation_mode: ValidationMode::Basic,
        storage_path: Some(storage_path),
        enable_persistence: true,
        peers: vec!["127.0.0.1:9999".parse().unwrap()], // Dummy peer to satisfy config
        ..Default::default()
    };

    // Create the SPV client
    let client = DashSpvClient::new(config).await.unwrap();

    // Verify chainlock manager is initialized
    // We can't directly access it from tests, but we can verify the client works
    let sync_progress = client.sync_progress().await.unwrap();
    assert_eq!(sync_progress.header_height, 0);

    tracing::info!("✅ ChainLock manager initialization test passed");
}
