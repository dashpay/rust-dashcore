//! Simple test to verify the fork detection fix
//! 
//! This tests that the SPV client can properly start and load state without
//! incorrectly detecting a fork.

use dash_spv::client::{ClientConfig, DashSpvClient};
use dashcore::Network;
use tempfile::TempDir;

#[tokio::test]
async fn test_fork_detection_basic() {
    // Initialize logging
    let _ = tracing_subscriber::fmt::init();
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let data_dir = temp_dir.path().to_path_buf();
    
    // Create client config with persistence enabled
    let config = ClientConfig {
        network: Network::Testnet,
        storage_path: Some(data_dir.clone()),
        enable_persistence: true,
        // Add a dummy peer (won't actually connect since we won't run the sync loop)
        peers: vec!["127.0.0.1:19999".parse().unwrap()],
        ..Default::default()
    };
    
    // Create the SPV client
    let mut client = DashSpvClient::new(config.clone())
        .await
        .expect("Failed to create SPV client");
    
    // Start the client - this should initialize properly without fork detection issues
    match client.start().await {
        Ok(_) => {
            tracing::info!("✅ Client started successfully");
            
            // Get initial sync progress
            let sync_progress = client.sync_progress().await
                .expect("Failed to get sync progress");
            
            // Should start at height 0 (genesis)
            assert_eq!(
                sync_progress.header_height, 0,
                "Client should start at genesis height"
            );
            
            tracing::info!("Initial height: {}", sync_progress.header_height);
            
            // Stop the client
            client.stop().await.expect("Failed to stop client");
        }
        Err(e) => {
            panic!("Failed to start client: {}", e);
        }
    }
    
    // Now create a new client instance to test state restoration
    let mut client2 = DashSpvClient::new(config)
        .await
        .expect("Failed to create second SPV client");
    
    // Start the second client - it should load state without fork detection issues
    match client2.start().await {
        Ok(_) => {
            tracing::info!("✅ Second client started successfully");
            
            // Should restore to the same state
            let sync_progress = client2.sync_progress().await
                .expect("Failed to get sync progress");
            
            assert_eq!(
                sync_progress.header_height, 0,
                "Client should restore to genesis height"
            );
            
            tracing::info!("Restored height: {}", sync_progress.header_height);
            
            // Stop the client
            client2.stop().await.expect("Failed to stop second client");
        }
        Err(e) => {
            panic!("Failed to start second client: {}", e);
        }
    }
    
    tracing::info!("✅ Fork detection test passed - client can start and restart without issues");
}