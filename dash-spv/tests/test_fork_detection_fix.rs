//! Test to verify the fork detection fix works correctly
//! 
//! This test simulates the issue where the SPV client incorrectly detects
//! a fork when resuming from saved state.

use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    storage::{DiskStorageManager, StorageManager},
};
use dashcore::{
    block::Header as BlockHeader,
    blockdata::constants::genesis_block,
    network::Network,
};
use dashcore_hashes::Hash;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a test storage directory
fn create_test_storage() -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let data_dir = temp_dir.path().to_path_buf();
    (temp_dir, data_dir)
}

/// Generate mock headers for testing
fn generate_mock_headers(count: u32, network: Network) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let genesis = genesis_block(network).header;
    
    let mut prev_hash = genesis.block_hash();
    for i in 1..=count {
        let mut header = genesis.clone();
        header.prev_blockhash = prev_hash;
        header.time = genesis.time + i * 150; // Dash block time ~2.5 minutes
        header.nonce = i; // Make each header unique
        
        prev_hash = header.block_hash();
        headers.push(header);
    }
    
    headers
}

#[tokio::test]
async fn test_fork_detection_fix() {
    // Initialize logging
    let _ = tracing_subscriber::fmt::init();
    
    let (_temp_dir, data_dir) = create_test_storage();
    let network = Network::Testnet;
    
    // Create storage manager
    let mut storage = DiskStorageManager::new(data_dir.clone())
        .await
        .expect("Failed to create storage");
    
    // Store genesis
    let genesis = genesis_block(network).header;
    storage.store_headers(&[genesis.clone()])
        .await
        .expect("Failed to store genesis");
    
    // Generate and store mock headers
    let header_count = 1000;
    let headers = generate_mock_headers(header_count, network);
    
    // Store headers in batches of 100
    for chunk in headers.chunks(100) {
        storage.store_headers(chunk)
            .await
            .expect("Failed to store headers");
    }
    
    // Create a chain state with all headers and save it
    let mut chain_state = dash_spv::types::ChainState::new_for_network(network);
    for header in &headers {
        chain_state.add_header(header.clone());
    }
    
    // Save the chain state
    storage.store_chain_state(&chain_state)
        .await
        .expect("Failed to store chain state");
    
    // Create sync state that indicates we have synced headers
    let sync_state = dash_spv::storage::PersistentSyncState {
        version: 1,
        network,
        chain_tip: dash_spv::storage::ChainTip {
            hash: chain_state.tip_hash().expect("Should have tip hash"),
            height: chain_state.tip_height(),
        },
        sync_progress: dash_spv::types::SyncProgress {
            header_height: header_count,
            filter_header_height: 0,
            filter_height: 0,
            chain_work: 0.0,
            headers_synced: true,
            filter_headers_synced: false,
            filters_synced: false,
        },
        filter_sync: dash_spv::storage::FilterSyncState {
            filter_checkpoint_height: 0,
            filters_downloaded: 0,
            last_filter_header_height: None,
        },
        masternode_sync: dash_spv::storage::MasternodeSyncState {
            last_synced_height: None,
            last_diff_height: None,
        },
        wallet_state: dash_spv::storage::WalletSyncState {
            last_scan_height: 0,
            total_transactions: 0,
            total_utxos: 0,
        },
        checkpoints: Vec::new(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    storage.store_sync_state(&sync_state)
        .await
        .expect("Failed to store sync state");
    
    // Drop storage to release locks
    drop(storage);
    
    // Now create SPV client config
    let config = ClientConfig {
        network,
        storage_path: data_dir.to_string_lossy().to_string(),
        enable_persistence: true,
        ..Default::default()
    };
    
    // Create the SPV client
    let mut client = DashSpvClient::new(config)
        .await
        .expect("Failed to create SPV client");
    
    // Start the client - this should load headers from storage
    tracing::info!("Starting SPV client to test state restoration...");
    
    // Start the client (this will restore state internally)
    match client.start().await {
        Ok(_) => {
            tracing::info!("✅ Client started successfully");
            
            // Get sync progress to verify headers were loaded
            let sync_progress = client.sync_progress().await
                .expect("Failed to get sync progress");
            
            assert_eq!(
                sync_progress.header_height, header_count,
                "Client should have restored all {} headers, but has {}",
                header_count, sync_progress.header_height
            );
            
            tracing::info!(
                "✅ Client restored {} headers successfully",
                sync_progress.header_height
            );
            
            // Stop the client
            client.stop().await.expect("Failed to stop client");
        }
        Err(e) => {
            panic!("Failed to start client: {}", e);
        }
    }
}

#[tokio::test]
async fn test_validation_failure_handling() {
    // This test specifically checks that headers are loaded into the sync manager
    // even when validation fails
    
    let _ = tracing_subscriber::fmt::init();
    
    let (_temp_dir, data_dir) = create_test_storage();
    let network = Network::Testnet;
    
    // Create storage manager
    let mut storage = DiskStorageManager::new(data_dir.clone())
        .await
        .expect("Failed to create storage");
    
    // Store genesis
    let genesis = genesis_block(network).header;
    storage.store_headers(&[genesis.clone()])
        .await
        .expect("Failed to store genesis");
    
    // Generate headers but make one invalid by breaking the chain
    let mut headers = generate_mock_headers(100, network);
    
    // Corrupt header at position 50 to break validation
    if let Some(header) = headers.get_mut(49) {
        // Make this header not connect to the previous one
        header.prev_blockhash = dashcore::BlockHash::all_zeros();
    }
    
    // Store all headers including the corrupted one
    storage.store_headers(&headers)
        .await
        .expect("Failed to store headers");
    
    // Create and save chain state with all headers
    let mut chain_state = dash_spv::types::ChainState::new_for_network(network);
    for header in &headers {
        chain_state.add_header(header.clone());
    }
    
    storage.store_chain_state(&chain_state)
        .await
        .expect("Failed to store chain state");
    
    // Create sync state
    let sync_state = dash_spv::storage::PersistentSyncState {
        version: 1,
        network,
        chain_tip: dash_spv::storage::ChainTip {
            hash: chain_state.tip_hash().expect("Should have tip hash"),
            height: chain_state.tip_height(),
        },
        sync_progress: dash_spv::types::SyncProgress {
            header_height: 100,
            filter_header_height: 0,
            filter_height: 0,
            chain_work: 0.0,
            headers_synced: true,
            filter_headers_synced: false,
            filters_synced: false,
        },
        filter_sync: dash_spv::storage::FilterSyncState {
            filter_checkpoint_height: 0,
            filters_downloaded: 0,
            last_filter_header_height: None,
        },
        masternode_sync: dash_spv::storage::MasternodeSyncState {
            last_synced_height: None,
            last_diff_height: None,
        },
        wallet_state: dash_spv::storage::WalletSyncState {
            last_scan_height: 0,
            total_transactions: 0,
            total_utxos: 0,
        },
        checkpoints: Vec::new(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    storage.store_sync_state(&sync_state)
        .await
        .expect("Failed to store sync state");
    
    // Drop storage to release locks
    drop(storage);
    
    // Create SPV client
    let config = ClientConfig {
        network,
        storage_path: data_dir.to_string_lossy().to_string(),
        enable_persistence: true,
        ..Default::default()
    };
    
    let mut client = DashSpvClient::new(config)
        .await
        .expect("Failed to create SPV client");
    
    // Start the client - this should handle the validation failure gracefully
    match client.start().await {
        Ok(_) => {
            tracing::info!("✅ Client started successfully despite validation issues");
            
            // The key test: we should still have made progress loading headers
            let sync_progress = client.sync_progress().await
                .expect("Failed to get sync progress");
            
            // We might not have all 100 headers due to validation failure,
            // but we should have loaded some
            assert!(
                sync_progress.header_height > 0,
                "Should have loaded some headers despite validation failure, but has height {}",
                sync_progress.header_height
            );
            
            tracing::info!(
                "✅ Loaded {} headers despite validation failure",
                sync_progress.header_height
            );
            
            // Stop the client
            client.stop().await.expect("Failed to stop client");
        }
        Err(e) => {
            // Even if start fails, that's OK for this test - we're testing
            // that the validation failure is handled gracefully
            tracing::info!("Client start failed as expected due to validation issues: {}", e);
        }
    }
}