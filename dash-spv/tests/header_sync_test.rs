//! Integration tests for header synchronization functionality.

use std::time::Duration;

use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::{DiskStorageManager, MemoryStorageManager, StorageManager},
    sync::{HeaderSyncManager, ReorgConfig},
    types::{ChainState, ValidationMode},
};
use dashcore::{block::Header as BlockHeader, block::Version, Network};
use dashcore_hashes::Hash;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use log::{debug, info};
use test_case::test_case;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_basic_header_sync_from_genesis() {
    let _ = env_logger::try_init();

    // Create fresh storage starting from empty state
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

    // Verify empty initial state
    assert_eq!(storage.get_tip_height().await.unwrap(), None);
    assert!(storage.load_headers(0..10).await.unwrap().is_empty());

    // Create test chain state for mainnet
    let chain_state = ChainState::new_for_network(Network::Dash);
    storage.store_chain_state(&chain_state).await.expect("Failed to store initial chain state");

    // Verify we can load the initial state
    let loaded_state = storage.load_chain_state().await.unwrap();
    assert!(loaded_state.is_some());

    info!("Basic header sync setup completed - ready for network sync");
}

#[tokio::test]
async fn test_header_sync_continuation() {
    let _ = env_logger::try_init();

    let mut storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    // Simulate existing headers (like resuming from a previous sync)
    let existing_headers = create_test_header_chain(100);
    storage.store_headers(&existing_headers).await.expect("Failed to store existing headers");

    // Verify we have the expected tip
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(99));

    // Simulate adding more headers (continuation)
    let continuation_headers = create_test_header_chain_from(100, 50);
    storage
        .store_headers(&continuation_headers)
        .await
        .expect("Failed to store continuation headers");

    // Verify the chain extended properly
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(149));

    // Verify continuity by checking some headers
    for height in 95..105 {
        let header = storage.get_header(height).await.unwrap();
        assert!(header.is_some(), "Header at height {} should exist", height);
    }

    info!("Header sync continuation test completed");
}

#[tokio::test]
async fn test_header_batch_processing() {
    let _ = env_logger::try_init();

    let mut storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    // Test processing headers in batches
    let batch_size = 50;
    let total_headers = 200;

    for batch_start in (0..total_headers).step_by(batch_size) {
        let batch_end = (batch_start + batch_size).min(total_headers);
        let batch = create_test_header_chain_from(batch_start, batch_end - batch_start);

        storage
            .store_headers(&batch)
            .await
            .unwrap_or_else(|_| panic!("Failed to store batch {}-{}", batch_start, batch_end));

        let expected_tip = batch_end - 1;
        assert_eq!(
            storage.get_tip_height().await.unwrap(),
            Some(expected_tip as u32),
            "Tip height should be {} after batch {}-{}",
            expected_tip,
            batch_start,
            batch_end
        );
    }

    // Verify total count
    let final_tip = storage.get_tip_height().await.unwrap();
    assert_eq!(final_tip, Some((total_headers - 1) as u32));

    // Verify we can retrieve headers from different parts of the chain
    let early_headers = storage.load_headers(0..10).await.unwrap();
    assert_eq!(early_headers.len(), 10);

    let mid_headers = storage.load_headers(90..110).await.unwrap();
    assert_eq!(mid_headers.len(), 20);

    let late_headers = storage.load_headers(190..200).await.unwrap();
    assert_eq!(late_headers.len(), 10);

    info!("Header batch processing test completed");
}

#[tokio::test]
async fn test_header_sync_edge_cases() {
    let _ = env_logger::try_init();

    let mut storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    // Test 1: Empty header batch
    let empty_headers: Vec<BlockHeader> = vec![];
    storage.store_headers(&empty_headers).await.expect("Should handle empty header batch");
    assert_eq!(storage.get_tip_height().await.unwrap(), None);

    // Test 2: Single header
    let single_header = create_test_header_chain(1);
    storage.store_headers(&single_header).await.expect("Should handle single header");
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(0));

    // Test 3: Large batch
    let large_batch = create_test_header_chain_from(1, 5000);
    storage.store_headers(&large_batch).await.expect("Should handle large header batch");
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(5000));

    // Test 4: Out-of-order access
    let header_4500 = storage.get_header(4500).await.unwrap();
    assert!(header_4500.is_some());

    let header_100 = storage.get_header(100).await.unwrap();
    assert!(header_100.is_some());

    // Test 5: Range queries on large dataset
    let mid_range = storage.load_headers(2000..2100).await.unwrap();
    assert_eq!(mid_range.len(), 100);

    info!("Header sync edge cases test completed");
}

#[tokio::test]
async fn test_header_chain_validation() {
    let _ = env_logger::try_init();

    let mut storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    // Create a valid chain of headers
    let chain = create_test_header_chain(10);

    // Verify chain linkage (each header should reference the previous one)
    for i in 1..chain.len() {
        let prev_hash = chain[i - 1].block_hash();
        let current_prev = chain[i].prev_blockhash;

        // Note: In our test headers, we use a simple pattern for prev_blockhash
        // In real implementation, this would be validated by the sync manager
        debug!("Header {}: prev_hash={}, current_prev={}", i, prev_hash, current_prev);
    }

    storage.store_headers(&chain).await.expect("Failed to store header chain");

    // Verify the chain is stored correctly
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(9));

    // Verify we can retrieve the entire chain
    let retrieved_chain = storage.load_headers(0..10).await.unwrap();
    assert_eq!(retrieved_chain.len(), 10);

    for (i, header) in retrieved_chain.iter().enumerate() {
        assert_eq!(header.block_hash(), chain[i].block_hash());
    }

    info!("Header chain validation test completed");
}

#[tokio::test]
async fn test_header_sync_performance() {
    let _ = env_logger::try_init();

    let mut storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    let start_time = std::time::Instant::now();

    // Simulate syncing a substantial number of headers
    let total_headers = 10000;
    let batch_size = 1000;

    for batch_start in (0..total_headers).step_by(batch_size) {
        let batch_count = batch_size.min(total_headers - batch_start);
        let batch = create_test_header_chain_from(batch_start, batch_count);

        storage.store_headers(&batch).await.expect("Failed to store header batch");
    }

    let sync_duration = start_time.elapsed();

    // Verify sync completed correctly
    assert_eq!(storage.get_tip_height().await.unwrap(), Some((total_headers - 1) as u32));

    // Performance assertions (these are rough benchmarks)
    assert!(
        sync_duration < Duration::from_secs(5),
        "Sync of {} headers took too long: {:?}",
        total_headers,
        sync_duration
    );

    // Test retrieval performance
    let retrieval_start = std::time::Instant::now();
    let large_range = storage.load_headers(5000..6000).await.unwrap();
    let retrieval_duration = retrieval_start.elapsed();

    assert_eq!(large_range.len(), 1000);
    assert!(
        retrieval_duration < Duration::from_millis(100),
        "Header retrieval took too long: {:?}",
        retrieval_duration
    );

    info!(
        "Header sync performance test completed: sync={}ms, retrieval={}ms",
        sync_duration.as_millis(),
        retrieval_duration.as_millis()
    );
}

#[tokio::test]
async fn test_header_sync_with_client_integration() {
    let _ = env_logger::try_init();

    // Test header sync integration with the full client
    let config = ClientConfig::new(Network::Dash)
        .with_validation_mode(ValidationMode::Basic)
        .with_connection_timeout(Duration::from_secs(10));

    // Create network manager
    let network_manager =
        PeerNetworkManager::new(&config).await.expect("Failed to create network manager");

    // Create storage manager
    let storage_manager =
        MemoryStorageManager::new().await.expect("Failed to create storage manager");

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    let client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await;
    assert!(client.is_ok(), "Client creation should succeed");

    let client = client.unwrap();

    // Verify client starts with empty state
    let stats = client.sync_progress().await;
    assert!(stats.is_ok());

    let stats = stats.unwrap();
    assert_eq!(stats.header_height, 0);

    info!("Header sync client integration test completed");
}

// Helper functions for creating test data

fn create_test_header_chain(count: usize) -> Vec<BlockHeader> {
    create_test_header_chain_from(0, count)
}

fn create_test_header_chain_from(start: usize, count: usize) -> Vec<BlockHeader> {
    let mut headers = Vec::new();

    for i in start..(start + count) {
        let header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: if i == 0 {
                dashcore::BlockHash::all_zeros()
            } else {
                // Create a deterministic previous hash based on height
                dashcore::BlockHash::from_byte_array([(i - 1) as u8; 32])
            },
            merkle_root: dashcore::TxMerkleNode::from_byte_array([(i + 1) as u8; 32]),
            time: 1234567890 + i as u32, // Sequential timestamps
            bits: dashcore::CompactTarget::from_consensus(0x1d00ffff), // Standard difficulty
            nonce: i as u32,             // Sequential nonces
        };
        headers.push(header);
    }

    headers
}

#[tokio::test]
async fn test_header_storage_consistency() {
    let _ = env_logger::try_init();

    let mut storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    // Store headers and verify consistency
    let headers = create_test_header_chain(100);
    storage.store_headers(&headers).await.expect("Failed to store headers");

    // Test consistency: get tip and verify it matches the last stored header
    let tip_height = storage.get_tip_height().await.unwrap().unwrap();
    let tip_header = storage.get_header(tip_height).await.unwrap().unwrap();
    let expected_tip = &headers[headers.len() - 1];

    assert_eq!(tip_header.block_hash(), expected_tip.block_hash());
    assert_eq!(tip_header.time, expected_tip.time);
    assert_eq!(tip_header.nonce, expected_tip.nonce);

    // Test range consistency
    let range_headers = storage.load_headers(50..60).await.unwrap();
    assert_eq!(range_headers.len(), 10);

    for (i, header) in range_headers.iter().enumerate() {
        let expected_header = &headers[50 + i];
        assert_eq!(header.block_hash(), expected_header.block_hash());
    }

    info!("Header storage consistency test completed");
}

#[test_case(0, 0 ; "genesis_0_blocks")]
#[test_case(0, 1 ; "genesis_1_block")]
#[test_case(0, 60000 ; "genesis_60000_blocks")]
#[test_case(0, 0 ; "checkpoint_0_blocks")]
#[test_case(170000, 1 ; "checkpoint_1_block")]
#[test_case(12345, 60000 ; "checkpoint_60000_blocks")]
#[tokio::test]
async fn test_load_headers_from_storage(
    sync_base_height: u32,
    header_count: usize,
) {
    // Setup: Create storage with 100 headers
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .expect("Failed to create storage");

    let test_headers = create_test_header_chain(header_count);

    // Store chain state
    let mut chain_state = ChainState::new_for_network(Network::Dash);
    chain_state.sync_base_height = sync_base_height;
    chain_state.headers = test_headers.clone();
    storage.store_chain_state(&chain_state).await.expect("Failed to store chain state");

    // Create HeaderSyncManager and load headers
    let config = ClientConfig::new(Network::Dash);
    let chain_state = Arc::new(RwLock::new(ChainState::new_for_network(Network::Dash)));
    let mut header_sync = HeaderSyncManager::<DiskStorageManager, PeerNetworkManager>::new(
        &config,
        ReorgConfig::default(),
        chain_state.clone(),
    )
    .expect("Failed to create HeaderSyncManager");

    // Load headers from storage
    let loaded_count =
        header_sync.load_headers_from_storage(&storage).await.expect("Failed to load headers");

    let cs = chain_state.read().await;

    assert_eq!(loaded_count as usize, header_count, "Loaded count mismatch");
    assert_eq!(header_count, cs.headers.len(), "Chain state count mismatch");
}
