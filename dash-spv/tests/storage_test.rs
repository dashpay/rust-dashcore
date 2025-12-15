//! Integration tests for storage layer functionality.

use dash_spv::error::StorageError;
use dash_spv::storage::{DiskStorageManager, StorageManager};
use dash_spv::types::ChainState;
use dashcore::{block::Header as BlockHeader, block::Version, Network};
use dashcore_hashes::Hash;
use tempfile::TempDir;

#[tokio::test]
async fn test_memory_storage_basic_operations() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Test initial state
    assert_eq!(storage.get_tip_height().await.unwrap(), None);
    assert!(storage.load_headers(0..10).await.unwrap().is_empty());

    // Create some test headers (simplified for testing)
    let test_headers = create_test_headers(5);

    // Store headers
    storage.store_headers(&test_headers).await.expect("Failed to store headers");

    // Verify tip height
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(4)); // 0-indexed

    // Verify header retrieval
    let retrieved_headers = storage.load_headers(0..5).await.unwrap();
    assert_eq!(retrieved_headers.len(), 5);

    for (i, header) in retrieved_headers.iter().enumerate() {
        assert_eq!(header.block_hash(), test_headers[i].block_hash());
    }

    // Test individual header retrieval
    for (i, _) in test_headers.iter().enumerate().take(5) {
        let header = storage.get_header(i as u32).await.unwrap();
        assert!(header.is_some());
        assert_eq!(header.unwrap().block_hash(), test_headers[i].block_hash());
    }

    // Test out-of-bounds access
    assert!(storage.get_header(10).await.unwrap().is_none());
}

#[tokio::test]
async fn test_memory_storage_header_ranges() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    let test_headers = create_test_headers(10);
    storage.store_headers(&test_headers).await.expect("Failed to store headers");

    // Test various ranges
    let partial_headers = storage.load_headers(2..7).await.unwrap();
    assert_eq!(partial_headers.len(), 5);

    let first_three = storage.load_headers(0..3).await.unwrap();
    assert_eq!(first_three.len(), 3);

    let last_three = storage.load_headers(7..10).await.unwrap();
    assert_eq!(last_three.len(), 3);

    // Test range beyond available data
    let beyond_range = storage.load_headers(8..15).await.unwrap();
    assert_eq!(beyond_range.len(), 2); // Only 8 and 9 exist

    // Test empty range
    let empty_range = storage.load_headers(15..20).await.unwrap();
    assert!(empty_range.is_empty());
}

#[tokio::test]
async fn test_memory_storage_incremental_headers() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Add headers incrementally to simulate real sync
    for i in 0..3 {
        let batch = create_test_headers_from(i * 5, 5);
        storage.store_headers(&batch).await.expect("Failed to store header batch");

        let expected_tip = (i + 1) * 5 - 1;
        assert_eq!(storage.get_tip_height().await.unwrap(), Some(expected_tip as u32));
    }

    // Verify total count
    let all_headers = storage.load_headers(0..15).await.unwrap();
    assert_eq!(all_headers.len(), 15);

    // Verify continuity
    for i in 0..15 {
        let header = storage.get_header(i as u32).await.unwrap();
        assert!(header.is_some());
    }
}

#[tokio::test]
async fn test_memory_storage_filter_headers() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Create test filter headers
    let test_filter_headers = create_test_filter_headers(5);

    // Store filter headers
    storage
        .store_filter_headers(&test_filter_headers)
        .await
        .expect("Failed to store filter headers");

    // Verify filter tip height
    assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(4));

    // Verify filter header retrieval
    let retrieved = storage.load_filter_headers(0..5).await.unwrap();
    assert_eq!(retrieved.len(), 5);

    for (i, _) in test_filter_headers.iter().enumerate().take(5) {
        let filter_header = storage.get_filter_header(i as u32).await.unwrap();
        assert!(filter_header.is_some());
        assert_eq!(filter_header.unwrap(), test_filter_headers[i]);
    }
}

#[tokio::test]
async fn test_memory_storage_filters() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Store some test filters at consecutive heights
    let filter_data_0 = vec![1, 2, 3, 4, 5];
    let filter_data_1 = vec![6, 7, 8, 9, 10];
    let filter_data_2 = vec![11, 12, 13, 14, 15];
    storage.store_filter(100, &filter_data_0).await.expect("Failed to store filter");
    storage.store_filter(101, &filter_data_1).await.expect("Failed to store filter");
    storage.store_filter(102, &filter_data_2).await.expect("Failed to store filter");

    // Retrieve single filter via range
    let retrieved_filters = storage.load_filters(100..101).await.unwrap();
    assert_eq!(retrieved_filters.len(), 1);
    assert_eq!(retrieved_filters[0], filter_data_0);

    // Retrieve multiple filters
    let retrieved_filters = storage.load_filters(100..103).await.unwrap();
    assert_eq!(retrieved_filters.len(), 3);
    assert_eq!(retrieved_filters[0], filter_data_0);
    assert_eq!(retrieved_filters[1], filter_data_1);
    assert_eq!(retrieved_filters[2], filter_data_2);

    // Test non-existent range returns empty vector
    let empty_filters = storage.load_filters(999..1000).await.unwrap();
    assert!(empty_filters.is_empty());
}

#[tokio::test]
async fn test_memory_storage_chain_state() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Create test chain state
    let chain_state = ChainState::new_for_network(Network::Dash);

    // Store chain state
    storage.store_chain_state(&chain_state).await.expect("Failed to store chain state");

    // Retrieve chain state
    let retrieved_state = storage.load_chain_state().await.unwrap();
    assert!(retrieved_state.is_some());
    // Note: ChainState doesn't store network directly, but we can verify it was created properly
    assert!(retrieved_state.is_some());

    // Test initial state
    let fresh_storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");
    assert!(fresh_storage.load_chain_state().await.unwrap().is_none());
}

#[tokio::test]
async fn test_memory_storage_metadata() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Store metadata
    let key = "test_key";
    let value = b"test_value";
    storage.store_metadata(key, value).await.expect("Failed to store metadata");

    // Retrieve metadata
    let retrieved_value = storage.load_metadata(key).await.unwrap();
    assert!(retrieved_value.is_some());
    assert_eq!(retrieved_value.unwrap(), value);

    // Test non-existent key
    assert!(storage.load_metadata("non_existent").await.unwrap().is_none());

    // Store multiple metadata entries
    storage.store_metadata("key1", b"value1").await.unwrap();
    storage.store_metadata("key2", b"value2").await.unwrap();

    assert_eq!(storage.load_metadata("key1").await.unwrap().unwrap(), b"value1");
    assert_eq!(storage.load_metadata("key2").await.unwrap().unwrap(), b"value2");
}

#[tokio::test]
async fn test_memory_storage_clear() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Add some data
    let test_headers = create_test_headers(5);
    storage.store_headers(&test_headers).await.unwrap();

    let filter_headers = create_test_filter_headers(3);
    storage.store_filter_headers(&filter_headers).await.unwrap();

    storage.store_filter(1, &[1, 2, 3]).await.unwrap();
    storage.store_metadata("test", b"data").await.unwrap();

    // Verify data exists
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(4));
    assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(2));
    assert!(!storage.load_filters(1..2).await.unwrap().is_empty());
    assert!(storage.load_metadata("test").await.unwrap().is_some());

    // Clear storage
    storage.clear().await.expect("Failed to clear storage");

    // Verify everything is cleared
    assert_eq!(storage.get_tip_height().await.unwrap(), None);
    assert_eq!(storage.get_filter_tip_height().await.unwrap(), None);
    assert!(storage.load_filters(1..2).await.unwrap().is_empty());
    assert!(storage.load_metadata("test").await.unwrap().is_none());
    assert!(storage.load_headers(0..5).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_memory_storage_stats() {
    let mut storage =
        DiskStorageManager::new(TempDir::new().expect("Failed to create tmp dir").path().into())
            .await
            .expect("Failed to create tmp storage");

    // Initially empty
    let stats = storage.stats().await.expect("Failed to get stats");
    assert_eq!(stats.header_count, 0);
    assert_eq!(stats.filter_header_count, 0);
    assert_eq!(stats.filter_count, 0);

    // Add some data
    let test_headers = create_test_headers(10);
    storage.store_headers(&test_headers).await.unwrap();

    let filter_headers = create_test_filter_headers(5);
    storage.store_filter_headers(&filter_headers).await.unwrap();

    storage.store_filter(1, &[1, 2, 3, 4, 5]).await.unwrap();
    storage.store_filter(2, &[6, 7, 8]).await.unwrap();

    // Check updated stats
    let stats = storage.stats().await.expect("Failed to get stats");
    assert_eq!(stats.header_count, 10);
    assert_eq!(stats.filter_header_count, 5);
    assert_eq!(stats.filter_count, 2);
    assert!(stats.total_size > 0);
    assert!(stats.component_sizes.contains_key("headers"));
    assert!(stats.component_sizes.contains_key("filter_headers"));
    assert!(stats.component_sizes.contains_key("filters"));
}

// Helper functions for creating test data

fn create_test_headers(count: usize) -> Vec<BlockHeader> {
    create_test_headers_from(0, count)
}

fn create_test_headers_from(start: usize, count: usize) -> Vec<BlockHeader> {
    let mut headers = Vec::new();

    for i in start..(start + count) {
        // Create a minimal valid header for testing
        // Note: These are not real headers, just valid structures for testing
        let header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: if i == 0 {
                dashcore::BlockHash::all_zeros()
            } else {
                // In real implementation, this would be the hash of the previous header
                dashcore::BlockHash::from_byte_array([i as u8; 32])
            },
            merkle_root: dashcore::TxMerkleNode::from_byte_array([(i + 1) as u8; 32]),
            time: 1234567890 + i as u32,
            bits: dashcore::CompactTarget::from_consensus(0x1d00ffff),
            nonce: i as u32,
        };
        headers.push(header);
    }

    headers
}

fn create_test_filter_headers(count: usize) -> Vec<dashcore::hash_types::FilterHeader> {
    let mut filter_headers = Vec::new();

    for i in 0..count {
        let filter_header = dashcore::hash_types::FilterHeader::from_byte_array([i as u8; 32]);
        filter_headers.push(filter_header);
    }

    filter_headers
}

#[tokio::test]
async fn test_disk_storage_reopen_after_clean_shutdown() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let path = temp_dir.path().to_path_buf();

    // Create storage, use it, then shutdown cleanly
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();
        // Store some data to verify it persists
        let headers = create_test_headers(5);
        storage.store_headers(&headers).await.unwrap();
        // Shutdown ensures all data is persisted
        storage.shutdown().await;
    }

    // Reopen - should succeed and have the data
    let storage = DiskStorageManager::new(path.clone()).await;
    assert!(storage.is_ok(), "Should reopen after clean shutdown");

    let storage = storage.unwrap();
    let tip = storage.get_tip_height().await.unwrap();
    assert_eq!(tip, Some(4), "Data should persist across reopen");
}

#[tokio::test]
async fn test_disk_storage_concurrent_access_blocked() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let path = temp_dir.path().to_path_buf();

    let storage1 = DiskStorageManager::new(path.clone()).await;
    assert!(storage1.is_ok(), "First storage manager should succeed");
    let _storage1 = storage1.unwrap();

    // Second storage manager for same path should fail
    let storage2 = DiskStorageManager::new(path.clone()).await;
    assert!(storage2.is_err(), "Second storage manager should fail");

    match storage2.err().unwrap() {
        StorageError::DirectoryLocked(msg) => {
            assert!(msg.contains("already in use"));
        }
        other => panic!("Expected DirectoryLocked error, got: {:?}", other),
    }

    // First storage manager should still be usable
    assert!(_storage1.get_tip_height().await.is_ok());
}

#[tokio::test]
async fn test_disk_storage_lock_file_lifecycle() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let path = temp_dir.path().to_path_buf();
    let lock_path = path.join(".lock");

    // Lock file created when storage opens
    {
        let _storage = DiskStorageManager::new(path.clone()).await.unwrap();
        assert!(lock_path.exists(), "Lock file should exist while storage is open");
    }

    // Lock file removed when storage drops
    assert!(!lock_path.exists(), "Lock file should be removed after storage drops");

    // Can reopen storage after previous one dropped
    let storage2 = DiskStorageManager::new(path.clone()).await;
    assert!(storage2.is_ok(), "Should reopen after previous storage dropped");
}
