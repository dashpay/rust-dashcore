//! Integration tests for storage layer functionality.

use dash_spv::storage::{MemoryStorageManager, StorageManager};
use dash_spv::types::ChainState;
use dashcore::{block::Header as BlockHeader, block::Version, Network};
use dashcore_hashes::Hash;

#[tokio::test]
async fn test_memory_storage_basic_operations() {
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

    // Store some test filters
    let filter_data = vec![1, 2, 3, 4, 5];
    storage.store_filter(100, &filter_data).await.expect("Failed to store filter");

    // Retrieve filter
    let retrieved_filter = storage.load_filter(100).await.unwrap();
    assert!(retrieved_filter.is_some());
    assert_eq!(retrieved_filter.unwrap(), filter_data);

    // Test non-existent filter
    assert!(storage.load_filter(999).await.unwrap().is_none());
}

#[tokio::test]
async fn test_memory_storage_chain_state() {
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    let fresh_storage = MemoryStorageManager::new().await.expect("Failed to create fresh storage");
    assert!(fresh_storage.load_chain_state().await.unwrap().is_none());
}

#[tokio::test]
async fn test_memory_storage_metadata() {
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
    assert!(storage.load_filter(1).await.unwrap().is_some());
    assert!(storage.load_metadata("test").await.unwrap().is_some());

    // Clear storage
    storage.clear().await.expect("Failed to clear storage");

    // Verify everything is cleared
    assert_eq!(storage.get_tip_height().await.unwrap(), None);
    assert_eq!(storage.get_filter_tip_height().await.unwrap(), None);
    assert!(storage.load_filter(1).await.unwrap().is_none());
    assert!(storage.load_metadata("test").await.unwrap().is_none());
    assert!(storage.load_headers(0..5).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_memory_storage_stats() {
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

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
async fn test_load_filters_range() {
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

    // Store some filters at various heights
    storage.store_filter(100, &[1, 2, 3]).await.expect("Failed to store filter at 100");
    storage.store_filter(101, &[4, 5, 6]).await.expect("Failed to store filter at 101");
    storage.store_filter(103, &[7, 8, 9]).await.expect("Failed to store filter at 103"); // Skip 102
    storage.store_filter(104, &[10, 11, 12]).await.expect("Failed to store filter at 104");

    // Load filters in range 100..105
    let filters = storage.load_filters(100..105).await.expect("Failed to load filters");

    // Should get 4 filters (100, 101, 103, 104) - 102 is missing
    assert_eq!(filters.len(), 4, "Should load 4 filters");
    assert_eq!(filters[0], (100, vec![1, 2, 3]), "Filter at 100 mismatch");
    assert_eq!(filters[1], (101, vec![4, 5, 6]), "Filter at 101 mismatch");
    assert_eq!(filters[2], (103, vec![7, 8, 9]), "Filter at 103 mismatch");
    assert_eq!(filters[3], (104, vec![10, 11, 12]), "Filter at 104 mismatch");

    // Load smaller range
    let filters =
        storage.load_filters(101..103).await.expect("Failed to load filters in smaller range");
    assert_eq!(filters.len(), 1, "Should load 1 filter"); // Only 101, not 103 (end is exclusive)
    assert_eq!(filters[0], (101, vec![4, 5, 6]), "Filter at 101 mismatch in smaller range");

    // Load empty range
    let filters = storage.load_filters(200..205).await.expect("Failed to load empty range");
    assert_eq!(filters.len(), 0, "Should load 0 filters from empty range");
}

#[tokio::test]
async fn test_load_filters_range_limit() {
    let mut storage = MemoryStorageManager::new().await.expect("Failed to create memory storage");

    // Store some filters
    for i in 0..20 {
        storage.store_filter(i, &[i as u8]).await.expect("Failed to store filter");
    }

    // Test maximum allowed range (10,000 blocks)
    let result = storage.load_filters(0..10_000).await;
    assert!(result.is_ok(), "Should allow exactly 10,000 block range");

    // Test range exceeding limit (10,001 blocks)
    let result = storage.load_filters(0..10_001).await;
    assert!(result.is_err(), "Should reject range exceeding 10,000 blocks");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("exceeds maximum") && error_msg.contains("10000"),
        "Error message should mention the limit"
    );

    // Test large range with different start
    let result = storage.load_filters(5000..15_001).await;
    assert!(result.is_err(), "Should reject range of 10,001 blocks regardless of start");

    // Test range just under limit (9,999 blocks) - should succeed
    let result = storage.load_filters(0..9_999).await;
    assert!(result.is_ok(), "Should allow 9,999 block range");

    // Test very large range
    let result = storage.load_filters(0..100_000).await;
    assert!(result.is_err(), "Should reject very large range");
}
