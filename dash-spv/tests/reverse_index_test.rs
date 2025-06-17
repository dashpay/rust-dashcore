use dash_spv::storage::{MemoryStorageManager, DiskStorageManager, StorageManager};
use dashcore::block::Header as BlockHeader;
use dashcore::hashes::Hash;
use std::path::PathBuf;

#[tokio::test]
async fn test_reverse_index_memory_storage() {
    let mut storage = MemoryStorageManager::new().await.unwrap();
    
    // Create some test headers
    let mut headers = Vec::new();
    for i in 0..10 {
        let header = create_test_header(i);
        headers.push(header);
    }
    
    // Store headers
    storage.store_headers(&headers).await.unwrap();
    
    // Test reverse lookups
    for (i, header) in headers.iter().enumerate() {
        let hash = header.block_hash();
        let height = storage.get_header_height_by_hash(&hash).await.unwrap();
        assert_eq!(height, Some(i as u32), "Height mismatch for header {}", i);
    }
    
    // Test non-existent hash
    let fake_hash = dashcore::BlockHash::from_byte_array([0xFF; 32]);
    let height = storage.get_header_height_by_hash(&fake_hash).await.unwrap();
    assert_eq!(height, None, "Should return None for non-existent hash");
}

#[tokio::test]
async fn test_reverse_index_disk_storage() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = PathBuf::from(temp_dir.path());
    
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();
        
        // Create and store headers
        let mut headers = Vec::new();
        for i in 0..10 {
            let header = create_test_header(i);
            headers.push(header);
        }
        
        storage.store_headers(&headers).await.unwrap();
        
        // Test reverse lookups
        for (i, header) in headers.iter().enumerate() {
            let hash = header.block_hash();
            let height = storage.get_header_height_by_hash(&hash).await.unwrap();
            assert_eq!(height, Some(i as u32), "Height mismatch for header {}", i);
        }
        
        // Force save to disk by storing many more headers to trigger the save
        let mut more_headers = Vec::new();
        for i in 10..1000 {
            more_headers.push(create_test_header(i));
        }
        storage.store_headers(&more_headers).await.unwrap();
    }
    
    // Test persistence - reload storage and verify index still works
    {
        let storage = DiskStorageManager::new(path).await.unwrap();
        
        // The index should have been rebuilt from the loaded headers
        // We need to get the actual headers that were stored to test properly
        for i in 0..10 {
            let stored_header = storage.get_header(i).await.unwrap().unwrap();
            let hash = stored_header.block_hash();
            let height = storage.get_header_height_by_hash(&hash).await.unwrap();
            assert_eq!(height, Some(i as u32), "Height mismatch after reload for header {}", i);
        }
    }
}

#[tokio::test]
async fn test_clear_clears_index() {
    let mut storage = MemoryStorageManager::new().await.unwrap();
    
    // Store some headers
    let header = create_test_header(0);
    storage.store_headers(&[header]).await.unwrap();
    
    let hash = header.block_hash();
    assert!(storage.get_header_height_by_hash(&hash).await.unwrap().is_some());
    
    // Clear storage
    storage.clear().await.unwrap();
    
    // Verify index is cleared
    assert!(storage.get_header_height_by_hash(&hash).await.unwrap().is_none());
}

// Helper function to create a test header with unique data
fn create_test_header(index: u32) -> BlockHeader {
    // Create a header with unique prev_blockhash based on index
    let mut prev_hash_bytes = [0u8; 32];
    prev_hash_bytes[0..4].copy_from_slice(&index.to_le_bytes());
    
    BlockHeader {
        version: dashcore::blockdata::block::Version::from_consensus(1),
        prev_blockhash: dashcore::BlockHash::from_byte_array(prev_hash_bytes),
        merkle_root: dashcore::TxMerkleNode::from_byte_array([0; 32]),
        time: 1234567890 + index,
        bits: dashcore::CompactTarget::from_consensus(0x1d00ffff),
        nonce: index,
    }
}