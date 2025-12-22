//! Integration tests for storage layer functionality.

use dash_spv::error::StorageError;
use dash_spv::storage::{DiskStorageManager, StorageManager};
use dashcore::{block::Header as BlockHeader, block::Version};
use dashcore_hashes::Hash;
use tempfile::TempDir;

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
    let tip = storage.get_tip_height().await;
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
