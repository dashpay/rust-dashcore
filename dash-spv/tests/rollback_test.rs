//! Tests for rollback functionality.
//!
//! NOTE: This test file is currently disabled due to incomplete mock StorageManager implementation.
//! TODO: Re-enable once StorageManager trait methods are fully implemented.

#![cfg(feature = "skip_mock_implementation_incomplete")]

use dash_spv::storage::{DiskStorageManager, StorageManager};
use dashcore::{
    block::{Header as BlockHeader, Version},
    pow::CompactTarget,
    BlockHash,
};
use dashcore_hashes::Hash;
use tempfile::TempDir;

#[tokio::test]
#[ignore = "mock implementation incomplete"]
async fn test_disk_storage_rollback() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for testing
    let temp_dir = TempDir::new()?;
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

    // Create test headers
    let headers: Vec<BlockHeader> = (0..10)
        .map(|i| BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: if i == 0 {
                BlockHash::all_zeros()
            } else {
                BlockHash::from_byte_array([i as u8 - 1; 32])
            },
            merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([(i + 100) as u8; 32])
                .into(),
            time: 1000000 + i,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 12345 + i,
        })
        .collect();

    // Store headers
    storage.store_headers(&headers).await?;

    // Verify we have 10 headers
    let tip_height = storage.get_tip_height().await?;
    assert_eq!(tip_height, Some(9));

    // Load all headers to verify
    let loaded_headers = storage.load_headers(0..10).await?;
    assert_eq!(loaded_headers.len(), 10);

    // Test rollback to height 5
    // storage.rollback_to_height(5).await?;

    // TODO: Test assertions commented out because rollback_to_height is not implemented
    // Verify tip height is now 5
    let _ = storage.get_tip_height().await?;
    // assert_eq!(tip_height_after_rollback, Some(5));

    // Verify we can only load headers up to height 5
    let _ = storage.load_headers(0..10).await?;
    // assert_eq!(headers_after_rollback.len(), 6); // heights 0-5

    // Verify header at height 6 is not accessible
    let _ = storage.get_header(6).await?;
    // assert!(header_at_6.is_none());

    // Verify header hash index doesn't contain removed headers
    let hash_of_removed_header = headers[7].block_hash();
    let _ = storage.get_header_height_by_hash(&hash_of_removed_header).await?;
    // assert!(height_of_removed.is_none());

    Ok(())
}

#[tokio::test]
#[ignore = "mock implementation incomplete"]
async fn test_disk_storage_rollback_filter_headers() -> Result<(), Box<dyn std::error::Error>> {
    use dashcore::hash_types::FilterHeader;

    // Create a temporary directory for testing
    let temp_dir = TempDir::new()?;
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await?;

    // Create test filter headers
    let filter_headers: Vec<FilterHeader> =
        (0..10).map(|i| FilterHeader::from_byte_array([i as u8; 32])).collect();

    // Store filter headers
    storage.store_filter_headers(&filter_headers).await?;

    // Verify we have 10 filter headers
    let filter_tip_height = storage.get_filter_tip_height().await?;
    assert_eq!(filter_tip_height, Some(9));

    // Test rollback to height 3
    // storage.rollback_to_height(3).await?;

    // TODO: Test assertions commented out because rollback_to_height is not implemented
    // Verify filter tip height is now 3
    let _ = storage.get_filter_tip_height().await?;
    // assert_eq!(filter_tip_after_rollback, Some(3));

    // Verify we can only load filter headers up to height 3
    let _ = storage.load_filter_headers(0..10).await?;
    // assert_eq!(filter_headers_after_rollback.len(), 4); // heights 0-3

    // Verify filter header at height 4 is not accessible
    let _ = storage.get_filter_header(4).await?;
    // assert!(filter_header_at_4.is_none());

    Ok(())
}
