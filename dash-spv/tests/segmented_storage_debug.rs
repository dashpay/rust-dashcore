//! Debug test for segmented storage.

use dash_spv::storage::{BlockHeaderStorage, DiskStorageManager, StorageManager};
use dashcore::block::{Header as BlockHeader, Version};
use dashcore::pow::CompactTarget;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use tempfile::TempDir;

/// Create a test header for a given height.
fn create_test_header(height: u32) -> BlockHeader {
    BlockHeader {
        version: Version::from_consensus(1),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: dashcore_hashes::sha256d::Hash::all_zeros().into(),
        time: height,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: height,
    }
}

#[tokio::test]
async fn test_basic_storage() {
    println!("Creating temp dir...");
    let temp_dir = TempDir::new().unwrap();
    println!("Temp dir: {:?}", temp_dir.path());

    println!("Creating storage manager...");
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();
    println!("Storage manager created");

    // Store just 10 headers
    println!("Creating headers...");
    let headers: Vec<BlockHeader> = (0..10).map(create_test_header).collect();

    println!("Storing headers...");
    storage.store_headers(&headers).await.unwrap();
    println!("Headers stored");

    // Check tip height
    let tip = storage.get_tip_height().await;
    println!("Tip height: {:?}", tip);
    assert_eq!(tip, Some(9));

    // Read back a header
    let header = storage.get_header(5).await.unwrap();
    println!("Header at height 5: {:?}", header.is_some());
    assert!(header.is_some());
    assert_eq!(header.unwrap().time, 5);

    println!("Shutting down storage...");
    storage.shutdown().await;
    println!("Test completed successfully");
}
