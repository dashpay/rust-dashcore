//! Simple test without background saving.

use dash_spv::storage::{BlockHeaderStorage, DiskStorageManager};
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
async fn test_simple_storage() {
    println!("Creating temp dir...");
    let temp_dir = TempDir::new().unwrap();

    println!("Creating storage manager...");
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    println!("Testing get_tip_height before storing anything...");
    let initial_tip = storage.get_tip_height().await;
    println!("Initial tip: {:?}", initial_tip);
    assert_eq!(initial_tip, None);

    println!("Creating single header...");
    let header = create_test_header(0);

    println!("Storing single header...");
    storage.store_headers(&[header]).await.unwrap();
    println!("Single header stored");

    println!("Checking tip height...");
    let tip = storage.get_tip_height().await;
    println!("Tip height after storing one header: {:?}", tip);
    assert_eq!(tip, Some(0));

    println!("Test completed successfully");
}
