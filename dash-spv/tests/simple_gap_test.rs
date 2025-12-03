//! Basic test for CFHeader gap detection functionality.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

use dash_spv::{
    client::ClientConfig,
    storage::{MemoryStorageManager, StorageManager},
    sync::filters::FilterSyncManager,
};
use dashcore::{block::Header as BlockHeader, BlockHash, Network};
use dashcore_hashes::Hash;

/// Create a mock block header
fn create_mock_header(height: u32) -> BlockHeader {
    BlockHeader {
        version: dashcore::block::Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: dashcore::hash_types::TxMerkleNode::all_zeros(),
        time: 1234567890 + height,
        bits: dashcore::pow::CompactTarget::from_consensus(0x1d00ffff),
        nonce: height,
    }
}

#[tokio::test]
async fn test_basic_gap_detection() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    use dash_spv::network::PeerNetworkManager;
    let filter_sync: FilterSyncManager<MemoryStorageManager, PeerNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Store just a few headers to test basic functionality
    let headers = vec![create_mock_header(1), create_mock_header(2), create_mock_header(3)];

    storage.store_headers(&headers).await.unwrap();

    // Check gap detection - should detect gap since no filter headers stored
    let result = filter_sync.check_cfheader_gap(&storage).await;
    assert!(result.is_ok(), "Gap detection should not error");

    let (has_gap, block_height, filter_height, gap_size) = result.unwrap();
    assert!(has_gap, "Should detect gap when no filter headers exist");
    assert!(block_height > 0, "Block height should be > 0");
    assert_eq!(filter_height, 0, "Filter height should be 0");
    assert_eq!(gap_size, block_height, "Gap size should equal block height when no filter headers");
}
