//! Tests for edge case handling in filter header sync, particularly at the tip.

use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

use dash_spv::{
    error::NetworkResult,
    network::NetworkManager,
    storage::{BlockHeaderStorage, DiskStorageManager, FilterHeaderStorage},
    sync::filters::FilterSyncManager,
    ClientConfigBuilder,
};
use dashcore::{
    block::Header as BlockHeader, hash_types::FilterHeader, network::message::NetworkMessage,
    BlockHash,
};
use dashcore_hashes::Hash;

/// Create a mock block header
fn create_mock_header(height: u32, prev_hash: BlockHash) -> BlockHeader {
    BlockHeader {
        version: dashcore::block::Version::ONE,
        prev_blockhash: prev_hash,
        merkle_root: dashcore::hash_types::TxMerkleNode::all_zeros(),
        time: 1234567890 + height,
        bits: dashcore::pow::CompactTarget::from_consensus(0x1d00ffff),
        nonce: height,
    }
}

/// Create a mock filter header
fn create_mock_filter_header(height: u32) -> FilterHeader {
    FilterHeader::from_slice(&[height as u8; 32]).unwrap()
}

/// Mock network manager that captures sent messages
struct MockNetworkManager {
    sent_messages: Arc<Mutex<Vec<NetworkMessage>>>,
}

impl MockNetworkManager {
    fn new() -> Self {
        Self {
            sent_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn get_sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent_messages.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl NetworkManager for MockNetworkManager {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&mut self) -> NetworkResult<()> {
        Ok(())
    }

    async fn disconnect(&mut self) -> NetworkResult<()> {
        Ok(())
    }

    async fn send_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        self.sent_messages.lock().await.push(message);
        Ok(())
    }

    async fn receive_message(&mut self) -> NetworkResult<Option<NetworkMessage>> {
        Ok(None)
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn peer_count(&self) -> usize {
        1
    }

    fn peer_info(&self) -> Vec<dash_spv::types::PeerInfo> {
        Vec::new()
    }

    async fn get_peer_best_height(&self) -> dash_spv::error::NetworkResult<Option<u32>> {
        Ok(Some(100))
    }

    async fn has_peer_with_service(
        &self,
        _service_flags: dashcore::network::constants::ServiceFlags,
    ) -> bool {
        true
    }

    async fn get_last_message_peer_id(&self) -> dash_spv::types::PeerId {
        dash_spv::types::PeerId(1)
    }

    async fn update_peer_dsq_preference(&mut self, _wants_dsq: bool) -> NetworkResult<()> {
        Ok(())
    }
}

#[tokio::test]
async fn test_filter_sync_at_tip_edge_case() {
    let config = ClientConfigBuilder::mainnet()
        .storage_path(TempDir::new().unwrap().path())
        .build()
        .expect("Valid config");

    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = DiskStorageManager::new(&config).await.expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    // Set up storage with headers and filter headers at the same height (tip)
    let height = 100;
    let mut headers = Vec::new();
    let mut filter_headers = Vec::new();
    let mut prev_hash = BlockHash::all_zeros();

    for i in 1..=height {
        let header = create_mock_header(i, prev_hash);
        prev_hash = header.block_hash();
        headers.push(header);
        filter_headers.push(create_mock_filter_header(i));
    }

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Verify initial state
    let tip_height = storage.get_tip_height().await.unwrap();
    let filter_tip_height = storage.get_filter_tip_height().await.unwrap().unwrap();
    assert_eq!(tip_height, height - 1); // 0-indexed
    assert_eq!(filter_tip_height, height - 1); // 0-indexed

    // Try to start filter sync when already at tip
    let result = filter_sync.start_sync_headers(&mut network, &mut storage).await;
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Should not start sync when already at tip");

    // Verify no messages were sent
    let sent_messages = network.get_sent_messages().await;
    assert_eq!(sent_messages.len(), 0, "Should not send any messages when at tip");
}

#[tokio::test]
async fn test_no_invalid_getcfheaders_at_tip() {
    let config = ClientConfigBuilder::mainnet()
        .storage_path(TempDir::new().unwrap().path())
        .build()
        .expect("Valid config");

    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = DiskStorageManager::new(&config).await.expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    // Create a scenario where we're one block behind
    let height = 100;
    let mut headers = Vec::new();
    let mut filter_headers = Vec::new();
    let mut prev_hash = BlockHash::all_zeros();

    // Store headers up to height
    for i in 1..=height {
        let header = create_mock_header(i, prev_hash);
        prev_hash = header.block_hash();
        headers.push(header);
    }

    // Store filter headers up to height - 1
    for i in 1..=(height - 1) {
        filter_headers.push(create_mock_filter_header(i));
    }

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Start filter sync
    let result = filter_sync.start_sync_headers(&mut network, &mut storage).await;
    assert!(result.is_ok());
    assert!(result.unwrap(), "Should start sync when behind by 1 block");

    // Check the sent message
    let sent_messages = network.get_sent_messages().await;
    assert_eq!(sent_messages.len(), 1, "Should send exactly one message");

    match &sent_messages[0] {
        NetworkMessage::GetCFHeaders(get_cf_headers) => {
            // The critical check: start_height must be <= height of stop_hash
            assert_eq!(
                get_cf_headers.start_height,
                height - 1,
                "Start height should be {}",
                height - 1
            );
            // We can't easily verify the stop_hash height here, but the request should be valid
            println!(
                "GetCFHeaders request: start_height={}, stop_hash={}",
                get_cf_headers.start_height, get_cf_headers.stop_hash
            );
        }
        _ => panic!("Expected GetCFHeaders message"),
    }
}
