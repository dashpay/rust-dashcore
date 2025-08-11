//! Tests for edge case handling in filter header sync, particularly at the tip.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use dash_spv::{
    client::ClientConfig,
    error::NetworkResult,
    network::NetworkManager,
    storage::{MemoryStorageManager, StorageManager},
    sync::filters::FilterSyncManager,
};
use dashcore::{
    block::Header as BlockHeader, hash_types::FilterHeader, network::message::NetworkMessage,
    BlockHash, Network,
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

    fn get_sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent_messages.lock().unwrap().clone()
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
        self.sent_messages.lock().unwrap().push(message);
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

    async fn send_ping(&mut self) -> NetworkResult<u64> {
        Ok(0)
    }

    async fn handle_ping(&mut self, _nonce: u64) -> NetworkResult<()> {
        Ok(())
    }

    fn handle_pong(&mut self, _nonce: u64) -> NetworkResult<()> {
        Ok(())
    }

    fn should_ping(&self) -> bool {
        false
    }

    fn cleanup_old_pings(&mut self) {}

    fn get_message_sender(&self) -> tokio::sync::mpsc::Sender<NetworkMessage> {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx
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

    async fn get_peers_with_service(
        &self,
        _service_flags: dashcore::network::constants::ServiceFlags,
    ) -> Vec<dash_spv::types::PeerInfo> {
        vec![]
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
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();
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
    let tip_height = storage.get_tip_height().await.unwrap().unwrap();
    let filter_tip_height = storage.get_filter_tip_height().await.unwrap().unwrap();
    assert_eq!(tip_height, height - 1); // 0-indexed
    assert_eq!(filter_tip_height, height - 1); // 0-indexed

    // Try to start filter sync when already at tip
    let result = filter_sync.start_sync_headers(&mut network, &mut storage).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false, "Should not start sync when already at tip");

    // Verify no messages were sent
    let sent_messages = network.get_sent_messages();
    assert_eq!(sent_messages.len(), 0, "Should not send any messages when at tip");
}

#[tokio::test]
async fn test_filter_sync_gap_detection_edge_case() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Test case 1: No gap (same height)
    let height = 1000;
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

    let (has_gap, block_height, filter_height, gap_size) =
        filter_sync.check_cfheader_gap(&storage).await.unwrap();

    assert!(!has_gap, "Should not detect gap when heights are equal");
    assert_eq!(block_height, height - 1); // 0-indexed
    assert_eq!(filter_height, height - 1);
    assert_eq!(gap_size, 0);

    // Test case 2: Gap of 1 (considered no gap)
    // Add one more header to create a gap of 1
    let next_header = create_mock_header(height + 1, prev_hash);
    storage.store_headers(&[next_header]).await.unwrap();

    let (has_gap, block_height, filter_height, gap_size) =
        filter_sync.check_cfheader_gap(&storage).await.unwrap();

    assert!(!has_gap, "Should not detect gap when difference is only 1 block");
    assert_eq!(block_height, height); // 0-indexed, so 1001 blocks = height 1000
    assert_eq!(filter_height, height - 1);
    assert_eq!(gap_size, 1);

    // Test case 3: Gap of 2 (should be detected)
    // Add one more header to create a gap of 2
    prev_hash = next_header.block_hash();
    let next_header2 = create_mock_header(height + 2, prev_hash);
    storage.store_headers(&[next_header2]).await.unwrap();

    let (has_gap, block_height, filter_height, gap_size) =
        filter_sync.check_cfheader_gap(&storage).await.unwrap();

    assert!(has_gap, "Should detect gap when difference is 2 or more blocks");
    assert_eq!(block_height, height + 1); // 0-indexed
    assert_eq!(filter_height, height - 1);
    assert_eq!(gap_size, 2);
}

#[tokio::test]
async fn test_no_invalid_getcfheaders_at_tip() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();
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
    let sent_messages = network.get_sent_messages();
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
