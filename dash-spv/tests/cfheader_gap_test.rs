//! Tests for CFHeader gap detection and auto-restart functionality.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use dash_spv::{
    client::ClientConfig,
    error::{NetworkError, NetworkResult},
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

/// Create a mock filter header
fn create_mock_filter_header() -> FilterHeader {
    FilterHeader::all_zeros()
}

#[tokio::test]
async fn test_cfheader_gap_detection_no_gap() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Store 100 block headers and 100 filter headers (no gap)
    let mut headers = Vec::new();
    let mut filter_headers = Vec::new();

    for i in 1..=100 {
        headers.push(create_mock_header(i));
        filter_headers.push(create_mock_filter_header());
    }

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Check gap detection
    let (has_gap, block_height, filter_height, gap_size) =
        filter_sync.check_cfheader_gap(&storage).await.unwrap();

    assert!(!has_gap, "Should not detect gap when heights are equal");
    assert_eq!(block_height, 99); // 0-indexed, so 100 headers = height 99
    assert_eq!(filter_height, 99);
    assert_eq!(gap_size, 0);
}

#[tokio::test]
async fn test_cfheader_gap_detection_with_gap() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Store 200 block headers but only 150 filter headers (gap of 50)
    let mut headers = Vec::new();
    let mut filter_headers = Vec::new();

    for i in 1..=200 {
        headers.push(create_mock_header(i));
    }

    for _i in 1..=150 {
        filter_headers.push(create_mock_filter_header());
    }

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Check gap detection
    let (has_gap, block_height, filter_height, gap_size) =
        filter_sync.check_cfheader_gap(&storage).await.unwrap();

    assert!(has_gap, "Should detect gap when block headers > filter headers");
    assert_eq!(block_height, 199); // 0-indexed, so 200 headers = height 199
    assert_eq!(filter_height, 149); // 0-indexed, so 150 headers = height 149
    assert_eq!(gap_size, 50);
}

#[tokio::test]
async fn test_cfheader_gap_detection_filter_ahead() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Store 100 block headers but 120 filter headers (filter ahead - no gap)
    let mut headers = Vec::new();
    let mut filter_headers = Vec::new();

    for i in 1..=100 {
        headers.push(create_mock_header(i));
    }

    for _i in 1..=120 {
        filter_headers.push(create_mock_filter_header());
    }

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Check gap detection
    let (has_gap, block_height, filter_height, gap_size) =
        filter_sync.check_cfheader_gap(&storage).await.unwrap();

    assert!(!has_gap, "Should not detect gap when filter headers >= block headers");
    assert_eq!(block_height, 99); // 0-indexed, so 100 headers = height 99
    assert_eq!(filter_height, 119); // 0-indexed, so 120 headers = height 119
    assert_eq!(gap_size, 0);
}

#[tokio::test]
async fn test_cfheader_restart_cooldown() {
    let mut config = ClientConfig::new(Network::Dash);
    config.cfheader_gap_restart_cooldown_secs = 1; // 1 second cooldown for testing

    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync = FilterSyncManager::new(&config, received_heights);

    let mut storage = MemoryStorageManager::new().await.unwrap();

    // Store headers with a gap
    let mut headers = Vec::new();
    let mut filter_headers = Vec::new();

    for i in 1..=200 {
        headers.push(create_mock_header(i));
    }

    for _i in 1..=100 {
        filter_headers.push(create_mock_filter_header());
    }

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Create a mock network manager (will fail when trying to restart)
    struct MockNetworkManager;

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

        async fn send_message(&mut self, _message: NetworkMessage) -> NetworkResult<()> {
            Err(NetworkError::ConnectionFailed("Mock failure".to_string()))
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
    }

    let mut network = MockNetworkManager;

    // First attempt should try to restart (and fail)
    let result1 = filter_sync.maybe_restart_cfheader_sync_for_gap(&mut network, &mut storage).await;
    assert!(result1.is_err(), "First restart attempt should fail with mock network");

    // Second attempt immediately should be blocked by cooldown
    let result2 = filter_sync.maybe_restart_cfheader_sync_for_gap(&mut network, &mut storage).await;
    assert!(result2.is_ok(), "Second attempt should not error");
    assert!(!result2.unwrap(), "Second attempt should return false due to cooldown");

    // Wait for cooldown to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Third attempt should try again (and fail)
    let result3 = filter_sync.maybe_restart_cfheader_sync_for_gap(&mut network, &mut storage).await;
    // The third attempt should either fail (if trying to restart) or return Ok(false) if max attempts reached
    let should_fail_or_be_disabled = result3.is_err() || (result3.is_ok() && !result3.unwrap());
    assert!(
        should_fail_or_be_disabled,
        "Third restart attempt should fail or be disabled after cooldown"
    );
}
