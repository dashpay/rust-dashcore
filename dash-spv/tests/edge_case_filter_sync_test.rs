//! Tests for edge case handling in filter header sync, particularly at the tip.

use dash_spv::test_utils::MockNetworkManager;
use dash_spv::{
    client::ClientConfig,
    storage::{BlockHeaderStorage, DiskStorageManager, FilterHeaderStorage},
    sync::legacy::filters::FilterSyncManager,
};
use dashcore::{
    block::Header as BlockHeader, hash_types::FilterHeader, network::message::NetworkMessage,
    Network,
};
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_filter_sync_at_tip_edge_case() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    let mut storage = DiskStorageManager::new(TempDir::new().unwrap().path().to_path_buf())
        .await
        .expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    // Set up storage with headers and filter headers at the same height (tip)
    const TIP_HEIGHT: u32 = 100;
    let headers = BlockHeader::dummy_batch(0..TIP_HEIGHT + 1);
    let filter_headers = FilterHeader::dummy_batch(0..TIP_HEIGHT + 1);

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Verify initial state
    let tip_height = storage.get_tip_height().await.unwrap();
    let filter_tip_height = storage.get_filter_tip_height().await.unwrap().unwrap();
    assert_eq!(tip_height, TIP_HEIGHT); // 0-indexed
    assert_eq!(filter_tip_height, TIP_HEIGHT); // 0-indexed

    // Try to start filter sync when already at tip
    let result = filter_sync.start_sync_headers(&mut network, &mut storage).await;
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Should not start sync when already at tip");

    // Verify no messages were sent
    let sent_messages = network.sent_messages();
    assert_eq!(sent_messages.len(), 0, "Should not send any messages when at tip");
}

#[tokio::test]
async fn test_no_invalid_getcfheaders_at_tip() {
    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    let mut storage = DiskStorageManager::new(TempDir::new().unwrap().path().to_path_buf())
        .await
        .expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    // Create a scenario where we're one filter header behind
    // FilterHeader at TIP_HEIGHT is the one missing
    const TIP_HEIGHT: u32 = 99;
    let headers = BlockHeader::dummy_batch(0..TIP_HEIGHT + 1);
    let filter_headers = FilterHeader::dummy_batch(0..TIP_HEIGHT);

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Start filter sync
    let result = filter_sync.start_sync_headers(&mut network, &mut storage).await;
    assert!(result.is_ok());
    assert!(result.unwrap(), "Should start sync when behind by 1 block");

    // Check the sent message
    let sent_messages = network.sent_messages();
    assert_eq!(sent_messages.len(), 1, "Should send exactly one message");

    match &sent_messages[0] {
        NetworkMessage::GetCFHeaders(get_cf_headers) => {
            // The critical check: start_height must be <= height of stop_hash
            assert_eq!(
                get_cf_headers.start_height, TIP_HEIGHT,
                "Start height should be {}",
                TIP_HEIGHT
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
