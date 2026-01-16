//! Tests for block downloading on filter match functionality.

use dash_spv::test_utils::MockNetworkManager;
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

use dashcore::block::Block;

use dash_spv::{
    client::Config, storage::DiskStorageManager, sync::FilterSyncManager,
    types::FilterMatch,
};

fn create_test_config() -> Config {
    Config::testnet()
        .without_masternodes()
        .with_validation_mode(dash_spv::types::ValidationMode::None)
        .with_storage_path(TempDir::new().unwrap().path())
}

#[tokio::test]
async fn test_filter_sync_manager_creation() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    assert!(!filter_sync.has_pending_downloads());
    assert_eq!(filter_sync.pending_download_count(), 0);
}

#[tokio::test]
async fn test_request_block_download() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);
    let mut network = MockNetworkManager::new();

    let filter_match = FilterMatch::dummy(100);

    // Request block download
    let result = filter_sync.request_block_download(filter_match.clone(), &mut network).await;
    assert!(result.is_ok());

    // Check sync manager state
    assert!(filter_sync.has_pending_downloads());
    assert_eq!(filter_sync.pending_download_count(), 1);
}

#[tokio::test]
async fn test_duplicate_block_request_prevention() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);
    let mut network = MockNetworkManager::new();

    let filter_match = FilterMatch::dummy(100);

    // Request block download twice
    filter_sync.request_block_download(filter_match.clone(), &mut network).await.unwrap();
    filter_sync.request_block_download(filter_match.clone(), &mut network).await.unwrap();

    // Should only track one download
    assert_eq!(filter_sync.pending_download_count(), 1);
}

#[tokio::test]
async fn test_handle_downloaded_block() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);
    let mut network = MockNetworkManager::new();

    let block = Block::dummy(100, vec![]);
    let block_hash = block.block_hash();
    let filter_match = FilterMatch::dummy(100);

    // Request the block
    filter_sync.request_block_download(filter_match.clone(), &mut network).await.unwrap();

    // Handle the downloaded block
    let result = filter_sync.handle_downloaded_block(&block).await.unwrap();

    // Should return the matched filter
    assert!(result.is_some());
    let returned_match = result.unwrap();
    assert_eq!(returned_match.block_hash, block_hash);
    assert_eq!(returned_match.height, 100);
    assert!(returned_match.block_requested);

    // Should no longer have pending downloads
    assert!(!filter_sync.has_pending_downloads());
    assert_eq!(filter_sync.pending_download_count(), 0);
}

#[tokio::test]
async fn test_handle_unexpected_block() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    let block = Block::dummy(0, vec![]);

    // Handle a block that wasn't requested
    let result = filter_sync.handle_downloaded_block(&block).await.unwrap();

    // Should return None for unexpected block
    assert!(result.is_none());
}

#[tokio::test]
async fn test_process_multiple_filter_matches() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);
    let mut network = MockNetworkManager::new();

    let filter_matches =
        vec![FilterMatch::dummy(100), FilterMatch::dummy(101), FilterMatch::dummy(102)];

    // Process filter matches and request downloads
    let result =
        filter_sync.process_filter_matches_and_download(filter_matches, &mut network).await;
    assert!(result.is_ok());

    // Should track 3 pending downloads
    assert_eq!(filter_sync.pending_download_count(), 3);
}

#[tokio::test]
async fn test_sync_manager_integration() {}

#[tokio::test]
async fn test_filter_match_and_download_workflow() {
    let config = create_test_config();
    let _storage = DiskStorageManager::new(&config).await.expect("Failed to create tmp storage");
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);
    let mut network = MockNetworkManager::new();

    // Create test address (WatchItem replaced with wallet-based tracking)
    // let address = create_test_address();

    // This is a simplified test - in real usage, we'd need to:
    // 1. Store filter headers and filters
    // 2. Check filters for matches
    // 3. Request block downloads for matches
    // 4. Handle downloaded blocks
    // 5. Extract wallet transactions from blocks

    // For now, just test that we can create filter matches and request downloads
    let filter_matches = vec![FilterMatch::dummy(100)];

    let result =
        filter_sync.process_filter_matches_and_download(filter_matches, &mut network).await;
    assert!(result.is_ok());

    assert!(filter_sync.has_pending_downloads());
}

#[tokio::test]
async fn test_reset_clears_download_state() {
    let config = create_test_config();
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);
    let mut network = MockNetworkManager::new();

    let filter_match = FilterMatch::dummy(100);

    // Request block download
    filter_sync.request_block_download(filter_match, &mut network).await.unwrap();
    assert!(filter_sync.has_pending_downloads());

    // Reset should clear all state
    filter_sync.reset();
    assert!(!filter_sync.has_pending_downloads());
    assert_eq!(filter_sync.pending_download_count(), 0);
}
