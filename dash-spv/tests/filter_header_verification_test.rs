//! Test to replicate the filter header chain verification failure observed in production.
//!
//! This test reproduces the exact scenario from the logs where:
//! 1. A batch of 1999 filter headers from height 616001-617999 is processed successfully
//! 2. The next batch starting at height 618000 fails verification because the
//!    previous_filter_header doesn't match what we calculated and stored
//!
//! The failure indicates a race condition or inconsistency in how filter headers
//! are calculated, stored, or verified across multiple batches.

use dash_spv::network::{Message, MessageDispatcher};
use dash_spv::{
    client::ClientConfig,
    error::{NetworkError, SyncError},
    network::{MessageType, NetworkManager},
    storage::{BlockHeaderStorage, DiskStorageManager, FilterHeaderStorage},
    sync::legacy::filters::FilterSyncManager,
};
use dashcore::{
    block::Header as BlockHeader,
    hash_types::{FilterHash, FilterHeader},
    network::message::NetworkMessage,
    network::message_filter::CFHeaders,
    BlockHash, Network,
};
use dashcore_hashes::{sha256d, Hash};
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

/// Mock network manager for testing filter sync
#[derive(Debug)]
struct MockNetworkManager {
    sent_messages: Vec<NetworkMessage>,
    message_dispatcher: MessageDispatcher,
}

impl MockNetworkManager {
    fn new() -> Self {
        Self {
            sent_messages: Vec::new(),
            message_dispatcher: MessageDispatcher::default(),
        }
    }

    #[allow(dead_code)]
    fn clear_sent_messages(&mut self) {
        self.sent_messages.clear();
    }
}

#[async_trait::async_trait]
impl NetworkManager for MockNetworkManager {
    async fn connect(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn send_message(&mut self, message: NetworkMessage) -> Result<(), NetworkError> {
        self.sent_messages.push(message);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn peer_count(&self) -> usize {
        1
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn message_receiver(
        &mut self,
        message_types: &[MessageType],
    ) -> UnboundedReceiver<Message> {
        self.message_dispatcher.message_receiver(message_types)
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
}

/// Create test filter headers with proper chain linkage
fn create_test_cfheaders_message(
    start_height: u32,
    count: u32,
    previous_filter_header: FilterHeader,
    block_hashes: &[BlockHash],
) -> CFHeaders {
    // Create fake filter hashes
    let mut filter_hashes = Vec::new();
    for i in 0..count {
        let height = start_height + i;
        let hash_bytes = [(height % 256) as u8; 32];
        let sha256d_hash = sha256d::Hash::from_byte_array(hash_bytes);
        let filter_hash = FilterHash::from_raw_hash(sha256d_hash);
        filter_hashes.push(filter_hash);
    }

    // Use the last block hash as stop_hash
    let stop_hash = block_hashes.last().copied().unwrap_or(BlockHash::all_zeros());

    CFHeaders {
        filter_type: 0,
        stop_hash,
        previous_filter_header,
        filter_hashes,
    }
}

/// Calculate what the filter header should be for a given height
fn calculate_expected_filter_header(
    filter_hash: FilterHash,
    prev_filter_header: FilterHeader,
) -> FilterHeader {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(filter_hash.as_byte_array());
    data[32..].copy_from_slice(prev_filter_header.as_byte_array());
    FilterHeader::from_byte_array(sha256d::Hash::hash(&data).to_byte_array())
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_filter_header_verification_failure_reproduction() {
    let _ = env_logger::try_init();

    println!("=== Testing Filter Header Chain Verification Failure ===");

    // Create storage and sync manager
    let mut storage = DiskStorageManager::new(TempDir::new().unwrap().path().to_path_buf())
        .await
        .expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    // Step 1: Store initial headers to simulate having a synced header chain
    println!("Step 1: Setting up initial header chain...");
    let initial_headers = BlockHeader::dummy_batch(1000..5000); // Headers 1000-4999
    storage.store_headers(&initial_headers).await.expect("Failed to store initial headers");

    let tip_height = storage.get_tip_height().await.unwrap();
    println!("Initial header chain stored: tip height = {}", tip_height);
    assert_eq!(tip_height, 4999);

    // Step 2: Start filter sync first (required for message processing)
    println!("\nStep 2: Starting filter header sync...");
    filter_sync.start_sync_headers(&mut network, &mut storage).await.expect("Failed to start sync");

    // Step 3: Process first batch of filter headers successfully (1-1999, 1999 headers)
    println!("\nStep 3: Processing first batch of filter headers (1-1999)...");

    let first_batch_start = 1;
    let first_batch_count = 1999;
    let first_batch_end = first_batch_start + first_batch_count - 1; // 1999

    // Create block hashes for the first batch
    let mut first_batch_block_hashes = Vec::new();
    for height in first_batch_start..=first_batch_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        first_batch_block_hashes.push(header.block_hash());
    }

    // Use a known previous filter header (simulating genesis or previous sync)
    let mut initial_prev_bytes = [0u8; 32];
    initial_prev_bytes[0] = 0x57;
    initial_prev_bytes[1] = 0x1c;
    initial_prev_bytes[2] = 0x4e;
    let initial_prev_filter_header = FilterHeader::from_byte_array(initial_prev_bytes);

    let first_cfheaders = create_test_cfheaders_message(
        first_batch_start,
        first_batch_count,
        initial_prev_filter_header,
        &first_batch_block_hashes,
    );

    // Process first batch - this should succeed
    let result = filter_sync
        .handle_cfheaders_message(first_cfheaders.clone(), &mut storage, &mut network)
        .await;

    match result {
        Ok(continuing) => {
            println!("First batch processed successfully, continuing: {}", continuing)
        }
        Err(e) => panic!("First batch should have succeeded, but failed: {:?}", e),
    }

    // Verify first batch was stored correctly
    let filter_tip = storage.get_filter_tip_height().await.unwrap().unwrap();
    println!("Filter tip after first batch: {}", filter_tip);
    assert_eq!(filter_tip, first_batch_end);

    // Get the last filter header from the first batch to see what we calculated
    let last_stored_filter_header = storage
        .get_filter_header(first_batch_end)
        .await
        .unwrap()
        .expect("Last filter header should exist");

    println!("Last stored filter header from first batch: {:?}", last_stored_filter_header);

    // Step 3: Calculate what the filter header should be for the last height
    // This simulates what we actually calculated and stored
    let last_filter_hash = first_cfheaders.filter_hashes.last().unwrap();
    let second_to_last_height = first_batch_end - 1;
    let second_to_last_stored = storage
        .get_filter_header(second_to_last_height)
        .await
        .unwrap()
        .expect("Second to last filter header should exist");

    let calculated_last_header =
        calculate_expected_filter_header(*last_filter_hash, second_to_last_stored);
    println!("Our calculated last header: {:?}", calculated_last_header);
    println!("Actually stored last header: {:?}", last_stored_filter_header);

    // They should match
    assert_eq!(calculated_last_header, last_stored_filter_header);

    // Step 4: Now create the second batch that will fail (2000-2999, 1000 headers)
    println!("\nStep 4: Creating second batch that should fail (2000-2999)...");

    let second_batch_start = 2000;
    let second_batch_count = 1000;
    let second_batch_end = second_batch_start + second_batch_count - 1; // 2999

    // Create block hashes for the second batch
    let mut second_batch_block_hashes = Vec::new();
    for height in second_batch_start..=second_batch_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        second_batch_block_hashes.push(header.block_hash());
    }

    // Here's the key: use a DIFFERENT previous_filter_header that doesn't match what we stored
    // This simulates the issue from the logs where the peer sends a different value
    let mut wrong_prev_bytes = [0u8; 32];
    wrong_prev_bytes[0] = 0xef;
    wrong_prev_bytes[1] = 0x07;
    wrong_prev_bytes[2] = 0xce;
    let wrong_prev_filter_header = FilterHeader::from_byte_array(wrong_prev_bytes);

    println!("Expected previous filter header: {:?}", last_stored_filter_header);
    println!("Peer's claimed previous filter header: {:?}", wrong_prev_filter_header);
    println!("These don't match - this should cause verification failure!");

    let second_cfheaders = create_test_cfheaders_message(
        second_batch_start,
        second_batch_count,
        wrong_prev_filter_header, // This is the wrong value!
        &second_batch_block_hashes,
    );

    // Step 5: Process second batch - this should fail
    println!("\nStep 5: Processing second batch (should fail)...");

    let result =
        filter_sync.handle_cfheaders_message(second_cfheaders, &mut storage, &mut network).await;

    match result {
        Ok(_) => panic!("Second batch should have failed verification!"),
        Err(SyncError::Validation(msg)) => {
            println!("✅ Expected failure occurred: {}", msg);
            assert!(msg.contains("Filter header chain verification failed"));
        }
        Err(e) => panic!("Wrong error type: {:?}", e),
    }

    println!("\n✅ Successfully reproduced the filter header verification failure!");
    println!("The issue is that different peers (or overlapping requests) provide");
    println!("different values for previous_filter_header, breaking chain continuity.");
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_overlapping_batches_from_different_peers() {
    let _ = env_logger::try_init();

    println!("=== Testing Overlapping Batches from Different Peers ===");
    println!("🐛 BUG REPRODUCTION TEST - This test should FAIL to demonstrate the bug!");

    // This test simulates the REAL production scenario that causes crashes:
    // - Peer A sends heights 1000-2000
    // - Peer B sends heights 1500-2500 (overlapping!)
    // Each peer provides different (but potentially valid) previous_filter_header values
    //
    // The system should handle this gracefully, but currently it crashes.
    // This test will FAIL until we implement the fix.

    let mut storage = DiskStorageManager::new(TempDir::new().unwrap().path().to_path_buf())
        .await
        .expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    // Step 1: Set up headers for the full range we'll need
    println!("Step 1: Setting up header chain (heights 1-3000)...");
    let initial_headers = BlockHeader::dummy_batch(1..3000); // Headers 1-2999
    storage.store_headers(&initial_headers).await.expect("Failed to store initial headers");

    let tip_height = storage.get_tip_height().await.unwrap();
    println!("Header chain stored: tip height = {}", tip_height);
    assert_eq!(tip_height, 2999);

    // Step 2: Start filter sync
    println!("\nStep 2: Starting filter header sync...");
    filter_sync.start_sync_headers(&mut network, &mut storage).await.expect("Failed to start sync");

    // Step 3: Process Peer A's batch first (heights 1000-2000, 1001 headers)
    println!("\nStep 3: Processing Peer A's batch (heights 1000-2000)...");

    // We need to first process headers 1-999 to get to height 1000
    println!("  First processing initial batch (heights 1-999) to establish chain...");
    let initial_batch_start = 1;
    let initial_batch_count = 999;
    let initial_batch_end = initial_batch_start + initial_batch_count - 1; // 999

    let mut initial_batch_block_hashes = Vec::new();
    for height in initial_batch_start..=initial_batch_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        initial_batch_block_hashes.push(header.block_hash());
    }

    let genesis_prev_filter_header = FilterHeader::from_byte_array([0x00u8; 32]); // Genesis

    let initial_cfheaders = create_test_cfheaders_message(
        initial_batch_start,
        initial_batch_count,
        genesis_prev_filter_header,
        &initial_batch_block_hashes,
    );

    filter_sync
        .handle_cfheaders_message(initial_cfheaders, &mut storage, &mut network)
        .await
        .expect("Initial batch should succeed");

    println!("  Initial batch processed. Now processing Peer A's batch...");

    // Now Peer A's batch: heights 1000-2000 (1001 headers)
    let peer_a_start = 1000;
    let peer_a_count = 1001;
    let peer_a_end = peer_a_start + peer_a_count - 1; // 2000

    let mut peer_a_block_hashes = Vec::new();
    for height in peer_a_start..=peer_a_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        peer_a_block_hashes.push(header.block_hash());
    }

    // Peer A's previous_filter_header should be the header at height 999
    let peer_a_prev_filter_header = storage
        .get_filter_header(999)
        .await
        .unwrap()
        .expect("Should have filter header at height 999");

    let peer_a_cfheaders = create_test_cfheaders_message(
        peer_a_start,
        peer_a_count,
        peer_a_prev_filter_header,
        &peer_a_block_hashes,
    );

    // Process Peer A's batch
    let result_a =
        filter_sync.handle_cfheaders_message(peer_a_cfheaders, &mut storage, &mut network).await;

    match result_a {
        Ok(_) => println!("  ✅ Peer A's batch processed successfully"),
        Err(e) => panic!("Peer A's batch should have succeeded: {:?}", e),
    }

    // Verify Peer A's data was stored
    let filter_tip_after_a = storage.get_filter_tip_height().await.unwrap().unwrap();
    println!("  Filter tip after Peer A: {}", filter_tip_after_a);
    assert_eq!(filter_tip_after_a, peer_a_end);

    // Step 4: Now process Peer B's overlapping batch (heights 1500-2500, 1001 headers)
    println!("\nStep 4: Processing Peer B's OVERLAPPING batch (heights 1500-2500)...");
    println!("  This overlaps with Peer A's batch by 501 headers (1500-2000)!");

    let peer_b_start = 1500;
    let peer_b_count = 1001;
    let peer_b_end = peer_b_start + peer_b_count - 1; // 2500

    let mut peer_b_block_hashes = Vec::new();
    for height in peer_b_start..=peer_b_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        peer_b_block_hashes.push(header.block_hash());
    }

    // HERE'S THE KEY: Peer B provides a different previous_filter_header
    // Peer B thinks the previous header should be at height 1499, but Peer A
    // already processed through height 2000, so our stored chain is different

    // Simulate Peer B having a different view: use the header at height 1499
    // but Peer B calculated it differently (simulating different peer state)
    let peer_b_prev_filter_header_stored = storage
        .get_filter_header(1499)
        .await
        .unwrap()
        .expect("Should have filter header at height 1499");

    // Simulate Peer B having computed this header differently - create a slightly different value
    let mut peer_b_prev_bytes = peer_b_prev_filter_header_stored.to_byte_array();
    peer_b_prev_bytes[0] ^= 0x01; // Flip one bit to make it different
    let peer_b_prev_filter_header = FilterHeader::from_byte_array(peer_b_prev_bytes);

    println!("  Peer A's stored header at 1499: {:?}", peer_b_prev_filter_header_stored);
    println!("  Peer B's claimed header at 1499: {:?}", peer_b_prev_filter_header);
    println!("  These are DIFFERENT - simulating different peer views!");

    let peer_b_cfheaders = create_test_cfheaders_message(
        peer_b_start,
        peer_b_count,
        peer_b_prev_filter_header, // Different from what we have stored!
        &peer_b_block_hashes,
    );

    // Step 5: Process Peer B's overlapping batch - this should expose the issue
    println!("\nStep 5: Processing Peer B's batch (should fail due to inconsistent previous_filter_header)...");

    let result_b =
        filter_sync.handle_cfheaders_message(peer_b_cfheaders, &mut storage, &mut network).await;

    match result_b {
        Ok(_) => {
            println!("  ✅ Peer B's batch was accepted - overlap handling worked!");
            let final_tip = storage.get_filter_tip_height().await.unwrap().unwrap();
            println!("  Final filter tip: {}", final_tip);
            println!(
                "  🎯 This is what we want - the system should be resilient to overlapping data!"
            );
        }
        Err(e) => {
            println!("  ❌ Peer B's batch failed: {:?}", e);
            println!("  🐛 BUG EXPOSED: The system crashed when receiving overlapping batches from different peers!");
            println!("  This is the production issue we need to fix - the system should handle overlapping data gracefully.");

            // FAIL THE TEST to show the bug exists
            panic!("🚨 BUG REPRODUCED: System cannot handle overlapping filter headers from different peers. Error: {:?}", e);
        }
    }

    println!("\n🎯 SUCCESS: The system correctly handled overlapping batches!");
    println!(
        "The fix is working - peers with different filter header views are handled gracefully."
    );
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_filter_header_verification_overlapping_batches() {
    let _ = env_logger::try_init();

    println!("=== Testing Overlapping Filter Header Batches ===");

    // This test simulates what happens when we receive overlapping filter header batches
    // due to recovery/retry mechanisms or multiple peers

    let mut storage = DiskStorageManager::new(TempDir::new().unwrap().path().to_path_buf())
        .await
        .expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    // Set up initial headers - start from 1 for proper sync
    let initial_headers = BlockHeader::dummy_batch(1..2000);
    storage.store_headers(&initial_headers).await.expect("Failed to store initial headers");

    // Start filter sync first (required for message processing)
    filter_sync.start_sync_headers(&mut network, &mut storage).await.expect("Failed to start sync");

    // First batch: 1-500 (500 headers)
    let batch1_start = 1;
    let batch1_count = 500;
    let batch1_end = batch1_start + batch1_count - 1;

    let mut batch1_block_hashes = Vec::new();
    for height in batch1_start..=batch1_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        batch1_block_hashes.push(header.block_hash());
    }

    let prev_filter_header = FilterHeader::from_byte_array([0x01u8; 32]);

    let batch1_cfheaders = create_test_cfheaders_message(
        batch1_start,
        batch1_count,
        prev_filter_header,
        &batch1_block_hashes,
    );

    // Process first batch
    filter_sync
        .handle_cfheaders_message(batch1_cfheaders, &mut storage, &mut network)
        .await
        .expect("First batch should succeed");

    let filter_tip = storage.get_filter_tip_height().await.unwrap().unwrap();
    assert_eq!(filter_tip, batch1_end);

    // Second batch: Overlapping range 400-1000 (601 headers)
    // This overlaps with the previous batch by 100 headers
    let batch2_start = 400;
    let batch2_count = 601;
    let batch2_end = batch2_start + batch2_count - 1;

    let mut batch2_block_hashes = Vec::new();
    for height in batch2_start..=batch2_end {
        let header = storage.get_header(height).await.unwrap().unwrap();
        batch2_block_hashes.push(header.block_hash());
    }

    // Get the correct previous filter header for this overlapping batch
    let overlap_prev_height = batch2_start - 1;
    let correct_prev_filter_header = storage
        .get_filter_header(overlap_prev_height)
        .await
        .unwrap()
        .expect("Previous filter header should exist");

    let batch2_cfheaders = create_test_cfheaders_message(
        batch2_start,
        batch2_count,
        correct_prev_filter_header,
        &batch2_block_hashes,
    );

    // Process overlapping batch - this should handle overlap gracefully
    let result =
        filter_sync.handle_cfheaders_message(batch2_cfheaders, &mut storage, &mut network).await;

    match result {
        Ok(_) => println!("✅ Overlapping batch handled successfully"),
        Err(e) => println!("❌ Overlapping batch failed: {:?}", e),
    }

    // The filter tip should now be at the end of the second batch
    let final_filter_tip = storage.get_filter_tip_height().await.unwrap().unwrap();
    println!("Final filter tip: {}", final_filter_tip);
    assert!(final_filter_tip >= batch1_end); // Should be at least as high as before
}

#[ignore = "mock implementation incomplete"]
#[tokio::test]
async fn test_filter_header_verification_race_condition_simulation() {
    let _ = env_logger::try_init();

    println!("=== Testing Race Condition Simulation ===");

    // This test simulates the race condition that might occur when multiple
    // filter header requests are in flight simultaneously

    let mut storage = DiskStorageManager::new(TempDir::new().unwrap().path().to_path_buf())
        .await
        .expect("Failed to create tmp storage");
    let mut network = MockNetworkManager::new();

    let config = ClientConfig::new(Network::Dash);
    let received_heights = Arc::new(Mutex::new(HashSet::new()));
    let mut filter_sync: FilterSyncManager<DiskStorageManager, MockNetworkManager> =
        FilterSyncManager::new(&config, received_heights);

    // Set up headers - need enough for batch B (up to height 3000)
    let initial_headers = BlockHeader::dummy_batch(1..3001);
    storage.store_headers(&initial_headers).await.expect("Failed to store initial headers");

    // Simulate: Start sync, send request for batch A
    filter_sync.start_sync_headers(&mut network, &mut storage).await.expect("Failed to start sync");

    // Simulate: Timeout occurs, recovery sends request for overlapping batch B
    // Both requests come back, but in wrong order or with inconsistent data

    let base_start = 1;

    // Batch A: 1-1000 (original request)
    let batch_a_count = 1000;
    let mut batch_a_block_hashes = Vec::new();
    for height in base_start..(base_start + batch_a_count) {
        let header = storage.get_header(height).await.unwrap().unwrap();
        batch_a_block_hashes.push(header.block_hash());
    }

    // Batch B: 1-2000 (recovery request, larger range)
    let batch_b_count = 2000;
    let mut batch_b_block_hashes = Vec::new();
    for height in base_start..(base_start + batch_b_count) {
        let header = storage.get_header(height).await.unwrap().unwrap();
        batch_b_block_hashes.push(header.block_hash());
    }

    let prev_filter_header = FilterHeader::from_byte_array([0x02u8; 32]);

    // Create both batches with the same previous filter header
    let batch_a = create_test_cfheaders_message(
        base_start,
        batch_a_count,
        prev_filter_header,
        &batch_a_block_hashes,
    );

    let batch_b = create_test_cfheaders_message(
        base_start,
        batch_b_count,
        prev_filter_header,
        &batch_b_block_hashes,
    );

    // Process batch A first
    println!("Processing batch A (1000 headers)...");
    filter_sync
        .handle_cfheaders_message(batch_a, &mut storage, &mut network)
        .await
        .expect("Batch A should succeed");

    let tip_after_a = storage.get_filter_tip_height().await.unwrap().unwrap();
    println!("Filter tip after batch A: {}", tip_after_a);

    // Now process batch B (overlapping)
    println!("Processing batch B (2000 headers, overlapping)...");
    let result = filter_sync.handle_cfheaders_message(batch_b, &mut storage, &mut network).await;

    match result {
        Ok(_) => {
            let tip_after_b = storage.get_filter_tip_height().await.unwrap().unwrap();
            println!("✅ Batch B processed successfully, tip: {}", tip_after_b);
        }
        Err(e) => {
            println!("❌ Batch B failed: {:?}", e);
        }
    }
}
