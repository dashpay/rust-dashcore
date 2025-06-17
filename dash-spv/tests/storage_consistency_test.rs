//! Tests for storage consistency issues.
//! 
//! These tests are designed to expose the storage bug where get_tip_height() 
//! returns a value but get_header() at that height returns None.

use dash_spv::storage::{DiskStorageManager, StorageManager};
use dashcore::block::{Header as BlockHeader, Version};
use dashcore::pow::CompactTarget;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

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
async fn test_tip_height_header_consistency_basic() {
    println!("=== Testing basic tip height vs header consistency ===");
    
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .unwrap();

    // Store some headers
    let headers: Vec<BlockHeader> = (0..1000).map(create_test_header).collect();
    storage.store_headers(&headers).await.unwrap();
    
    // Check consistency immediately
    let tip_height = storage.get_tip_height().await.unwrap();
    println!("Tip height: {:?}", tip_height);
    
    if let Some(height) = tip_height {
        let header = storage.get_header(height).await.unwrap();
        println!("Header at tip height {}: {:?}", height, header.is_some());
        assert!(header.is_some(), "Header should exist at tip height {}", height);
        
        // Also test a few heights before the tip
        for test_height in height.saturating_sub(10)..=height {
            let test_header = storage.get_header(test_height).await.unwrap();
            assert!(test_header.is_some(), "Header should exist at height {}", test_height);
        }
    }
    
    storage.shutdown().await.unwrap();
    println!("✅ Basic consistency test passed");
}

#[tokio::test]
async fn test_tip_height_header_consistency_after_save() {
    println!("=== Testing tip height vs header consistency after background save ===");
    
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    
    // Phase 1: Store headers and let background save complete
    {
        let mut storage = DiskStorageManager::new(storage_path.clone())
            .await
            .unwrap();

        let headers: Vec<BlockHeader> = (0..50000).map(create_test_header).collect();
        storage.store_headers(&headers).await.unwrap();
        
        // Wait for background save to complete
        sleep(Duration::from_secs(1)).await;
        
        let tip_height = storage.get_tip_height().await.unwrap();
        println!("Phase 1 - Tip height: {:?}", tip_height);
        
        if let Some(height) = tip_height {
            let header = storage.get_header(height).await.unwrap();
            assert!(header.is_some(), "Header should exist at tip height {} in phase 1", height);
        }
        
        storage.shutdown().await.unwrap();
    }
    
    // Phase 2: Reload and check consistency
    {
        let storage = DiskStorageManager::new(storage_path.clone())
            .await
            .unwrap();
            
        let tip_height = storage.get_tip_height().await.unwrap();
        println!("Phase 2 - Tip height after reload: {:?}", tip_height);
        
        if let Some(height) = tip_height {
            let header = storage.get_header(height).await.unwrap();
            println!("Header at tip height {} after reload: {:?}", height, header.is_some());
            assert!(header.is_some(), "Header should exist at tip height {} after reload", height);
            
            // Test a range around the tip
            for test_height in height.saturating_sub(10)..=height {
                let test_header = storage.get_header(test_height).await.unwrap();
                assert!(test_header.is_some(), "Header should exist at height {} after reload", test_height);
            }
        }
    }
    
    println!("✅ Consistency after save test passed");
}

#[tokio::test]
async fn test_tip_height_header_consistency_large_dataset() {
    println!("=== Testing tip height vs header consistency with large dataset ===");
    
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .unwrap();

    // Store headers across multiple segments (like real sync scenario)
    let total_headers = 200_000;
    let batch_size = 10_000;
    
    for batch_start in (0..total_headers).step_by(batch_size) {
        let batch_end = (batch_start + batch_size).min(total_headers);
        let headers: Vec<BlockHeader> = (batch_start..batch_end).map(|h| create_test_header(h as u32)).collect();
        
        storage.store_headers(&headers).await.unwrap();
        
        // Check consistency after each batch
        let tip_height = storage.get_tip_height().await.unwrap();
        if let Some(height) = tip_height {
            let header = storage.get_header(height).await.unwrap();
            if header.is_none() {
                panic!("❌ CONSISTENCY BUG DETECTED: tip_height={} but get_header({}) returned None after batch ending at {}", 
                       height, height, batch_end - 1);
            }
            
            // Also check the expected tip based on what we just stored
            let expected_tip = (batch_end - 1) as u32;
            if height != expected_tip {
                println!("⚠️ Tip height {} doesn't match expected {} after storing batch ending at {}", 
                        height, expected_tip, batch_end - 1);
            }
        }
        
        if batch_start % 50_000 == 0 {
            println!("Processed {} headers, current tip: {:?}", batch_end, tip_height);
        }
    }
    
    // Final consistency check
    let final_tip = storage.get_tip_height().await.unwrap();
    println!("Final tip height: {:?}", final_tip);
    
    if let Some(height) = final_tip {
        let header = storage.get_header(height).await.unwrap();
        assert!(header.is_some(), "❌ FINAL CONSISTENCY CHECK FAILED: Header should exist at final tip height {}", height);
        
        // Test several heights around the tip
        for test_height in height.saturating_sub(100)..=height {
            let test_header = storage.get_header(test_height).await.unwrap();
            if test_header.is_none() {
                panic!("❌ CONSISTENCY BUG: Header missing at height {} (tip is {})", test_height, height);
            }
        }
    }
    
    storage.shutdown().await.unwrap();
    println!("✅ Large dataset consistency test passed");
}

#[tokio::test]
async fn test_concurrent_tip_header_access() {
    println!("=== Testing tip height vs header consistency under concurrent access ===");
    
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    
    // Store initial data
    {
        let mut storage = DiskStorageManager::new(storage_path.clone())
            .await
            .unwrap();
        let headers: Vec<BlockHeader> = (0..100_000).map(create_test_header).collect();
        storage.store_headers(&headers).await.unwrap();
        storage.shutdown().await.unwrap();
    }
    
    // Test concurrent access from multiple storage instances
    let mut handles = vec![];
    
    for i in 0..5 {
        let path = storage_path.clone();
        let handle = tokio::spawn(async move {
            let storage = DiskStorageManager::new(path).await.unwrap();
            
            // Repeatedly check consistency
            for iteration in 0..100 {
                let tip_height = storage.get_tip_height().await.unwrap();
                
                if let Some(height) = tip_height {
                    let header = storage.get_header(height).await.unwrap();
                    if header.is_none() {
                        panic!("❌ CONCURRENCY BUG DETECTED in task {}, iteration {}: tip_height={} but get_header({}) returned None", 
                               i, iteration, height, height);
                    }
                    
                    // Also test a few specific heights
                    for offset in 0..5 {
                        let test_height = height.saturating_sub(offset);
                        let test_header = storage.get_header(test_height).await.unwrap();
                        if test_header.is_none() {
                            panic!("❌ CONCURRENCY BUG: Header missing at height {} (tip is {}) in task {}", 
                                   test_height, height, i);
                        }
                    }
                }
                
                // Small delay to allow other tasks to run
                if iteration % 20 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }
            
            println!("Task {} completed 100 consistency checks", i);
        });
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }
    
    println!("✅ Concurrent access consistency test passed");
}

#[tokio::test]
async fn test_reproduce_filter_sync_bug() {
    println!("=== Attempting to reproduce the exact filter sync bug scenario ===");
    
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .unwrap();

    // Simulate the exact scenario from the logs:
    // - Headers synced to some height (e.g., 2283503)
    // - Filter sync tries to access height 2251689 but it doesn't exist
    // - Fallback tries tip height 2283503 but that also fails
    
    let simulated_tip = 2283503;
    let problematic_height = 2251689;
    
    // Store headers up to a certain point, but with gaps to simulate the bug
    println!("Storing headers with intentional gaps to reproduce bug...");
    
    // Store headers 0 to 2251688 (just before the problematic height)
    for batch_start in (0..problematic_height).step_by(10_000) {
        let batch_end = (batch_start + 10_000).min(problematic_height);
        let headers: Vec<BlockHeader> = (batch_start..batch_end).map(create_test_header).collect();
        storage.store_headers(&headers).await.unwrap();
    }
    
    // Skip headers 2251689 to 2283502 (create a gap)
    
    // Store only the "tip" header at 2283503
    let tip_header = vec![create_test_header(simulated_tip)];
    storage.store_headers(&tip_header).await.unwrap();
    
    // Now check what get_tip_height() returns
    let reported_tip = storage.get_tip_height().await.unwrap();
    println!("Storage reports tip height: {:?}", reported_tip);
    
    if let Some(tip_height) = reported_tip {
        println!("Checking if header exists at reported tip height {}...", tip_height);
        let tip_header = storage.get_header(tip_height).await.unwrap();
        println!("Header at tip height {}: {:?}", tip_height, tip_header.is_some());
        
        if tip_header.is_none() {
            println!("🎯 REPRODUCED THE BUG! get_tip_height() returned {} but get_header({}) returned None", 
                     tip_height, tip_height);
        }
        
        println!("Checking if header exists at problematic height {}...", problematic_height);
        let problematic_header = storage.get_header(problematic_height).await.unwrap();
        println!("Header at problematic height {}: {:?}", problematic_height, problematic_header.is_some());
        
        // Try the exact logic from the filter sync bug
        if problematic_header.is_none() {
            println!("Header not found at calculated height {}, trying fallback to tip {}", 
                     problematic_height, tip_height);
            
            if tip_header.is_none() {
                println!("🔥 EXACT BUG REPRODUCED: Fallback to tip {} also failed - this is the exact error from the logs!", 
                         tip_height);
                panic!("Reproduced the exact filter sync bug scenario");
            }
        }
    }
    
    storage.shutdown().await.unwrap();
    println!("Bug reproduction test completed");
}

#[tokio::test]
async fn test_segment_boundary_consistency() {
    println!("=== Testing consistency across segment boundaries ===");
    
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .unwrap();

    // Store headers that cross segment boundaries
    // Assuming segments are 50,000 headers each
    let segment_size = 50_000;
    let headers: Vec<BlockHeader> = (0..segment_size + 100).map(create_test_header).collect();
    
    storage.store_headers(&headers).await.unwrap();
    
    // Check consistency around segment boundaries
    let boundary_heights = vec![
        segment_size - 1,  // Last in first segment
        segment_size,      // First in second segment
        segment_size + 1,  // Second in second segment
    ];
    
    let tip_height = storage.get_tip_height().await.unwrap().unwrap();
    println!("Tip height: {}", tip_height);
    
    for height in boundary_heights {
        if height <= tip_height {
            let header = storage.get_header(height).await.unwrap();
            assert!(header.is_some(), "Header should exist at segment boundary height {}", height);
            println!("✅ Header exists at segment boundary height {}", height);
        }
    }
    
    // Check tip consistency
    let tip_header = storage.get_header(tip_height).await.unwrap();
    assert!(tip_header.is_some(), "Header should exist at tip height {}", tip_height);
    
    storage.shutdown().await.unwrap();
    println!("✅ Segment boundary consistency test passed");
}

#[tokio::test]
async fn test_reproduce_tip_height_segment_eviction_race() {
    println!("=== Attempting to reproduce tip height vs segment eviction race condition ===");
    
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf())
        .await
        .unwrap();

    // The race condition occurs when:
    // 1. cached_tip_height is updated after storing headers
    // 2. Segment containing the tip header gets evicted before it's saved to disk
    // 3. get_header() fails to find the header that get_tip_height() says exists
    
    // Force segment eviction by storing enough headers to exceed MAX_ACTIVE_SEGMENTS (10)
    // Each segment holds 50,000 headers, so we need 10+ segments = 500,000+ headers
    
    let segment_size = 50_000;
    let num_segments = 12; // Exceed MAX_ACTIVE_SEGMENTS = 10
    let total_headers = segment_size * num_segments;
    
    println!("Storing {} headers across {} segments to force eviction...", total_headers, num_segments);
    
    // Store headers in batches, checking for the race condition after each batch
    let batch_size = 5_000;
    
    for batch_start in (0..total_headers).step_by(batch_size) {
        let batch_end = (batch_start + batch_size).min(total_headers);
        let headers: Vec<BlockHeader> = (batch_start..batch_end).map(|h| create_test_header(h as u32)).collect();
        
        // Store the batch
        storage.store_headers(&headers).await.unwrap();
        
        // Immediately check for race condition
        let tip_height = storage.get_tip_height().await.unwrap();
        
        if let Some(height) = tip_height {
            // Try to access the tip header multiple times to catch race condition
            for attempt in 0..5 {
                let header_result = storage.get_header(height).await.unwrap();
                if header_result.is_none() {
                    println!("🎯 RACE CONDITION REPRODUCED!");
                    println!("   Batch: {}-{}", batch_start, batch_end - 1);
                    println!("   Attempt: {}", attempt + 1);
                    println!("   get_tip_height() returned: {}", height);
                    println!("   get_header({}) returned: None", height);
                    println!("   This is the exact race condition causing the filter sync bug!");
                    panic!("Successfully reproduced the tip height vs segment eviction race condition");
                }
                
                // Small delay to allow potential eviction
                sleep(Duration::from_millis(1)).await;
            }
        }
        
        // Also check a few headers before the tip
        if let Some(height) = tip_height {
            for check_height in height.saturating_sub(10)..=height {
                let header_result = storage.get_header(check_height).await.unwrap();
                if header_result.is_none() {
                    println!("🎯 RACE CONDITION REPRODUCED AT HEIGHT {}!", check_height);
                    println!("   get_tip_height() returned: {}", height);
                    println!("   get_header({}) returned: None", check_height);
                    panic!("Race condition: header missing before tip height");
                }
            }
        }
        
        if batch_start % (segment_size * 2) == 0 {
            println!("   Processed {} headers, tip: {:?}", batch_end, tip_height);
        }
    }
    
    println!("Race condition test completed without reproducing the bug");
    println!("This might indicate the race condition requires specific timing or conditions");
    
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_tip_height_access_with_eviction() {
    println!("=== Testing concurrent tip height access during segment eviction ===");
    
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    
    // Store a large dataset to trigger eviction
    {
        let mut storage = DiskStorageManager::new(storage_path.clone()).await.unwrap();
        
        // Store 600,000 headers (12 segments) to force eviction
        let headers: Vec<BlockHeader> = (0..600_000).map(|h| create_test_header(h as u32)).collect();
        
        for chunk in headers.chunks(50_000) {
            storage.store_headers(chunk).await.unwrap();
        }
        
        storage.shutdown().await.unwrap();
    }
    
    // Now test concurrent access that might trigger the race condition
    let mut handles = vec![];
    
    for task_id in 0..10 {
        let path = storage_path.clone();
        let handle = tokio::spawn(async move {
            let storage = DiskStorageManager::new(path).await.unwrap();
            
            for iteration in 0..50 {
                // Get tip height
                let tip_height = storage.get_tip_height().await.unwrap();
                
                if let Some(height) = tip_height {
                    // Immediately try to access the tip header
                    let header_result = storage.get_header(height).await.unwrap();
                    
                    if header_result.is_none() {
                        panic!("🎯 CONCURRENT RACE CONDITION REPRODUCED in task {}, iteration {}!\n   get_tip_height() = {}\n   get_header({}) = None", 
                               task_id, iteration, height, height);
                    }
                    
                    // Also test accessing random segments to trigger eviction
                    let segment_height = (iteration * 50_000) % 600_000;
                    let _ = storage.get_header(segment_height as u32).await.unwrap();
                }
                
                if iteration % 10 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }
            
            println!("Task {} completed without detecting race condition", task_id);
        });
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }
    
    println!("✅ Concurrent access test completed without reproducing race condition");
}