//! Tests for segmented disk storage implementation.

use dash_spv::storage::{DiskStorageManager, StorageManager};
use dashcore::block::{Header as BlockHeader, Version};
use dashcore::hash_types::FilterHeader;
use dashcore::pow::CompactTarget;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::time::sleep;

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

/// Create a test filter header for a given height.
fn create_test_filter_header(height: u32) -> FilterHeader {
    // Create unique filter headers
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&height.to_le_bytes());
    FilterHeader::from_raw_hash(dashcore_hashes::sha256d::Hash::from_byte_array(bytes))
}

#[tokio::test]
async fn test_segmented_storage_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store headers across multiple segments
    let headers: Vec<BlockHeader> = (0..100_000).map(create_test_header).collect();

    // Store in batches
    for chunk in headers.chunks(10_000) {
        storage.store_headers(chunk).await.unwrap();
    }

    // Verify we can read them back
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(99_999));

    // Check individual headers
    assert_eq!(storage.get_header(0).await.unwrap().unwrap().time, 0);
    assert_eq!(storage.get_header(49_999).await.unwrap().unwrap().time, 49_999);
    assert_eq!(storage.get_header(50_000).await.unwrap().unwrap().time, 50_000);
    assert_eq!(storage.get_header(99_999).await.unwrap().unwrap().time, 99_999);

    // Load range across segments
    let loaded = storage.load_headers(49_998..50_002).await.unwrap();
    assert_eq!(loaded.len(), 4);
    assert_eq!(loaded[0].time, 49_998);
    assert_eq!(loaded[1].time, 49_999);
    assert_eq!(loaded[2].time, 50_000);
    assert_eq!(loaded[3].time, 50_001);

    // Ensure proper shutdown
    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_segmented_storage_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Store data
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();
        
        // Verify storage starts empty
        assert_eq!(storage.get_tip_height().await.unwrap(), None, "Storage should start empty");

        let headers: Vec<BlockHeader> = (0..75_000).map(create_test_header).collect();
        storage.store_headers(&headers).await.unwrap();

        // Wait for background save
        sleep(Duration::from_millis(500)).await;

        storage.shutdown().await.unwrap();
    }

    // Load data in new instance
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        let actual_tip = storage.get_tip_height().await.unwrap();
        if actual_tip != Some(74_999) {
            println!("Expected tip 74,999 but got {:?}", actual_tip);
            // Try to understand what's stored
            if let Some(tip) = actual_tip {
                if let Ok(Some(header)) = storage.get_header(tip).await {
                    println!("Header at tip {}: time={}", tip, header.time);
                }
            }
        }
        assert_eq!(actual_tip, Some(74_999));

        // Verify data integrity
        assert_eq!(storage.get_header(0).await.unwrap().unwrap().time, 0);
        assert_eq!(storage.get_header(74_999).await.unwrap().unwrap().time, 74_999);

        // Load across segments
        let loaded = storage.load_headers(49_995..50_005).await.unwrap();
        assert_eq!(loaded.len(), 10);
        for (i, header) in loaded.iter().enumerate() {
            assert_eq!(header.time, 49_995 + i as u32);
        }
    }
}

#[tokio::test]
async fn test_reverse_index_with_segments() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store headers across segments
    let headers: Vec<BlockHeader> = (0..100_000).map(create_test_header).collect();
    storage.store_headers(&headers).await.unwrap();

    // Test reverse index lookups
    for height in [0, 25_000, 49_999, 50_000, 50_001, 75_000, 99_999] {
        let header = &headers[height as usize];
        let hash = header.block_hash();
        assert_eq!(storage.get_header_height_by_hash(&hash).await.unwrap(), Some(height));
    }

    // Test non-existent hash
    let fake_hash = create_test_header(u32::MAX).block_hash();
    assert_eq!(storage.get_header_height_by_hash(&fake_hash).await.unwrap(), None);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_filter_header_segments() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store filter headers across segments
    let filter_headers: Vec<FilterHeader> = (0..75_000).map(create_test_filter_header).collect();

    for chunk in filter_headers.chunks(10_000) {
        storage.store_filter_headers(chunk).await.unwrap();
    }

    assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(74_999));

    // Check individual filter headers
    assert_eq!(storage.get_filter_header(0).await.unwrap().unwrap(), create_test_filter_header(0));
    assert_eq!(
        storage.get_filter_header(50_000).await.unwrap().unwrap(),
        create_test_filter_header(50_000)
    );

    // Load range across segments
    let loaded = storage.load_filter_headers(49_998..50_002).await.unwrap();
    assert_eq!(loaded.len(), 4);
    for (i, fh) in loaded.iter().enumerate() {
        assert_eq!(*fh, create_test_filter_header(49_998 + i as u32));
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_access() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Store initial headers
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();
        let headers: Vec<BlockHeader> = (0..100_000).map(create_test_header).collect();
        storage.store_headers(&headers).await.unwrap();
        storage.shutdown().await.unwrap();
    }

    // Test concurrent reads with multiple storage instances
    let mut handles = vec![];

    for i in 0..5 {
        let path = path.clone();
        let handle = tokio::spawn(async move {
            let storage = DiskStorageManager::new(path).await.unwrap();
            let start = i * 20_000;
            let end = start + 10_000;

            // Read headers in this range multiple times
            for _ in 0..10 {
                let loaded = storage.load_headers(start..end).await.unwrap();
                assert_eq!(loaded.len(), 10_000);
                assert_eq!(loaded[0].time, start);
                assert_eq!(loaded[9_999].time, end - 1);
            }
        });
        handles.push(handle);
    }

    // Wait for all readers
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_segment_eviction() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store headers across many segments (more than MAX_ACTIVE_SEGMENTS)
    let headers: Vec<BlockHeader> = (0..600_000).map(create_test_header).collect();

    // Store in chunks
    for chunk in headers.chunks(50_000) {
        storage.store_headers(chunk).await.unwrap();
    }

    // Access different segments to trigger eviction
    for i in 0..12 {
        let height = i * 50_000;
        let header = storage.get_header(height).await.unwrap().unwrap();
        assert_eq!(header.time, height);
    }

    // Verify data is still accessible after eviction
    assert_eq!(storage.get_header(0).await.unwrap().unwrap().time, 0);
    assert_eq!(storage.get_header(599_999).await.unwrap().unwrap().time, 599_999);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_background_save_timing() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Store headers
        let headers: Vec<BlockHeader> = (0..10_000).map(create_test_header).collect();
        storage.store_headers(&headers).await.unwrap();

        // Headers should be in memory but not yet saved to disk
        // (unless 10 seconds have passed, which they shouldn't have)

        // Store more headers to trigger save
        let more_headers: Vec<BlockHeader> = (10_000..20_000).map(create_test_header).collect();
        storage.store_headers(&more_headers).await.unwrap();

        // Wait for background save
        sleep(Duration::from_millis(500)).await;

        storage.shutdown().await.unwrap();
    }

    // Verify data was saved
    {
        let storage = DiskStorageManager::new(path).await.unwrap();
        assert_eq!(storage.get_tip_height().await.unwrap(), Some(19_999));
        assert_eq!(storage.get_header(15_000).await.unwrap().unwrap().time, 15_000);
    }
}

#[tokio::test]
async fn test_clear_storage() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store data
    let headers: Vec<BlockHeader> = (0..10_000).map(create_test_header).collect();
    storage.store_headers(&headers).await.unwrap();

    assert_eq!(storage.get_tip_height().await.unwrap(), Some(9_999));

    // Clear storage
    storage.clear().await.unwrap();

    // Verify everything is cleared
    assert_eq!(storage.get_tip_height().await.unwrap(), None);
    assert_eq!(storage.get_header(0).await.unwrap(), None);
    assert_eq!(storage.get_header_height_by_hash(&headers[0].block_hash()).await.unwrap(), None);
}

#[tokio::test]
async fn test_mixed_operations() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store headers and filter headers
    let headers: Vec<BlockHeader> = (0..75_000).map(create_test_header).collect();
    let filter_headers: Vec<FilterHeader> = (0..75_000).map(create_test_filter_header).collect();

    storage.store_headers(&headers).await.unwrap();
    storage.store_filter_headers(&filter_headers).await.unwrap();

    // Store some filters
    for height in [1000, 5000, 50_000, 70_000] {
        let filter_data = vec![height as u8; 100];
        storage.store_filter(height, &filter_data).await.unwrap();
    }

    // Store metadata
    storage.store_metadata("test_key", b"test_value").await.unwrap();

    // Verify everything
    assert_eq!(storage.get_tip_height().await.unwrap(), Some(74_999));
    assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(74_999));

    assert_eq!(storage.load_filter(1000).await.unwrap().unwrap(), vec![(1000 % 256) as u8; 100]);
    assert_eq!(
        storage.load_filter(50_000).await.unwrap().unwrap(),
        vec![(50_000 % 256) as u8; 100]
    );

    assert_eq!(storage.load_metadata("test_key").await.unwrap().unwrap(), b"test_value");

    // Get stats
    let stats = storage.stats().await.unwrap();
    assert_eq!(stats.header_count, 75_000);
    assert_eq!(stats.filter_header_count, 75_000);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_filter_header_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    // Phase 1: Create storage and save filter headers
    {
        let mut storage = DiskStorageManager::new(storage_path.clone()).await.unwrap();

        // Store filter headers across segments
        let filter_headers: Vec<FilterHeader> =
            (0..75_000).map(create_test_filter_header).collect();

        for chunk in filter_headers.chunks(10_000) {
            storage.store_filter_headers(chunk).await.unwrap();
        }

        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(74_999));

        // Properly shutdown to ensure data is saved
        storage.shutdown().await.unwrap();
    }

    // Phase 2: Create new storage instance and verify filter headers are loaded
    {
        let storage = DiskStorageManager::new(storage_path.clone()).await.unwrap();

        // Check that filter tip height is correctly loaded
        assert_eq!(storage.get_filter_tip_height().await.unwrap(), Some(74_999));

        // Verify we can read filter headers
        assert_eq!(
            storage.get_filter_header(0).await.unwrap().unwrap(),
            create_test_filter_header(0)
        );
        assert_eq!(
            storage.get_filter_header(50_000).await.unwrap().unwrap(),
            create_test_filter_header(50_000)
        );
        assert_eq!(
            storage.get_filter_header(74_999).await.unwrap().unwrap(),
            create_test_filter_header(74_999)
        );

        // Load range across segments
        let loaded = storage.load_filter_headers(49_998..50_002).await.unwrap();
        assert_eq!(loaded.len(), 4);
        assert_eq!(loaded[0], create_test_filter_header(49_998));
        assert_eq!(loaded[3], create_test_filter_header(50_001));
    }
}

#[tokio::test]
async fn test_performance_improvement() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store a large number of headers
    let headers: Vec<BlockHeader> = (0..200_000).map(create_test_header).collect();

    let start = Instant::now();
    for chunk in headers.chunks(10_000) {
        storage.store_headers(chunk).await.unwrap();
    }
    let store_time = start.elapsed();

    println!("Stored 200,000 headers in {:?}", store_time);

    // Test random access performance
    let start = Instant::now();
    for _ in 0..1000 {
        let height = rand::random::<u32>() % 200_000;
        let _ = storage.get_header(height).await.unwrap();
    }
    let access_time = start.elapsed();

    println!("1000 random accesses in {:?}", access_time);
    assert!(access_time < Duration::from_secs(1), "Random access should be fast");

    // Test reverse index performance
    let start = Instant::now();
    for _ in 0..1000 {
        let height = rand::random::<u32>() % 200_000;
        let hash = headers[height as usize].block_hash();
        let _ = storage.get_header_height_by_hash(&hash).await.unwrap();
    }
    let lookup_time = start.elapsed();

    println!("1000 hash lookups in {:?}", lookup_time);
    assert!(lookup_time < Duration::from_secs(1), "Hash lookups should be fast");

    storage.shutdown().await.unwrap();
}
