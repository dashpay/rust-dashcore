//! Tests for segmented compact block filter storage.
//!
//! These tests verify the segmented storage implementation for BIP-158 compact block filters.
//! Filters are variable-length (100 bytes to ~5KB typical) and stored using index+data files.

use dash_spv::storage::{DiskStorageManager, FILTERS_PER_SEGMENT};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

/// Create test filter data for a given height.
/// Uses height to create unique, recognizable filter data.
fn create_test_filter(height: u32) -> Vec<u8> {
    // Create variable-length filter data based on height
    // Simulates real BIP-158 filters which vary in size
    let length = 100 + (height % 500) as usize; // 100-599 bytes
    let mut data = Vec::with_capacity(length);

    // Store height in first 4 bytes for verification
    data.extend_from_slice(&height.to_le_bytes());

    // Fill rest with predictable pattern
    for i in 4..length {
        data.push(((height + i as u32) % 256) as u8);
    }
    data
}

#[tokio::test]
async fn test_store_single_filter() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    let filter = create_test_filter(42);
    storage.store_filter(42, &filter).await.unwrap();

    let loaded = storage.load_filter(42).await.unwrap();
    assert_eq!(loaded, Some(filter));

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_store_multiple_filters_same_segment() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store 10 filters in the same segment (segment 0: heights 0-49999)
    let heights = [0, 10, 100, 1000, 5000, 10000, 25000, 40000, 49000, 49999];

    for &height in &heights {
        let filter = create_test_filter(height);
        storage.store_filter(height, &filter).await.unwrap();
    }

    // Verify all filters
    for &height in &heights {
        let expected = create_test_filter(height);
        let loaded = storage.load_filter(height).await.unwrap();
        assert_eq!(loaded, Some(expected), "Filter at height {} mismatch", height);
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_store_filters_across_segments() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store filters across segment boundary (50000 filters per segment)
    let heights = [49998, 49999, 50000, 50001, 100000, 100001];

    for &height in &heights {
        let filter = create_test_filter(height);
        storage.store_filter(height, &filter).await.unwrap();
    }

    // Verify all filters
    for &height in &heights {
        let expected = create_test_filter(height);
        let loaded = storage.load_filter(height).await.unwrap();
        assert_eq!(loaded, Some(expected), "Filter at height {} mismatch", height);
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_load_nonexistent_filter() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Load filter that was never stored
    let loaded = storage.load_filter(12345).await.unwrap();
    assert_eq!(loaded, None);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_filter_segment_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    let heights = [100, 1000, 50000, 50001];

    // Store filters
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for &height in &heights {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        // Wait for background save
        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Load in new instance
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        for &height in &heights {
            let expected = create_test_filter(height);
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(loaded, Some(expected), "Filter at height {} not persisted", height);
        }
    }
}

#[tokio::test]
async fn test_filter_with_varying_sizes() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Test filters of different sizes (simulating real BIP-158 filter variance)
    let test_cases = [
        (0, vec![0u8; 50]),   // Very small filter
        (1, vec![1u8; 200]),  // Typical small filter
        (2, vec![2u8; 500]),  // Medium filter
        (3, vec![3u8; 2000]), // Large filter
        (4, vec![4u8; 5000]), // Very large filter
    ];

    for (height, filter) in &test_cases {
        storage.store_filter(*height, filter).await.unwrap();
    }

    for (height, expected) in &test_cases {
        let loaded = storage.load_filter(*height).await.unwrap();
        assert_eq!(loaded.as_ref(), Some(expected), "Filter at height {} size mismatch", height);
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_clear_filters_clears_data() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store some filters
    for height in [100, 1000, 50000] {
        let filter = create_test_filter(height);
        storage.store_filter(height, &filter).await.unwrap();
    }

    // Verify they exist
    assert!(storage.load_filter(100).await.unwrap().is_some());

    // Clear filters
    storage.clear_filters().await.unwrap();

    // Verify they're gone
    assert_eq!(storage.load_filter(100).await.unwrap(), None);
    assert_eq!(storage.load_filter(1000).await.unwrap(), None);
    assert_eq!(storage.load_filter(50000).await.unwrap(), None);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_store_filter_at_height_zero() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    let filter = vec![0xDE, 0xAD, 0xBE, 0xEF];
    storage.store_filter(0, &filter).await.unwrap();

    let loaded = storage.load_filter(0).await.unwrap();
    assert_eq!(loaded, Some(filter));

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_overwrite_existing_filter() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    let filter_v1 = vec![1, 2, 3, 4];
    let filter_v2 = vec![5, 6, 7, 8, 9, 10];

    storage.store_filter(100, &filter_v1).await.unwrap();
    assert_eq!(storage.load_filter(100).await.unwrap(), Some(filter_v1));

    storage.store_filter(100, &filter_v2).await.unwrap();
    assert_eq!(storage.load_filter(100).await.unwrap(), Some(filter_v2));

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_empty_filter() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    let empty_filter: Vec<u8> = vec![];
    storage.store_filter(42, &empty_filter).await.unwrap();

    // Empty filter stored with length 0 should return None (not found)
    // because the index entry has length=0 which is treated as "no filter"
    let loaded = storage.load_filter(42).await.unwrap();
    assert_eq!(loaded, None);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_sequential_filters() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store 100 sequential filters (common real-world pattern)
    for height in 0..100 {
        let filter = create_test_filter(height);
        storage.store_filter(height, &filter).await.unwrap();
    }

    // Verify all
    for height in 0..100 {
        let expected = create_test_filter(height);
        let loaded = storage.load_filter(height).await.unwrap();
        assert_eq!(loaded, Some(expected), "Filter at height {} mismatch", height);
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_segment_eviction() {
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store filters across many segments to trigger eviction
    // MAX_ACTIVE_FILTER_DATA_SEGMENTS is 5, so storing in 7 segments should trigger eviction
    let heights = [0, 50000, 100000, 150000, 200000, 250000, 300000];

    for &height in &heights {
        let filter = create_test_filter(height);
        storage.store_filter(height, &filter).await.unwrap();
    }

    // Wait for background save
    sleep(Duration::from_millis(500)).await;

    // All filters should still be loadable (from disk if evicted)
    for &height in &heights {
        let expected = create_test_filter(height);
        let loaded = storage.load_filter(height).await.unwrap();
        assert_eq!(loaded, Some(expected), "Filter at height {} not found after eviction", height);
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_load_from_disk_after_restart() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Store and persist filters
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for height in [0, 1000, 2000] {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Fresh storage instance - segments not in memory
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        // These should load from disk (.idx + .dat files)
        for height in [0, 1000, 2000] {
            let expected = create_test_filter(height);
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(loaded, Some(expected), "Filter at height {} not loaded from disk", height);
        }
    }
}

#[tokio::test]
async fn test_segment_file_format_on_disk() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        storage.store_filter(0, &[1, 2, 3]).await.unwrap();
        storage.store_filter(1, &[4, 5, 6, 7, 8]).await.unwrap();

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify combined segment file exists and has correct magic bytes
    let segment_path = path.join("filters/filter_data_segment_0000.dat");
    assert!(segment_path.exists(), "Segment file should exist");

    let segment_data = std::fs::read(&segment_path).unwrap();
    assert!(segment_data.len() >= 12, "Segment file too small");

    // Check magic bytes: "FDSF" (Filter Data Segment Format)
    assert_eq!(&segment_data[0..4], b"FDSF", "Invalid magic bytes");

    // Check version
    let version = u16::from_le_bytes([segment_data[4], segment_data[5]]);
    assert_eq!(version, 1, "Invalid version");

    // Check entry count
    let count = u16::from_le_bytes([segment_data[6], segment_data[7]]);
    assert!(count >= 2, "Should have at least 2 entries");

    // Check data offset
    let data_offset =
        u32::from_le_bytes([segment_data[8], segment_data[9], segment_data[10], segment_data[11]]);
    assert!(data_offset > 12, "Data offset should be after header");
}

#[tokio::test]
async fn test_load_from_reloaded_segment_after_eviction() {
    // This tests the "filter in index but not in memory cache" code path.
    // Scenario:
    // 1. Store filter in segment 0
    // 2. Evict segment 0 by filling other segments
    // 3. Store NEW filter in segment 0 (reloads segment from disk, index loaded but filters empty)
    // 4. Load ORIGINAL filter (should load from disk via index)

    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store original filter at height 1000 (segment 0)
    let original_filter = vec![0xAA; 100];
    storage.store_filter(1000, &original_filter).await.unwrap();

    // Force save so data is on disk
    sleep(Duration::from_millis(500)).await;

    // Fill segments 1-5 to evict segment 0 (MAX_ACTIVE_FILTER_DATA_SEGMENTS is 5)
    for seg in 1..=5 {
        let height = seg * 50000;
        storage.store_filter(height, &create_test_filter(height)).await.unwrap();
    }

    // Store NEW filter in segment 0 - this reloads segment from disk
    let new_filter = vec![0xBB; 50];
    storage.store_filter(2000, &new_filter).await.unwrap();

    // Load original filter - segment is in memory but original filter not in cache
    let loaded = storage.load_filter(1000).await.unwrap();
    assert_eq!(loaded, Some(original_filter), "Original filter should load from disk via index");

    // Also verify new filter works
    let loaded_new = storage.load_filter(2000).await.unwrap();
    assert_eq!(loaded_new, Some(new_filter));

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_load_nonexistent_filter_from_loaded_segment() {
    // Tests loading a filter that doesn't exist from a segment that IS loaded
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store filter at height 100 to load segment 0
    storage.store_filter(100, &[1, 2, 3]).await.unwrap();

    // Try to load filter at height 200 (same segment, never stored)
    let loaded = storage.load_filter(200).await.unwrap();
    assert_eq!(loaded, None);

    // Try to load filter at height 50000 (different segment, never loaded)
    let loaded2 = storage.load_filter(50000).await.unwrap();
    assert_eq!(loaded2, None);

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_startup_loads_filter_data_tip() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Store filters and verify tip is tracked
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Store filters at various heights
        storage.store_filter(0, &[1, 2, 3]).await.unwrap();
        storage.store_filter(100, &[4, 5, 6]).await.unwrap();
        storage.store_filter(500, &[7, 8, 9]).await.unwrap();

        // Verify tip is tracked during storage
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(500), "Tip should be 500 after storing");

        // Wait for background save and shutdown
        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Restart and verify tip is restored from disk
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(500), "Tip should be restored to 500 after restart");
    }
}

#[tokio::test]
async fn test_sparse_index_persistence() {
    // Tests that sparse index (gaps in heights) persists correctly
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    let heights = [10, 100, 500, 1000, 5000];

    // Store sparse filters
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for &height in &heights {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify all sparse entries are loadable after restart
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        for &height in &heights {
            let expected = create_test_filter(height);
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(loaded, Some(expected), "Sparse filter at {} should load", height);
        }

        // Verify gaps return None
        assert_eq!(storage.load_filter(50).await.unwrap(), None);
        assert_eq!(storage.load_filter(200).await.unwrap(), None);
    }
}

#[tokio::test]
async fn test_reconstruct_filter_data_on_eviction() {
    // This test verifies reconstruct_filter_data works by forcing eviction
    // of a dirty segment and then loading the data back
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store filters with specific patterns to verify reconstruction
    let test_data: Vec<(u32, Vec<u8>)> =
        vec![(0, vec![0xAA; 100]), (1, vec![0xBB; 200]), (2, vec![0xCC; 150])];

    for (height, filter) in &test_data {
        storage.store_filter(*height, filter).await.unwrap();
    }

    // Force eviction by filling other segments (MAX_ACTIVE_FILTER_DATA_SEGMENTS is 5)
    for seg in 1..=5 {
        let height = seg * 50000;
        storage.store_filter(height, &[seg as u8; 50]).await.unwrap();
    }

    // Wait for any background saves
    sleep(Duration::from_millis(500)).await;

    // Now access segment 0 again - it was evicted, so data must be reconstructed/loaded from disk
    // First store a new filter to trigger segment reload
    storage.store_filter(3, &[0xDD; 75]).await.unwrap();

    // Verify original filters are still accessible (loaded from disk via reconstructed data)
    for (height, expected) in &test_data {
        let loaded = storage.load_filter(*height).await.unwrap();
        assert_eq!(loaded.as_ref(), Some(expected), "Filter at {} after eviction", height);
    }

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_multi_segment_with_multiple_filters_per_segment() {
    // Tests storing multiple filters in multiple segments and loading them back
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Define filters across 3 segments (0, 1, 2) with multiple filters each
    // Segment 0: heights 0-49999, Segment 1: 50000-99999, Segment 2: 100000-149999
    let test_filters: Vec<(u32, Vec<u8>)> = vec![
        // Segment 0
        (0, vec![0x00; 100]),
        (100, vec![0x01; 150]),
        (1000, vec![0x02; 200]),
        (49999, vec![0x03; 250]),
        // Segment 1
        (50000, vec![0x10; 120]),
        (50500, vec![0x11; 180]),
        (75000, vec![0x12; 220]),
        (99999, vec![0x13; 280]),
        // Segment 2
        (100000, vec![0x20; 130]),
        (125000, vec![0x21; 190]),
        (149999, vec![0x22; 240]),
    ];

    // Store all filters
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for (height, filter) in &test_filters {
            storage.store_filter(*height, filter).await.unwrap();
        }

        // Verify all are immediately accessible
        for (height, expected) in &test_filters {
            let loaded = storage.load_filter(*height).await.unwrap();
            assert_eq!(loaded.as_ref(), Some(expected), "Filter {} not found before save", height);
        }

        // Wait for background save
        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify all combined segment files exist
    for seg in 0..3 {
        let seg_path = path.join(format!("filters/filter_data_segment_{:04}.dat", seg));
        assert!(seg_path.exists(), "Segment {} file missing", seg);
    }

    // Load from fresh instance and verify all filters
    {
        let storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Verify tip height is the max height stored
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(149999), "Tip should be highest stored height");

        // Verify all filters load correctly from disk
        for (height, expected) in &test_filters {
            let loaded = storage.load_filter(*height).await.unwrap();
            assert_eq!(
                loaded.as_ref(),
                Some(expected),
                "Filter {} not found after restart",
                height
            );
        }

        // Verify gaps return None
        assert_eq!(storage.load_filter(500).await.unwrap(), None);
        assert_eq!(storage.load_filter(60000).await.unwrap(), None);
        assert_eq!(storage.load_filter(110000).await.unwrap(), None);
    }
}

#[tokio::test]
async fn test_multi_segment_sequential_then_random_access() {
    // Tests sequential storage followed by random access pattern across segments
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Store sequential filters across segment boundary
    let heights: Vec<u32> = (49990..50010).collect(); // 20 filters spanning segments 0 and 1

    for height in &heights {
        let filter = create_test_filter(*height);
        storage.store_filter(*height, &filter).await.unwrap();
    }

    // Random access pattern - jump between segments
    let access_order = [50005, 49995, 50000, 49999, 50009, 49990];
    for &height in &access_order {
        let expected = create_test_filter(height);
        let loaded = storage.load_filter(height).await.unwrap();
        assert_eq!(loaded, Some(expected), "Random access to {} failed", height);
    }

    storage.shutdown().await.unwrap();
}

// =============================================================================
// Crash Resilience Tests
// =============================================================================

#[tokio::test]
async fn test_no_temp_files_after_save() {
    // Verifies atomic writes don't leave temp files behind
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Store several filters to trigger saves
        for height in [0, 100, 1000, 5000] {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        // Wait for background save
        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Check no .tmp files exist in filters directory
    let filters_dir = path.join("filters");
    if filters_dir.exists() {
        for entry in std::fs::read_dir(&filters_dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            assert!(
                !name_str.ends_with(".tmp"),
                "Temp file {} should not exist after shutdown",
                name_str
            );
            assert!(
                !name_str.starts_with("."),
                "Hidden temp file {} should not exist after shutdown",
                name_str
            );
        }
    }
}

#[tokio::test]
async fn test_atomic_write_data_integrity() {
    // Verifies data written with atomic writes is readable and correct
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    let test_filters: Vec<(u32, Vec<u8>)> = vec![
        (0, vec![0xDE, 0xAD, 0xBE, 0xEF]),
        (1, (0..255).collect()),
        (2, vec![0xFF; 1000]),
        (3, vec![0x00; 500]),
    ];

    // Store and shutdown
    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for (height, filter) in &test_filters {
            storage.store_filter(*height, filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Reload and verify byte-by-byte
    {
        let storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for (height, expected) in &test_filters {
            let loaded = storage.load_filter(*height).await.unwrap();
            assert!(loaded.is_some(), "Filter {} should exist", height);
            let loaded = loaded.unwrap();
            assert_eq!(loaded.len(), expected.len(), "Filter {} length mismatch", height);
            assert_eq!(&loaded, expected, "Filter {} data mismatch", height);
        }
    }
}

#[tokio::test]
async fn test_file_not_corrupted_after_multiple_overwrites() {
    // Verifies that multiple overwrites using atomic writes don't corrupt data
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Overwrite the same filter multiple times
        for i in 0..10 {
            let filter = vec![i as u8; 100 + i * 10];
            storage.store_filter(0, &filter).await.unwrap();
            sleep(Duration::from_millis(100)).await;
        }

        // Final value should be the last one
        let final_filter = vec![9u8; 190];
        let loaded = storage.load_filter(0).await.unwrap();
        assert_eq!(loaded, Some(final_filter.clone()));

        storage.shutdown().await.unwrap();
    }

    // Verify after restart
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        let final_filter = vec![9u8; 190];
        let loaded = storage.load_filter(0).await.unwrap();
        assert_eq!(loaded, Some(final_filter));
    }
}

#[tokio::test]
async fn test_concurrent_segment_saves() {
    // Verifies that concurrent saves to different segments work correctly
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Rapidly store filters across multiple segments
        let heights = [
            0, 50000, 100000, 150000, 200000, // Different segments
            1, 50001, 100001, 150001, 200001, // Same segments, different offsets
        ];

        for &height in &heights {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify all filters
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        let heights = [0, 50000, 100000, 150000, 200000, 1, 50001, 100001, 150001, 200001];

        for &height in &heights {
            let expected = create_test_filter(height);
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(
                loaded,
                Some(expected),
                "Filter {} corrupted after concurrent saves",
                height
            );
        }
    }
}

#[tokio::test]
async fn test_full_segment_with_sparse_filters() {
    // Tests storing filters across the full range of a segment (0 to FILTERS_PER_SEGMENT-1)
    // Uses sparse storage to avoid excessive test time while still testing segment boundaries

    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    let test_heights: Vec<u32> = vec![
        0,                         // Start of segment
        1,                         // Second position
        100,                       // Early in segment
        1000,                      // Mid-early
        FILTERS_PER_SEGMENT / 2,   // Middle
        FILTERS_PER_SEGMENT - 100, // Near end
        FILTERS_PER_SEGMENT - 2,   // Second to last
        FILTERS_PER_SEGMENT - 1,   // Last position in segment
    ];

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Store filters at sparse positions across the segment
        for &height in &test_heights {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify all stored filters persist correctly
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        for &height in &test_heights {
            let expected = create_test_filter(height);
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(
                loaded,
                Some(expected),
                "Filter at height {} not found or incorrect after restart",
                height
            );
        }

        // Verify non-stored positions return None
        let non_stored = storage.load_filter(500).await.unwrap();
        assert_eq!(non_stored, None, "Non-stored filter should return None");
    }
}

#[tokio::test]
async fn test_multiple_full_segments() {
    // Tests multiple segments, each with filters at boundary positions

    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Heights that span 3 full segments
    let test_heights: Vec<u32> = vec![
        // Segment 0
        0,
        FILTERS_PER_SEGMENT - 1,
        // Segment 1
        FILTERS_PER_SEGMENT,
        FILTERS_PER_SEGMENT + FILTERS_PER_SEGMENT / 2,
        2 * FILTERS_PER_SEGMENT - 1,
        // Segment 2
        2 * FILTERS_PER_SEGMENT,
        2 * FILTERS_PER_SEGMENT + 100,
        3 * FILTERS_PER_SEGMENT - 1,
    ];

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for &height in &test_heights {
            let filter = create_test_filter(height);
            storage.store_filter(height, &filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify after restart
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        for &height in &test_heights {
            let expected = create_test_filter(height);
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(
                loaded,
                Some(expected),
                "Filter at height {} in multi-segment test not found",
                height
            );
        }
    }
}

#[tokio::test]
async fn test_file_format_detailed_validation() {
    // Validates every field of the file format in detail
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Store filters with known sizes for precise validation
    let filter1 = vec![0xAA; 150]; // 150 bytes at height 0
    let filter2 = vec![0xBB; 200]; // 200 bytes at height 5
    let filter3 = vec![0xCC; 100]; // 100 bytes at height 10

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        storage.store_filter(0, &filter1).await.unwrap();
        storage.store_filter(5, &filter2).await.unwrap();
        storage.store_filter(10, &filter3).await.unwrap();

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Read and validate raw file structure
    let segment_path = path.join("filters/filter_data_segment_0000.dat");
    let segment_data = std::fs::read(&segment_path).unwrap();

    // Header validation (12 bytes)
    // Magic: "FDSF" (0x46, 0x44, 0x53, 0x46)
    assert_eq!(segment_data[0], 0x46, "Magic byte 0 should be 'F'");
    assert_eq!(segment_data[1], 0x44, "Magic byte 1 should be 'D'");
    assert_eq!(segment_data[2], 0x53, "Magic byte 2 should be 'S'");
    assert_eq!(segment_data[3], 0x46, "Magic byte 3 should be 'F'");

    // Version: 1 (little-endian u16)
    let version = u16::from_le_bytes([segment_data[4], segment_data[5]]);
    assert_eq!(version, 1, "Version should be 1");

    // Count: should be 11 (indices 0-10 inclusive, even if some are empty)
    let count = u16::from_le_bytes([segment_data[6], segment_data[7]]);
    assert_eq!(count, 11, "Count should be 11 (highest index + 1)");

    // Data offset: header (12) + index entries (11 * 12 = 132) = 144
    let data_offset =
        u32::from_le_bytes([segment_data[8], segment_data[9], segment_data[10], segment_data[11]]);
    assert_eq!(data_offset, 144, "Data offset should be 144 bytes");

    // Validate index entries (12 bytes each: offset u64 + length u32)
    let index_start = 12;

    // Entry 0: filter1 at offset 0, length 150
    let entry0_offset = u64::from_le_bytes([
        segment_data[index_start],
        segment_data[index_start + 1],
        segment_data[index_start + 2],
        segment_data[index_start + 3],
        segment_data[index_start + 4],
        segment_data[index_start + 5],
        segment_data[index_start + 6],
        segment_data[index_start + 7],
    ]);
    let entry0_length = u32::from_le_bytes([
        segment_data[index_start + 8],
        segment_data[index_start + 9],
        segment_data[index_start + 10],
        segment_data[index_start + 11],
    ]);
    // Offsets in file are ABSOLUTE (relative to file start, not data section)
    // data_offset = 144, so first filter is at absolute offset 144
    assert_eq!(entry0_offset, 144, "Entry 0 absolute offset should be 144 (data_offset + 0)");
    assert_eq!(entry0_length, 150, "Entry 0 length should be 150");

    // Entry 5: filter2 at absolute offset 294 (144 + 150), length 200
    let entry5_start = index_start + 5 * 12;
    let entry5_offset = u64::from_le_bytes([
        segment_data[entry5_start],
        segment_data[entry5_start + 1],
        segment_data[entry5_start + 2],
        segment_data[entry5_start + 3],
        segment_data[entry5_start + 4],
        segment_data[entry5_start + 5],
        segment_data[entry5_start + 6],
        segment_data[entry5_start + 7],
    ]);
    let entry5_length = u32::from_le_bytes([
        segment_data[entry5_start + 8],
        segment_data[entry5_start + 9],
        segment_data[entry5_start + 10],
        segment_data[entry5_start + 11],
    ]);
    assert_eq!(entry5_offset, 294, "Entry 5 absolute offset should be 294 (144 + 150)");
    assert_eq!(entry5_length, 200, "Entry 5 length should be 200");

    // Entry 10: filter3 at absolute offset 494 (144 + 150 + 200), length 100
    let entry10_start = index_start + 10 * 12;
    let entry10_offset = u64::from_le_bytes([
        segment_data[entry10_start],
        segment_data[entry10_start + 1],
        segment_data[entry10_start + 2],
        segment_data[entry10_start + 3],
        segment_data[entry10_start + 4],
        segment_data[entry10_start + 5],
        segment_data[entry10_start + 6],
        segment_data[entry10_start + 7],
    ]);
    let entry10_length = u32::from_le_bytes([
        segment_data[entry10_start + 8],
        segment_data[entry10_start + 9],
        segment_data[entry10_start + 10],
        segment_data[entry10_start + 11],
    ]);
    assert_eq!(entry10_offset, 494, "Entry 10 absolute offset should be 494 (144 + 350)");
    assert_eq!(entry10_length, 100, "Entry 10 length should be 100");

    // Verify empty entries have length 0
    for empty_idx in [1, 2, 3, 4, 6, 7, 8, 9] {
        let empty_start = index_start + empty_idx * 12;
        let empty_length = u32::from_le_bytes([
            segment_data[empty_start + 8],
            segment_data[empty_start + 9],
            segment_data[empty_start + 10],
            segment_data[empty_start + 11],
        ]);
        assert_eq!(empty_length, 0, "Empty entry {} should have length 0", empty_idx);
    }

    // Validate data section content
    let data_start = data_offset as usize;

    // Filter 1 data at offset 0
    assert_eq!(&segment_data[data_start..data_start + 150], &filter1[..], "Filter 1 data mismatch");

    // Filter 2 data at offset 150
    assert_eq!(
        &segment_data[data_start + 150..data_start + 350],
        &filter2[..],
        "Filter 2 data mismatch"
    );

    // Filter 3 data at offset 350
    assert_eq!(
        &segment_data[data_start + 350..data_start + 450],
        &filter3[..],
        "Filter 3 data mismatch"
    );

    // Verify total file size
    let expected_size = 12 + (11 * 12) + 150 + 200 + 100; // header + index + data
    assert_eq!(segment_data.len(), expected_size, "Total file size mismatch");
}

#[tokio::test]
async fn test_large_filter_storage() {
    // Test storing and loading large filters (1MB+)
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // Create 1MB filter
    let large_filter: Vec<u8> = (0..1_000_000u32).map(|i| (i % 256) as u8).collect();

    storage.store_filter(0, &large_filter).await.unwrap();

    // Verify it can be loaded correctly
    let loaded = storage.load_filter(0).await.unwrap();
    assert_eq!(loaded.as_ref().map(|v| v.len()), Some(1_000_000), "Large filter size mismatch");
    assert_eq!(loaded, Some(large_filter), "Large filter content mismatch");

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_filter_data_integrity_after_many_writes() {
    // Test that repeated writes to same positions maintain data integrity
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    let heights = [0, 100, 500, 1000];
    let mut final_filters: std::collections::HashMap<u32, Vec<u8>> =
        std::collections::HashMap::new();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Write multiple times to same heights
        for round in 0..5usize {
            for &height in &heights {
                let filter = vec![(round * 10 + height as usize % 10) as u8; 100 + round * 50];
                storage.store_filter(height, &filter).await.unwrap();
                final_filters.insert(height, filter);
            }
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify only final values are present
    {
        let storage = DiskStorageManager::new(path).await.unwrap();

        for (&height, expected) in &final_filters {
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(
                loaded.as_ref(),
                Some(expected),
                "Filter at height {} should contain final write value",
                height
            );
        }
    }
}

#[tokio::test]
async fn test_index_gaps_handling() {
    // Test that gaps in filter heights are handled correctly
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Store filters with large gaps
    let heights_with_filters = [0, 1000, 5000, 10000, 49999];
    let mut filters: std::collections::HashMap<u32, Vec<u8>> = std::collections::HashMap::new();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        for &height in &heights_with_filters {
            let filter = create_test_filter(height);
            filters.insert(height, filter.clone());
            storage.store_filter(height, &filter).await.unwrap();
        }

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify segment file structure
    let segment_path = path.join("filters/filter_data_segment_0000.dat");
    let segment_data = std::fs::read(&segment_path).unwrap();

    // Count should be 50000 (highest index + 1)
    let count = u16::from_le_bytes([segment_data[6], segment_data[7]]);
    assert_eq!(count, 50000, "Count should cover highest index");

    // Verify reload works correctly
    {
        let storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Stored filters should load correctly
        for (&height, expected) in &filters {
            let loaded = storage.load_filter(height).await.unwrap();
            assert_eq!(loaded, Some(expected.clone()), "Stored filter at {} missing", height);
        }

        // Non-stored heights should return None
        for gap_height in [1, 500, 999, 2000, 7500, 20000] {
            let loaded = storage.load_filter(gap_height).await.unwrap();
            assert_eq!(loaded, None, "Gap at height {} should return None", gap_height);
        }
    }
}

#[tokio::test]
async fn test_filter_boundary_values() {
    // Test filters with boundary/edge values
    let temp_dir = TempDir::new().unwrap();
    let mut storage = DiskStorageManager::new(temp_dir.path().to_path_buf()).await.unwrap();

    // All zeros filter
    let zeros = vec![0u8; 100];
    storage.store_filter(0, &zeros).await.unwrap();

    // All ones filter
    let ones = vec![0xFF; 100];
    storage.store_filter(1, &ones).await.unwrap();

    // Alternating pattern
    let alternating: Vec<u8> = (0..100)
        .map(|i| {
            if i % 2 == 0 {
                0x55
            } else {
                0xAA
            }
        })
        .collect();
    storage.store_filter(2, &alternating).await.unwrap();

    // Single byte
    let single = vec![0x42];
    storage.store_filter(3, &single).await.unwrap();

    // Verify all load correctly
    assert_eq!(storage.load_filter(0).await.unwrap(), Some(zeros));
    assert_eq!(storage.load_filter(1).await.unwrap(), Some(ones));
    assert_eq!(storage.load_filter(2).await.unwrap(), Some(alternating));
    assert_eq!(storage.load_filter(3).await.unwrap(), Some(single));

    storage.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_segment_tip_height_tracking() {
    // Test that filter data tip height is tracked correctly
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();

        // Initial tip should be None
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, None, "Initial tip should be None");

        // Store at height 100
        storage.store_filter(100, &[1, 2, 3]).await.unwrap();
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(100), "Tip should be 100 after first store");

        // Store at lower height - tip should NOT change
        storage.store_filter(50, &[4, 5, 6]).await.unwrap();
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(100), "Tip should remain 100 after storing at lower height");

        // Store at higher height - tip should update
        storage.store_filter(200, &[7, 8, 9]).await.unwrap();
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(200), "Tip should be 200 after storing higher");

        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Verify tip persists after restart
    {
        let storage = DiskStorageManager::new(path).await.unwrap();
        let tip = storage.get_filter_data_tip_height().await.unwrap();
        assert_eq!(tip, Some(200), "Tip should persist as 200 after restart");
    }
}

#[tokio::test]
async fn test_concurrent_reads_single_segment() {
    // Test concurrent read access to same segment
    use std::sync::Arc;

    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().to_path_buf();

    // Pre-populate segment
    let filters: Vec<(u32, Vec<u8>)> = (0..100).map(|h| (h, create_test_filter(h))).collect();

    {
        let mut storage = DiskStorageManager::new(path.clone()).await.unwrap();
        for (height, filter) in &filters {
            storage.store_filter(*height, filter).await.unwrap();
        }
        sleep(Duration::from_millis(500)).await;
        storage.shutdown().await.unwrap();
    }

    // Concurrent reads
    let storage = Arc::new(DiskStorageManager::new(path).await.unwrap());

    let mut handles = vec![];
    for _ in 0..10 {
        let storage_clone = Arc::clone(&storage);
        let filters_clone = filters.clone();
        let handle = tokio::spawn(async move {
            for (height, expected) in filters_clone {
                let loaded = storage_clone.load_filter(height).await.unwrap();
                assert_eq!(loaded, Some(expected), "Concurrent read failed at height {}", height);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
