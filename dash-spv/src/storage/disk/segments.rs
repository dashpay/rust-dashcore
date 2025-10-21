//! Segment management for cached header and filter segments.

use std::collections::HashMap;
use std::time::Instant;

use dashcore::{
    block::{Header as BlockHeader, Version},
    hash_types::FilterHeader,
    pow::CompactTarget,
    BlockHash,
};
use dashcore_hashes::Hash;

use crate::error::StorageResult;

use super::manager::DiskStorageManager;
use super::{HEADERS_PER_SEGMENT, MAX_ACTIVE_SEGMENTS};

/// State of a segment in memory
#[derive(Debug, Clone, PartialEq)]
pub(super) enum SegmentState {
    Clean,  // No changes, up to date on disk
    Dirty,  // Has changes, needs saving
    Saving, // Currently being saved in background
}

/// In-memory cache for a segment of headers
#[derive(Clone)]
pub(super) struct SegmentCache {
    pub(super) segment_id: u32,
    pub(super) headers: Vec<BlockHeader>,
    pub(super) valid_count: usize, // Number of actual valid headers (excluding padding)
    pub(super) state: SegmentState,
    pub(super) last_saved: Instant,
    pub(super) last_accessed: Instant,
}

/// In-memory cache for a segment of filter headers
#[derive(Clone)]
pub(super) struct FilterSegmentCache {
    pub(super) segment_id: u32,
    pub(super) filter_headers: Vec<FilterHeader>,
    pub(super) state: SegmentState,
    pub(super) last_saved: Instant,
    pub(super) last_accessed: Instant,
}

/// Creates a sentinel header used for padding segments.
/// This header has invalid values that cannot be mistaken for valid blocks.
pub(super) fn create_sentinel_header() -> BlockHeader {
    BlockHeader {
        version: Version::from_consensus(i32::MAX), // Invalid version
        prev_blockhash: BlockHash::from_byte_array([0xFF; 32]), // All 0xFF pattern
        merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([0xFF; 32]).into(),
        time: u32::MAX,                                  // Far future timestamp
        bits: CompactTarget::from_consensus(0xFFFFFFFF), // Invalid difficulty
        nonce: u32::MAX,                                 // Max nonce value
    }
}

/// Ensure a segment is loaded in memory.
pub(super) async fn ensure_segment_loaded(
    manager: &DiskStorageManager,
    segment_id: u32,
) -> StorageResult<()> {
    // Process background worker notifications to clear save_pending flags
    manager.process_worker_notifications().await;

    let mut segments = manager.active_segments.write().await;

    if segments.contains_key(&segment_id) {
        // Update last accessed time
        if let Some(segment) = segments.get_mut(&segment_id) {
            segment.last_accessed = Instant::now();
        }
        return Ok(());
    }

    // Load segment from disk
    let segment_path = manager.base_path.join(format!("headers/segment_{:04}.dat", segment_id));
    let mut headers = if segment_path.exists() {
        super::io::load_headers_from_file(&segment_path).await?
    } else {
        Vec::new()
    };

    // Store the actual number of valid headers before padding
    let valid_count = headers.len();

    // Ensure the segment has space for all possible headers in this segment
    // This is crucial for proper indexing
    let expected_size = HEADERS_PER_SEGMENT as usize;
    if headers.len() < expected_size {
        // Pad with sentinel headers that cannot be mistaken for valid blocks
        let sentinel_header = create_sentinel_header();
        headers.resize(expected_size, sentinel_header);
    }

    // Evict old segments if needed
    if segments.len() >= MAX_ACTIVE_SEGMENTS {
        evict_oldest_segment(manager, &mut segments).await?;
    }

    segments.insert(
        segment_id,
        SegmentCache {
            segment_id,
            headers,
            valid_count,
            state: SegmentState::Clean,
            last_saved: Instant::now(),
            last_accessed: Instant::now(),
        },
    );

    Ok(())
}

/// Evict the oldest (least recently accessed) segment.
pub(super) async fn evict_oldest_segment(
    manager: &DiskStorageManager,
    segments: &mut HashMap<u32, SegmentCache>,
) -> StorageResult<()> {
    if let Some(oldest_id) = segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(id, _)| *id)
    {
        // Get the segment to check if it needs saving
        if let Some(oldest_segment) = segments.get(&oldest_id) {
            // Save if dirty or saving before evicting - do it synchronously to ensure data consistency
            if oldest_segment.state != SegmentState::Clean {
                tracing::debug!(
                    "Synchronously saving segment {} before eviction (state: {:?})",
                    oldest_segment.segment_id,
                    oldest_segment.state
                );
                let segment_path = manager
                    .base_path
                    .join(format!("headers/segment_{:04}.dat", oldest_segment.segment_id));
                super::io::save_segment_to_disk(&segment_path, &oldest_segment.headers).await?;
                tracing::debug!("Successfully saved segment {} to disk", oldest_segment.segment_id);
            }
        }

        segments.remove(&oldest_id);
    }

    Ok(())
}

/// Ensure a filter segment is loaded in memory.
pub(super) async fn ensure_filter_segment_loaded(
    manager: &DiskStorageManager,
    segment_id: u32,
) -> StorageResult<()> {
    // Process background worker notifications to clear save_pending flags
    manager.process_worker_notifications().await;

    let mut segments = manager.active_filter_segments.write().await;

    if segments.contains_key(&segment_id) {
        // Update last accessed time
        if let Some(segment) = segments.get_mut(&segment_id) {
            segment.last_accessed = Instant::now();
        }
        return Ok(());
    }

    // Load segment from disk
    let segment_path =
        manager.base_path.join(format!("filters/filter_segment_{:04}.dat", segment_id));
    let filter_headers = if segment_path.exists() {
        super::io::load_filter_headers_from_file(&segment_path).await?
    } else {
        Vec::new()
    };

    // Evict old segments if needed
    if segments.len() >= MAX_ACTIVE_SEGMENTS {
        evict_oldest_filter_segment(manager, &mut segments).await?;
    }

    segments.insert(
        segment_id,
        FilterSegmentCache {
            segment_id,
            filter_headers,
            state: SegmentState::Clean,
            last_saved: Instant::now(),
            last_accessed: Instant::now(),
        },
    );

    Ok(())
}

/// Evict the oldest (least recently accessed) filter segment.
pub(super) async fn evict_oldest_filter_segment(
    manager: &DiskStorageManager,
    segments: &mut HashMap<u32, FilterSegmentCache>,
) -> StorageResult<()> {
    if let Some((oldest_id, oldest_segment)) =
        segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(id, s)| (*id, s.clone()))
    {
        // Save if dirty or saving before evicting - do it synchronously to ensure data consistency
        if oldest_segment.state != SegmentState::Clean {
            tracing::trace!(
                "Synchronously saving filter segment {} before eviction (state: {:?})",
                oldest_segment.segment_id,
                oldest_segment.state
            );
            let segment_path = manager
                .base_path
                .join(format!("filters/filter_segment_{:04}.dat", oldest_segment.segment_id));
            super::io::save_filter_segment_to_disk(&segment_path, &oldest_segment.filter_headers)
                .await?;
            tracing::debug!(
                "Successfully saved filter segment {} to disk",
                oldest_segment.segment_id
            );
        }

        segments.remove(&oldest_id);
    }

    Ok(())
}

/// Save all dirty segments to disk via background worker.
pub(super) async fn save_dirty_segments(manager: &DiskStorageManager) -> StorageResult<()> {
    use super::manager::WorkerCommand;

    if let Some(tx) = &manager.worker_tx {
        // Collect segments to save (only dirty ones)
        let (segments_to_save, segment_ids_to_mark) = {
            let segments = manager.active_segments.read().await;
            let to_save: Vec<_> = segments
                .values()
                .filter(|s| s.state == SegmentState::Dirty)
                .map(|s| (s.segment_id, s.headers.clone()))
                .collect();
            let ids_to_mark: Vec<_> = to_save.iter().map(|(id, _)| *id).collect();
            (to_save, ids_to_mark)
        };

        // Send header segments to worker
        for (segment_id, headers) in segments_to_save {
            let _ = tx
                .send(WorkerCommand::SaveHeaderSegment {
                    segment_id,
                    headers,
                })
                .await;
        }

        // Mark ONLY the header segments we're actually saving as Saving
        {
            let mut segments = manager.active_segments.write().await;
            for segment_id in &segment_ids_to_mark {
                if let Some(segment) = segments.get_mut(segment_id) {
                    segment.state = SegmentState::Saving;
                    segment.last_saved = Instant::now();
                }
            }
        }

        // Collect filter segments to save (only dirty ones)
        let (filter_segments_to_save, filter_segment_ids_to_mark) = {
            let segments = manager.active_filter_segments.read().await;
            let to_save: Vec<_> = segments
                .values()
                .filter(|s| s.state == SegmentState::Dirty)
                .map(|s| (s.segment_id, s.filter_headers.clone()))
                .collect();
            let ids_to_mark: Vec<_> = to_save.iter().map(|(id, _)| *id).collect();
            (to_save, ids_to_mark)
        };

        // Send filter segments to worker
        for (segment_id, filter_headers) in filter_segments_to_save {
            let _ = tx
                .send(WorkerCommand::SaveFilterSegment {
                    segment_id,
                    filter_headers,
                })
                .await;
        }

        // Mark ONLY the filter segments we're actually saving as Saving
        {
            let mut segments = manager.active_filter_segments.write().await;
            for segment_id in &filter_segment_ids_to_mark {
                if let Some(segment) = segments.get_mut(segment_id) {
                    segment.state = SegmentState::Saving;
                    segment.last_saved = Instant::now();
                }
            }
        }

        // Save the index only if it has grown significantly (every 10k new entries)
        let current_index_size = manager.header_hash_index.read().await.len();
        let last_save_count = *manager.last_index_save_count.read().await;

        // Save if index has grown by 10k entries, or if we've never saved before
        if current_index_size >= last_save_count + 10_000 || last_save_count == 0 {
            let index = manager.header_hash_index.read().await.clone();
            let _ = tx
                .send(WorkerCommand::SaveIndex {
                    index,
                })
                .await;

            // Update the last save count
            *manager.last_index_save_count.write().await = current_index_size;
            tracing::debug!(
                "Scheduled index save (size: {}, last_save: {})",
                current_index_size,
                last_save_count
            );
        }
    }

    Ok(())
}
