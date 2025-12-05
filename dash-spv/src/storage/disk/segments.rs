//! Segment management for cached header and filter segments.

use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use dashcore::{
    block::{Header as BlockHeader, Version},
    consensus::Encodable,
    hash_types::FilterHeader,
    pow::CompactTarget,
    BlockHash,
};
use dashcore_hashes::Hash;

use crate::{error::StorageResult, StorageError};

use super::manager::DiskStorageManager;

/// State of a segment in memory
#[derive(Debug, Clone, PartialEq)]
pub(super) enum SegmentState {
    Clean,  // No changes, up to date on disk
    Dirty,  // Has changes, needs saving
    Saving, // Currently being saved in background
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

pub(super) trait SegmentableHeader: Sized {
    fn write_to_disk(&self, writer: &mut BufWriter<File>) -> StorageResult<usize>;
}

/// In-memory cache for a segment of headers
#[derive(Debug, Clone)]
pub(super) struct SegmentCache<H: SegmentableHeader> {
    pub(super) segment_id: u32,
    pub(super) headers: Vec<H>,
    pub(super) valid_count: usize, // Number of actual valid headers (excluding padding)
    pub(super) state: SegmentState,
    pub(super) last_saved: Instant,
    pub(super) last_accessed: Instant,
    disk_path_base: String,
}

impl SegmentableHeader for BlockHeader {
    fn write_to_disk(&self, writer: &mut BufWriter<File>) -> StorageResult<usize> {
        // Skip sentinel headers (used for padding)
        if self.version.to_consensus() == i32::MAX
            && self.time == u32::MAX
            && self.nonce == u32::MAX
            && self.prev_blockhash == BlockHash::from_byte_array([0xFF; 32])
        {
            return Ok(0);
        }

        self.consensus_encode(writer)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to encode header: {}", e)))
    }
}

impl SegmentableHeader for FilterHeader {
    fn write_to_disk(&self, writer: &mut BufWriter<File>) -> StorageResult<usize> {
        self.consensus_encode(writer).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to encode filter header: {}", e))
        })
    }
}

impl SegmentCache<FilterHeader> {
    pub fn new_filter_header_cache(
        segment_id: u32,
        headers: Vec<FilterHeader>,
        valid_count: usize,
    ) -> Self {
        Self::new(segment_id, headers, valid_count, String::from("filters/filter_segment"))
    }
}

impl SegmentCache<BlockHeader> {
    pub fn new_block_header_cache(
        segment_id: u32,
        headers: Vec<BlockHeader>,
        valid_count: usize,
    ) -> Self {
        Self::new(segment_id, headers, valid_count, String::from("headers/segment"))
    }
}

impl<H: SegmentableHeader> SegmentCache<H> {
    fn new(segment_id: u32, headers: Vec<H>, valid_count: usize, disk_path_base: String) -> Self {
        Self {
            segment_id,
            headers,
            valid_count,
            state: SegmentState::Clean,
            last_saved: Instant::now(),
            last_accessed: Instant::now(),
            disk_path_base,
        }
    }

    fn relative_disk_path(&self) -> PathBuf {
        format!("{}_{:04}.dat", self.disk_path_base, self.segment_id).into()
    }

    pub fn save(&self, base_path: &Path) -> StorageResult<()> {
        let path = base_path.join(self.relative_disk_path());
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        let mut writer = BufWriter::new(file);

        for header in self.headers.iter() {
            header.write_to_disk(&mut writer)?;
        }

        writer.flush()?;
        Ok(())
    }

    pub fn evict(&self, base_path: &Path) -> StorageResult<()> {
        // Save if dirty or saving before evicting - do it synchronously to ensure data consistency
        if self.state != SegmentState::Clean {
            return Ok(());
        }

        tracing::trace!(
            "Synchronously saving segment {} before eviction (state: {:?})",
            self.segment_id,
            self.state
        );

        self.save(base_path)?;

        tracing::debug!("Successfully saved segment cache {} to disk", self.segment_id);

        Ok(())
    }
}

// TODO: cleanup needed
/// Save all dirty segments to disk via background worker.
pub(super) async fn save_dirty_segments(manager: &DiskStorageManager) -> StorageResult<()> {
    use super::manager::WorkerCommand;

    if let Some(tx) = &manager.worker_tx {
        // Collect segments to save (only dirty ones)
        let (segments_cache_to_save, segment_ids_to_mark) = {
            let segments = manager.active_segments.read().await;
            let to_save: Vec<_> =
                segments.values().filter(|s| s.state == SegmentState::Dirty).cloned().collect();
            let ids_to_mark: Vec<_> = to_save.iter().map(|cache| cache.segment_id).collect();
            (to_save, ids_to_mark)
        };

        // Send header segments to worker
        for cache in segments_cache_to_save {
            let _ = tx.send(WorkerCommand::SaveBlockHeaderSegmentCache(cache)).await;
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
            let to_save: Vec<_> =
                segments.values().filter(|s| s.state == SegmentState::Dirty).cloned().collect();
            let ids_to_mark: Vec<_> = to_save.iter().map(|cache| cache.segment_id).collect();
            (to_save, ids_to_mark)
        };

        // Send filter segments to worker
        for cache in filter_segments_to_save {
            let _ = tx.send(WorkerCommand::SaveFilterHeaderSegmentCache(cache.clone())).await;
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
