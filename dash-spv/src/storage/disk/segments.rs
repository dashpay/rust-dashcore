//! Segment management for cached header and filter segments.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use dashcore::{
    block::{Header as BlockHeader, Version},
    consensus::{encode, Decodable, Encodable},
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

pub(super) trait Persistable: Sized + Encodable + Decodable {
    fn persist(&self, writer: &mut BufWriter<File>) -> StorageResult<usize>;
    fn relative_disk_path(segment_id: u32) -> PathBuf;
}

/// In-memory cache for a segment of headers
#[derive(Debug, Clone)]
pub(super) struct SegmentCache<H: Persistable> {
    pub(super) segment_id: u32,
    pub(super) headers: Vec<H>,
    pub(super) valid_count: usize, // Number of actual valid headers (excluding padding)
    pub(super) state: SegmentState,
    pub(super) last_saved: Instant,
    pub(super) last_accessed: Instant,
}

impl Persistable for BlockHeader {
    fn persist(&self, writer: &mut BufWriter<File>) -> StorageResult<usize> {
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

    fn relative_disk_path(segment_id: u32) -> PathBuf {
        format!("headers/segment_{:04}.dat", segment_id).into()
    }
}

impl Persistable for FilterHeader {
    fn persist(&self, writer: &mut BufWriter<File>) -> StorageResult<usize> {
        self.consensus_encode(writer).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to encode filter header: {}", e))
        })
    }

    fn relative_disk_path(segment_id: u32) -> PathBuf {
        format!("filters/filter_segment_{:04}.dat", segment_id).into()
    }
}

impl SegmentCache<FilterHeader> {
    pub async fn load_filter_header_cache(
        base_path: &Path,
        segment_id: u32,
    ) -> StorageResult<Self> {
        // Load segment from disk
        let segment_path = base_path.join(FilterHeader::relative_disk_path(segment_id));

        let headers = if segment_path.exists() {
            load_header_segments(&segment_path)?
        } else {
            Vec::new()
        };

        Ok(Self::new(segment_id, headers, 0))
    }
}

impl SegmentCache<BlockHeader> {
    pub async fn load_block_header_cache(base_path: &Path, segment_id: u32) -> StorageResult<Self> {
        // Load segment from disk
        let segment_path = base_path.join(BlockHeader::relative_disk_path(segment_id));

        let mut headers = if segment_path.exists() {
            load_header_segments(&segment_path)?
        } else {
            Vec::new()
        };

        // Store the actual number of valid headers before padding
        let valid_count = headers.len();

        // Ensure the segment has space for all possible headers in this segment
        // This is crucial for proper indexing
        let expected_size = super::HEADERS_PER_SEGMENT as usize;
        if headers.len() < expected_size {
            // Pad with sentinel headers that cannot be mistaken for valid blocks
            let sentinel_header = create_sentinel_header();
            headers.resize(expected_size, sentinel_header);
        }

        Ok(Self::new(segment_id, headers, valid_count))
    }
}

impl<H: Persistable> SegmentCache<H> {
    fn new(segment_id: u32, headers: Vec<H>, valid_count: usize) -> Self {
        Self {
            segment_id,
            headers,
            valid_count,
            state: SegmentState::Clean,
            last_saved: Instant::now(),
            last_accessed: Instant::now(),
        }
    }

    pub fn save(&self, base_path: &Path) -> StorageResult<()> {
        let path = base_path.join(H::relative_disk_path(self.segment_id));

        save_header_segments(&self.headers, &path)
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

/// Save all dirty segments to disk via background worker.
pub(super) async fn save_dirty_segments_cache(manager: &DiskStorageManager) -> StorageResult<()> {
    use super::manager::WorkerCommand;

    if let Some(tx) = &manager.worker_tx {
        process_segments(&manager.active_segments, tx, |cache| {
            WorkerCommand::SaveBlockHeaderSegmentCache(cache)
        })
        .await;

        process_segments(&manager.active_filter_segments, tx, |cache| {
            WorkerCommand::SaveFilterHeaderSegmentCache(cache)
        })
        .await;

        process_index(manager, tx).await;
    }

    return Ok(());

    async fn process_segments<H: Persistable + Clone>(
        segments_caches_map: &tokio::sync::RwLock<HashMap<u32, SegmentCache<H>>>,
        tx: &tokio::sync::mpsc::Sender<WorkerCommand>,
        make_command: impl Fn(SegmentCache<H>) -> WorkerCommand,
    ) {
        // Collect segments to save (only dirty ones)
        let (to_save, ids_to_mark) = {
            let segments = segments_caches_map.read().await;
            let to_save: Vec<_> =
                segments.values().filter(|s| s.state == SegmentState::Dirty).cloned().collect();
            let ids_to_mark: Vec<_> = to_save.iter().map(|cache| cache.segment_id).collect();
            (to_save, ids_to_mark)
        };

        // Send header segments to worker
        for cache in to_save {
            let _ = tx.send(make_command(cache)).await;
        }

        // Mark ONLY the header segments we're actually saving as Saving
        {
            let mut segments = segments_caches_map.write().await;
            for id in &ids_to_mark {
                if let Some(segment) = segments.get_mut(id) {
                    segment.state = SegmentState::Saving;
                    segment.last_saved = Instant::now();
                }
            }
        }
    }

    async fn process_index(
        manager: &DiskStorageManager,
        tx: &tokio::sync::mpsc::Sender<WorkerCommand>,
    ) {
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
}

pub fn load_header_segments<H: Decodable>(path: &Path) -> StorageResult<Vec<H>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut headers = Vec::new();

    loop {
        match H::consensus_decode(&mut reader) {
            Ok(header) => headers.push(header),
            Err(encode::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                return Err(StorageError::ReadFailed(format!("Failed to decode header: {}", e)))
            }
        }
    }

    Ok(headers)
}

fn save_header_segments<H: Persistable>(headers: &[H], path: &PathBuf) -> StorageResult<()> {
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    let mut writer = BufWriter::new(file);

    for header in headers {
        header.persist(&mut writer)?;
    }

    writer.flush().map_err(|e| e.into())
}
