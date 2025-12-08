//! Segment management for cached header and filter segments.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    ops::Range,
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

pub(super) trait Persistable: Sized + Encodable + Decodable + Clone {
    const FOLDER_NAME: &'static str;
    fn relative_disk_path(segment_id: u32) -> PathBuf;
    fn new_sentinel() -> Self;
}

impl Persistable for BlockHeader {
    const FOLDER_NAME: &'static str = "headers";

    fn relative_disk_path(segment_id: u32) -> PathBuf {
        format!("{}/segment_{:04}.dat", Self::FOLDER_NAME, segment_id).into()
    }

    fn new_sentinel() -> Self {
        BlockHeader {
            version: Version::from_consensus(i32::MAX), // Invalid version
            prev_blockhash: BlockHash::from_byte_array([0xFF; 32]), // All 0xFF pattern
            merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([0xFF; 32]).into(),
            time: u32::MAX,                                  // Far future timestamp
            bits: CompactTarget::from_consensus(0xFFFFFFFF), // Invalid difficulty
            nonce: u32::MAX,                                 // Max nonce value
        }
    }
}

impl Persistable for FilterHeader {
    const FOLDER_NAME: &'static str = "filters";

    fn relative_disk_path(segment_id: u32) -> PathBuf {
        format!("{}/filter_segment_{:04}.dat", Self::FOLDER_NAME, segment_id).into()
    }

    fn new_sentinel() -> Self {
        FilterHeader::from_byte_array([0u8; 32])
    }
}

/// In-memory cache for all segments of headers
#[derive(Debug)]
pub struct SegmentCache<H: Persistable> {
    segments: HashMap<u32, Segment<H>>,
    tip_height: Option<u32>,
    sync_base_height: u32,
    base_path: PathBuf,
}

impl<H: Persistable> SegmentCache<H> {
    /// Maximum number of segments to keep in memory
    const MAX_ACTIVE_SEGMENTS: usize = 10;

    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            segments: HashMap::new(),
            tip_height: None,
            sync_base_height: 0,
            base_path: base_path.into(),
        }
    }

    /// Get the segment ID for a given height.
    pub(super) fn index_to_segment_id(height: u32) -> u32 {
        height / super::HEADERS_PER_SEGMENT
    }

    /// Get the segment offset for a given height.
    pub(super) fn index_to_offset(height: u32) -> usize {
        (height % super::HEADERS_PER_SEGMENT) as usize
    }

    pub fn set_sync_base_height(&mut self, height: u32) {
        self.sync_base_height = height;
    }

    pub fn clear(&mut self) {
        self.segments.clear();
        self.tip_height = None;
    }

    pub async fn get_segment(&mut self, segment_id: u32) -> StorageResult<&Segment<H>> {
        let segment = self.get_segment_mut(segment_id).await?;
        Ok(&*segment)
    }

    // TODO: This logic can be improved for sure but for now it works (I guess)
    pub async fn get_segment_mut<'a>(
        &'a mut self,
        segment_id: u32,
    ) -> StorageResult<&'a mut Segment<H>> {
        let segments_len = self.segments.len();
        let segments = &mut self.segments;

        if segments.contains_key(&segment_id) {
            let segment = segments.get_mut(&segment_id).expect("We already checked that it exists");
            segment.last_accessed = Instant::now();
            return Ok(segment);
        }

        if segments_len >= Self::MAX_ACTIVE_SEGMENTS {
            let key_to_evict =
                segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(k, v)| (*k, v));

            if let Some((key, v)) = key_to_evict {
                v.evict(&self.base_path)?;
                segments.remove(&key);
            }
        }

        // Load and insert
        let segment = Segment::load(&self.base_path, segment_id).await?;
        let segment = segments.entry(segment_id).or_insert(segment);
        Ok(segment)
    }

    pub async fn get_headers(&mut self, range: Range<u32>) -> StorageResult<Vec<H>> {
        let mut headers = Vec::new();

        // Convert blockchain height range to storage index range using sync_base_height
        let sync_base_height = self.sync_base_height;

        let storage_start = if sync_base_height > 0 && range.start >= sync_base_height {
            range.start - sync_base_height
        } else {
            range.start
        };

        let storage_end = if sync_base_height > 0 && range.end > sync_base_height {
            range.end - sync_base_height
        } else {
            range.end
        };

        let start_segment = Self::index_to_segment_id(storage_start);
        let end_segment = Self::index_to_segment_id(storage_end.saturating_sub(1));

        for segment_id in start_segment..=end_segment {
            let segment = self.get_segment(segment_id).await?;

            let start_idx = if segment_id == start_segment {
                Self::index_to_offset(storage_start)
            } else {
                0
            };

            let end_idx = if segment_id == end_segment {
                Self::index_to_offset(storage_end.saturating_sub(1)) + 1
            } else {
                segment.headers.len()
            };

            // Only include headers up to valid_count to avoid returning sentinel headers
            let actual_end_idx = end_idx.min(segment.valid_count);

            if start_idx < segment.headers.len()
                && actual_end_idx <= segment.headers.len()
                && start_idx < actual_end_idx
            {
                headers.extend_from_slice(&segment.headers[start_idx..actual_end_idx]);
            }
        }

        Ok(headers)
    }

    pub async fn store_headers(
        &mut self,
        headers: &[H],
        manager: &DiskStorageManager,
    ) -> StorageResult<()> {
        // Early return if no headers to store
        if headers.is_empty() {
            tracing::trace!("DiskStorage: no headers to store");
            return Ok(());
        }

        // Determine the next blockchain height
        let start_height = self.next_height();

        let mut storage_index = self.height_to_storage_index(start_height);

        // Use trace for single headers, debug for small batches, info for large batches
        match headers.len() {
            1 => tracing::trace!("SegmentsCache: storing 1 header at blockchain height {} (storage index {})",
                start_height, storage_index),
            2..=10 => tracing::debug!(
                "SegmentsCache: storing {} headers starting at blockchain height {} (storage index {})",
                headers.len(),
                start_height,
                storage_index
            ),
            _ => tracing::info!(
                "SegmentsCache: storing {} headers starting at blockchain height {} (storage index {})",
                headers.len(),
                start_height,
                storage_index
            ),
        }

        for header in headers {
            let segment_id = Self::index_to_segment_id(storage_index);
            let offset = Self::index_to_offset(storage_index);

            // Update segment
            let segments = self.get_segment_mut(segment_id).await?;
            segments.insert(header.clone(), offset);

            storage_index += 1;
        }

        // Update cached tip height with blockchain height
        if start_height + storage_index > 0 {
            self.tip_height = Some(start_height + storage_index - 1);
        }

        // Save dirty segments periodically (every 1000 filter headers)
        if headers.len() >= 1000 || start_height % 1000 == 0 {
            self.save_dirty(manager).await?;
        }

        Ok(())
    }

    async fn save_dirty(&self, _manager: &DiskStorageManager) -> StorageResult<()> {
        todo!()
    }

    pub fn tip_height(&self) -> Option<u32> {
        self.tip_height
    }

    pub fn next_height(&self) -> u32 {
        let current_tip = self.tip_height();
        match current_tip {
            Some(tip) => tip + 1,
            None => self.sync_base_height,
        }
    }

    /// Convert blockchain height to storage index
    /// For checkpoint sync, storage index is relative to sync_base_height
    fn height_to_storage_index(&self, height: u32) -> u32 {
        debug_assert!(
            height >= self.sync_base_height,
            "Height must be greater than or equal to sync_base_height"
        );

        height - self.sync_base_height
    }
}

/// In-memory cache for a segment of headers
#[derive(Debug, Clone)]
pub(super) struct Segment<H: Persistable> {
    pub(super) segment_id: u32,
    pub(super) headers: Vec<H>,
    pub(super) valid_count: usize, // Number of actual valid headers (excluding padding)
    pub(super) state: SegmentState,
    pub(super) last_saved: Instant,
    pub(super) last_accessed: Instant,
}

impl<H: Persistable> Segment<H> {
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

    pub async fn load(base_path: &Path, segment_id: u32) -> StorageResult<Self> {
        // Load segment from disk
        let segment_path = base_path.join(H::relative_disk_path(segment_id));

        let mut headers = if segment_path.exists() {
            load_header_segments(&segment_path)?
        } else {
            Vec::with_capacity(super::HEADERS_PER_SEGMENT as usize)
        };

        // Store the actual number of valid headers before padding
        let valid_count = headers.len();

        // Ensure the segment has space for all possible headers in this segment
        // This is crucial for proper indexing
        if headers.len() < super::HEADERS_PER_SEGMENT as usize {
            // Pad with sentinel headers that cannot be mistaken for valid blocks
            let sentinel_header = H::new_sentinel();
            headers.resize(super::HEADERS_PER_SEGMENT as usize, sentinel_header);
        }

        Ok(Self::new(segment_id, headers, valid_count))
    }

    pub fn persist(&self, base_path: &Path) -> StorageResult<()> {
        let path = base_path.join(H::relative_disk_path(self.segment_id));

        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        let mut writer = BufWriter::new(file);

        for header in self.headers.iter() {
            header.consensus_encode(&mut writer).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to encode segment item: {}", e))
            })?;
        }

        writer.flush().map_err(|e| e.into())
    }

    pub fn insert(&mut self, item: H, offset: usize) {
        // Only increment valid_count when offset equals the current valid_count
        // This ensures valid_count represents contiguous valid headers without gaps
        if offset == self.valid_count {
            self.valid_count += 1;
        }

        self.headers[offset] = item;
        // Transition to Dirty state (from Clean, Dirty, or Saving)
        self.state = SegmentState::Dirty;
        self.last_accessed = std::time::Instant::now();
    }

    pub fn evict(&self, base_path: &Path) -> StorageResult<()> {
        // Save if dirty or saving before evicting - do it synchronously to ensure data consistency
        if self.state == SegmentState::Clean {
            return Ok(());
        }

        tracing::trace!(
            "Synchronously saving segment {} before eviction (state: {:?})",
            self.segment_id,
            self.state
        );

        self.persist(base_path)?;

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
        segments_cache: &tokio::sync::RwLock<SegmentCache<H>>,
        tx: &tokio::sync::mpsc::Sender<WorkerCommand>,
        make_command: impl Fn(Segment<H>) -> WorkerCommand,
    ) {
        // Collect segments to save (only dirty ones)
        let (to_save, ids_to_mark) = {
            let segments_cache = segments_cache.read().await;
            let to_save: Vec<_> = segments_cache
                .segments
                .values()
                .filter(|s| s.state == SegmentState::Dirty)
                .cloned()
                .collect();
            let ids_to_mark: Vec<_> = to_save.iter().map(|cache| cache.segment_id).collect();
            (to_save, ids_to_mark)
        };

        // Send header segments to worker
        for cache in to_save {
            let _ = tx.send(make_command(cache)).await;
        }

        // Mark ONLY the header segments we're actually saving as Saving
        {
            let mut segments_cache = segments_cache.write().await;
            for id in &ids_to_mark {
                if let Some(segment) = segments_cache.segments.get_mut(id) {
                    segment.state = SegmentState::Saving;
                    segment.last_saved = Instant::now();
                }
            }
        }
    }

    // TODO: Dont yet understand what we are saving here
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
    let mut headers = Vec::with_capacity(super::HEADERS_PER_SEGMENT as usize);

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
