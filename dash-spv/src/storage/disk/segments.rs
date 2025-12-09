//! Segment management for items implementing the Persistable trait.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
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

use crate::{error::StorageResult, storage::disk::manager::WorkerCommand, StorageError};

use super::manager::DiskStorageManager;

/// State of a segment in memory
#[derive(Debug, Clone, PartialEq)]
enum SegmentState {
    Clean,  // No changes, up to date on disk
    Dirty,  // Has changes, needs saving
    Saving, // Currently being saved in background
}

pub trait Persistable: Sized + Encodable + Decodable + PartialEq + Clone {
    const FOLDER_NAME: &'static str;
    const SEGMENT_PREFIX: &'static str = "segment";
    const DATA_FILE_EXTENSION: &'static str = "dat";

    fn relative_disk_path(segment_id: u32) -> PathBuf {
        format!(
            "{}/{}_{:04}.{}",
            Self::FOLDER_NAME,
            Self::SEGMENT_PREFIX,
            segment_id,
            Self::DATA_FILE_EXTENSION
        )
        .into()
    }

    fn new_sentinel() -> Self;
    fn make_save_command(segment: &Segment<Self>) -> WorkerCommand;
}

impl Persistable for BlockHeader {
    const FOLDER_NAME: &'static str = "block_headers";

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

    fn make_save_command(segment: &Segment<Self>) -> WorkerCommand {
        WorkerCommand::SaveBlockHeaderSegmentCache {
            segment_id: segment.segment_id,
        }
    }
}

impl Persistable for FilterHeader {
    const FOLDER_NAME: &'static str = "filter_headers";

    fn new_sentinel() -> Self {
        FilterHeader::from_byte_array([0u8; 32])
    }

    fn make_save_command(segment: &Segment<Self>) -> WorkerCommand {
        WorkerCommand::SaveFilterHeaderSegmentCache {
            segment_id: segment.segment_id,
        }
    }
}

/// In-memory cache for all segments of items
#[derive(Debug)]
pub struct SegmentCache<I: Persistable> {
    segments: HashMap<u32, Segment<I>>,
    tip_height: Option<u32>,
    sync_base_height: u32,
    base_path: PathBuf,
}

impl SegmentCache<BlockHeader> {
    pub async fn build_block_index_from_segments(
        &mut self,
    ) -> StorageResult<HashMap<BlockHash, u32>> {
        let segments_dir = self.base_path.join(BlockHeader::FOLDER_NAME);

        let blocks_count = self.next_height() - self.sync_base_height;
        let mut block_index = HashMap::with_capacity(blocks_count as usize);

        let entries = fs::read_dir(&segments_dir)?;

        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };

            if !name.starts_with(BlockHeader::SEGMENT_PREFIX) {
                continue;
            }

            if !name.ends_with(&format!(".{}", BlockHeader::DATA_FILE_EXTENSION)) {
                continue;
            }

            let segment_id = match name[8..12].parse::<u32>() {
                Ok(id) => id,
                Err(_) => continue,
            };

            let storage_start_idx = Self::segment_id_to_start_index(segment_id);
            let mut block_height = self.storage_index_to_height(storage_start_idx);

            let segment = self.get_segment(&segment_id).await?;

            for item in segment.items.iter() {
                block_index.insert(item.block_hash(), block_height);

                block_height += 1;
            }
        }

        Ok(block_index)
    }
}

impl<I: Persistable> SegmentCache<I> {
    /// Maximum number of segments to keep in memory
    const MAX_ACTIVE_SEGMENTS: usize = 10;

    pub async fn new(base_path: impl Into<PathBuf>) -> StorageResult<Self> {
        let base_path = base_path.into();
        let items_dir = base_path.join(I::FOLDER_NAME);

        let sync_base_height = 0; // TODO: This needs to have a value at this point

        let mut cache = Self {
            segments: HashMap::with_capacity(Self::MAX_ACTIVE_SEGMENTS),
            tip_height: None,
            sync_base_height,
            base_path,
        };

        // Building the metadata
        if let Ok(entries) = fs::read_dir(&items_dir) {
            let mut max_segment_id = None;

            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(I::SEGMENT_PREFIX)
                        && name.ends_with(&format!(".{}", I::DATA_FILE_EXTENSION))
                    {
                        let segment_id_start = I::SEGMENT_PREFIX.len() + 1;
                        let segment_id_end = segment_id_start + 4;

                        if let Ok(id) = name[segment_id_start..segment_id_end].parse::<u32>() {
                            max_segment_id =
                                Some(max_segment_id.map_or(id, |max: u32| max.max(id)));
                        }
                    }
                }
            }

            if let Some(segment_id) = max_segment_id {
                let segment = cache.get_segment(&segment_id).await?;
                let last_storage_index =
                    segment_id * Segment::<I>::ITEMS_PER_SEGMENT + segment.valid_count - 1;

                let tip_height = cache.storage_index_to_height(last_storage_index);
                cache.tip_height = Some(tip_height);
            }
        }

        Ok(cache)
    }

    /// Get the segment ID for a given height.
    #[inline]
    fn index_to_segment_id(height: u32) -> u32 {
        height / Segment::<I>::ITEMS_PER_SEGMENT
    }

    #[inline]
    fn segment_id_to_start_index(segment_id: u32) -> u32 {
        segment_id * Segment::<I>::ITEMS_PER_SEGMENT
    }

    /// Get the segment offset for a given height.
    #[inline]
    fn index_to_offset(height: u32) -> u32 {
        height % Segment::<I>::ITEMS_PER_SEGMENT
    }

    #[inline]
    pub fn set_sync_base_height(&mut self, height: u32) {
        self.sync_base_height = height;
    }

    pub fn clear_in_memory(&mut self) {
        self.segments.clear();
        self.tip_height = None;
    }

    pub async fn clear_all(&mut self) -> StorageResult<()> {
        self.clear_in_memory();

        let persistence_dir = self.base_path.join(I::FOLDER_NAME);
        if persistence_dir.exists() {
            tokio::fs::remove_dir_all(&persistence_dir).await?;
        }
        tokio::fs::create_dir_all(&persistence_dir).await?;

        Ok(())
    }

    pub async fn get_segment(&mut self, segment_id: &u32) -> StorageResult<&Segment<I>> {
        let segment = self.get_segment_mut(segment_id).await?;
        Ok(&*segment)
    }

    // TODO: This logic can be improved for sure but for now it works (I guess)
    pub async fn get_segment_mut<'a>(
        &'a mut self,
        segment_id: &u32,
    ) -> StorageResult<&'a mut Segment<I>> {
        let segments_len = self.segments.len();
        let segments = &mut self.segments;

        if segments.contains_key(segment_id) {
            let segment = segments.get_mut(segment_id).expect("We already checked that it exists");
            segment.last_accessed = Instant::now();
            return Ok(segment);
        }

        if segments_len >= Self::MAX_ACTIVE_SEGMENTS {
            let key_to_evict =
                segments.iter_mut().min_by_key(|(_, s)| s.last_accessed).map(|(k, v)| (*k, v));

            if let Some((key, segment)) = key_to_evict {
                segment.persist(&self.base_path)?;
                segments.remove(&key);
            }
        }

        // Load and insert
        let segment = Segment::load(&self.base_path, *segment_id).await?;
        let segment = segments.entry(*segment_id).or_insert(segment);
        Ok(segment)
    }

    pub async fn get_items(&mut self, height_range: Range<u32>) -> StorageResult<Vec<I>> {
        let storage_start_idx = self.height_to_storage_index(height_range.start);
        let storage_end_idx = self.height_to_storage_index(height_range.end);

        let mut items = Vec::with_capacity((storage_end_idx - storage_start_idx) as usize);

        let start_segment = Self::index_to_segment_id(storage_start_idx);
        let end_segment = Self::index_to_segment_id(storage_end_idx.saturating_sub(1));

        for segment_id in start_segment..=end_segment {
            let segment = self.get_segment(&segment_id).await?;
            let item_count = segment.items.len() as u32;

            let seg_start_idx = if segment_id == start_segment {
                Self::index_to_offset(storage_start_idx)
            } else {
                0
            };

            let seg_end_idx = if segment_id == end_segment {
                Self::index_to_offset(storage_end_idx.saturating_sub(1)) + 1
            } else {
                item_count
            };

            // Only include items up to valid_count to avoid returning sentinel items
            let actual_end_idx = seg_end_idx.min(segment.valid_count);

            if seg_start_idx < item_count
                && actual_end_idx <= item_count
                && seg_start_idx < actual_end_idx
            {
                items.extend_from_slice(
                    &segment.items[seg_start_idx as usize..actual_end_idx as usize],
                );
            }
        }

        Ok(items)
    }

    pub async fn store_items(
        &mut self,
        items: &[I],
        manager: &DiskStorageManager,
    ) -> StorageResult<()> {
        self.store_items_at_height(items, self.next_height(), manager).await
    }

    pub async fn store_items_at_height(
        &mut self,
        items: &[I],
        start_height: u32,
        manager: &DiskStorageManager,
    ) -> StorageResult<()> {
        // Early return if no items to store
        if items.is_empty() {
            tracing::trace!("DiskStorage: no items to store");
            return Ok(());
        }

        let mut storage_index = self.height_to_storage_index(start_height);

        // Use trace for single items, debug for small batches, info for large batches
        match items.len() {
            1 => tracing::trace!(
                "SegmentsCache: storing 1 item at height {} (storage index {})",
                start_height,
                storage_index
            ),
            2..=10 => tracing::debug!(
                "SegmentsCache: storing {} items starting at height {} (storage index {})",
                items.len(),
                start_height,
                storage_index
            ),
            _ => tracing::info!(
                "SegmentsCache: storing {} items starting at height {} (storage index {})",
                items.len(),
                start_height,
                storage_index
            ),
        }

        for item in items {
            let segment_id = Self::index_to_segment_id(storage_index);
            let offset = Self::index_to_offset(storage_index);

            // Update segment
            let segments = self.get_segment_mut(&segment_id).await?;
            segments.insert(item.clone(), offset);

            storage_index += 1;
        }

        // Update cached tip height with blockchain height
        let last_item_height = self.storage_index_to_height(storage_index).saturating_sub(1);
        self.tip_height = match self.tip_height {
            Some(current) => Some(current.max(last_item_height)),
            None => Some(last_item_height),
        };

        // Persist dirty segments periodically (every 1000 filter items)
        if items.len() >= 1000 || start_height.is_multiple_of(1000) {
            self.persist_dirty(manager).await;
        }

        Ok(())
    }

    pub async fn persist_dirty(&mut self, manager: &DiskStorageManager) {
        // Collect segments to persist (only dirty ones)
        let segments: Vec<_> =
            self.segments.values().filter(|s| s.state == SegmentState::Dirty).collect();

        // Send header segments to worker if exists
        if let Some(tx) = &manager.worker_tx {
            for segment in segments {
                let _ = tx.send(I::make_save_command(segment)).await;
            }
        }
    }

    #[inline]
    pub fn tip_height(&self) -> Option<u32> {
        self.tip_height
    }

    #[inline]
    pub fn next_height(&self) -> u32 {
        let current_tip = self.tip_height();
        match current_tip {
            Some(tip) => tip + 1,
            None => self.sync_base_height,
        }
    }

    /// Convert blockchain height to storage index
    /// For checkpoint sync, storage index is relative to sync_base_height
    #[inline]
    fn height_to_storage_index(&self, height: u32) -> u32 {
        debug_assert!(
            height >= self.sync_base_height,
            "Height must be greater than or equal to sync_base_height"
        );

        height - self.sync_base_height
    }

    #[inline]
    pub fn storage_index_to_height(&self, storage_index: u32) -> u32 {
        storage_index + self.sync_base_height
    }
}

/// In-memory cache for a segment of items
#[derive(Debug, Clone)]
pub struct Segment<I: Persistable> {
    segment_id: u32,
    items: Vec<I>,
    valid_count: u32, // Number of actual valid items (excluding padding)
    state: SegmentState,
    last_accessed: Instant,
}

impl<I: Persistable> Segment<I> {
    const ITEMS_PER_SEGMENT: u32 = 50_000;

    fn new(segment_id: u32, items: Vec<I>, valid_count: u32) -> Self {
        Self {
            segment_id,
            items,
            valid_count,
            state: SegmentState::Clean,
            last_accessed: Instant::now(),
        }
    }

    pub async fn load(base_path: &Path, segment_id: u32) -> StorageResult<Self> {
        // Load segment from disk
        let segment_path = base_path.join(I::relative_disk_path(segment_id));

        let mut items = if segment_path.exists() {
            let file = File::open(&segment_path)?;
            let mut reader = BufReader::new(file);
            let mut items = Vec::with_capacity(Segment::<I>::ITEMS_PER_SEGMENT as usize);

            loop {
                match I::consensus_decode(&mut reader) {
                    Ok(item) => items.push(item),
                    Err(encode::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break
                    }
                    Err(e) => {
                        return Err(StorageError::ReadFailed(format!(
                            "Failed to decode item: {}",
                            e
                        )))
                    }
                }
            }

            items
        } else {
            Vec::with_capacity(Self::ITEMS_PER_SEGMENT as usize)
        };

        // Store the actual number of valid items before padding
        let valid_count = items.len() as u32;

        // Ensure the segment has space for all possible items in this segment
        // This is crucial for proper indexing
        if items.len() < Self::ITEMS_PER_SEGMENT as usize {
            items.resize(Self::ITEMS_PER_SEGMENT as usize, I::new_sentinel());
        }

        Ok(Self::new(segment_id, items, valid_count))
    }

    pub fn persist(&mut self, base_path: &Path) -> StorageResult<()> {
        if self.state == SegmentState::Clean {
            return Ok(());
        }

        let path = base_path.join(I::relative_disk_path(self.segment_id));

        if let Err(e) = fs::create_dir_all(path.parent().unwrap()) {
            return Err(StorageError::WriteFailed(format!("Failed to persist segment: {}", e)));
        }

        self.state = SegmentState::Saving;

        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        let mut writer = BufWriter::new(file);

        let sentinel: I = I::new_sentinel();

        for item in self.items.iter() {
            // Sentinels are expected to fill the last empty positions of the segment
            // If there is a gap, that could be considered a bug since valid_count
            // stops making sense. We can talk in a future about removing sentinels
            // but that implies that we cannot insert with and offset or that we have
            // to make sure that the offset is not out of bounds.
            if *item == sentinel {
                break;
            }

            item.consensus_encode(&mut writer).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to encode segment item: {}", e))
            })?;
        }

        writer.flush()?;

        self.state = SegmentState::Clean;
        Ok(())
    }

    pub fn insert(&mut self, item: I, offset: u32) {
        // Only increment valid_count when offset equals the current valid_count
        // This ensures valid_count represents contiguous valid items without gaps
        if offset == self.valid_count {
            self.valid_count += 1;
        }

        self.items[offset as usize] = item;
        // Transition to Dirty state (from Clean, Dirty, or Saving)
        self.state = SegmentState::Dirty;
        self.last_accessed = std::time::Instant::now();
    }
}
