//! Segment management and persistence for items implementing the Persistable trait.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    ops::Range,
    path::{Path, PathBuf},
    time::Instant,
};

use dashcore::{
    block::Header as BlockHeader,
    consensus::{encode, Decodable, Encodable},
    hash_types::FilterHeader,
    BlockHash,
};

use crate::{
    error::StorageResult,
    storage::disk::{io::atomic_write, manager::WorkerCommand},
    StorageError,
};

use super::manager::DiskStorageManager;

/// State of a segment in memory
#[derive(Debug, Clone, PartialEq)]
enum SegmentState {
    Clean,  // No changes, up to date on disk
    Dirty,  // Has changes, needs saving
    Saving, // Currently being saved in background
}

/// Index entry for a single compact block filter in a data segment.
/// Stores the byte offset and length needed to read the filter from the data file.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct FilterDataIndexEntry {
    /// Byte offset in the data file where this filter starts
    pub(super) offset: u64,
    /// Length of the filter data in bytes (0 means no filter stored)
    pub(super) length: u32,
}

/// In-memory cache for a segment of compact block filters.
/// Compact filters have variable length (typically 100 bytes to ~5KB).
/// We store an index of offsets and cache individual filters on demand.
#[derive(Clone)]
pub(super) struct FilterDataSegmentCache {
    pub(super) segment_id: u32,
    /// Index entries for each filter position in the segment.
    /// Position corresponds to (height % FILTERS_PER_SEGMENT).
    /// Length of 0 indicates no filter stored at that position.
    /// Offsets are RELATIVE to the data section (not file start).
    pub(super) index: Vec<FilterDataIndexEntry>,
    /// Cached filter data, keyed by segment offset.
    /// Not all filters are cached - loaded on demand.
    pub(super) filters: HashMap<usize, Vec<u8>>,
    /// Number of filters stored in this segment
    pub(super) filter_count: usize,
    /// Current total size of data written (for calculating next offset)
    pub(super) current_data_size: u64,
    /// Byte offset where data section starts in the combined file (for loading filters)
    pub(super) file_data_offset: u64,
    /// Segment state
    pub(super) state: SegmentState,
    /// Last saved time
    pub(super) last_saved: Instant,
    /// Last access time
    pub(super) last_accessed: Instant,
}

/// Evict the oldest (least recently accessed) filter data segment.
pub(super) async fn evict_oldest_filter_data_segment(
    manager: &DiskStorageManager,
    segments: &mut HashMap<u32, FilterDataSegmentCache>,
) -> StorageResult<()> {
    if let Some((oldest_id, oldest_segment)) =
        segments.iter().min_by_key(|(_, s)| s.last_accessed).map(|(id, s)| (*id, s.clone()))
    {
        if oldest_segment.state != SegmentState::Clean {
            tracing::trace!(
                "Synchronously saving filter data segment {} before eviction (state: {:?})",
                oldest_segment.segment_id,
                oldest_segment.state
            );

            // Reconstruct data from cached filters
            let data = reconstruct_filter_data(&oldest_segment);

            let segment_path = manager
                .base_path
                .join(format!("filters/filter_data_segment_{:04}.dat", oldest_segment.segment_id));

            super::io::save_filter_data_segment(&segment_path, &oldest_segment.index, &data)
                .await?;

            tracing::debug!(
                "Successfully saved filter data segment {} to disk",
                oldest_segment.segment_id
            );
        }

        segments.remove(&oldest_id);
    }

    Ok(())
}

/// Reconstruct filter data bytes from a segment cache for saving.
fn reconstruct_filter_data(segment: &FilterDataSegmentCache) -> Vec<u8> {
    let mut data = vec![0u8; segment.current_data_size as usize];

    for (offset, filter) in &segment.filters {
        if *offset < segment.index.len() {
            let entry = &segment.index[*offset];
            if entry.length > 0 {
                let start = entry.offset as usize;
                let end = start + entry.length as usize;
                if end <= data.len() {
                    data[start..end].copy_from_slice(filter);
                }
            }
        }
    }

    data
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

    fn make_save_command(segment: &Segment<Self>) -> WorkerCommand;
}

impl Persistable for BlockHeader {
    const FOLDER_NAME: &'static str = "block_headers";

    fn make_save_command(segment: &Segment<Self>) -> WorkerCommand {
        WorkerCommand::SaveBlockHeaderSegmentCache {
            segment_id: segment.segment_id,
        }
    }
}

impl Persistable for FilterHeader {
    const FOLDER_NAME: &'static str = "filter_headers";

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
            let mut block_height = self.index_to_height(storage_start_idx);

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
    const MAX_ACTIVE_SEGMENTS: usize = 10;

    pub async fn load_or_new(
        base_path: impl Into<PathBuf>,
        sync_base_height: u32,
    ) -> StorageResult<Self> {
        let base_path = base_path.into();
        let items_dir = base_path.join(I::FOLDER_NAME);

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
                    segment_id * Segment::<I>::ITEMS_PER_SEGMENT + segment.items.len() as u32 - 1;

                let tip_height = cache.index_to_height(last_storage_index);
                cache.tip_height = Some(tip_height);
            }
        }

        Ok(cache)
    }

    /// Get the segment ID for a given storage index.
    #[inline]
    fn index_to_segment_id(index: u32) -> u32 {
        index / Segment::<I>::ITEMS_PER_SEGMENT
    }

    #[inline]
    fn segment_id_to_start_index(segment_id: u32) -> u32 {
        segment_id * Segment::<I>::ITEMS_PER_SEGMENT
    }

    /// Get the segment offset for a given storage index.
    #[inline]
    fn index_to_offset(index: u32) -> u32 {
        index % Segment::<I>::ITEMS_PER_SEGMENT
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
                segment.persist(&self.base_path).await?;
                segments.remove(&key);
            }
        }

        // Load and insert
        let segment = Segment::load(&self.base_path, *segment_id).await?;
        let segment = segments.entry(*segment_id).or_insert(segment);
        Ok(segment)
    }

    pub async fn get_items(&mut self, height_range: Range<u32>) -> StorageResult<Vec<I>> {
        debug_assert!(height_range.start <= height_range.end);

        let storage_start_idx = self.height_to_index(height_range.start);
        let storage_end_idx = self.height_to_index(height_range.end);

        let mut items = Vec::with_capacity((storage_end_idx - storage_start_idx) as usize);

        let start_segment = Self::index_to_segment_id(storage_start_idx);
        let end_segment = Self::index_to_segment_id(storage_end_idx);

        for segment_id in start_segment..=end_segment {
            let segment = self.get_segment_mut(&segment_id).await?;
            let item_count = segment.items.len() as u32;

            let seg_start_idx = if segment_id == start_segment {
                Self::index_to_offset(storage_start_idx)
            } else {
                0
            };

            let seg_end_idx = if segment_id == end_segment {
                Self::index_to_offset(storage_end_idx).min(item_count)
            } else {
                item_count
            };

            items.extend_from_slice(segment.get(seg_start_idx..seg_end_idx));
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
        if items.is_empty() {
            tracing::trace!("DiskStorage: no items to store");
            return Ok(());
        }

        let mut storage_index = self.height_to_index(start_height);

        tracing::debug!(
            "SegmentsCache: storing {} items starting at height {} (storage index {})",
            items.len(),
            start_height,
            storage_index
        );

        for item in items {
            let segment_id = Self::index_to_segment_id(storage_index);
            let offset = Self::index_to_offset(storage_index);

            // Update segment
            let segments = self.get_segment_mut(&segment_id).await?;
            segments.insert(item.clone(), offset);

            storage_index += 1;
        }

        // Update cached tip height with blockchain height
        let last_item_height = self.index_to_height(storage_index).saturating_sub(1);
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
    fn height_to_index(&self, height: u32) -> u32 {
        debug_assert!(
            height >= self.sync_base_height,
            "Height must be greater than or equal to sync_base_height"
        );

        height - self.sync_base_height
    }

    #[inline]
    pub fn index_to_height(&self, index: u32) -> u32 {
        index + self.sync_base_height
    }
}

/// In-memory cache for a segment of items
#[derive(Debug, Clone)]
pub struct Segment<I: Persistable> {
    segment_id: u32,
    items: Vec<I>,
    state: SegmentState,
    last_accessed: Instant,
}

impl<I: Persistable> Segment<I> {
    const ITEMS_PER_SEGMENT: u32 = 50_000;

    fn new(segment_id: u32, mut items: Vec<I>, state: SegmentState) -> Self {
        debug_assert!(items.len() <= Self::ITEMS_PER_SEGMENT as usize);
        items.truncate(Self::ITEMS_PER_SEGMENT as usize);

        Self {
            segment_id,
            items,
            state,
            last_accessed: Instant::now(),
        }
    }

    pub async fn load(base_path: &Path, segment_id: u32) -> StorageResult<Self> {
        // Load segment from disk
        let segment_path = base_path.join(I::relative_disk_path(segment_id));

        let (items, state) = if segment_path.exists() {
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

            (items, SegmentState::Clean)
        } else {
            (Vec::with_capacity(Self::ITEMS_PER_SEGMENT as usize), SegmentState::Dirty)
        };

        Ok(Self::new(segment_id, items, state))
    }

    pub async fn persist(&mut self, base_path: &Path) -> StorageResult<()> {
        if self.state == SegmentState::Clean {
            return Ok(());
        }

        let path = base_path.join(I::relative_disk_path(self.segment_id));

        if let Err(e) = fs::create_dir_all(path.parent().unwrap()) {
            return Err(StorageError::WriteFailed(format!("Failed to persist segment: {}", e)));
        }

        self.state = SegmentState::Saving;

        let mut buffer = Vec::new();

        for item in self.items.iter() {
            item.consensus_encode(&mut buffer).map_err(|e| {
                StorageError::WriteFailed(format!("Failed to encode segment item: {}", e))
            })?;
        }

        atomic_write(&path, &buffer).await?;

        self.state = SegmentState::Clean;
        Ok(())
    }

    pub fn insert(&mut self, item: I, offset: u32) {
        debug_assert!(offset < Self::ITEMS_PER_SEGMENT);

        let offset = offset as usize;

        debug_assert!(offset <= self.items.len());

        if offset < self.items.len() {
            self.items[offset] = item;
        } else if offset == self.items.len() {
            self.items.push(item);
        } else {
            tracing::error!(
                "Tried to store an item out of the allowed bounds (offset {}) in segment with id {}",
                offset,
                self.segment_id
            );
        }

        // Transition to Dirty state (from Clean, Dirty, or Saving)
        self.state = SegmentState::Dirty;
        self.last_accessed = std::time::Instant::now();
    }

    pub fn get(&mut self, range: Range<u32>) -> &[I] {
        self.last_accessed = std::time::Instant::now();

        if range.start as usize >= self.items.len() {
            return &[];
        };

        let end = range.end.min(self.items.len() as u32);

        &self.items[range.start as usize..end as usize]
    }
}

#[cfg(test)]
mod tests {
    use dashcore_hashes::Hash;
    use tempfile::TempDir;

    use super::*;

    trait TestStruct {
        fn new_test(id: u32) -> Self;
    }

    impl TestStruct for FilterHeader {
        fn new_test(id: u32) -> Self {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&id.to_le_bytes());
            FilterHeader::from_raw_hash(dashcore_hashes::sha256d::Hash::from_byte_array(bytes))
        }
    }

    #[tokio::test]
    async fn test_segment_cache_eviction() {
        let tmp_dir = TempDir::new().unwrap();

        const MAX_SEGMENTS: u32 = SegmentCache::<FilterHeader>::MAX_ACTIVE_SEGMENTS as u32;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path(), 0)
            .await
            .expect("Failed to create new segment_cache");

        // This logic is a little tricky. Each cache can contain up to MAX_SEGMENTS segments in memory.
        // By storing MAX_SEGMENTS + 1 items, we ensure that the cache will evict the first introduced.
        // Then, by asking again in order starting in 0, we force the cache to load the evicted segment
        // from disk, evicting at the same time the next, 1 in this case. Then we ask for the 1 that we
        // know is evicted and so on.

        for i in 0..=MAX_SEGMENTS {
            let segment = cache.get_segment_mut(&i).await.expect("Failed to create a new segment");
            assert!(segment.items.is_empty());
            assert!(segment.state == SegmentState::Dirty);

            segment.items = vec![FilterHeader::new_test(i)];
        }

        for i in 0..=MAX_SEGMENTS {
            assert_eq!(cache.segments.len(), MAX_SEGMENTS as usize);

            let segment = cache.get_segment_mut(&i).await.expect("Failed to load segment");

            assert_eq!(segment.items.len(), 1);
            assert_eq!(segment.get(0..1), [FilterHeader::new_test(i)]);
            assert!(segment.state == SegmentState::Clean);
        }
    }

    #[tokio::test]
    async fn test_segment_cache_persist_load() {
        let tmp_dir = TempDir::new().unwrap();

        let items: Vec<_> = (0..10).map(FilterHeader::new_test).collect();

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path(), 0)
            .await
            .expect("Failed to create new segment_cache");

        let segment = cache.get_segment_mut(&0).await.expect("Failed to create a new segment");

        assert_eq!(segment.state, SegmentState::Dirty);
        segment.items = items.clone();

        assert!(segment.persist(tmp_dir.path()).await.is_ok());

        cache.clear_in_memory();
        assert!(cache.segments.is_empty());

        let segment = cache.get_segment(&0).await.expect("Failed to load segment");

        assert_eq!(segment.items, items);
        assert_eq!(segment.state, SegmentState::Clean);

        cache.clear_all().await.expect("Failed to clean on-memory and on-disk data");
        assert!(cache.segments.is_empty());

        let segment = cache.get_segment(&0).await.expect("Failed to create a new segment");

        assert!(segment.items.is_empty());
        assert_eq!(segment.state, SegmentState::Dirty);
    }

    #[tokio::test]
    async fn test_segment_cache_get_insert() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path(), 0)
            .await
            .expect("Failed to create new segment_cache");

        let items = cache
            .get_items(0..ITEMS_PER_SEGMENT)
            .await
            .expect("segment cache couldn't return items");

        assert!(items.is_empty());

        let items = cache
            .get_items(0..ITEMS_PER_SEGMENT + 1)
            .await
            .expect("segment cache couldn't return items");

        assert!(items.is_empty());

        // Cannot test the store logic bcs it depends on the DiskStorageManager, test that struct properly or
        // remove the necessity of it
    }

    #[tokio::test]
    async fn test_segment_persist_load() {
        let tmp_dir = TempDir::new().unwrap();

        let segment_id = 10;

        const MAX_ITEMS: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        // Testing with half full segment
        let items = (0..MAX_ITEMS / 2).map(FilterHeader::new_test).collect();
        let mut segment = Segment::new(segment_id, items, SegmentState::Dirty);

        assert_eq!(segment.get(MAX_ITEMS..MAX_ITEMS + 1), []);
        assert_eq!(
            segment.get(0..MAX_ITEMS / 2),
            &(0..MAX_ITEMS / 2).map(FilterHeader::new_test).collect::<Vec<_>>()
        );
        assert_eq!(
            segment.get(MAX_ITEMS / 2 - 1..MAX_ITEMS / 2),
            [FilterHeader::new_test(MAX_ITEMS / 2 - 1)]
        );
        assert_eq!(segment.get(MAX_ITEMS / 2..MAX_ITEMS / 2 + 1), []);
        assert_eq!(segment.get(MAX_ITEMS - 1..MAX_ITEMS), []);

        assert_eq!(segment.state, SegmentState::Dirty);
        assert!(segment.persist(tmp_dir.path()).await.is_ok());
        assert_eq!(segment.state, SegmentState::Clean);

        let mut loaded_segment =
            Segment::<FilterHeader>::load(tmp_dir.path(), segment_id).await.unwrap();

        assert_eq!(
            loaded_segment.get(MAX_ITEMS..MAX_ITEMS + 1),
            segment.get(MAX_ITEMS..MAX_ITEMS + 1)
        );
        assert_eq!(loaded_segment.get(0..1), segment.get(0..1));
        assert_eq!(
            loaded_segment.get(MAX_ITEMS / 2 - 1..MAX_ITEMS / 2),
            segment.get(MAX_ITEMS / 2 - 1..MAX_ITEMS / 2)
        );
        assert_eq!(
            loaded_segment.get(MAX_ITEMS / 2..MAX_ITEMS / 2 + 1),
            segment.get(MAX_ITEMS / 2..MAX_ITEMS / 2 + 1)
        );
        assert_eq!(
            loaded_segment.get(MAX_ITEMS - 1..MAX_ITEMS),
            segment.get(MAX_ITEMS - 1..MAX_ITEMS)
        );
    }

    #[test]
    fn test_segment_insert_get() {
        let segment_id = 10;

        const MAX_ITEMS: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let items = (0..10).map(FilterHeader::new_test).collect();

        let mut segment = Segment::new(segment_id, items, SegmentState::Dirty);

        assert_eq!(segment.items.len(), 10);
        assert_eq!(
            segment.get(0..MAX_ITEMS + 1),
            &(0..10).map(FilterHeader::new_test).collect::<Vec<_>>()
        );

        segment.insert(FilterHeader::new_test(4), 4);
        segment.insert(FilterHeader::new_test(10), 10);

        assert_eq!(segment.items.len(), 11);
        assert_eq!(
            segment.get(0..MAX_ITEMS + 1),
            &(0..11).map(FilterHeader::new_test).collect::<Vec<_>>()
        );
    }
}
