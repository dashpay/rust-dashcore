//! Segment management and persistence for items implementing the Persistable trait.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::BufReader,
    ops::Range,
    path::{Path, PathBuf},
    time::Instant,
};

use dashcore::{
    block::{Header as BlockHeader, Version},
    consensus::{encode, Decodable, Encodable},
    hash_types::FilterHeader,
    Block, BlockHash, CompactTarget,
};
use dashcore_hashes::Hash;

use crate::{
    error::StorageResult,
    storage::io::atomic_write,
    types::{HashedBlock, HashedBlockHeader},
    StorageError,
};

pub trait Persistable: Sized + Encodable + Decodable + PartialEq + Clone {
    const SEGMENT_PREFIX: &'static str = "segment";
    const DATA_FILE_EXTENSION: &'static str = "dat";

    fn segment_file_name(segment_id: u32) -> String {
        format!("{}_{:04}.{}", Self::SEGMENT_PREFIX, segment_id, Self::DATA_FILE_EXTENSION)
    }

    fn sentinel() -> Self;
}

impl Persistable for Vec<u8> {
    fn sentinel() -> Self {
        vec![]
    }
}

impl Persistable for HashedBlockHeader {
    fn sentinel() -> Self {
        let header = BlockHeader {
            version: Version::from_consensus(i32::MAX), // Invalid version
            prev_blockhash: BlockHash::from_byte_array([0xFF; 32]), // All 0xFF pattern
            merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([0xFF; 32]).into(),
            time: u32::MAX,                                  // Far future timestamp
            bits: CompactTarget::from_consensus(0xFFFFFFFF), // Invalid difficulty
            nonce: u32::MAX,
        };

        Self::from(header)
    }
}

impl Persistable for FilterHeader {
    fn sentinel() -> Self {
        FilterHeader::from_byte_array([0u8; 32])
    }
}

impl Persistable for HashedBlock {
    fn sentinel() -> Self {
        let block = Block {
            header: *HashedBlockHeader::sentinel().header(),
            txdata: Vec::new(),
        };
        Self::from(block)
    }
}

/// In-memory cache for all segments of items
#[derive(Debug)]
pub struct SegmentCache<I: Persistable> {
    segments: HashMap<u32, Segment<I>>,
    evicted: HashMap<u32, Segment<I>>,
    tip_height: Option<u32>,
    start_height: Option<u32>,
    segments_dir: PathBuf,
    /// Segment ids whose backing files must be removed on the next `persist`.
    /// Populated by `truncate_above` for segments that are dropped entirely.
    to_delete: HashSet<u32>,
}

impl<I: Persistable> SegmentCache<I> {
    const MAX_ACTIVE_SEGMENTS: usize = 10;

    pub async fn load_or_new(segments_dir: impl Into<PathBuf>) -> StorageResult<Self> {
        let segments_dir = segments_dir.into();

        let mut cache = Self {
            segments: HashMap::with_capacity(Self::MAX_ACTIVE_SEGMENTS),
            evicted: HashMap::new(),
            tip_height: None,
            start_height: None,
            segments_dir: segments_dir.clone(),
            to_delete: HashSet::new(),
        };

        // Building the metadata
        if let Ok(entries) = fs::read_dir(&segments_dir) {
            let mut max_seg_id = None;
            let mut min_seg_id = None;

            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(I::SEGMENT_PREFIX)
                        && name.ends_with(&format!(".{}", I::DATA_FILE_EXTENSION))
                    {
                        let segment_id_start = I::SEGMENT_PREFIX.len() + 1;
                        let segment_id_end = segment_id_start + 4;

                        if let Ok(id) = name[segment_id_start..segment_id_end].parse::<u32>() {
                            max_seg_id = Some(max_seg_id.map_or(id, |max: u32| max.max(id)));
                            min_seg_id = Some(min_seg_id.map_or(id, |min: u32| min.min(id)));
                        }
                    }
                }
            }

            if let Some(segment_id) = max_seg_id {
                let segment = cache.get_segment(&segment_id).await?;

                cache.tip_height = segment
                    .last_valid_offset()
                    .map(|offset| Self::segment_id_to_start_height(segment_id) + offset);
            }

            if let Some(segment_id) = min_seg_id {
                let segment = cache.get_segment(&segment_id).await?;

                cache.start_height = segment
                    .first_valid_offset()
                    .map(|offset| Self::segment_id_to_start_height(segment_id) + offset);
            }
        }

        Ok(cache)
    }

    #[inline]
    fn height_to_segment_id(height: u32) -> u32 {
        height / Segment::<I>::ITEMS_PER_SEGMENT
    }

    #[inline]
    fn segment_id_to_start_height(segment_id: u32) -> u32 {
        segment_id * Segment::<I>::ITEMS_PER_SEGMENT
    }

    /// Get the segment offset for a given storage index.
    #[inline]
    fn height_to_offset(height: u32) -> u32 {
        height % Segment::<I>::ITEMS_PER_SEGMENT
    }

    async fn get_segment(&mut self, segment_id: &u32) -> StorageResult<&Segment<I>> {
        let segment = self.get_segment_mut(segment_id).await?;
        Ok(&*segment)
    }

    async fn get_segment_mut<'a>(
        &'a mut self,
        segment_id: &u32,
    ) -> StorageResult<&'a mut Segment<I>> {
        let segments_len = self.segments.len();

        if self.segments.contains_key(segment_id) {
            let segment =
                self.segments.get_mut(segment_id).expect("We already checked that it exists");
            return Ok(segment);
        }

        if segments_len >= Self::MAX_ACTIVE_SEGMENTS {
            let key_to_evict =
                self.segments.iter_mut().min_by_key(|(_, s)| s.last_accessed).map(|(k, v)| (*k, v));

            if let Some((key, _)) = key_to_evict {
                if let Some(segment) = self.segments.remove(&key) {
                    if segment.state == SegmentState::Dirty {
                        self.evicted.insert(key, segment);
                    }
                }
            }
        }

        // If the segment is already in the to_persist map, load it from there.
        // If the segment is queued for deletion, return a fresh empty segment.
        // The next `persist` will atomically overwrite the stale file.
        // Otherwise, load it from disk.
        let segment = if let Some(segment) = self.evicted.remove(segment_id) {
            segment
        } else if self.to_delete.remove(segment_id) {
            Segment::new(*segment_id, vec![], SegmentState::Dirty)
        } else {
            Segment::load(&self.segments_dir, *segment_id).await?
        };

        let segment = self.segments.entry(*segment_id).or_insert(segment);
        Ok(segment)
    }

    /// Load a contiguous range of items by height.
    ///
    /// Returns `StorageError::InvalidArgument` when the requested range extends
    /// into a segment queued for deletion by a prior `truncate_above` (before
    /// the next `persist`). Callers reading across a truncation boundary must
    /// clamp their range to `tip_height` first, or fall back to per-item reads
    /// via `get_item`, which returns `Ok(None)` for those slots.
    pub async fn get_items(&mut self, height_range: Range<u32>) -> StorageResult<Vec<I>> {
        debug_assert!(height_range.start < height_range.end);

        let start = height_range.start;
        let end = height_range.end;

        let mut items = Vec::with_capacity((end - start) as usize);

        let start_segment = Self::height_to_segment_id(start);

        // Because the end is not included, we dont want to visit the segment
        // where that height is present.
        //
        // Example: For start = 0 and end = ITEM_PER_SEGMENT,
        // Self::height_to_segment_id(end) = 1 but all the elements in
        // [start, end) are in segment 0. If we don't do the
        // subtraction we would do 2 iterations.
        let end_segment = Self::height_to_segment_id(end - 1);

        for segment_id in start_segment..=end_segment {
            // Same guard as `get_item`: a segment queued for deletion holds
            // nothing but sentinels by construction. Loading it via
            // `get_segment_mut` would consume the deletion intent and queue
            // an all-sentinel rewrite, so refuse the read instead.
            if self.to_delete.contains(&segment_id) {
                return Err(StorageError::InvalidArgument(format!(
                    "get_items range {height_range:?} extends into segment {segment_id} queued for deletion"
                )));
            }

            let segment = self.get_segment_mut(&segment_id).await?;

            let seg_start = if segment_id == start_segment {
                Self::height_to_offset(start)
            } else {
                0
            };

            let seg_end = if segment_id == end_segment {
                Self::height_to_offset(end)
            } else {
                Segment::<I>::ITEMS_PER_SEGMENT
            };

            #[cfg(debug_assertions)]
            {
                match segment.first_valid_offset() {
                    Some(offset) if offset <= seg_start => {}
                    _ => panic!("Trying to access invalid offset ({seg_start}) in segment with first_valid_offset = {:?}", segment.first_valid_offset()),
                }
            }

            // This edge case occurs when the end height is multiple of ITEMS_PER_SEGMENT.
            // In this case, we just extend from seg_start until the end.
            //
            // Note that 0 == ITEMS_PER_SEGMENT (mod ITEMS_PER_SEGMENT)
            if seg_end == 0 {
                items.extend_from_slice(segment.get(seg_start..Segment::<I>::ITEMS_PER_SEGMENT));
                continue;
            }

            #[cfg(debug_assertions)]
            {
                match segment.last_valid_offset() {
                    Some(offset) if offset >= seg_end - 1 => {} // seg_end is not included, interval of the form [seg_start, seg_end)
                    _ => panic!("Trying to access invalid offset ({}) in segment with last_valid_offset = {:?}", seg_end - 1, segment.last_valid_offset()),
                }
            }

            items.extend_from_slice(segment.get(seg_start..seg_end));
        }

        Ok(items)
    }

    /// Get a single item by height. Returns `None` for sentinel (empty) slots.
    /// Unlike `get_items()`, this does not assert dense storage, safe for sparse data.
    ///
    /// For heights in a segment queued for deletion by a prior `truncate_above`
    /// (before the next `persist`), this returns `Ok(None)` rather than the
    /// `StorageError::InvalidArgument` that `get_items` returns. Callers must
    /// not interpret `Ok(None)` here as a fallback for an error from `get_items`.
    /// The two APIs report truncated slots differently by design.
    pub async fn get_item(&mut self, height: u32) -> StorageResult<Option<I>> {
        let segment_id = Self::height_to_segment_id(height);

        // A segment queued for deletion holds nothing but sentinels by
        // construction. Short-circuit so a read above the truncated tip does
        // not consume the deletion intent in `get_segment_mut` and replace
        // the stale on-disk file with a fresh all-sentinel blob.
        if self.to_delete.contains(&segment_id) {
            return Ok(None);
        }

        let offset = Self::height_to_offset(height);
        let segment = self.get_segment_mut(&segment_id).await?;
        let item = segment.get_single(offset);
        if *item == I::sentinel() {
            Ok(None)
        } else {
            Ok(Some(item.clone()))
        }
    }

    pub async fn store_items(&mut self, items: &[I]) -> StorageResult<()> {
        self.store_items_at_height(items, self.next_height()).await
    }

    pub async fn store_items_at_height(
        &mut self,
        items: &[I],
        start_height: u32,
    ) -> StorageResult<()> {
        if items.is_empty() {
            tracing::trace!("DiskStorage: no items to store");
            return Ok(());
        }

        let mut height = start_height;

        tracing::debug!(
            "SegmentsCache: storing {} items starting at height {}",
            items.len(),
            height,
        );

        for item in items {
            let segment_id = Self::height_to_segment_id(height);
            let offset = Self::height_to_offset(height);

            // Update segment
            let segment = self.get_segment_mut(&segment_id).await?;
            segment.insert(item.clone(), offset);

            height += 1;
        }

        // Update cached tip height and start height
        // if needed
        self.tip_height = match self.tip_height {
            Some(current) => Some(current.max(height - 1)),
            None => Some(height - 1),
        };

        self.start_height = match self.start_height {
            Some(current) => Some(current.min(start_height)),
            None => Some(start_height),
        };

        Ok(())
    }

    /// Truncate the cache so that no items above `target_height` remain.
    ///
    /// Segments entirely above the target are dropped from memory and queued for
    /// deletion on the next `persist`. The segment containing `target_height + 1`
    /// has its tail slots reset to `I::sentinel()` so subsequent `Segment::insert`
    /// calls into the same range remain sound.
    ///
    /// Returns an error if `target_height` is below `start_height`, since the
    /// resulting cache would have a hole below its origin. Callers must guard
    /// against truncating an empty cache except as a no-op (no error).
    ///
    /// The truncation is not durable until the next successful `persist` call.
    /// A crash between `truncate_above` and `persist` may leave orphaned segment
    /// files on disk, causing `tip_height` to be recomputed from stale data on
    /// restart and the cache to reopen at the pre-truncation tip.
    pub async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        let tip = match self.tip_height {
            Some(tip) => tip,
            None => return Ok(()),
        };

        if target_height >= tip {
            return Ok(());
        }

        if let Some(start) = self.start_height {
            if target_height < start {
                return Err(StorageError::InvalidArgument(format!(
                    "truncate_above({target_height}) below start_height ({start})"
                )));
            }
        }

        let boundary_segment_id = Self::height_to_segment_id(target_height);
        let boundary_offset = Self::height_to_offset(target_height);
        let max_segment_id = Self::height_to_segment_id(tip);

        // Load the boundary segment first so any disk I/O error is surfaced
        // before mutating cache state. After this point only infallible
        // in-memory operations run, so the function cannot leave the cache
        // in a half-truncated state.
        if boundary_offset + 1 < Segment::<I>::ITEMS_PER_SEGMENT {
            let segment = self.get_segment_mut(&boundary_segment_id).await?;
            segment.reset_above(boundary_offset);
        }

        for segment_id in (boundary_segment_id + 1)..=max_segment_id {
            self.segments.remove(&segment_id);
            self.evicted.remove(&segment_id);
            self.to_delete.insert(segment_id);
        }

        self.tip_height = Some(target_height);

        Ok(())
    }

    pub async fn persist(&mut self, segments_dir: impl Into<PathBuf>) {
        let segments_dir = segments_dir.into();

        let mut failed = HashSet::new();
        for id in self.to_delete.drain() {
            let path = segments_dir.join(I::segment_file_name(id));
            match tokio::fs::remove_file(&path).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::error!("Failed to delete segment file {:?}: {}", path, e);
                    failed.insert(id);
                }
            }
        }
        self.to_delete.extend(failed);

        for (id, segments) in self.evicted.iter_mut() {
            if let Err(e) = segments.persist(&segments_dir).await {
                tracing::error!("Failed to persist segment with id {id}: {e}");
            }
        }

        self.evicted.clear();

        for (id, segments) in self.segments.iter_mut() {
            if let Err(e) = segments.persist(&segments_dir).await {
                tracing::error!("Failed to persist segment with id {id}: {e}");
            }
        }
    }

    #[inline]
    pub fn tip_height(&self) -> Option<u32> {
        self.tip_height
    }

    #[inline]
    pub fn start_height(&self) -> Option<u32> {
        self.start_height
    }

    #[inline]
    pub fn next_height(&self) -> u32 {
        match self.tip_height() {
            Some(height) => height + 1,
            None => 0,
        }
    }
}

/// State of a segment in memory
#[derive(Debug, Clone, PartialEq)]
enum SegmentState {
    Clean, // No changes, up to date on disk
    Dirty, // Has changes, needs saving
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
        items.resize(Self::ITEMS_PER_SEGMENT as usize, I::sentinel());

        Self {
            segment_id,
            items,
            state,
            last_accessed: Instant::now(),
        }
    }

    pub fn first_valid_offset(&self) -> Option<u32> {
        let sentinel = I::sentinel();

        for (index, item) in self.items.iter().enumerate() {
            if item != &sentinel {
                return Some(index as u32);
            }
        }

        None
    }

    pub fn last_valid_offset(&self) -> Option<u32> {
        let sentinel = I::sentinel();

        for (index, item) in self.items.iter().enumerate().rev() {
            if item != &sentinel {
                return Some(index as u32);
            }
        }

        None
    }

    pub async fn load(base_path: &Path, segment_id: u32) -> StorageResult<Self> {
        // Load segment from disk
        let segment_path = base_path.join(I::segment_file_name(segment_id));

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
            let mut vec = Vec::new();
            vec.resize(Self::ITEMS_PER_SEGMENT as usize, I::sentinel());
            (vec, SegmentState::Dirty)
        };

        Ok(Self::new(segment_id, items, state))
    }

    pub async fn persist(&mut self, segments_dir: impl Into<PathBuf>) -> StorageResult<()> {
        if self.state == SegmentState::Clean {
            return Ok(());
        }

        let segments_dir = segments_dir.into();
        let path = segments_dir.join(I::segment_file_name(self.segment_id));

        if let Err(e) = fs::create_dir_all(path.parent().unwrap()) {
            return Err(StorageError::WriteFailed(format!("Failed to persist segment: {}", e)));
        }

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

    /// Reset all slots strictly above `offset` to the sentinel value.
    /// The slot at `offset` is preserved. Marks the segment dirty if any
    /// slot was changed.
    fn reset_above(&mut self, offset: u32) {
        debug_assert!(offset < Self::ITEMS_PER_SEGMENT);

        let sentinel = I::sentinel();
        let start = (offset as usize) + 1;
        let mut changed = false;

        for slot in &mut self.items[start..] {
            if *slot != sentinel {
                *slot = sentinel.clone();
                changed = true;
            }
        }

        if changed {
            self.state = SegmentState::Dirty;
            self.last_accessed = Instant::now();
        }
    }

    pub fn insert(&mut self, item: I, offset: u32) {
        debug_assert!(offset < Self::ITEMS_PER_SEGMENT);

        let offset = offset as usize;

        // If, at any moment, we allow the Segment to replace non
        // sentinel items, feel free to remove this debug assert.
        // This a bug prevention mechanism based on the assumption that
        // we are not storing an already valid and stored item.
        debug_assert!(self.items[offset] == I::sentinel());

        self.items[offset] = item;

        self.state = SegmentState::Dirty;
        self.last_accessed = std::time::Instant::now();
    }

    /// Get a single item by offset, returning the raw value (may be a sentinel).
    pub fn get_single(&mut self, offset: u32) -> &I {
        self.last_accessed = Instant::now();
        &self.items[offset as usize]
    }

    pub fn get(&mut self, range: Range<u32>) -> &[I] {
        debug_assert!(range.start < self.items.len() as u32);
        debug_assert!(range.end <= self.items.len() as u32);

        self.last_accessed = std::time::Instant::now();

        let res = &self.items[range.start as usize..range.end as usize];

        // Checking for gaps in the requested range in development
        #[cfg(debug_assertions)]
        {
            let sentinel = I::sentinel();
            for item in res {
                debug_assert!(
                    *item != sentinel,
                    "Found a gap in segment {} in interval [{},{})",
                    self.segment_id,
                    range.start,
                    range.end
                );
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_segment_cache_eviction() {
        let tmp_dir = TempDir::new().unwrap();

        const MAX_SEGMENTS: u32 = SegmentCache::<FilterHeader>::MAX_ACTIVE_SEGMENTS as u32;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path())
            .await
            .expect("Failed to create new segment_cache");

        // This logic is a little tricky. Each cache can contain up to MAX_SEGMENTS segments in memory.
        // By storing MAX_SEGMENTS + 1 items, we ensure that the cache will evict the first introduced.
        // Then, by asking again in order starting in 0, we force the cache to load the evicted segment
        // evicting at the same time the next, 1 in this case. Then we ask for the 1 that we know is
        // evicted and so on.

        for i in 0..=MAX_SEGMENTS {
            let segment = cache.get_segment_mut(&i).await.expect("Failed to create a new segment");
            assert!(segment.state == SegmentState::Dirty);

            segment.insert(FilterHeader::dummy(i), 0);
        }

        for i in 0..=MAX_SEGMENTS {
            assert_eq!(cache.segments.len(), MAX_SEGMENTS as usize);

            let segment = cache.get_segment_mut(&i).await.expect("Failed to load segment");

            assert_eq!(segment.get(0..1), [FilterHeader::dummy(i)]);
        }
    }

    #[tokio::test]
    async fn test_segment_cache_persist_load() {
        let tmp_dir = TempDir::new().unwrap();

        let items = FilterHeader::dummy_batch(0..10);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path())
            .await
            .expect("Failed to create new segment_cache");

        cache.store_items_at_height(&items, 10).await.expect("Failed to store items");

        cache.persist(tmp_dir.path()).await;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path())
            .await
            .expect("Failed to load new segment_cache");

        assert_eq!(
            cache.get_items(10..20).await.expect("Failed to get items from segment cache"),
            items
        );
    }

    #[tokio::test]
    async fn test_segment_cache_get_insert() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path())
            .await
            .expect("Failed to create new segment_cache");

        let items = FilterHeader::dummy_batch(0..ITEMS_PER_SEGMENT * 2 + ITEMS_PER_SEGMENT / 2);

        cache.store_items(&items).await.expect("Failed to store items");

        assert_eq!(
            items[0..ITEMS_PER_SEGMENT as usize],
            cache.get_items(0..ITEMS_PER_SEGMENT).await.expect("Failed to get items")
        );

        assert_eq!(
            items[0..(ITEMS_PER_SEGMENT - 1) as usize],
            cache.get_items(0..ITEMS_PER_SEGMENT - 1).await.expect("Failed to get items")
        );

        assert_eq!(
            items[0..(ITEMS_PER_SEGMENT + 1) as usize],
            cache.get_items(0..ITEMS_PER_SEGMENT + 1).await.expect("Failed to get items")
        );
    }

    #[tokio::test]
    async fn test_segment_persist_load() {
        let tmp_dir = TempDir::new().unwrap();

        let segment_id = 10;

        const MAX_ITEMS: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        // Testing with half full segment
        let items = FilterHeader::dummy_batch(0..MAX_ITEMS / 2);
        let mut segment = Segment::new(segment_id, items.clone(), SegmentState::Dirty);

        assert_eq!(segment.first_valid_offset(), Some(0));
        assert_eq!(segment.last_valid_offset(), Some(MAX_ITEMS / 2 - 1));
        assert_eq!(segment.get(0..MAX_ITEMS / 2), &items[0..MAX_ITEMS as usize / 2]);
        assert_eq!(
            segment.get(MAX_ITEMS / 2 - 1..MAX_ITEMS / 2),
            [FilterHeader::dummy(MAX_ITEMS / 2 - 1)]
        );

        assert_eq!(segment.state, SegmentState::Dirty);
        assert!(segment.persist(tmp_dir.path()).await.is_ok());
        assert_eq!(segment.state, SegmentState::Clean);

        let mut loaded_segment =
            Segment::<FilterHeader>::load(tmp_dir.path(), segment_id).await.unwrap();

        assert_eq!(loaded_segment.first_valid_offset(), Some(0));
        assert_eq!(loaded_segment.last_valid_offset(), Some(MAX_ITEMS / 2 - 1));
        assert_eq!(loaded_segment.get(0..MAX_ITEMS / 2), &items[0..MAX_ITEMS as usize / 2]);
        assert_eq!(
            loaded_segment.get(MAX_ITEMS / 2 - 1..MAX_ITEMS / 2),
            [FilterHeader::dummy(MAX_ITEMS / 2 - 1)]
        );
    }

    #[tokio::test]
    async fn test_truncate_above_within_segment() {
        let tmp_dir = TempDir::new().unwrap();

        let items = FilterHeader::dummy_batch(0..20);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        assert_eq!(cache.tip_height(), Some(19));

        cache.truncate_above(9).await.unwrap();
        assert_eq!(cache.tip_height(), Some(9));
        assert_eq!(cache.start_height(), Some(0));

        let kept = cache.get_items(0..10).await.unwrap();
        assert_eq!(kept, items[0..10]);

        // Re-store into the truncated range — must not panic on the sentinel debug_assert.
        let replacement = FilterHeader::dummy_batch(100..110);
        cache.store_items_at_height(&replacement, 10).await.unwrap();
        assert_eq!(cache.tip_height(), Some(19));

        let reread = cache.get_items(10..20).await.unwrap();
        assert_eq!(reread, replacement);
    }

    #[tokio::test]
    async fn test_truncate_within_segment_persist_reload() {
        let tmp_dir = TempDir::new().unwrap();

        let items = FilterHeader::dummy_batch(0..20);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.truncate_above(9).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        // Reopen without re-storing to verify the boundary segment was rewritten
        // with sentinel slots above the cut. If `reset_above`'s dirty flag were
        // skipped, the stale on-disk slots would survive and `tip_height` would
        // come back as 19.
        let mut reloaded = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        assert_eq!(reloaded.tip_height(), Some(9));
        assert_eq!(reloaded.get_items(0..10).await.unwrap(), items[0..10]);
        for height in 10..20u32 {
            assert_eq!(reloaded.get_item(height).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn test_truncate_above_segment_boundary() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let items = FilterHeader::dummy_batch(0..ITEMS_PER_SEGMENT + 5);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        assert_eq!(cache.tip_height(), Some(ITEMS_PER_SEGMENT + 4));

        // Persist first so segment 1's file is actually on disk, otherwise the
        // post-truncate `!exists()` check below would be trivially true.
        cache.persist(tmp_dir.path()).await;
        let dropped_segment_file = tmp_dir.path().join(FilterHeader::segment_file_name(1));
        assert!(dropped_segment_file.exists());

        cache.truncate_above(ITEMS_PER_SEGMENT - 1).await.unwrap();
        assert_eq!(cache.tip_height(), Some(ITEMS_PER_SEGMENT - 1));

        let kept = cache.get_items(0..ITEMS_PER_SEGMENT).await.unwrap();
        assert_eq!(kept, items[0..ITEMS_PER_SEGMENT as usize]);

        cache.persist(tmp_dir.path()).await;
        assert!(!dropped_segment_file.exists());

        // Reload and verify the truncation is durable.
        let mut reloaded = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        assert_eq!(reloaded.tip_height(), Some(ITEMS_PER_SEGMENT - 1));

        // Re-storing into the dropped segment is sound.
        let new_items = FilterHeader::dummy_batch(500..505);
        reloaded.store_items_at_height(&new_items, ITEMS_PER_SEGMENT).await.unwrap();
        assert_eq!(reloaded.tip_height(), Some(ITEMS_PER_SEGMENT + 4));
        let reread = reloaded.get_items(ITEMS_PER_SEGMENT..ITEMS_PER_SEGMENT + 5).await.unwrap();
        assert_eq!(reread, new_items);
    }

    #[tokio::test]
    async fn test_truncate_above_then_store_into_dropped_segment_without_persist() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let items = FilterHeader::dummy_batch(0..ITEMS_PER_SEGMENT + 5);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.truncate_above(ITEMS_PER_SEGMENT - 1).await.unwrap();

        // Re-store into the dropped segment BEFORE persist runs. Without the
        // to_delete check in get_segment_mut, the stale on-disk file would be
        // loaded and the insert would hit the sentinel debug_assert.
        let replacement = FilterHeader::dummy_batch(500..505);
        cache.store_items_at_height(&replacement, ITEMS_PER_SEGMENT).await.unwrap();
        assert_eq!(cache.tip_height(), Some(ITEMS_PER_SEGMENT + 4));

        let reread = cache.get_items(ITEMS_PER_SEGMENT..ITEMS_PER_SEGMENT + 5).await.unwrap();
        assert_eq!(reread, replacement);

        cache.persist(tmp_dir.path()).await;
        let mut reloaded = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        assert_eq!(reloaded.tip_height(), Some(ITEMS_PER_SEGMENT + 4));
        let reread = reloaded.get_items(ITEMS_PER_SEGMENT..ITEMS_PER_SEGMENT + 5).await.unwrap();
        assert_eq!(reread, replacement);
    }

    #[tokio::test]
    async fn test_read_above_truncated_tip_preserves_deletion() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let items = FilterHeader::dummy_batch(0..ITEMS_PER_SEGMENT + 5);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        let dropped_segment_file = tmp_dir.path().join(FilterHeader::segment_file_name(1));
        assert!(dropped_segment_file.exists());

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.truncate_above(ITEMS_PER_SEGMENT - 1).await.unwrap();

        // Reading above the truncated tip must not cancel the pending deletion.
        // Without the to_delete short-circuit in get_item, this read would
        // remove the entry from to_delete and queue an all-sentinel rewrite.
        assert_eq!(cache.get_item(ITEMS_PER_SEGMENT + 2).await.unwrap(), None);
        assert_eq!(cache.get_item(ITEMS_PER_SEGMENT).await.unwrap(), None);

        cache.persist(tmp_dir.path()).await;
        assert!(!dropped_segment_file.exists());
    }

    #[tokio::test]
    async fn test_get_items_above_truncated_tip_preserves_deletion() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let items = FilterHeader::dummy_batch(0..ITEMS_PER_SEGMENT + 5);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        let dropped_segment_file = tmp_dir.path().join(FilterHeader::segment_file_name(1));
        assert!(dropped_segment_file.exists());

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.truncate_above(ITEMS_PER_SEGMENT - 1).await.unwrap();

        // A range read that spans into a segment queued for deletion must
        // error rather than consuming the deletion intent and handing back
        // sentinels.
        assert!(matches!(
            cache.get_items(ITEMS_PER_SEGMENT..ITEMS_PER_SEGMENT + 5).await,
            Err(StorageError::InvalidArgument(_))
        ));

        cache.persist(tmp_dir.path()).await;
        assert!(!dropped_segment_file.exists());
    }

    #[tokio::test]
    async fn test_truncate_above_tip_is_noop() {
        let tmp_dir = TempDir::new().unwrap();

        let items = FilterHeader::dummy_batch(0..10);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();

        cache.truncate_above(9).await.unwrap();
        assert_eq!(cache.tip_height(), Some(9));

        cache.truncate_above(100).await.unwrap();
        assert_eq!(cache.tip_height(), Some(9));

        let kept = cache.get_items(0..10).await.unwrap();
        assert_eq!(kept, items);
    }

    #[tokio::test]
    async fn test_truncate_empty_cache_is_noop() {
        let tmp_dir = TempDir::new().unwrap();

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();

        cache.truncate_above(0).await.unwrap();
        cache.truncate_above(100).await.unwrap();
        assert_eq!(cache.tip_height(), None);
    }

    #[tokio::test]
    async fn test_truncate_below_start_errors() {
        let tmp_dir = TempDir::new().unwrap();

        let items = FilterHeader::dummy_batch(0..5);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 10).await.unwrap();
        assert_eq!(cache.start_height(), Some(10));

        assert!(cache.truncate_above(5).await.is_err());
        assert_eq!(cache.tip_height(), Some(14));
        assert_eq!(cache.start_height(), Some(10));
    }

    #[tokio::test]
    async fn test_sequential_truncations_within_same_segment() {
        let tmp_dir = TempDir::new().unwrap();
        let items = FilterHeader::dummy_batch(0..30);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();

        cache.truncate_above(20).await.unwrap();
        assert_eq!(cache.tip_height(), Some(20));

        cache.truncate_above(10).await.unwrap();
        assert_eq!(cache.tip_height(), Some(10));
        assert_eq!(cache.start_height(), Some(0));

        // Re-store into the doubly-truncated range. Both `reset_above` passes
        // must have left the slots as sentinels for `insert` to remain sound.
        let replacement = FilterHeader::dummy_batch(200..220);
        cache.store_items_at_height(&replacement, 11).await.unwrap();
        assert_eq!(cache.tip_height(), Some(30));
        assert_eq!(cache.get_items(11..31).await.unwrap(), replacement);
    }

    #[tokio::test]
    async fn test_sequential_truncations_across_segment_boundaries() {
        let tmp_dir = TempDir::new().unwrap();

        const ITEMS_PER_SEGMENT: u32 = Segment::<FilterHeader>::ITEMS_PER_SEGMENT;

        let items = FilterHeader::dummy_batch(0..ITEMS_PER_SEGMENT * 3);

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.store_items_at_height(&items, 0).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        let mut cache = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        cache.truncate_above(ITEMS_PER_SEGMENT * 2 + 5).await.unwrap();
        cache.truncate_above(ITEMS_PER_SEGMENT + 5).await.unwrap();
        cache.persist(tmp_dir.path()).await;

        // Segment 2 must be gone on disk (dropped by the second cut),
        // segment 1 stays (its tail was reset by `reset_above`).
        assert!(!tmp_dir.path().join(FilterHeader::segment_file_name(2)).exists());
        assert!(tmp_dir.path().join(FilterHeader::segment_file_name(1)).exists());

        let mut reloaded = SegmentCache::<FilterHeader>::load_or_new(tmp_dir.path()).await.unwrap();
        assert_eq!(reloaded.tip_height(), Some(ITEMS_PER_SEGMENT + 5));
        let replacement = FilterHeader::dummy_batch(500..510);
        reloaded.store_items_at_height(&replacement, ITEMS_PER_SEGMENT + 6).await.unwrap();
        assert_eq!(
            reloaded.get_items(ITEMS_PER_SEGMENT + 6..ITEMS_PER_SEGMENT + 16).await.unwrap(),
            replacement
        );
    }

    #[test]
    fn test_segment_insert_get() {
        let segment_id = 10;

        let items = FilterHeader::dummy_batch(0..10);

        let mut segment = Segment::new(segment_id, items, SegmentState::Dirty);

        assert_eq!(segment.first_valid_offset(), Some(0));
        assert_eq!(segment.last_valid_offset(), Some(9));
        assert_eq!(segment.get(0..10), &(0..10).map(FilterHeader::dummy).collect::<Vec<_>>());

        segment.insert(FilterHeader::dummy(10), 10);

        assert_eq!(segment.last_valid_offset(), Some(10));
        assert_eq!(segment.get(0..11), &(0..11).map(FilterHeader::dummy).collect::<Vec<_>>());
    }
}
