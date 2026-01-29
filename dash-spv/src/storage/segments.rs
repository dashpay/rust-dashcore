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
        // If the segment is not in the to_persist map, load it from disk.
        let segment = if let Some(segment) = self.evicted.remove(segment_id) {
            segment
        } else {
            Segment::load(&self.segments_dir, *segment_id).await?
        };

        let segment = self.segments.entry(*segment_id).or_insert(segment);
        Ok(segment)
    }

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

    pub async fn persist(&mut self, segments_dir: impl Into<PathBuf>) {
        let segments_dir = segments_dir.into();

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
