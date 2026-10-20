//! Block storage for persisting full blocks that contain wallet-relevant transactions.

use std::path::PathBuf;

use crate::error::StorageResult;
use crate::storage::segments::SegmentCache;
use crate::storage::PersistentStorage;
use crate::types::HashedBlock;
use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use tokio::sync::RwLock;

/// Trait for block storage operations.
#[async_trait]
pub trait BlockStorage: Send + Sync + 'static {
    /// Store a block at a specific height.
    async fn store_block(
        &mut self,
        height: CoreBlockHeight,
        block: HashedBlock,
    ) -> StorageResult<()>;

    /// Load a single block by height.
    async fn load_block(&self, height: CoreBlockHeight) -> StorageResult<Option<HashedBlock>>;

    /// Drop all blocks with `height > target_height`.
    ///
    /// Truncating above the current tip is a no-op, truncating below
    /// `start_height` returns an error. Changes are applied in-memory and
    /// flushed on the next `persist`.
    ///
    /// The truncation is not durable until the next successful `persist` call.
    /// A crash between `truncate_above` and `persist` may leave orphaned segment
    /// files on disk and cause the storage to reopen at the pre-truncation tip.
    async fn truncate_above(&mut self, target_height: CoreBlockHeight) -> StorageResult<()>;

    /// Declare the highest block height that has been applied to every
    /// interested wallet, allowing the storage to stop holding those block
    /// bodies in memory.
    ///
    /// Blocks at or below this height stay readable: `load_block` reloads them
    /// from disk on demand. The watermark may move backwards when a rescan
    /// re-processes lower heights.
    ///
    /// Defaults to a no-op for implementations that hold no in-memory cache.
    async fn set_committed_height(&mut self, _height: CoreBlockHeight) {}
}

/// Persistent storage for full blocks using segmented files.
pub struct PersistentBlockStorage {
    /// Block storage segments.
    blocks: RwLock<SegmentCache<HashedBlock>>,
}

impl PersistentBlockStorage {
    const FOLDER_NAME: &str = "blocks";
}

#[async_trait]
impl PersistentStorage for PersistentBlockStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let blocks_folder = storage_path.join(Self::FOLDER_NAME);

        tracing::debug!("Opening PersistentBlockStorage from {:?}", blocks_folder);

        let blocks: SegmentCache<HashedBlock> = SegmentCache::load_or_new(&blocks_folder).await?;

        Ok(Self {
            blocks: RwLock::new(blocks),
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let blocks_folder = storage_path.into().join(Self::FOLDER_NAME);
        tokio::fs::create_dir_all(&blocks_folder).await?;
        self.blocks.write().await.persist(&blocks_folder).await;
        Ok(())
    }
}

#[async_trait]
impl BlockStorage for PersistentBlockStorage {
    async fn store_block(&mut self, height: u32, hashed_block: HashedBlock) -> StorageResult<()> {
        self.blocks.write().await.store_items_at_height(&[hashed_block], height).await
    }

    async fn load_block(&self, height: u32) -> StorageResult<Option<HashedBlock>> {
        self.blocks.write().await.get_item(height).await
    }

    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.blocks.write().await.truncate_above(target_height).await
    }

    async fn set_committed_height(&mut self, height: u32) {
        self.blocks.write().await.set_committed_height(height);
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_store_and_load_block() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        let hashed_block = HashedBlock::dummy(100, vec![]);
        storage.store_block(100, hashed_block.clone()).await.unwrap();

        let loaded = storage.load_block(100).await.unwrap();
        assert_eq!(loaded, Some(hashed_block));
    }

    #[tokio::test]
    async fn test_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let hashed_block = HashedBlock::dummy(100, vec![]);

        {
            let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
            storage.store_block(100, hashed_block.clone()).await.unwrap();
            storage.persist(temp_dir.path()).await.unwrap();
        }

        {
            let storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
            let loaded = storage.load_block(100).await.unwrap();
            assert_eq!(loaded, Some(hashed_block));
        }
    }

    #[tokio::test]
    async fn test_load_nonexistent_block() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        let loaded = storage.load_block(999).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_truncate_above_wrapper_smoke() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        for height in 0..5 {
            storage.store_block(height, HashedBlock::dummy(height, vec![])).await.unwrap();
        }

        storage.truncate_above(2).await.unwrap();

        assert_eq!(storage.load_block(2).await.unwrap(), Some(HashedBlock::dummy(2, vec![])));
        assert_eq!(storage.load_block(3).await.unwrap(), None);
    }

    /// Block bodies are the dominant memory consumer during a long backfill.
    /// Once applied, they must leave memory while staying loadable from disk —
    /// `handle_sync_event` re-reads stored blocks by height on resume/rescan.
    #[tokio::test]
    async fn test_committed_blocks_are_released_but_still_loadable() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        // One block in each of segments 0, 1 and 2 (50_000 heights per segment).
        // Carry real transaction payloads so the reload proves the block bodies
        // round-trip, not merely that a slot is occupied.
        let txs = vec![dashcore::Transaction::dummy_empty()];
        let low = HashedBlock::dummy(10, txs.clone());
        let mid = HashedBlock::dummy(50_010, txs.clone());
        let tip = HashedBlock::dummy(100_010, txs);

        storage.store_block(10, low.clone()).await.unwrap();
        storage.store_block(50_010, mid.clone()).await.unwrap();
        storage.store_block(100_010, tip.clone()).await.unwrap();
        storage.persist(temp_dir.path()).await.unwrap();

        assert_eq!(storage.blocks.read().await.resident_segment_ids(), vec![0, 1, 2]);

        // Everything below segment 2 has been applied to the wallets.
        storage.set_committed_height(99_999).await;
        storage.persist(temp_dir.path()).await.unwrap();

        // Segments 0 and 1 are gone from memory; the frontier segment stays.
        assert_eq!(
            storage.blocks.read().await.resident_segment_ids(),
            vec![2],
            "applied block segments must be released"
        );

        // All three blocks still load, byte-identically, via the disk fallback.
        assert_eq!(storage.load_block(10).await.unwrap(), Some(low));
        assert_eq!(storage.load_block(50_010).await.unwrap(), Some(mid));
        assert_eq!(storage.load_block(100_010).await.unwrap(), Some(tip));

        // Gaps inside a released segment still report absent, not sentinel data.
        assert_eq!(storage.load_block(11).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_returns_none_for_gaps() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        // Store blocks at non-contiguous height
        let hashed_block_1 = HashedBlock::dummy(100, vec![]);
        let hashed_block_2 = HashedBlock::dummy(200, vec![]);

        storage.store_block(100, hashed_block_1.clone()).await.unwrap();
        storage.store_block(200, hashed_block_2.clone()).await.unwrap();

        // Stored blocks should load correctly
        assert_eq!(storage.load_block(100).await.unwrap(), Some(hashed_block_1));
        assert_eq!(storage.load_block(200).await.unwrap(), Some(hashed_block_2));

        // Height in between (gap) should return None, not a sentinel
        assert_eq!(storage.load_block(150).await.unwrap(), None);

        // Heights outside range should also return None
        assert_eq!(storage.load_block(50).await.unwrap(), None);
        assert_eq!(storage.load_block(250).await.unwrap(), None);
    }
}
