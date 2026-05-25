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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;
    use tokio::sync::Barrier;

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
    async fn test_truncate_above_drops_blocks_and_allows_restore() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        for height in 100..110 {
            storage.store_block(height, HashedBlock::dummy(height, vec![])).await.unwrap();
        }

        storage.truncate_above(104).await.unwrap();

        assert_eq!(storage.load_block(104).await.unwrap(), Some(HashedBlock::dummy(104, vec![])));
        for height in 105..110 {
            assert_eq!(storage.load_block(height).await.unwrap(), None);
        }

        let replacement = HashedBlock::dummy(105, vec![]);
        storage.store_block(105, replacement.clone()).await.unwrap();
        assert_eq!(storage.load_block(105).await.unwrap(), Some(replacement));
    }

    #[tokio::test]
    async fn test_truncate_above_persist_reopen_blocks() {
        let temp_dir = TempDir::new().unwrap();
        {
            let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
            for height in 100..110 {
                storage.store_block(height, HashedBlock::dummy(height, vec![])).await.unwrap();
            }
            storage.truncate_above(104).await.unwrap();
            storage.persist(temp_dir.path()).await.unwrap();
        }

        let storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
        assert_eq!(storage.load_block(104).await.unwrap(), Some(HashedBlock::dummy(104, vec![])));
        for height in 105..110 {
            assert_eq!(storage.load_block(height).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn test_truncate_above_tip_noop_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        storage.store_block(50, HashedBlock::dummy(50, vec![])).await.unwrap();
        storage.truncate_above(1_000).await.unwrap();
        assert_eq!(storage.load_block(50).await.unwrap(), Some(HashedBlock::dummy(50, vec![])));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_truncate_and_read_under_contention() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
        for height in 0..20 {
            storage.store_block(height, HashedBlock::dummy(height, vec![])).await.unwrap();
        }

        // The outer `RwLock` is required because `truncate_above` takes `&mut self`
        // and so the writer and reader cannot literally execute in parallel, but a
        // `Barrier` guarantees both tasks are scheduled and racing for the lock
        // before either acquires it. Under the multi-thread runtime this exercises
        // the read/write contention path while keeping the post-state assertions
        // deterministic.
        let shared = Arc::new(RwLock::new(storage));
        let barrier = Arc::new(Barrier::new(2));

        let reader = {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                for _ in 0..50 {
                    let _ = shared.read().await.load_block(5).await.unwrap();
                }
            })
        };

        let writer = {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                shared.write().await.truncate_above(10).await.unwrap();
            })
        };

        reader.await.unwrap();
        writer.await.unwrap();

        let guard = shared.read().await;
        assert_eq!(guard.load_block(5).await.unwrap(), Some(HashedBlock::dummy(5, vec![])));
        assert_eq!(guard.load_block(15).await.unwrap(), None);
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
