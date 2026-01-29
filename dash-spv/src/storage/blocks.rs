//! Block storage for persisting full blocks that contain wallet-relevant transactions.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::error::StorageResult;
use crate::storage::segments::{Persistable, SegmentCache};
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
}

/// Persistent storage for full blocks using segmented files.
pub struct PersistentBlockStorage {
    /// Block storage segments.
    blocks: RwLock<SegmentCache<HashedBlock>>,
    /// Set of available block heights used for fast lookups and to bypass sentinel loading and gap
    /// detection asserts (in debug builds) in the underlying segment implementation.
    available_heights: HashSet<CoreBlockHeight>,
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

        let mut blocks: SegmentCache<HashedBlock> =
            SegmentCache::load_or_new(&blocks_folder).await?;

        let mut available_heights = HashSet::new();

        if let (Some(start), Some(end)) = (blocks.start_height(), blocks.tip_height()) {
            let hashed_blocks = blocks.get_items(start..end + 1).await?;
            let sentinel = HashedBlock::sentinel();
            for (i, hashed_block) in hashed_blocks.iter().enumerate() {
                if hashed_block != &sentinel {
                    available_heights.insert(start + i as CoreBlockHeight);
                }
            }
        }

        Ok(Self {
            blocks: RwLock::new(blocks),
            available_heights,
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
        self.available_heights.insert(height);
        self.blocks.write().await.store_items_at_height(&[hashed_block], height).await
    }

    async fn load_block(&self, height: u32) -> StorageResult<Option<HashedBlock>> {
        // This early return avoids unnecessary disk lookups and bypasses sentinel loading and gap
        // detection asserts (in debug builds) in the underlying segment implementation.
        if !self.available_heights.contains(&height) {
            return Ok(None);
        }
        Ok(self.blocks.write().await.get_items(height..height + 1).await?.first().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
