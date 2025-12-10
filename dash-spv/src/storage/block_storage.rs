//! Block storage for persisting full blocks that contain wallet-relevant transactions.

use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

use async_trait::async_trait;
use bincode::config;
use bincode::serde::{decode_from_slice, encode_to_vec};
use dashcore::{Block, BlockHash};
use tokio::sync::RwLock;

use crate::error::StorageResult;
use crate::storage::io::atomic_write;
use crate::storage::segments::SegmentCache;
use crate::storage::PersistentStorage;
use crate::StorageError;

/// Trait for block storage operations.
#[async_trait]
pub trait BlockStorage: Send + Sync + 'static {
    /// Store a block at a specific height.
    async fn store_block(&mut self, height: u32, block: &Block) -> StorageResult<()>;

    /// Load a single block by height.
    async fn load_block(&self, height: u32) -> StorageResult<Option<Block>>;

    /// Load blocks for a given height range.
    async fn load_blocks(&self, range: Range<u32>) -> StorageResult<Vec<Block>>;

    /// Get the tip height of stored blocks.
    async fn get_block_tip_height(&self) -> Option<u32>;

    /// Get the start height of stored blocks.
    async fn get_block_start_height(&self) -> Option<u32>;

    /// Check if a block exists by hash.
    async fn has_block(&self, hash: &BlockHash) -> bool;

    /// Get block height by hash.
    async fn get_block_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>>;
}

/// Persistent storage for full blocks using segmented files.
pub struct PersistentBlockStorage {
    blocks: RwLock<SegmentCache<Block>>,
    block_hash_index: HashMap<BlockHash, u32>,
}

impl PersistentBlockStorage {
    const FOLDER_NAME: &str = "blocks";
    const INDEX_FILE_NAME: &str = "block_index.dat";
}

#[async_trait]
impl PersistentStorage for PersistentBlockStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let blocks_folder = storage_path.join(Self::FOLDER_NAME);
        let index_path = blocks_folder.join(Self::INDEX_FILE_NAME);

        tracing::debug!("Opening PersistentBlockStorage from {:?}", blocks_folder);

        let blocks = SegmentCache::load_or_new(&blocks_folder).await.map_err(|e| {
            tracing::error!("Failed to load block segments from {:?}: {}", blocks_folder, e);
            e
        })?;

        // Load index if it exists
        let block_hash_index = match tokio::fs::read(&index_path).await {
            Ok(content) => {
                decode_from_slice(&content, config::standard()).map(|(v, _)| v).unwrap_or_default()
            }
            Err(_) => HashMap::new(),
        };

        Ok(Self {
            blocks: RwLock::new(blocks),
            block_hash_index,
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let blocks_folder = storage_path.into().join(Self::FOLDER_NAME);
        let index_path = blocks_folder.join(Self::INDEX_FILE_NAME);

        tokio::fs::create_dir_all(&blocks_folder).await?;

        self.blocks.write().await.persist(&blocks_folder).await;

        // Persist the hash index
        let data = encode_to_vec(&self.block_hash_index, config::standard()).map_err(|e| {
            StorageError::WriteFailed(format!("Failed to serialize block index: {}", e))
        })?;

        atomic_write(&index_path, &data).await
    }
}

#[async_trait]
impl BlockStorage for PersistentBlockStorage {
    async fn store_block(&mut self, height: u32, block: &Block) -> StorageResult<()> {
        let hash = block.block_hash();

        // Skip if block already exists
        if self.block_hash_index.contains_key(&hash) {
            return Ok(());
        }

        self.blocks
            .write()
            .await
            .store_items_at_height(std::slice::from_ref(block), height)
            .await?;
        self.block_hash_index.insert(hash, height);

        Ok(())
    }

    async fn load_block(&self, height: u32) -> StorageResult<Option<Block>> {
        let tip_height = match self.blocks.read().await.tip_height() {
            Some(h) => h,
            None => return Ok(None),
        };

        if height > tip_height {
            return Ok(None);
        }

        let start_height = match self.blocks.read().await.start_height() {
            Some(h) => h,
            None => return Ok(None),
        };

        if height < start_height {
            return Ok(None);
        }

        Ok(self.blocks.write().await.get_items(height..height + 1).await?.into_iter().next())
    }

    async fn load_blocks(&self, range: Range<u32>) -> StorageResult<Vec<Block>> {
        self.blocks.write().await.get_items(range).await
    }

    async fn get_block_tip_height(&self) -> Option<u32> {
        self.blocks.read().await.tip_height()
    }

    async fn get_block_start_height(&self) -> Option<u32> {
        self.blocks.read().await.start_height()
    }

    async fn has_block(&self, hash: &BlockHash) -> bool {
        self.block_hash_index.contains_key(hash)
    }

    async fn get_block_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.block_hash_index.get(hash).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::block::{Header, Version};
    use dashcore::pow::CompactTarget;
    use dashcore_hashes::Hash;
    use tempfile::TempDir;

    fn create_test_block(height: u32) -> Block {
        Block {
            header: Header {
                version: Version::from_consensus(1),
                prev_blockhash: BlockHash::from_byte_array([height as u8; 32]),
                merkle_root: dashcore::hashes::sha256d::Hash::from_byte_array([height as u8; 32])
                    .into(),
                time: height,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: height,
            },
            txdata: vec![],
        }
    }

    #[tokio::test]
    async fn test_store_and_load_block() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        let block = create_test_block(100);
        let hash = block.block_hash();

        storage.store_block(100, &block).await.unwrap();

        let loaded = storage.load_block(100).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().block_hash(), hash);
    }

    #[tokio::test]
    async fn test_has_block() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        let block = create_test_block(50);
        let hash = block.block_hash();

        assert!(!storage.has_block(&hash).await);

        storage.store_block(50, &block).await.unwrap();

        assert!(storage.has_block(&hash).await);
    }

    #[tokio::test]
    async fn test_get_block_height_by_hash() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        let block = create_test_block(200);
        let hash = block.block_hash();

        storage.store_block(200, &block).await.unwrap();

        let height = storage.get_block_height_by_hash(&hash).await.unwrap();
        assert_eq!(height, Some(200));
    }

    #[tokio::test]
    async fn test_persist_and_reload() {
        let temp_dir = TempDir::new().unwrap();
        let block_hash;

        {
            let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
            let block = create_test_block(100);
            block_hash = block.block_hash();
            storage.store_block(100, &block).await.unwrap();
            storage.persist(temp_dir.path()).await.unwrap();
        }

        {
            let storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();
            assert!(storage.has_block(&block_hash).await);
            assert_eq!(storage.get_block_tip_height().await, Some(100));
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
    async fn test_multiple_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockStorage::open(temp_dir.path()).await.unwrap();

        for height in [10, 20, 30] {
            let block = create_test_block(height);
            storage.store_block(height, &block).await.unwrap();
        }

        assert_eq!(storage.get_block_tip_height().await, Some(30));
        assert_eq!(storage.get_block_start_height().await, Some(10));

        for height in [10, 20, 30] {
            let loaded = storage.load_block(height).await.unwrap();
            assert!(loaded.is_some());
        }
    }
}
