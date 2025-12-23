//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use dashcore::block::Header as BlockHeader;
use dashcore::BlockHash;

use crate::error::StorageResult;
use crate::storage::io::atomic_write;
use crate::storage::segments::SegmentCache;
use crate::storage::PersistentStorage;
use crate::StorageError;

#[async_trait]
pub trait BlockHeaderStorage {
    /// Store block headers.
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()>;

    /// Store block headers.
    async fn store_headers_at_height(
        &mut self,
        headers: &[BlockHeader],
        height: u32,
    ) -> StorageResult<()>;

    /// Load block headers in the given range.
    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>>;

    /// Get a specific header by blockchain height.
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>>;

    /// Get the current tip blockchain height.
    async fn get_tip_height(&self) -> Option<u32>;

    async fn get_start_height(&self) -> Option<u32>;

    async fn get_stored_headers_len(&self) -> u32;

    /// Get header height by block hash (reverse lookup).
    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>>;
}

pub struct PersistentBlockHeaderStorage {
    block_headers: Arc<RwLock<SegmentCache<BlockHeader>>>,
    header_hash_index: Arc<RwLock<HashMap<BlockHash, u32>>>,
}

#[async_trait]
impl PersistentStorage for PersistentBlockHeaderStorage {
    async fn load(&self) -> StorageResult<Self> {
        let index_path = self.base_path.join("headers/index.dat");

        let block_headers = SegmentCache::load_or_new(base_path).await;

        let header_hash_index = if let Ok(index) =
            tokio::fs::read(&index_path).await.and_then(|content| bincode::deserialize(&content))
        {
            index
        } else {
            block_headers.build_block_index_from_segments().await
        };

        let block_headers = Arc::new(RwLock::new(block_headers));
        let header_hash_index = Arc::new(RwLock::new(header_hash_index));

        Ok(Self {
            block_headers,
            header_hash_index,
        })
    }

    async fn persist(&self) {
        let index_path = self.base_path.join("headers/index.dat");

        self.block_headers.write().await.persist().await;

        let data = bincode::serialize(&self.header_hash_index.read().await)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to serialize index: {}", e)))?;

        atomic_write(&index_path, &data).await
    }
}

#[async_trait]
impl BlockHeaderStorage for PersistentBlockHeaderStorage {
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let height = self.block_headers.read().await.next_height();
        self.store_headers_at_height(headers, height).await
    }

    async fn store_headers_at_height(
        &mut self,
        headers: &[BlockHeader],
        height: u32,
    ) -> StorageResult<()> {
        let mut height = height;

        let hashes = headers.iter().map(|header| header.block_hash()).collect::<Vec<_>>();

        self.block_headers.write().await.store_items_at_height(headers, height).await?;

        // Update reverse index
        let mut reverse_index = self.header_hash_index.write().await;

        for hash in hashes {
            reverse_index.insert(hash, height);
            height += 1;
        }

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.block_headers.write().await.get_items(range).await
    }

    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        if let Some(tip_height) = self.get_tip_height().await {
            if height > tip_height {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        if let Some(start_height) = self.get_start_height().await {
            if height < start_height {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        Ok(self.block_headers.write().await.get_items(height..height + 1).await?.first().copied())
    }

    async fn get_tip_height(&self) -> Option<u32> {
        self.block_headers.read().await.tip_height()
    }

    async fn get_start_height(&self) -> Option<u32> {
        self.block_headers.read().await.start_height()
    }

    async fn get_stored_headers_len(&self) -> u32 {
        let headers_guard = self.block_headers.read().await;
        let start_height = if let Some(start_height) = headers_guard.start_height() {
            start_height
        } else {
            return 0;
        };

        let end_height = if let Some(end_height) = headers_guard.tip_height() {
            end_height
        } else {
            return 0;
        };

        end_height - start_height + 1
    }

    /// Get header height by block hash (reverse lookup).
    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.read().await.get(hash).copied())
    }
}
