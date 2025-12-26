//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

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
    block_headers: SegmentCache<BlockHeader>,
    header_hash_index: HashMap<BlockHash, u32>,
}

impl PersistentBlockHeaderStorage {
    const FOLDER_NAME: &str = "block_headers";
    const INDEX_FILE_NAME: &str = "index.dat";
}

#[async_trait]
impl PersistentStorage for PersistentBlockHeaderStorage {
    async fn load(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();

        let index_path = storage_path.join(Self::FOLDER_NAME).join(Self::INDEX_FILE_NAME);

        let block_headers = SegmentCache::load_or_new(storage_path).await?;

        let header_hash_index = match tokio::fs::read(&index_path)
            .await
            .ok()
            .map(|content| bincode::deserialize(&content).ok())
            .flatten()
        {
            Some(index) => index,
            _ => block_headers.build_block_index_from_segments().await?,
        };

        Ok(Self {
            block_headers,
            header_hash_index,
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let block_headers_folder = storage_path.into().join(Self::FOLDER_NAME);
        let index_path = block_headers_folder.join(Self::INDEX_FILE_NAME);

        tokio::fs::create_dir_all(&block_headers_folder).await?;

        self.block_headers.persist(&block_headers_folder).await;

        let data = bincode::serialize(&self.header_hash_index)
            .map_err(|e| StorageError::WriteFailed(format!("Failed to serialize index: {}", e)))?;

        atomic_write(&index_path, &data).await
    }
}

#[async_trait]
impl BlockHeaderStorage for PersistentBlockHeaderStorage {
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()> {
        let height = self.block_headers.next_height();
        self.store_headers_at_height(headers, height).await
    }

    async fn store_headers_at_height(
        &mut self,
        headers: &[BlockHeader],
        height: u32,
    ) -> StorageResult<()> {
        let mut height = height;

        let hashes = headers.iter().map(|header| header.block_hash()).collect::<Vec<_>>();

        self.block_headers.store_items_at_height(headers, height).await?;

        for hash in hashes {
            self.header_hash_index.insert(hash, height);
            height += 1;
        }

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.block_headers.get_items(range).await
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

        Ok(self.load_headers(height..height + 1).await?.first().copied())
    }

    async fn get_tip_height(&self) -> Option<u32> {
        self.block_headers.tip_height()
    }

    async fn get_start_height(&self) -> Option<u32> {
        self.block_headers.start_height()
    }

    async fn get_stored_headers_len(&self) -> u32 {
        let start_height = if let Some(start_height) = self.block_headers.start_height() {
            start_height
        } else {
            return 0;
        };

        let end_height = if let Some(end_height) = self.block_headers.tip_height() {
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
        Ok(self.header_hash_index.get(hash).copied())
    }
}
