//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

use crate::error::StorageResult;
use crate::storage::segments::SegmentCache;
use crate::storage::PersistentStorage;
use crate::types::HashedBlockHeader;
use async_trait::async_trait;
use dashcore::block::Header as BlockHeader;
use dashcore::prelude::CoreBlockHeight;
use dashcore::BlockHash;
use tokio::sync::RwLock;

#[derive(Debug, PartialEq)]
pub struct BlockHeaderTip {
    height: CoreBlockHeight,
    header: BlockHeader,
    hash: BlockHash,
}

impl BlockHeaderTip {
    pub fn new(height: CoreBlockHeight, hashed_block_header: HashedBlockHeader) -> Self {
        Self {
            height,
            header: *hashed_block_header.header(),
            hash: *hashed_block_header.hash(),
        }
    }
    pub fn height(&self) -> CoreBlockHeight {
        self.height
    }
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }
    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }
}

#[async_trait]
pub trait BlockHeaderStorage {
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()>;

    async fn store_headers_at_height(
        &mut self,
        headers: &[BlockHeader],
        height: u32,
    ) -> StorageResult<()>;

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>>;

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

    async fn get_tip_height(&self) -> Option<u32>;

    async fn get_tip(&self) -> Option<BlockHeaderTip>;

    async fn get_start_height(&self) -> Option<u32>;

    async fn get_stored_headers_len(&self) -> u32;

    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>>;
}

pub struct PersistentBlockHeaderStorage {
    block_headers: RwLock<SegmentCache<HashedBlockHeader>>,
    header_hash_index: HashMap<BlockHash, u32>,
}

impl PersistentBlockHeaderStorage {
    const FOLDER_NAME: &str = "block_headers";
}

#[async_trait]
impl PersistentStorage for PersistentBlockHeaderStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let segments_folder = storage_path.join(Self::FOLDER_NAME);

        let mut block_headers: SegmentCache<HashedBlockHeader> =
            SegmentCache::load_or_new(&segments_folder).await?;

        let mut header_hash_index = HashMap::new();

        if let (Some(start), Some(end)) = (block_headers.start_height(), block_headers.tip_height())
        {
            let headers = block_headers.get_items(start..end + 1).await?;
            for (i, header) in headers.iter().enumerate() {
                let height = start + i as u32;
                header_hash_index.insert(*header.hash(), height);
            }
        }

        Ok(Self {
            block_headers: RwLock::new(block_headers),
            header_hash_index,
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let block_headers_folder = storage_path.into().join(Self::FOLDER_NAME);

        tokio::fs::create_dir_all(&block_headers_folder).await?;

        self.block_headers.write().await.persist(&block_headers_folder).await;

        Ok(())
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
        let headers =
            headers.iter().map(HashedBlockHeader::from).collect::<Vec<HashedBlockHeader>>();

        self.block_headers.write().await.store_items_at_height(&headers, height).await?;

        for header in headers {
            self.header_hash_index.insert(*header.hash(), height);
            height += 1;
        }

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        Ok(self
            .block_headers
            .write()
            .await
            .get_items(range)
            .await?
            .into_iter()
            .map(|cached| *cached.header())
            .collect())
    }

    async fn get_tip_height(&self) -> Option<u32> {
        self.block_headers.read().await.tip_height()
    }

    async fn get_tip(&self) -> Option<BlockHeaderTip> {
        let mut block_headers = self.block_headers.write().await;
        let tip_height = block_headers.tip_height()?;
        let hashed_header =
            block_headers.get_items(tip_height..tip_height + 1).await.ok()?.into_iter().next()?;
        Some(BlockHeaderTip::new(tip_height, hashed_header))
    }

    async fn get_start_height(&self) -> Option<u32> {
        self.block_headers.read().await.start_height()
    }

    async fn get_stored_headers_len(&self) -> u32 {
        let block_headers = self.block_headers.read().await;

        let start_height = if let Some(start_height) = block_headers.start_height() {
            start_height
        } else {
            return 0;
        };

        let end_height = if let Some(end_height) = block_headers.tip_height() {
            end_height
        } else {
            return 0;
        };

        end_height - start_height + 1
    }

    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>> {
        Ok(self.header_hash_index.get(hash).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_get_tip() {
        let headers = BlockHeader::dummy_batch(0..5);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        // Tip should be none before storing headers
        assert!(storage.get_tip().await.is_none());
        // Add one header and validate tip
        storage.store_headers(&headers[0..1]).await.unwrap();
        let tip = storage.get_tip().await.unwrap();
        let expected_tip = BlockHeaderTip::new(0, HashedBlockHeader::from(headers[0]));
        assert_eq!(tip, expected_tip);
        assert_eq!(storage.get_tip_height().await, Some(0));
        // Add multiple headers and validate tip
        storage.store_headers(&headers[1..]).await.unwrap();
        let tip = storage.get_tip().await.unwrap();
        let expected_tip = BlockHeaderTip::new(4, HashedBlockHeader::from(headers[4]));
        assert_eq!(tip, expected_tip);
        assert_eq!(storage.get_tip_height().await, Some(4));
    }
}
