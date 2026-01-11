//! Header storage operations for DiskStorageManager.

use std::collections::HashMap;
use std::ops::Range;
use std::path::PathBuf;

use crate::error::StorageResult;
use crate::storage::io::atomic_write;
use crate::storage::segments::SegmentCache;
use crate::storage::PersistentStorage;
use crate::StorageError;
use async_trait::async_trait;
use dashcore::block::Header as BlockHeader;
use dashcore::BlockHash;
use tokio::sync::RwLock;

/// Represents the current chain tip with height, header, and hash.
#[derive(Debug, Clone)]
pub struct HeaderTip {
    pub height: u32,
    pub header: BlockHeader,
    pub hash: BlockHash,
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

    async fn get_header_tip(&self) -> Option<HeaderTip>;

    async fn get_start_height(&self) -> Option<u32>;

    async fn get_stored_headers_len(&self) -> u32;

    async fn get_header_height_by_hash(
        &self,
        hash: &dashcore::BlockHash,
    ) -> StorageResult<Option<u32>>;
}

pub struct PersistentBlockHeaderStorage {
    block_headers: RwLock<SegmentCache<BlockHeader>>,
    header_hash_index: HashMap<BlockHash, u32>,
    cached_tip: Option<HeaderTip>,
}

impl PersistentBlockHeaderStorage {
    const FOLDER_NAME: &str = "block_headers";
    const INDEX_FILE_NAME: &str = "index.dat";
}

#[async_trait]
impl PersistentStorage for PersistentBlockHeaderStorage {
    async fn open(storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let storage_path = storage_path.into();
        let segments_folder = storage_path.join(Self::FOLDER_NAME);

        let index_path = segments_folder.join(Self::INDEX_FILE_NAME);

        let mut block_headers = SegmentCache::load_or_new(&segments_folder).await?;

        let header_hash_index = match tokio::fs::read(&index_path)
            .await
            .ok()
            .and_then(|content| bincode::deserialize(&content).ok())
        {
            Some(index) => index,
            _ => {
                if segments_folder.exists() {
                    block_headers.build_block_index_from_segments().await?
                } else {
                    HashMap::new()
                }
            }
        };

        // Initialize cached tip if headers exist
        let cached_tip = if let Some(tip_height) = block_headers.tip_height() {
            let headers = block_headers.get_items(tip_height..tip_height + 1).await?;
            headers.first().map(|header| {
                let hash = header.block_hash();
                HeaderTip {
                    height: tip_height,
                    header: *header,
                    hash,
                }
            })
        } else {
            None
        };

        Ok(Self {
            block_headers: RwLock::new(block_headers),
            header_hash_index,
            cached_tip,
        })
    }

    async fn persist(&mut self, storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        let block_headers_folder = storage_path.into().join(Self::FOLDER_NAME);
        let index_path = block_headers_folder.join(Self::INDEX_FILE_NAME);

        tokio::fs::create_dir_all(&block_headers_folder).await?;

        self.block_headers.write().await.persist(&block_headers_folder).await;

        let data = bincode::serialize(&self.header_hash_index)
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
        if headers.is_empty() {
            return Ok(());
        }

        let mut current_height = height;

        let hashes = headers.iter().map(|header| header.block_hash()).collect::<Vec<_>>();

        self.block_headers.write().await.store_items_at_height(headers, height).await?;

        for hash in hashes.iter() {
            self.header_hash_index.insert(*hash, current_height);
            current_height += 1;
        }

        // Update cached tip if these headers extend the chain
        let new_tip_height = current_height - 1;
        if self.cached_tip.as_ref().map_or(true, |tip| new_tip_height > tip.height) {
            let last_header = headers.last().unwrap();
            let last_hash = hashes.last().unwrap();
            self.cached_tip = Some(HeaderTip {
                height: new_tip_height,
                header: *last_header,
                hash: *last_hash,
            });
        }

        Ok(())
    }

    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        self.block_headers.write().await.get_items(range).await
    }

    async fn get_tip_height(&self) -> Option<u32> {
        self.block_headers.read().await.tip_height()
    }

    async fn get_header_tip(&self) -> Option<HeaderTip> {
        self.cached_tip.clone()
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
