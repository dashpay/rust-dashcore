use std::collections::HashMap;
use std::ops::Range;

use async_trait::async_trait;
use dashcore::block::Header as BlockHeader;
use dashcore::{BlockHash, TxMerkleNode};

use crate::error::StorageResult;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip};
use crate::types::HashedBlockHeader;

/// A [`BlockHeaderStorage`] that answers hash and height lookups from a map
/// and nothing else. A header it returns carries the mapped hash on a dummy
/// header, with its mapped merkle root if any. Everything else is inert.
#[derive(Default)]
pub struct MockHeaderStorage {
    pub heights: HashMap<BlockHash, u32>,
    pub merkle_roots: HashMap<BlockHash, TxMerkleNode>,
}

impl MockHeaderStorage {
    pub fn new(heights: HashMap<BlockHash, u32>) -> Self {
        Self {
            heights,
            merkle_roots: HashMap::new(),
        }
    }
}

#[async_trait]
impl BlockHeaderStorage for MockHeaderStorage {
    async fn store_headers(&mut self, _: &[HashedBlockHeader]) -> StorageResult<()> {
        Ok(())
    }
    async fn store_headers_at_height(
        &mut self,
        _: &[HashedBlockHeader],
        _: u32,
    ) -> StorageResult<()> {
        Ok(())
    }
    async fn load_headers(&self, _: Range<u32>) -> StorageResult<Vec<HashedBlockHeader>> {
        Ok(vec![])
    }
    async fn get_tip_height(&self) -> Option<u32> {
        None
    }
    async fn get_tip(&self) -> Option<BlockHeaderTip> {
        None
    }
    async fn get_start_height(&self) -> Option<u32> {
        None
    }
    async fn get_stored_headers_len(&self) -> u32 {
        0
    }
    async fn get_header(&self, height: u32) -> StorageResult<Option<HashedBlockHeader>> {
        Ok(self.heights.iter().find(|(_, h)| **h == height).map(|(hash, _)| {
            let mut header = BlockHeader::dummy(height);
            if let Some(merkle_root) = self.merkle_roots.get(hash) {
                header.merkle_root = *merkle_root;
            }
            HashedBlockHeader::with_trusted_hash(header, *hash)
        }))
    }
    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.heights.get(hash).copied())
    }
    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.heights.retain(|_, h| *h <= target_height);
        Ok(())
    }
}
