use std::collections::HashMap;
use std::ops::Range;

use async_trait::async_trait;
use dashcore::BlockHash;

use crate::error::StorageResult;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip};
use crate::types::HashedBlockHeader;

/// A [`BlockHeaderStorage`] that answers hash lookups from a map and nothing else.
/// Everything outside `get_header_height_by_hash` is inert.
pub struct MockHeaderStorage(pub HashMap<BlockHash, u32>);

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
    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.0.get(hash).copied())
    }
    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.0.retain(|_, h| *h <= target_height);
        Ok(())
    }
}
