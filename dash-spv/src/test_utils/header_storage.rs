use std::collections::HashMap;
use std::ops::Range;

use async_trait::async_trait;
use dashcore::block::Header;
use dashcore::network::message_sml::MnListDiff;
use dashcore::{BlockHash, TxMerkleNode};

use crate::error::StorageResult;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip};
use crate::types::HashedBlockHeader;

/// A [`BlockHeaderStorage`] that answers hash lookups and header reads from
/// maps and nothing else. Everything outside `get_header_height_by_hash` and
/// `get_header` is inert.
#[derive(Default)]
pub struct MockHeaderStorage {
    heights: HashMap<BlockHash, u32>,
    headers: HashMap<u32, HashedBlockHeader>,
}

impl MockHeaderStorage {
    /// Knows the height of every block in `heights` and holds no header.
    pub fn new(heights: HashMap<BlockHash, u32>) -> Self {
        MockHeaderStorage {
            heights,
            headers: HashMap::new(),
        }
    }

    /// Holds a header for `block_hash`, whose height must be known, that
    /// commits to `merkle_root`. The rest of the header is filler, and it is
    /// stored under `block_hash` rather than its own hash.
    pub fn with_header(mut self, block_hash: BlockHash, merkle_root: TxMerkleNode) -> Self {
        let height = *self.heights.get(&block_hash).expect("the block's height is known");
        let header = Header {
            merkle_root,
            ..Header::dummy(height)
        };
        self.headers.insert(height, HashedBlockHeader::with_trusted_hash(header, block_hash));
        self
    }

    /// Holds the header of `diff`'s block that its coinbase proof leads to, as
    /// [`MnListDiff::with_coinbase_committing_to`] sets it up.
    pub fn with_header_for(self, diff: &MnListDiff) -> Self {
        self.with_header(diff.block_hash, diff.dummy_block_merkle_root())
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
    async fn get_header(&self, height: u32) -> StorageResult<Option<HashedBlockHeader>> {
        Ok(self.headers.get(&height).cloned())
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
        Ok(self.heights.get(hash).copied())
    }
    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.heights.retain(|_, h| *h <= target_height);
        self.headers.retain(|h, _| *h <= target_height);
        Ok(())
    }
}
