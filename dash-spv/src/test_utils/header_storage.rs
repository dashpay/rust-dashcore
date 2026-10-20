use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use async_trait::async_trait;
use dashcore::block::Header as BlockHeader;
use dashcore::hashes::Hash;
use dashcore::network::message_sml::MnListDiff;
use dashcore::{BlockHash, TxMerkleNode};

use crate::error::StorageResult;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip};
use crate::types::HashedBlockHeader;

/// A [`BlockHeaderStorage`] that answers hash and height lookups for a chain
/// of one block per height and nothing else. A header it returns carries the
/// block's hash on a dummy header, with the merkle root [`Self::prove`]
/// recorded for the block, or the all-zero one. Everything else is inert.
#[derive(Clone)]
pub struct MockHeaderStorage {
    heights: HashMap<BlockHash, u32>,
    blocks: BTreeMap<u32, BlockHash>,
    merkle_roots: HashMap<BlockHash, TxMerkleNode>,
}

impl MockHeaderStorage {
    /// A chain of the blocks in `heights`, which must hold one per height.
    pub fn new(heights: HashMap<BlockHash, u32>) -> Self {
        let mut storage = MockHeaderStorage {
            heights: HashMap::new(),
            blocks: BTreeMap::new(),
            merkle_roots: HashMap::new(),
        };
        for (block_hash, height) in heights {
            assert!(!storage.blocks.contains_key(&height), "two blocks at height {height}");
            storage.insert(block_hash, height);
        }
        storage
    }

    /// Gives the header of `diff`'s block the merkle root the diff's coinbase
    /// proof leads to, so that the proof holds against it.
    pub fn prove(&mut self, diff: &MnListDiff) {
        self.merkle_roots.insert(diff.block_hash, diff.proven_merkle_root());
    }

    /// Puts `block_hash` at `height` in the chain, in place of the block
    /// there, if any.
    pub fn insert(&mut self, block_hash: BlockHash, height: u32) {
        self.remove(&block_hash);
        if let Some(replaced) = self.blocks.insert(height, block_hash) {
            self.heights.remove(&replaced);
        }
        self.heights.insert(block_hash, height);
    }

    /// Takes `block_hash` out of the chain.
    pub fn remove(&mut self, block_hash: &BlockHash) {
        if let Some(height) = self.heights.remove(block_hash) {
            self.blocks.remove(&height);
        }
    }

    /// The height of `block_hash`, if it is in the chain.
    pub fn height(&self, block_hash: &BlockHash) -> Option<u32> {
        self.heights.get(block_hash).copied()
    }

    /// The block at `height`, if any.
    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.blocks.get(&height).copied()
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
        Ok(self.hash_at(height).map(|block_hash| {
            let header = BlockHeader {
                merkle_root: self
                    .merkle_roots
                    .get(&block_hash)
                    .copied()
                    .unwrap_or_else(TxMerkleNode::all_zeros),
                ..BlockHeader::dummy(height)
            };
            HashedBlockHeader::with_trusted_hash(header, block_hash)
        }))
    }
    async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        Ok(self.height(hash))
    }
    async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
        self.heights.retain(|_, h| *h <= target_height);
        self.blocks.retain(|h, _| *h <= target_height);
        Ok(())
    }
}
