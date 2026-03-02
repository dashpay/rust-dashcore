use std::ops::Range;

use hashes::Hash;

use crate::{
    Block, BlockHash, CompactTarget, Header, Transaction, TxMerkleNode,
    bip158::{BlockFilter, BlockFilterWriter},
    block::Version,
};

impl Block {
    pub fn dummy(height: u32, transactions: Vec<Transaction>) -> Block {
        Block {
            header: Header::dummy(height),
            txdata: transactions,
        }
    }
}

impl BlockHash {
    pub fn dummy(id: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&id.to_le_bytes());
        BlockHash::from_byte_array(bytes)
    }
}

impl Header {
    pub fn dummy(height: u32) -> Self {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::dummy(height.saturating_sub(1)),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: height,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        }
    }

    pub fn dummy_batch(height_range: Range<u32>) -> Vec<Self> {
        height_range.map(Self::dummy).collect()
    }

    /// Create a chain of headers where each header's `prev_blockhash` is the
    /// actual `block_hash()` of the previous one. Uses an easy PoW target so
    /// headers pass validation.
    pub fn dummy_chain(count: usize, prev_blockhash: BlockHash) -> Vec<Self> {
        let mut headers = Vec::with_capacity(count);
        let mut prev = prev_blockhash;
        for i in 0..count {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: i as u32,
                bits: CompactTarget::from_consensus(0x2100ffff),
                nonce: i as u32,
            };
            prev = header.block_hash();
            headers.push(header);
        }
        headers
    }
}

impl BlockFilter {
    pub fn dummy(block: &Block) -> BlockFilter {
        let mut content = Vec::new();
        let mut writer = BlockFilterWriter::new(&mut content, block);

        // Add output scripts from the block
        writer.add_output_scripts();

        // Finish writing and construct the filter
        writer.finish().expect("Failed to finish filter");
        BlockFilter::new(&content)
    }
}
