use dash_network::Network;
use hashes::Hash;

use crate::{
    Block, BlockHash, CompactTarget, Header, Transaction, TxMerkleNode,
    bip158::{BlockFilter, BlockFilterWriter},
    block::Version,
    constants::genesis_block,
};

impl Block {
    pub fn dummy(network: Network) -> Self {
        genesis_block(network)
    }

    pub fn dummy_with_transactions(height: u32, transactions: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::dummy(height.saturating_sub(1)),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: height,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: transactions,
        }
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
