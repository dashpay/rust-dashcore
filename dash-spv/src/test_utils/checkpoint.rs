use dashcore::{BlockHash, CompactTarget, Target};
use dashcore_hashes::Hash;

use crate::chain::Checkpoint;

impl Checkpoint {
    pub fn dummy(height: u32, timestamp: u32) -> Checkpoint {
        let block_hash = BlockHash::dummy(height);
        let prev_blockhash = if height > 0 {
            BlockHash::dummy(height - 1)
        } else {
            BlockHash::all_zeros()
        };

        Checkpoint {
            height,
            block_hash,
            prev_blockhash,
            timestamp,
            target: Target::from_compact(CompactTarget::from_consensus(0x1d00ffff)),
            merkle_root: Some(block_hash),
            chain_work: format!("0x{:064x}", height * 1000),
            masternode_list_name: if height.is_multiple_of(100000) && height > 0 {
                Some(format!("ML{}__70230", height))
            } else {
                None
            },
            protocol_version: None,
            nonce: height * 123,
        }
    }
}
