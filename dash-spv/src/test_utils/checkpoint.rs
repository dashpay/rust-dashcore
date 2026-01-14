use dashcore::{CompactTarget, Header, Target};

use crate::chain::Checkpoint;

impl Checkpoint {
    pub fn dummy(height: u32) -> Checkpoint {
        let block_header = Header::dummy(height);

        Checkpoint {
            height,
            block_hash: block_header.block_hash(),
            prev_blockhash: block_header.prev_blockhash,
            timestamp: block_header.time,
            target: Target::from_compact(CompactTarget::from_consensus(0x1d00ffff)),
            merkle_root: Some(block_header.block_hash()),
            chain_work: format!("0x{:064x}", height.wrapping_mul(1000)),
            masternode_list_name: if height.is_multiple_of(100000) && height > 0 {
                Some(format!("ML{}__70230", height))
            } else {
                None
            },
            protocol_version: None,
            nonce: block_header.nonce,
        }
    }
}
