use dashcore::BlockHash;

use crate::transaction_checking::{BlockInfo, TransactionContext};

/// A delivery in the block at `height`.
pub fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_700_000_000,
    ))
}
