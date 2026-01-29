use crate::types::HashedBlock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Block, Transaction};

impl HashedBlock {
    pub fn dummy(height: CoreBlockHeight, transactions: Vec<Transaction>) -> Self {
        Self::from(Block::dummy(height, transactions))
    }
}
