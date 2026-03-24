//! Block metadata and transaction context types.

use dashcore::prelude::CoreBlockHeight;
use dashcore::BlockHash;

/// Block metadata attached to confirmed transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockInfo {
    pub(crate) height: CoreBlockHeight,
    pub(crate) block_hash: BlockHash,
    pub(crate) timestamp: u32,
}

impl BlockInfo {
    pub fn new(height: CoreBlockHeight, block_hash: BlockHash, timestamp: u32) -> Self {
        Self {
            height,
            block_hash,
            timestamp,
        }
    }

    pub fn height(&self) -> CoreBlockHeight {
        self.height
    }

    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

/// Context for transaction processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionContext {
    /// Transaction is in the mempool (unconfirmed)
    Mempool,
    /// Transaction is in the mempool with an InstantSend lock
    InstantSend,
    /// Transaction is in a block at the given height
    InBlock(BlockInfo),
    /// Transaction is in a chain-locked block at the given height
    InChainLockedBlock(BlockInfo),
}

impl std::fmt::Display for TransactionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionContext::Mempool => write!(f, "mempool"),
            TransactionContext::InstantSend => write!(f, "instant send"),
            TransactionContext::InBlock(info) => write!(f, "block {}", info.height),
            TransactionContext::InChainLockedBlock(info) => {
                write!(f, "chainlocked block {}", info.height)
            }
        }
    }
}

impl TransactionContext {
    /// Returns the confirmation state.
    pub(crate) fn confirmed(&self) -> bool {
        matches!(self, TransactionContext::InChainLockedBlock(_) | TransactionContext::InBlock(_))
    }

    /// Returns the block info if confirmed.
    pub(crate) fn block_info(&self) -> Option<&BlockInfo> {
        match self {
            TransactionContext::Mempool | TransactionContext::InstantSend => None,
            TransactionContext::InBlock(info) | TransactionContext::InChainLockedBlock(info) => {
                Some(info)
            }
        }
    }
}
