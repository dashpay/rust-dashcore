//! Chain reorganization handling
//!
//! This module implements the core logic for handling blockchain reorganizations,
//! including finding common ancestors, rolling back transactions, and switching chains.

use dashcore::{BlockHash, Header as BlockHeader, Transaction, Txid};

/// Event emitted when a reorganization occurs
#[derive(Debug, Clone)]
pub struct ReorgEvent {
    /// The common ancestor where chains diverged
    pub common_ancestor: BlockHash,
    /// Height of the common ancestor
    pub common_height: u32,
    /// Headers that were removed from the main chain
    pub disconnected_headers: Vec<BlockHeader>,
    /// Headers that were added to the main chain
    pub connected_headers: Vec<BlockHeader>,
    /// Transactions that may have changed confirmation status
    pub affected_transactions: Vec<Transaction>,
}

/// Data collected during the read phase of reorganization
#[allow(dead_code)]
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct ReorgData {
    /// The common ancestor where chains diverged
    pub(crate) common_ancestor: BlockHash,
    /// Height of the common ancestor
    pub(crate) common_height: u32,
    /// Headers that need to be disconnected from the main chain
    disconnected_headers: Vec<BlockHeader>,
    /// Block hashes and heights for disconnected blocks
    disconnected_blocks: Vec<(BlockHash, u32)>,
    /// Transaction IDs from disconnected blocks that affect the wallet
    affected_tx_ids: Vec<Txid>,
    /// Actual transactions that were affected (if available)
    affected_transactions: Vec<Transaction>,
}
