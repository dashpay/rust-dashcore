//! Wallet interface for SPV client integration
//!
//! This module defines the trait that SPV clients use to interact with wallets.

use async_trait::async_trait;
use dashcore::{Block, Transaction, Txid};

/// Trait for wallet implementations to receive SPV events
#[async_trait]
pub trait WalletInterface: Send + Sync {
    /// Called when a new block is received that may contain relevant transactions
    /// Returns transaction IDs that were relevant to the wallet
    async fn process_block(&mut self, block: &Block, height: u32) -> Vec<Txid>;

    /// Called when a transaction is seen in the mempool
    async fn process_mempool_transaction(&mut self, tx: &Transaction);

    /// Called when a reorg occurs and blocks need to be rolled back
    async fn handle_reorg(&mut self, from_height: u32, to_height: u32);

    /// Check if a compact filter matches any watched items
    /// Returns true if the block should be downloaded
    async fn check_compact_filter(&self, filter: &[u8], block_hash: &dashcore::BlockHash) -> bool;

    /// Get a reference to self as Any for downcasting in tests
    fn as_any(&self) -> &dyn std::any::Any;
}
