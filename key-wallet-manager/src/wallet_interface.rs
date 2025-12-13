//! Wallet interface for SPV client integration
//!
//! This module defines the trait that SPV clients use to interact with wallets.

use alloc::string::String;
use alloc::vec::Vec;
use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, Transaction, Txid};

/// Result of processing a block through the wallet
#[derive(Debug, Default, Clone)]
pub struct BlockProcessingResult {
    /// Transaction IDs that were newly discovered
    pub new_txids: Vec<Txid>,
    /// Transaction IDs that were already in wallet history
    pub existing_txids: Vec<Txid>,
    /// New addresses generated during gap limit maintenance
    pub new_addresses: Vec<Address>,
}

impl BlockProcessingResult {
    /// Returns all relevant transaction IDs (new and existing)
    pub fn relevant_txids(&self) -> impl Iterator<Item = &Txid> {
        self.new_txids.iter().chain(self.existing_txids.iter())
    }

    /// Returns the count of all relevant transactions (new and existing)
    pub fn relevant_tx_count(&self) -> usize {
        self.new_txids.len() + self.existing_txids.len()
    }
}

/// Trait for wallet implementations to receive SPV events
#[async_trait]
pub trait WalletInterface: Send + Sync + 'static {
    /// Called when a new block is received that may contain relevant transactions.
    /// Returns processing result including relevant transactions and any new addresses
    /// generated during gap limit maintenance.
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
    ) -> BlockProcessingResult;

    /// Called when a transaction is seen in the mempool
    async fn process_mempool_transaction(&mut self, tx: &Transaction);

    /// Get all addresses the wallet is monitoring for incoming transactions
    fn monitored_addresses(&self) -> Vec<Address>;

    /// Return the wallet's per-transaction net change and involved addresses if known.
    /// Returns (net_amount, addresses) where net_amount is received - sent in satoshis.
    /// If the wallet has no record for the transaction, returns None.
    async fn transaction_effect(
        &self,
        _tx: &Transaction,
    ) -> Option<(i64, alloc::vec::Vec<alloc::string::String>)> {
        None
    }

    /// Return the earliest block height that should be scanned for this wallet on the
    /// specified network. Implementations can use the wallet's birth height or other
    /// metadata to provide a more precise rescan starting point.
    ///
    /// The default implementation returns `None`, which signals that the caller should
    /// fall back to its existing behaviour.
    async fn earliest_required_height(&self) -> CoreBlockHeight {
        0
    }

    /// Provide a human-readable description of the wallet implementation.
    ///
    /// Implementations are encouraged to include high-level state such as the
    /// number of managed wallets, networks, or tracked scripts.
    async fn describe(&self) -> String {
        "Wallet interface description unavailable".to_string()
    }
}
