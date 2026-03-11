//! Wallet interface for SPV client integration
//!
//! This module defines the trait that SPV clients use to interact with wallets.

use crate::manager::WalletEvent;
use async_trait::async_trait;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, OutPoint, Transaction, Txid};
use tokio::sync::broadcast;

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

/// Result of processing a mempool transaction through the wallet
#[derive(Debug, Default, Clone)]
pub struct MempoolTransactionResult {
    /// Whether the transaction was relevant to any wallet.
    pub is_relevant: bool,
    /// Net amount change for the wallet (received - sent) in satoshis.
    pub net_amount: i64,
    /// Whether this is an outgoing transaction (net_amount < 0).
    pub is_outgoing: bool,
    /// Addresses involved in this transaction.
    pub addresses: Vec<Address>,
    /// New addresses generated during gap limit maintenance.
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

    /// Called when a transaction is seen in the mempool.
    /// Returns whether the transaction was relevant and any new addresses generated.
    /// When `is_instant_send` is true, the transaction already has an IS lock.
    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        is_instant_send: bool,
    ) -> MempoolTransactionResult;

    /// Get all addresses the wallet is monitoring for incoming transactions
    fn monitored_addresses(&self) -> Vec<Address>;

    /// Get all outpoints the wallet is watching (unspent outputs).
    /// Used for bloom filter construction to detect spends of our UTXOs.
    fn watched_outpoints(&self) -> Vec<OutPoint>;

    /// Return the wallet's per-transaction net change and involved addresses if known.
    /// Returns (net_amount, addresses) where net_amount is received - sent in satoshis.
    /// If the wallet has no record for the transaction, returns None.
    async fn transaction_effect(&self, _tx: &Transaction) -> Option<(i64, Vec<String>)> {
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

    /// Return the last fully processed height of the wallet.
    fn synced_height(&self) -> CoreBlockHeight;

    /// Update the wallet's synced height. This also triggers balance updates.
    fn update_synced_height(&mut self, height: CoreBlockHeight);

    /// Return the height at which filter scanning was last committed.
    /// Defaults to `synced_height()` for implementations that don't separate these concepts.
    // TODO: This can probably somehow be combined with synced_height().
    fn filter_committed_height(&self) -> CoreBlockHeight {
        self.synced_height()
    }

    /// Update the filter committed height. Call when a height is fully processed
    /// (including any rescans for newly discovered addresses).
    fn update_filter_committed_height(&mut self, height: CoreBlockHeight) {
        if height > self.synced_height() {
            self.update_synced_height(height);
        }
    }

    /// Return a revision counter that increments whenever the set of monitored
    /// addresses or watched outpoints changes. The mempool manager uses this to
    /// detect when its bloom filter is stale without requiring an external signal.
    fn monitor_revision(&self) -> u64 {
        0
    }

    /// Subscribe to wallet events (e.g. transactions received, balance changes).
    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent>;

    /// Process an InstantSend lock for a transaction already in the wallet.
    /// Marks UTXOs as IS-locked, emits status change and balance update events.
    fn process_instant_send_lock(&mut self, _txid: Txid) {}

    /// Provide a human-readable description of the wallet implementation.
    ///
    /// Implementations are encouraged to include high-level state such as the
    /// number of managed wallets, networks, or tracked scripts.
    async fn describe(&self) -> String {
        "Wallet interface description unavailable".to_string()
    }
}
