//! Wallet interface for SPV client integration
//!
//! This module defines the trait that SPV clients use to interact with wallets.

use crate::{WalletEvent, WalletId};
use async_trait::async_trait;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, OutPoint, Transaction, Txid};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::broadcast;

/// Result of processing a block through the wallet
#[derive(Debug, Default, Clone)]
pub struct BlockProcessingResult {
    /// Transaction IDs that were newly discovered
    pub new_txids: Vec<Txid>,
    /// Transaction IDs that were already in wallet history
    pub existing_txids: Vec<Txid>,
    /// New addresses generated per wallet during gap-limit maintenance.
    pub new_addresses: BTreeMap<WalletId, Vec<Address>>,
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

    /// Iterate over every newly generated address regardless of wallet attribution.
    pub fn all_new_addresses(&self) -> impl Iterator<Item = &Address> {
        self.new_addresses.values().flatten()
    }
}

/// Trait for wallet implementations to receive SPV events
#[async_trait]
pub trait WalletInterface: Send + Sync + 'static {
    /// Process a block, but only against the listed wallets. Implementations
    /// must update the per-wallet `last_processed_height` for each wallet in
    /// `wallets` once the block is applied to its state.
    ///
    /// Pass the result of `wallets_behind(height)` for the canonical "scan
    /// only the wallets that need this block" semantics.
    async fn process_block_for_wallets(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
        wallets: &BTreeSet<WalletId>,
    ) -> BlockProcessingResult;

    /// Called when a transaction is seen in the mempool.
    /// Returns whether the transaction was relevant and any new addresses generated.
    /// When `instant_lock` is `Some`, the transaction already has an IS lock.
    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        instant_lock: Option<InstantLock>,
    ) -> MempoolTransactionResult;

    /// Get all addresses the wallet is monitoring for incoming transactions
    fn monitored_addresses(&self) -> Vec<Address>;

    /// Get monitored addresses for a specific wallet.
    fn monitored_addresses_for(&self, wallet_id: &WalletId) -> Vec<Address>;

    /// Get all outpoints the wallet is watching (unspent outputs).
    /// Used for bloom filter construction to detect spends of our UTXOs.
    fn watched_outpoints(&self) -> Vec<OutPoint>;

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
    fn last_processed_height(&self) -> CoreBlockHeight;

    /// Return the lowest committed sync checkpoint across all managed wallets.
    /// Filter scanning resumes from this height. A new wallet added behind this
    /// drags the value down and triggers a rescan.
    fn synced_height(&self) -> CoreBlockHeight;

    /// Return the wallet IDs whose `synced_height` is strictly less than `height`,
    /// i.e. the wallets that still need filter coverage at that height.
    fn wallets_behind(&self, height: CoreBlockHeight) -> BTreeSet<WalletId>;

    /// Return the wallet IDs that still need filter coverage at heights up to
    /// and including `height`. Equivalent to `wallets_behind(height + 1)` but
    /// expresses the inclusive intent at the call site, so callers don't have
    /// to compensate the strict-less-than semantics with `+ 1`.
    fn wallets_not_yet_at(&self, height: CoreBlockHeight) -> BTreeSet<WalletId> {
        self.wallets_behind(height.saturating_add(1))
    }

    /// Return the per-wallet committed sync checkpoint, or `0` if unknown.
    fn wallet_synced_height(&self, wallet_id: &WalletId) -> CoreBlockHeight;

    /// Advance one wallet's committed sync checkpoint. Implementations must
    /// only advance forward (a value below the current is silently ignored).
    fn update_wallet_synced_height(&mut self, wallet_id: &WalletId, height: CoreBlockHeight);

    /// Advance one wallet's last-processed height after a block has been applied
    /// to its state. Implementations must only advance forward.
    fn update_wallet_last_processed_height(
        &mut self,
        wallet_id: &WalletId,
        height: CoreBlockHeight,
    );

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
    fn process_instant_send_lock(&mut self, _instant_lock: InstantLock) {}

    /// Apply a validated `chain_lock` to every wallet, promoting any
    /// `InBlock` records at height `<= chain_lock.block_height` to
    /// `InChainLockedBlock` and advancing each wallet's
    /// `last_applied_chain_lock`.
    ///
    /// Emits at most one [`WalletEvent::ChainLockProcessed`] per
    /// wallet, fired whenever the wallet's `last_applied_chain_lock`
    /// advanced (strictly forward by height, or `None` → `Some`). The
    /// event carries the full `ChainLock` plus any per-account net-new
    /// promotions in `locked_transactions` — empty when the chainlock
    /// advanced the metadata without promoting any record (durable
    /// consumers that persist the chainlock metadata must still listen
    /// for these empty-promotion events). Replays of the same chainlock
    /// (no metadata advance) are silent.
    ///
    /// Implementations must serialize calls relative to
    /// `process_block_for_wallets` to avoid interleaving promotions with
    /// in-flight block processing.
    fn apply_chain_lock(&mut self, chain_lock: ChainLock);

    /// Provide a human-readable description of the wallet implementation.
    ///
    /// Implementations are encouraged to include high-level state such as the
    /// number of managed wallets, networks, or tracked scripts.
    async fn describe(&self) -> String {
        "Wallet interface description unavailable".to_string()
    }
}
