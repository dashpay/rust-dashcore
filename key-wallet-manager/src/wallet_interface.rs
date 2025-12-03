//! Wallet interface for SPV client integration
//!
//! This module defines the trait that SPV clients use to interact with wallets.

use alloc::string::String;
use async_trait::async_trait;
use dashcore::bip158::BlockFilter;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Block, Transaction, Txid};
use key_wallet::Network;

/// Trait for wallet implementations to receive SPV events
#[async_trait]
pub trait WalletInterface: Send + Sync {
    /// Called when a new block is received that may contain relevant transactions
    /// Returns (transaction_ids, gap_limit_changed)
    /// - transaction_ids: Transaction IDs that were relevant to the wallet
    /// - gap_limit_changed: true if new addresses were generated due to gap limit maintenance
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
        network: Network,
    ) -> (Vec<Txid>, bool);

    /// Called when a transaction is seen in the mempool
    async fn process_mempool_transaction(&mut self, tx: &Transaction, network: Network);

    /// Called when a reorg occurs and blocks need to be rolled back
    async fn handle_reorg(
        &mut self,
        from_height: CoreBlockHeight,
        to_height: CoreBlockHeight,
        network: Network,
    );

    /// Check if a compact filter matches any watched items
    /// Returns true if the block should be downloaded
    async fn check_compact_filter(
        &mut self,
        filter: &BlockFilter,
        block_hash: &dashcore::BlockHash,
        network: Network,
    ) -> bool;

    /// Return the wallet's per-transaction net change and involved addresses if known.
    /// Returns (net_amount, addresses) where net_amount is received - sent in satoshis.
    /// If the wallet has no record for the transaction, returns None.
    async fn transaction_effect(
        &self,
        _tx: &Transaction,
        _network: Network,
    ) -> Option<(i64, alloc::vec::Vec<alloc::string::String>)> {
        None
    }

    /// Return the earliest block height that should be scanned for this wallet on the
    /// specified network. Implementations can use the wallet's birth height or other
    /// metadata to provide a more precise rescan starting point.
    ///
    /// The default implementation returns `None`, which signals that the caller should
    /// fall back to its existing behaviour.
    async fn earliest_required_height(&self, _network: Network) -> Option<CoreBlockHeight> {
        None
    }

    /// Provide a human-readable description of the wallet implementation.
    ///
    /// Implementations are encouraged to include high-level state such as the
    /// number of managed wallets, networks, or tracked scripts.
    async fn describe(&self, _network: Network) -> String {
        "Wallet interface description unavailable".to_string()
    }
}
