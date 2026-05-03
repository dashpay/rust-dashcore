//! Trait for managed account functionality
//!
//! This module defines the common interface for all managed account types.

use std::collections::BTreeMap;

#[cfg(feature = "keep_txs_in_memory")]
use crate::account::TransactionRecord;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::utxo::Utxo;
use crate::wallet::balance::WalletCoreBalance;
use crate::Network;
use dashcore::blockdata::transaction::OutPoint;
#[cfg(feature = "keep_txs_in_memory")]
use dashcore::Txid;

/// Common trait for all managed account types
pub trait ManagedAccountTrait {
    /// Get the managed account type
    fn managed_account_type(&self) -> &ManagedAccountType;

    /// Get mutable managed account type
    fn managed_account_type_mut(&mut self) -> &mut ManagedAccountType;

    /// Get the network
    fn network(&self) -> Network;

    /// Check if this is a watch-only account
    fn is_watch_only(&self) -> bool;

    /// Get balance
    fn balance(&self) -> &WalletCoreBalance;

    /// Get mutable balance
    fn balance_mut(&mut self) -> &mut WalletCoreBalance;

    /// Get transactions.
    ///
    /// Only available when the `keep_txs_in_memory` Cargo feature is enabled.
    #[cfg(feature = "keep_txs_in_memory")]
    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord>;

    /// Get mutable transactions.
    ///
    /// Only available when the `keep_txs_in_memory` Cargo feature is enabled.
    #[cfg(feature = "keep_txs_in_memory")]
    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord>;

    /// Get UTXOs
    fn utxos(&self) -> &BTreeMap<OutPoint, Utxo>;

    /// Get mutable UTXOs
    fn utxos_mut(&mut self) -> &mut BTreeMap<OutPoint, Utxo>;

    /// Get the account index
    fn index(&self) -> Option<u32> {
        self.managed_account_type().index()
    }

    /// Get the account index or 0 if none exists
    fn index_or_default(&self) -> u32 {
        self.managed_account_type().index_or_default()
    }
}
