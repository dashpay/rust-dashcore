//! Trait for managed account functionality
//!
//! This module defines the common interface for all managed account types.

use crate::account::AccountMetadata;
use crate::account::TransactionRecord;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::utxo::Utxo;
use crate::wallet::balance::WalletBalance;
use crate::Network;
use alloc::collections::BTreeMap;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Address, Txid};

/// Common trait for all managed account types
pub trait ManagedAccountTrait {
    /// Get the account type
    fn account_type(&self) -> &ManagedAccountType;

    /// Get mutable account type
    fn account_type_mut(&mut self) -> &mut ManagedAccountType;

    /// Get the network
    fn network(&self) -> Network;

    /// Get metadata
    fn metadata(&self) -> &AccountMetadata;

    /// Get mutable metadata
    fn metadata_mut(&mut self) -> &mut AccountMetadata;

    /// Check if this is a watch-only account
    fn is_watch_only(&self) -> bool;

    /// Get balance
    fn balance(&self) -> &WalletBalance;

    /// Get mutable balance
    fn balance_mut(&mut self) -> &mut WalletBalance;

    /// Get transactions
    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord>;

    /// Get mutable transactions
    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord>;

    /// Extract UTXOs from a transaction and add them to this account.
    ///
    /// Scans the transaction outputs for addresses belonging to `involved_addresses`
    /// and creates UTXOs for any matches.
    fn add_utxos_from_transaction(
        &mut self,
        tx: &dashcore::Transaction,
        involved_addresses: &alloc::collections::BTreeSet<Address>,
        network: Network,
        height: u32,
        is_confirmed: bool,
    );

    /// Get UTXOs
    fn utxos(&self) -> &BTreeMap<OutPoint, Utxo>;

    /// Get mutable UTXOs
    fn utxos_mut(&mut self) -> &mut BTreeMap<OutPoint, Utxo>;

    /// Get the account index
    fn index(&self) -> Option<u32> {
        self.account_type().index()
    }

    /// Get the account index or 0 if none exists
    fn index_or_default(&self) -> u32 {
        self.account_type().index_or_default()
    }
}
