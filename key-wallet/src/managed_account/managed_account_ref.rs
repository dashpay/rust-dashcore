//! Borrowed enum spanning [`ManagedCoreFundsAccount`] and [`ManagedCoreKeysAccount`].
//!
//! Several collection-level accessors (`all_accounts`, `get_by_account_type_match`,
//! etc.) need to return references to either funds-bearing or keys-only managed
//! accounts. [`ManagedAccountRef`] (and its mutable counterpart) provides the
//! shared API surface for those callers without requiring them to dispatch on
//! the concrete account type.
//!
//! Operations that only make sense on funds accounts (balance, UTXOs, transaction
//! recording, etc.) are NOT exposed here — callers that need them must match on
//! the variant explicitly.

use crate::account::AccountMetadata;
#[cfg(feature = "keep_txs_in_memory")]
use crate::account::TransactionRecord;
use crate::managed_account::address_pool::AddressInfo;
use crate::managed_account::{ManagedCoreFundsAccount, ManagedCoreKeysAccount};
use crate::transaction_checking::account_checker::AccountMatch;
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::TransactionContext;
use crate::Network;
use dashcore::{Address, ScriptBuf, Transaction, Txid};

/// Immutable reference to a managed core account, either funds-bearing or
/// keys-only.
///
/// See the [module-level docs](self) for context.
#[derive(Debug, Clone, Copy)]
pub enum ManagedAccountRef<'a> {
    /// Funds-bearing variant (Standard, CoinJoin, DashPay).
    Funds(&'a ManagedCoreFundsAccount),
    /// Keys-only variant (identity, asset-lock, provider).
    Keys(&'a ManagedCoreKeysAccount),
}

/// Mutable reference to a managed core account, either funds-bearing or
/// keys-only.
///
/// See the [module-level docs](self) for context.
#[derive(Debug)]
pub enum ManagedAccountRefMut<'a> {
    /// Funds-bearing variant (Standard, CoinJoin, DashPay).
    Funds(&'a mut ManagedCoreFundsAccount),
    /// Keys-only variant (identity, asset-lock, provider).
    Keys(&'a mut ManagedCoreKeysAccount),
}

impl<'a> ManagedAccountRef<'a> {
    /// Get the managed account type.
    pub fn managed_account_type(&self) -> &crate::managed_account::ManagedAccountType {
        match self {
            ManagedAccountRef::Funds(a) => &a.managed_account_type,
            ManagedAccountRef::Keys(a) => &a.managed_account_type,
        }
    }

    /// Get the network this account belongs to.
    pub fn network(&self) -> Network {
        match self {
            ManagedAccountRef::Funds(a) => a.network,
            ManagedAccountRef::Keys(a) => a.network,
        }
    }

    /// Get the account metadata.
    pub fn metadata(&self) -> &AccountMetadata {
        match self {
            ManagedAccountRef::Funds(a) => &a.metadata,
            ManagedAccountRef::Keys(a) => &a.metadata,
        }
    }

    /// Whether this is a watch-only account.
    pub fn is_watch_only(&self) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.is_watch_only,
            ManagedAccountRef::Keys(a) => a.is_watch_only,
        }
    }

    /// Check whether the address belongs to this account.
    pub fn contains_address(&self, address: &Address) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.contains_address(address),
            ManagedAccountRef::Keys(a) => a.contains_address(address),
        }
    }

    /// Check whether the script pubkey belongs to this account.
    pub fn contains_script_pub_key(&self, script_pub_key: &ScriptBuf) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.contains_script_pub_key(script_pub_key),
            ManagedAccountRef::Keys(a) => a.contains_script_pub_key(script_pub_key),
        }
    }

    /// Get address info for the given address, if owned.
    pub fn get_address_info(&self, address: &Address) -> Option<AddressInfo> {
        match self {
            ManagedAccountRef::Funds(a) => a.get_address_info(address),
            ManagedAccountRef::Keys(a) => a.get_address_info(address),
        }
    }

    /// Get every address known to this account, across all pools.
    pub fn all_addresses(&self) -> Vec<Address> {
        match self {
            ManagedAccountRef::Funds(a) => a.all_addresses(),
            ManagedAccountRef::Keys(a) => a.all_addresses(),
        }
    }

    /// Get the account's index, if it carries one.
    pub fn index(&self) -> Option<u32> {
        match self {
            ManagedAccountRef::Funds(a) => a.index(),
            ManagedAccountRef::Keys(a) => a.index(),
        }
    }

    /// Get the account index or 0 if none exists.
    pub fn index_or_default(&self) -> u32 {
        match self {
            ManagedAccountRef::Funds(a) => a.index_or_default(),
            ManagedAccountRef::Keys(a) => a.index_or_default(),
        }
    }

    /// Return the current monitor revision.
    pub fn monitor_revision(&self) -> u64 {
        match self {
            ManagedAccountRef::Funds(a) => a.monitor_revision(),
            ManagedAccountRef::Keys(a) => a.monitor_revision(),
        }
    }

    /// Returns whether this account has already processed `txid`.
    pub fn has_transaction(&self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.has_transaction(txid),
            ManagedAccountRef::Keys(a) => a.has_transaction(txid),
        }
    }

    /// Returns the stored transaction record for `txid`, if any.
    ///
    /// The returned reference shares the borrow with the underlying account
    /// rather than this enum value, so callers can hold it past a drop of
    /// the [`ManagedAccountRef`] wrapper. Always returns `None` when the
    /// `keep_txs_in_memory` Cargo feature is disabled.
    #[cfg(feature = "keep_txs_in_memory")]
    pub fn get_transaction(self, txid: &Txid) -> Option<&'a TransactionRecord> {
        match self {
            ManagedAccountRef::Funds(a) => a.get_transaction(txid),
            ManagedAccountRef::Keys(a) => a.get_transaction(txid),
        }
    }

    /// Iterate over the stored transactions of this account.
    ///
    /// Returns an empty iterator when the `keep_txs_in_memory` feature is
    /// disabled.
    #[cfg(feature = "keep_txs_in_memory")]
    pub fn transactions_iter(
        self,
    ) -> Box<dyn Iterator<Item = (&'a Txid, &'a TransactionRecord)> + 'a> {
        match self {
            ManagedAccountRef::Funds(a) => Box::new(a.transactions.iter()),
            ManagedAccountRef::Keys(a) => Box::new(a.transactions.iter()),
        }
    }

    /// Iterate over the stored transactions of this account.
    ///
    /// Returns an empty iterator when the `keep_txs_in_memory` feature is
    /// disabled.
    #[cfg(not(feature = "keep_txs_in_memory"))]
    pub fn transactions_iter(
        self,
    ) -> Box<
        dyn Iterator<
                Item = (
                    &'a Txid,
                    &'a crate::managed_account::transaction_record::TransactionRecord,
                ),
            > + 'a,
    > {
        Box::new(std::iter::empty())
    }

    /// Returns the stored transaction record for `txid`, if any.
    ///
    /// Always returns `None` when the `keep_txs_in_memory` Cargo feature is
    /// disabled.
    #[cfg(not(feature = "keep_txs_in_memory"))]
    pub fn get_transaction(
        self,
        _txid: &Txid,
    ) -> Option<&'a crate::managed_account::transaction_record::TransactionRecord> {
        None
    }

    /// Borrow the funds variant if this is a funds account.
    pub fn as_funds(&self) -> Option<&'a ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRef::Funds(a) => Some(*a),
            ManagedAccountRef::Keys(_) => None,
        }
    }

    /// Borrow the keys variant if this is a keys account.
    pub fn as_keys(&self) -> Option<&'a ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRef::Funds(_) => None,
            ManagedAccountRef::Keys(a) => Some(*a),
        }
    }
}

impl<'a> ManagedAccountRefMut<'a> {
    /// Get the managed account type.
    pub fn managed_account_type(&self) -> &crate::managed_account::ManagedAccountType {
        match self {
            ManagedAccountRefMut::Funds(a) => &a.managed_account_type,
            ManagedAccountRefMut::Keys(a) => &a.managed_account_type,
        }
    }

    /// Get the mutable managed account type.
    pub fn managed_account_type_mut(&mut self) -> &mut crate::managed_account::ManagedAccountType {
        match self {
            ManagedAccountRefMut::Funds(a) => &mut a.managed_account_type,
            ManagedAccountRefMut::Keys(a) => &mut a.managed_account_type,
        }
    }

    /// Get the network this account belongs to.
    pub fn network(&self) -> Network {
        match self {
            ManagedAccountRefMut::Funds(a) => a.network,
            ManagedAccountRefMut::Keys(a) => a.network,
        }
    }

    /// Get the account metadata.
    pub fn metadata(&self) -> &AccountMetadata {
        match self {
            ManagedAccountRefMut::Funds(a) => &a.metadata,
            ManagedAccountRefMut::Keys(a) => &a.metadata,
        }
    }

    /// Get mutable account metadata.
    pub fn metadata_mut(&mut self) -> &mut AccountMetadata {
        match self {
            ManagedAccountRefMut::Funds(a) => &mut a.metadata,
            ManagedAccountRefMut::Keys(a) => &mut a.metadata,
        }
    }

    /// Whether this is a watch-only account.
    pub fn is_watch_only(&self) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.is_watch_only,
            ManagedAccountRefMut::Keys(a) => a.is_watch_only,
        }
    }

    /// Check whether the address belongs to this account.
    pub fn contains_address(&self, address: &Address) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.contains_address(address),
            ManagedAccountRefMut::Keys(a) => a.contains_address(address),
        }
    }

    /// Check whether the script pubkey belongs to this account.
    pub fn contains_script_pub_key(&self, script_pub_key: &ScriptBuf) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.contains_script_pub_key(script_pub_key),
            ManagedAccountRefMut::Keys(a) => a.contains_script_pub_key(script_pub_key),
        }
    }

    /// Get address info for the given address, if owned.
    pub fn get_address_info(&self, address: &Address) -> Option<AddressInfo> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.get_address_info(address),
            ManagedAccountRefMut::Keys(a) => a.get_address_info(address),
        }
    }

    /// Get every address known to this account, across all pools.
    pub fn all_addresses(&self) -> Vec<Address> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.all_addresses(),
            ManagedAccountRefMut::Keys(a) => a.all_addresses(),
        }
    }

    /// Get the account's index, if it carries one.
    pub fn index(&self) -> Option<u32> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.index(),
            ManagedAccountRefMut::Keys(a) => a.index(),
        }
    }

    /// Get the account index or 0 if none exists.
    pub fn index_or_default(&self) -> u32 {
        match self {
            ManagedAccountRefMut::Funds(a) => a.index_or_default(),
            ManagedAccountRefMut::Keys(a) => a.index_or_default(),
        }
    }

    /// Increment the monitor revision to signal that the monitored address set
    /// changed.
    pub fn bump_monitor_revision(&mut self) {
        match self {
            ManagedAccountRefMut::Funds(a) => a.bump_monitor_revision(),
            ManagedAccountRefMut::Keys(a) => a.bump_monitor_revision(),
        }
    }

    /// Mark an address as used.
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.mark_address_used(address),
            ManagedAccountRefMut::Keys(a) => a.mark_address_used(address),
        }
    }

    /// Returns whether this account has already processed `txid`.
    pub fn has_transaction(&self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.has_transaction(txid),
            ManagedAccountRefMut::Keys(a) => a.has_transaction(txid),
        }
    }

    /// Returns the stored transaction record for `txid`, if any.
    ///
    /// Always returns `None` when the `keep_txs_in_memory` Cargo feature is
    /// disabled.
    #[cfg(feature = "keep_txs_in_memory")]
    pub fn get_transaction(&self, txid: &Txid) -> Option<&TransactionRecord> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.get_transaction(txid),
            ManagedAccountRefMut::Keys(a) => a.get_transaction(txid),
        }
    }

    /// Returns the stored transaction record for `txid`, if any.
    ///
    /// Always returns `None` when the `keep_txs_in_memory` Cargo feature is
    /// disabled.
    #[cfg(not(feature = "keep_txs_in_memory"))]
    pub fn get_transaction(
        &self,
        _txid: &Txid,
    ) -> Option<&crate::managed_account::transaction_record::TransactionRecord> {
        None
    }

    /// Record a new transaction on this account.
    ///
    /// On a funds account this updates UTXOs and balance bookkeeping; on a
    /// keys account it only updates `processed_txids` (and the per-tx record
    /// when `keep_txs_in_memory` is enabled).
    pub(crate) fn record_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> crate::managed_account::transaction_record::TransactionRecord {
        match self {
            ManagedAccountRefMut::Funds(a) => {
                a.record_transaction(tx, account_match, context, transaction_type)
            }
            ManagedAccountRefMut::Keys(a) => {
                a.record_transaction(tx, account_match, context, transaction_type)
            }
        }
    }

    /// Re-process an existing transaction with updated context.
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => {
                a.confirm_transaction(tx, account_match, context, transaction_type)
            }
            ManagedAccountRefMut::Keys(a) => {
                a.confirm_transaction(tx, account_match, context, transaction_type)
            }
        }
    }

    /// Mark UTXOs belonging to a transaction as InstantSend-locked.
    ///
    /// No-op on keys accounts, which never carry UTXOs.
    pub(crate) fn mark_utxos_instant_send(&mut self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.mark_utxos_instant_send(txid),
            ManagedAccountRefMut::Keys(_) => {
                let _ = txid;
                false
            }
        }
    }

    /// Update an in-memory transaction record's context.
    ///
    /// No-op (returns `false`) when `keep_txs_in_memory` is disabled or no
    /// matching record exists.
    #[cfg(feature = "keep_txs_in_memory")]
    pub(crate) fn update_transaction_record_context(
        &mut self,
        txid: &Txid,
        context: TransactionContext,
    ) -> Option<TransactionRecord> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.transactions.get_mut(txid).map(|r| {
                r.update_context(context);
                r.clone()
            }),
            ManagedAccountRefMut::Keys(a) => a.transactions.get_mut(txid).map(|r| {
                r.update_context(context);
                r.clone()
            }),
        }
    }

    /// Returns `true` if this account currently holds an in-memory record
    /// for `txid`.
    ///
    /// Equivalent to `has_transaction` when `keep_txs_in_memory` is enabled,
    /// otherwise always `false`.
    pub(crate) fn contains_transaction_record(&self, txid: &Txid) -> bool {
        #[cfg(feature = "keep_txs_in_memory")]
        {
            match self {
                ManagedAccountRefMut::Funds(a) => a.transactions.contains_key(txid),
                ManagedAccountRefMut::Keys(a) => a.transactions.contains_key(txid),
            }
        }
        #[cfg(not(feature = "keep_txs_in_memory"))]
        {
            let _ = txid;
            false
        }
    }

    /// Borrow the funds variant if this is a funds account.
    pub fn as_funds(&self) -> Option<&ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRefMut::Funds(a) => Some(&**a),
            ManagedAccountRefMut::Keys(_) => None,
        }
    }

    /// Borrow the funds variant mutably if this is a funds account.
    pub fn as_funds_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRefMut::Funds(a) => Some(&mut **a),
            ManagedAccountRefMut::Keys(_) => None,
        }
    }

    /// Borrow the keys variant if this is a keys account.
    pub fn as_keys(&self) -> Option<&ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRefMut::Funds(_) => None,
            ManagedAccountRefMut::Keys(a) => Some(&**a),
        }
    }

    /// Borrow the keys variant mutably if this is a keys account.
    pub fn as_keys_mut(&mut self) -> Option<&mut ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRefMut::Funds(_) => None,
            ManagedAccountRefMut::Keys(a) => Some(&mut **a),
        }
    }

    /// Convert into the underlying funds variant if this is a funds account.
    pub fn into_funds(self) -> Option<&'a mut ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRefMut::Funds(a) => Some(a),
            ManagedAccountRefMut::Keys(_) => None,
        }
    }

    /// Convert into the underlying keys variant if this is a keys account.
    pub fn into_keys(self) -> Option<&'a mut ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRefMut::Funds(_) => None,
            ManagedAccountRefMut::Keys(a) => Some(a),
        }
    }

    /// Reborrow as an immutable [`ManagedAccountRef`].
    pub fn as_ref(&self) -> ManagedAccountRef<'_> {
        match self {
            ManagedAccountRefMut::Funds(a) => ManagedAccountRef::Funds(a),
            ManagedAccountRefMut::Keys(a) => ManagedAccountRef::Keys(a),
        }
    }
}
