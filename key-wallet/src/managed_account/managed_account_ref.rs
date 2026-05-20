//! Borrowed enum spanning [`ManagedCoreFundsAccount`] and [`ManagedCoreKeysAccount`].
//!
//! Several collection-level accessors (`all_accounts`, `get_by_account_type_match`,
//! …) need to return references to either funds-bearing or keys-only managed
//! accounts. [`ManagedAccountRef`] (and its mutable counterpart
//! [`ManagedAccountRefMut`]) provides the shared API surface for those callers
//! without requiring them to dispatch on the concrete account type.
//!
//! Operations that only make sense on funds accounts (balance, UTXOs) are NOT
//! exposed here — callers that need them must use [`ManagedAccountRef::as_funds`]
//! / [`ManagedAccountRefMut::as_funds_mut`] to access the funds variant
//! directly.

use crate::account::TransactionRecord;
use crate::managed_account::address_pool::AddressInfo;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::managed_account::{ManagedCoreFundsAccount, ManagedCoreKeysAccount};
use crate::transaction_checking::account_checker::AccountMatch;
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::TransactionContext;
use crate::Network;
use dashcore::{Address, ScriptBuf, Transaction, Txid};
use std::collections::BTreeMap;

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
    /// Returns the funds account if this is the [`Funds`](Self::Funds) variant.
    pub fn as_funds(self) -> Option<&'a ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRef::Funds(a) => Some(a),
            ManagedAccountRef::Keys(_) => None,
        }
    }

    /// Returns the keys account if this is the [`Keys`](Self::Keys) variant.
    pub fn as_keys(self) -> Option<&'a ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRef::Funds(_) => None,
            ManagedAccountRef::Keys(a) => Some(a),
        }
    }

    /// Returns a reference to the underlying [`ManagedCoreKeysAccount`],
    /// regardless of variant. For [`Funds`](Self::Funds) this returns the
    /// inner keys account composed inside the funds account; for
    /// [`Keys`](Self::Keys) it returns the account itself.
    pub fn keys_account(self) -> &'a ManagedCoreKeysAccount {
        match self {
            ManagedAccountRef::Funds(a) => a.keys(),
            ManagedAccountRef::Keys(a) => a,
        }
    }

    /// Get the managed account type.
    pub fn managed_account_type(self) -> &'a ManagedAccountType {
        match self {
            ManagedAccountRef::Funds(a) => a.managed_account_type(),
            ManagedAccountRef::Keys(a) => a.managed_account_type(),
        }
    }

    /// Get the network this account belongs to.
    pub fn network(self) -> Network {
        match self {
            ManagedAccountRef::Funds(a) => a.network(),
            ManagedAccountRef::Keys(a) => a.network(),
        }
    }

    /// Get the transaction history map.
    pub fn transactions(self) -> &'a BTreeMap<Txid, TransactionRecord> {
        match self {
            ManagedAccountRef::Funds(a) => a.transactions(),
            ManagedAccountRef::Keys(a) => a.transactions(),
        }
    }

    /// Whether this account has already processed `txid`.
    pub fn has_transaction(self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.has_transaction(txid),
            ManagedAccountRef::Keys(a) => a.has_transaction(txid),
        }
    }

    /// Whether `txid` has been finalized (chainlocked).
    pub fn transaction_is_finalized(self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.transaction_is_finalized(txid),
            ManagedAccountRef::Keys(a) => a.transaction_is_finalized(txid),
        }
    }

    /// Return the current monitor revision.
    pub fn monitor_revision(self) -> u64 {
        match self {
            ManagedAccountRef::Funds(a) => a.monitor_revision(),
            ManagedAccountRef::Keys(a) => a.monitor_revision(),
        }
    }

    /// Whether `address` belongs to this account.
    pub fn contains_address(self, address: &Address) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.contains_address(address),
            ManagedAccountRef::Keys(a) => a.contains_address(address),
        }
    }

    /// Whether `script_pub_key` belongs to this account.
    pub fn contains_script_pub_key(self, script_pub_key: &ScriptBuf) -> bool {
        match self {
            ManagedAccountRef::Funds(a) => a.contains_script_pub_key(script_pub_key),
            ManagedAccountRef::Keys(a) => a.contains_script_pub_key(script_pub_key),
        }
    }

    /// Get [`AddressInfo`] for `address`, if owned by this account.
    pub fn get_address_info(self, address: &Address) -> Option<AddressInfo> {
        match self {
            ManagedAccountRef::Funds(a) => a.get_address_info(address),
            ManagedAccountRef::Keys(a) => a.get_address_info(address),
        }
    }

    /// Return all addresses tracked by this account (across all pools).
    pub fn all_addresses(self) -> Vec<Address> {
        match self {
            ManagedAccountRef::Funds(a) => a.all_addresses(),
            ManagedAccountRef::Keys(a) => a.all_addresses(),
        }
    }

    /// Return cached scriptPubKey bytes for every address tracked by this
    /// account, across all pools.
    pub fn all_script_pubkeys(self) -> Vec<ScriptBuf> {
        match self {
            ManagedAccountRef::Funds(a) => a.all_script_pubkeys(),
            ManagedAccountRef::Keys(a) => a.all_script_pubkeys(),
        }
    }
}

impl<'a> ManagedAccountRefMut<'a> {
    /// Borrow this mutable reference as an immutable [`ManagedAccountRef`].
    pub fn as_ref(&self) -> ManagedAccountRef<'_> {
        match self {
            ManagedAccountRefMut::Funds(a) => ManagedAccountRef::Funds(a),
            ManagedAccountRefMut::Keys(a) => ManagedAccountRef::Keys(a),
        }
    }

    /// Returns the funds account if this is the [`Funds`](Self::Funds) variant.
    pub fn as_funds(&self) -> Option<&ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRefMut::Funds(a) => Some(a),
            ManagedAccountRefMut::Keys(_) => None,
        }
    }

    /// Returns the keys account if this is the [`Keys`](Self::Keys) variant.
    pub fn as_keys(&self) -> Option<&ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRefMut::Funds(_) => None,
            ManagedAccountRefMut::Keys(a) => Some(a),
        }
    }

    /// Returns the funds account if this is the [`Funds`](Self::Funds) variant.
    pub fn as_funds_mut(&mut self) -> Option<&mut ManagedCoreFundsAccount> {
        match self {
            ManagedAccountRefMut::Funds(a) => Some(a),
            ManagedAccountRefMut::Keys(_) => None,
        }
    }

    /// Returns the keys account if this is the [`Keys`](Self::Keys) variant.
    pub fn as_keys_mut(&mut self) -> Option<&mut ManagedCoreKeysAccount> {
        match self {
            ManagedAccountRefMut::Funds(_) => None,
            ManagedAccountRefMut::Keys(a) => Some(a),
        }
    }

    /// Get the managed account type.
    pub fn managed_account_type(&self) -> &ManagedAccountType {
        match self {
            ManagedAccountRefMut::Funds(a) => a.managed_account_type(),
            ManagedAccountRefMut::Keys(a) => a.managed_account_type(),
        }
    }

    /// Get a mutable reference to the managed account type.
    pub fn managed_account_type_mut(&mut self) -> &mut ManagedAccountType {
        match self {
            ManagedAccountRefMut::Funds(a) => a.managed_account_type_mut(),
            ManagedAccountRefMut::Keys(a) => a.managed_account_type_mut(),
        }
    }

    /// Get the network this account belongs to.
    pub fn network(&self) -> Network {
        match self {
            ManagedAccountRefMut::Funds(a) => a.network(),
            ManagedAccountRefMut::Keys(a) => a.network(),
        }
    }

    /// Get the transaction history map.
    pub fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.transactions(),
            ManagedAccountRefMut::Keys(a) => a.transactions(),
        }
    }

    /// Get a mutable reference to the transaction history map.
    pub fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        match self {
            ManagedAccountRefMut::Funds(a) => a.transactions_mut(),
            ManagedAccountRefMut::Keys(a) => a.transactions_mut(),
        }
    }

    /// Whether this account has already processed `txid`.
    pub fn has_transaction(&self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.has_transaction(txid),
            ManagedAccountRefMut::Keys(a) => a.has_transaction(txid),
        }
    }

    /// Whether `txid` has been finalized (chainlocked).
    pub fn transaction_is_finalized(&self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.transaction_is_finalized(txid),
            ManagedAccountRefMut::Keys(a) => a.transaction_is_finalized(txid),
        }
    }

    /// Mark the address as used in whichever pool owns it. Returns `true` if
    /// the address was found and updated.
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.mark_address_used(address),
            ManagedAccountRefMut::Keys(a) => a.mark_address_used(address),
        }
    }

    /// Bump the monitor revision counter — call this when the monitored
    /// address set changes (e.g. new addresses generated).
    pub fn bump_monitor_revision(&mut self) {
        match self {
            ManagedAccountRefMut::Funds(a) => a.bump_monitor_revision(),
            ManagedAccountRefMut::Keys(a) => a.bump_monitor_revision(),
        }
    }

    /// Return the current monitor revision.
    pub fn monitor_revision(&self) -> u64 {
        match self {
            ManagedAccountRefMut::Funds(a) => a.monitor_revision(),
            ManagedAccountRefMut::Keys(a) => a.monitor_revision(),
        }
    }

    /// Record a new transaction for this account.
    ///
    /// Funds variants update UTXO state and balance; keys variants update
    /// only the transaction history. Both are subject to the
    /// `keep-finalized-transactions` Cargo feature for chainlocked records.
    pub fn record_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> TransactionRecord {
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
    ///
    /// Funds variants additionally refresh UTXO state. Returns the updated
    /// record only when confirmation status actually changes.
    pub fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
    ) -> Option<TransactionRecord> {
        match self {
            ManagedAccountRefMut::Funds(a) => {
                a.confirm_transaction(tx, account_match, context, transaction_type)
            }
            ManagedAccountRefMut::Keys(a) => {
                a.confirm_transaction(tx, account_match, context, transaction_type)
            }
        }
    }

    /// Mark all UTXOs belonging to `txid` as InstantSend-locked.
    ///
    /// Returns `true` if any UTXO was newly marked. Always returns `false`
    /// for the [`Keys`](Self::Keys) variant (no UTXOs to mark).
    pub fn mark_utxos_instant_send(&mut self, txid: &Txid) -> bool {
        match self {
            ManagedAccountRefMut::Funds(a) => a.mark_utxos_instant_send(txid),
            ManagedAccountRefMut::Keys(_) => false,
        }
    }
}

/// Owned managed core account, either funds-bearing or keys-only.
///
/// Used by [`ManagedAccountCollection::insert`] so the collection can accept
/// either variant in a single entry point. Use [`OwnedManagedCoreAccount::Funds`]
/// or [`OwnedManagedCoreAccount::Keys`] explicitly when constructing one.
///
/// [`ManagedAccountCollection::insert`]: crate::managed_account::managed_account_collection::ManagedAccountCollection::insert
#[derive(Debug, Clone)]
pub enum OwnedManagedCoreAccount {
    /// Funds-bearing variant (Standard, CoinJoin, DashPay).
    Funds(ManagedCoreFundsAccount),
    /// Keys-only variant (identity, asset-lock, provider).
    Keys(ManagedCoreKeysAccount),
}

impl OwnedManagedCoreAccount {
    /// Borrow this owned account as a [`ManagedAccountRef`].
    pub fn as_ref(&self) -> ManagedAccountRef<'_> {
        match self {
            OwnedManagedCoreAccount::Funds(a) => ManagedAccountRef::Funds(a),
            OwnedManagedCoreAccount::Keys(a) => ManagedAccountRef::Keys(a),
        }
    }

    /// Get the managed account type.
    pub fn managed_account_type(&self) -> &ManagedAccountType {
        self.as_ref().managed_account_type()
    }
}

impl From<ManagedCoreFundsAccount> for OwnedManagedCoreAccount {
    fn from(value: ManagedCoreFundsAccount) -> Self {
        OwnedManagedCoreAccount::Funds(value)
    }
}

impl From<ManagedCoreKeysAccount> for OwnedManagedCoreAccount {
    fn from(value: ManagedCoreKeysAccount) -> Self {
        OwnedManagedCoreAccount::Keys(value)
    }
}
