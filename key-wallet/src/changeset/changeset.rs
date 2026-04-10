//! Wallet-level changeset types.
//!
//! Changesets carry the wallet's **native types** directly (`Utxo`,
//! `TransactionRecord`, etc.) rather than flattened persistence-friendly
//! representations. Persistence backends (e.g. SQLite) translate from the
//! native types to their schema as part of their own code — that's a
//! persister concern, not a changeset concern.
//!
//! Every type in this module implements [`Merge`] so that multiple deltas
//! produced during processing can be accumulated into a single changeset
//! before being persisted.

use std::collections::{BTreeMap, BTreeSet};

use dashcore::{BlockHash, OutPoint, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::account::AccountType;
use crate::managed_account::address_pool::AddressPoolType;
use crate::managed_account::transaction_record::TransactionRecord;
use crate::utxo::Utxo;
use crate::Address;

use super::merge::Merge;

// ---------------------------------------------------------------------------
// Top-level WalletChangeSet
// ---------------------------------------------------------------------------

/// Atomic delta of wallet state produced by a mutation.
///
/// Composed of optional sub-changesets — `None` means no change in that area.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletChangeSet {
    /// HD account structure (account types added to the Wallet).
    /// On apply, re-derived from the seed via `wallet.add_account(type, None)`.
    pub account_keys: Option<AccountKeyChangeSet>,

    /// `ManagedCoreAccount` runtime state (addresses used, highest_used indices).
    pub account_states: Option<AccountStateChangeSet>,

    /// Core chain state (synced height, latest block hash).
    pub chain: Option<ChainChangeSet>,

    /// UTXO additions, spends, and InstantSend-lock transitions.
    pub utxos: Option<UtxoChangeSet>,

    /// Transaction records.
    pub transactions: Option<TransactionChangeSet>,

    /// Cached balance delta (signed).
    pub balance: Option<BalanceChangeSet>,
}

impl Merge for WalletChangeSet {
    fn merge(&mut self, other: Self) {
        self.account_keys.merge(other.account_keys);
        self.account_states.merge(other.account_states);
        self.chain.merge(other.chain);
        self.utxos.merge(other.utxos);
        self.transactions.merge(other.transactions);
        self.balance.merge(other.balance);
    }

    fn is_empty(&self) -> bool {
        self.account_keys.is_empty()
            && self.account_states.is_empty()
            && self.chain.is_empty()
            && self.utxos.is_empty()
            && self.transactions.is_empty()
            && self.balance.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AccountKeyChangeSet — HD account structure (keys derived from seed)
// ---------------------------------------------------------------------------

/// HD account types added to `Wallet.accounts`.
///
/// On restore, each account type is re-derived from the seed via
/// `Wallet::add_account(account_type, None)`. The keys themselves are not
/// persisted — only the fact that the account exists.
///
/// Uses `Vec` rather than `BTreeSet` because `AccountType` does not implement
/// `Ord`. Duplicates are deduplicated on merge.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountKeyChangeSet {
    pub added: Vec<AccountType>,
}

impl Merge for AccountKeyChangeSet {
    fn merge(&mut self, other: Self) {
        for account_type in other.added {
            if !self.added.contains(&account_type) {
                self.added.push(account_type);
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AccountStateChangeSet — per-account address pool state
// ---------------------------------------------------------------------------

/// Per-account address pool state changes.
///
/// Tracks which addresses have been marked used and the highest used
/// index per (account_index, pool_type). Used by `apply()` to restore
/// address pool state.
///
/// Routing on `apply()` uses the `Address` itself via
/// `ManagedWalletInfo::find_account_by_address_mut` — no per-account index
/// is needed in `addresses_used`. The `highest_used` map is keyed by
/// `(account_index, pool_type)` so Standard accounts (which have both an
/// external and internal pool) can track each pool independently. Single-
/// pool account types (Identity*, Provider*, …) don't grow their pools via
/// gap-limit maintenance so they don't populate this map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountStateChangeSet {
    /// Addresses marked as used during processing. `BTreeSet` so duplicates
    /// within a single changeset collapse automatically.
    pub addresses_used: BTreeSet<Address>,

    /// `(account_index, pool_type) → highest_used_index` after gap limit
    /// maintenance. Max-wins on merge. Matches `AddressPool::highest_used`.
    pub highest_used: BTreeMap<(u32, AddressPoolType), u32>,
}

impl Merge for AccountStateChangeSet {
    fn merge(&mut self, other: Self) {
        self.addresses_used.extend(other.addresses_used);
        for (key, new_highest) in other.highest_used {
            self.highest_used
                .entry(key)
                .and_modify(|current| *current = (*current).max(new_highest))
                .or_insert(new_highest);
        }
    }

    fn is_empty(&self) -> bool {
        self.addresses_used.is_empty() && self.highest_used.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ChainChangeSet — synced chain state
// ---------------------------------------------------------------------------

/// Core chain state changes (last processed height + block hash).
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ChainChangeSet {
    pub synced_height: Option<u32>,
    pub block_hash: Option<BlockHash>,
}

impl Merge for ChainChangeSet {
    fn merge(&mut self, other: Self) {
        // Later height wins.
        if let Some(h) = other.synced_height {
            match self.synced_height {
                Some(current) if current >= h => {}
                _ => self.synced_height = Some(h),
            }
        }
        if other.block_hash.is_some() {
            self.block_hash = other.block_hash;
        }
    }

    fn is_empty(&self) -> bool {
        self.synced_height.is_none() && self.block_hash.is_none()
    }
}

// ---------------------------------------------------------------------------
// UtxoChangeSet — UTXO additions, spends, IS-lock transitions
// ---------------------------------------------------------------------------

/// UTXO-level changes from a single mutation.
///
/// Carries the native `Utxo` type directly so `apply()` can insert without
/// conversion. The address inside each `Utxo` is used by the routing logic
/// in `WalletManager::apply` to find the owning `ManagedCoreAccount`.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UtxoChangeSet {
    pub added: BTreeMap<OutPoint, Utxo>,
    pub spent: BTreeSet<OutPoint>,
    pub instant_locked: BTreeSet<OutPoint>,
}

impl Merge for UtxoChangeSet {
    fn merge(&mut self, other: Self) {
        self.added.extend(other.added);
        self.spent.extend(other.spent);
        self.instant_locked.extend(other.instant_locked);
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.spent.is_empty() && self.instant_locked.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TransactionChangeSet — transaction record additions / updates
// ---------------------------------------------------------------------------

/// Transaction record changes.
///
/// Carries the native `TransactionRecord` type directly. Later merges
/// overwrite earlier ones for the same `Txid` (last write wins), matching
/// `BTreeMap::extend` semantics.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransactionChangeSet {
    pub records: BTreeMap<Txid, TransactionRecord>,
}

impl Merge for TransactionChangeSet {
    fn merge(&mut self, other: Self) {
        self.records.extend(other.records);
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ---------------------------------------------------------------------------
// BalanceChangeSet — cached balance deltas
// ---------------------------------------------------------------------------

/// Signed deltas to the wallet's cached balance buckets.
///
/// Deltas are composable: multiple changesets merged add up.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BalanceChangeSet {
    pub spendable_delta: i64,
    pub unconfirmed_delta: i64,
    pub immature_delta: i64,
    pub locked_delta: i64,
}

impl Merge for BalanceChangeSet {
    fn merge(&mut self, other: Self) {
        self.spendable_delta = self.spendable_delta.saturating_add(other.spendable_delta);
        self.unconfirmed_delta = self.unconfirmed_delta.saturating_add(other.unconfirmed_delta);
        self.immature_delta = self.immature_delta.saturating_add(other.immature_delta);
        self.locked_delta = self.locked_delta.saturating_add(other.locked_delta);
    }

    fn is_empty(&self) -> bool {
        self.spendable_delta == 0
            && self.unconfirmed_delta == 0
            && self.immature_delta == 0
            && self.locked_delta == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_changeset_is_empty_by_default() {
        let cs = WalletChangeSet::default();
        assert!(cs.is_empty());
    }

    #[test]
    fn wallet_changeset_merge_combines_sub_changesets() {
        let mut a = WalletChangeSet::default();
        let mut b = WalletChangeSet::default();
        a.chain = Some(ChainChangeSet {
            synced_height: Some(100),
            block_hash: None,
        });
        b.chain = Some(ChainChangeSet {
            synced_height: Some(150),
            block_hash: None,
        });
        a.merge(b);
        assert_eq!(a.chain.as_ref().unwrap().synced_height, Some(150));
    }

    #[test]
    fn balance_changeset_merge_sums_deltas() {
        let mut a = BalanceChangeSet {
            spendable_delta: 100,
            ..Default::default()
        };
        let b = BalanceChangeSet {
            spendable_delta: -50,
            unconfirmed_delta: 200,
            ..Default::default()
        };
        a.merge(b);
        assert_eq!(a.spendable_delta, 50);
        assert_eq!(a.unconfirmed_delta, 200);
    }

    #[test]
    fn account_state_changeset_merge_keeps_highest_used() {
        let ext0 = (0, AddressPoolType::External);
        let int0 = (0, AddressPoolType::Internal);
        let ext1 = (1, AddressPoolType::External);

        let mut a = AccountStateChangeSet::default();
        a.highest_used.insert(ext0, 5);
        let mut b = AccountStateChangeSet::default();
        b.highest_used.insert(ext0, 3); // lower — should NOT overwrite
        b.highest_used.insert(int0, 7); // different pool — should add
        b.highest_used.insert(ext1, 10); // different account — should add
        a.merge(b);
        assert_eq!(a.highest_used.get(&ext0), Some(&5));
        assert_eq!(a.highest_used.get(&int0), Some(&7));
        assert_eq!(a.highest_used.get(&ext1), Some(&10));
    }

    #[test]
    fn chain_changeset_merge_keeps_highest_height() {
        let mut a = ChainChangeSet {
            synced_height: Some(200),
            block_hash: None,
        };
        let b = ChainChangeSet {
            synced_height: Some(150),
            block_hash: None,
        };
        a.merge(b);
        assert_eq!(a.synced_height, Some(200));
    }
}
