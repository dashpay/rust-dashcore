//! Wallet-level changeset types.
//!
//! Changesets carry the wallet's **native types** directly (`Utxo`,
//! `TransactionRecord`, etc.) rather than flattened persistence-friendly
//! representations. Persistence backends (e.g. SQLite) translate from the
//! native types to their schema as part of their own code — that's a
//! persister concern, not a changeset concern.
//!
//! # Shape
//!
//! The top-level [`WalletChangeSet`] carries:
//! - **Wallet-scoped** sub-changesets that have no per-account meaning:
//!   [`AccountKeyChangeSet`] (which HD account types exist),
//!   [`ChainChangeSet`] (synced height), and [`BalanceChangeSet`] (cached
//!   balance delta).
//! - **Per-account** deltas in `per_account: BTreeMap<AccountType, _>`.
//!   Each bucket is an [`AccountChangeSet`] that scopes its own
//!   `addresses_used`, `highest_used`, `utxos_*`, and `transactions` to
//!   one `ManagedCoreAccount`.
//!
//! The per-account bucketing is intentional: at emission time each mutation
//! knows which account it's modifying, so it writes directly into
//! `per_account[key]`. At apply time each bucket is routed to its owning
//! account by a single `accounts.get_by_account_type_mut(&key)` lookup. No
//! address-based scanning, no ambiguity for multi-account transactions
//! (CoinJoin, cross-account transfers) where the same `Txid` carries
//! different per-account views.
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
/// See the module docs for the overall shape. Wallet-scoped sub-changesets
/// are `Option<T>`; per-account deltas live in `per_account`, keyed by
/// `AccountType`.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletChangeSet {
    /// HD account structure (account types added to the `Wallet`).
    /// On apply, re-derived from the seed via `wallet.add_account(ty, None)`.
    pub account_keys: Option<AccountKeyChangeSet>,

    /// Core chain state (synced height, latest block hash).
    pub chain: Option<ChainChangeSet>,

    /// Cached balance delta (signed, wallet-wide).
    pub balance: Option<BalanceChangeSet>,

    /// Per-account deltas, keyed by [`AccountType`]. Each bucket is
    /// populated by the owning `ManagedCoreAccount` at emission time and
    /// routed directly on apply — no address-based fallback scanning.
    pub per_account: BTreeMap<AccountType, AccountChangeSet>,
}

impl Merge for WalletChangeSet {
    fn merge(&mut self, other: Self) {
        self.account_keys.merge(other.account_keys);
        self.chain.merge(other.chain);
        self.balance.merge(other.balance);
        for (key, incoming) in other.per_account {
            self.per_account.entry(key).or_default().merge(incoming);
        }
    }

    fn is_empty(&self) -> bool {
        self.account_keys.is_empty()
            && self.chain.is_empty()
            && self.balance.is_empty()
            && self.per_account.values().all(|cs| cs.is_empty())
    }
}

impl WalletChangeSet {
    /// Get (or create) the per-account bucket for `account_type`.
    ///
    /// Used by the orchestrator during mutation accumulation to merge an
    /// [`AccountChangeSet`] returned by a per-account mutation method into
    /// the correct bucket.
    pub fn account_bucket(&mut self, account_type: AccountType) -> &mut AccountChangeSet {
        self.per_account.entry(account_type).or_default()
    }
}

// ---------------------------------------------------------------------------
// AccountChangeSet — per-account delta
// ---------------------------------------------------------------------------

/// All state changes belonging to a single [`ManagedCoreAccount`].
///
/// Produced by the per-account mutation methods on `ManagedCoreAccount`
/// (e.g. `mark_address_used`, `record_transaction`, `update_utxos`,
/// `mark_utxos_instant_send`, `update_transaction_context`). The owning
/// account type is stored outside this struct, as the key in
/// [`WalletChangeSet::per_account`].
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountChangeSet {
    /// Addresses marked as used during processing. `BTreeSet` so duplicate
    /// marks within a single changeset collapse automatically.
    pub addresses_used: BTreeSet<Address>,

    /// `pool_type → highest_used_index` after gap limit maintenance.
    /// Max-wins on merge. Mirrors `AddressPool::highest_used`.
    pub highest_used: BTreeMap<AddressPoolType, u32>,

    /// UTXOs received or upgraded (mempool → confirmed, unlocked → IS-locked).
    pub utxos_added: BTreeMap<OutPoint, Utxo>,

    /// UTXOs spent.
    pub utxos_spent: BTreeSet<OutPoint>,

    /// UTXOs that transitioned to InstantSend-locked.
    pub utxos_instant_locked: BTreeSet<OutPoint>,

    /// Transaction records inserted or updated, keyed by `Txid`. A single
    /// account holds at most one record per txid, so the map encoding
    /// gives last-write-wins dedup via `extend` on merge for free.
    pub transactions: BTreeMap<Txid, TransactionRecord>,
}

impl Merge for AccountChangeSet {
    fn merge(&mut self, other: Self) {
        self.addresses_used.extend(other.addresses_used);
        for (pool_type, new_highest) in other.highest_used {
            self.highest_used
                .entry(pool_type)
                .and_modify(|current| *current = (*current).max(new_highest))
                .or_insert(new_highest);
        }
        self.utxos_added.extend(other.utxos_added);
        self.utxos_spent.extend(other.utxos_spent);
        self.utxos_instant_locked.extend(other.utxos_instant_locked);
        // Last-write-wins dedup per txid, free via `BTreeMap::extend`.
        self.transactions.extend(other.transactions);
    }

    fn is_empty(&self) -> bool {
        self.addresses_used.is_empty()
            && self.highest_used.is_empty()
            && self.utxos_added.is_empty()
            && self.utxos_spent.is_empty()
            && self.utxos_instant_locked.is_empty()
            && self.transactions.is_empty()
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
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountKeyChangeSet {
    pub added: BTreeSet<AccountType>,
}

impl Merge for AccountKeyChangeSet {
    fn merge(&mut self, other: Self) {
        self.added.extend(other.added);
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty()
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
    use crate::account::StandardAccountType;

    fn bip44_account_0() -> AccountType {
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        }
    }

    fn bip44_account_1() -> AccountType {
        AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        }
    }

    #[test]
    fn wallet_changeset_is_empty_by_default() {
        let cs = WalletChangeSet::default();
        assert!(cs.is_empty());
    }

    #[test]
    fn wallet_changeset_merge_keeps_latest_chain_height() {
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
    fn account_changeset_merge_keeps_highest_used() {
        let mut a = AccountChangeSet::default();
        a.highest_used.insert(AddressPoolType::External, 5);
        a.highest_used.insert(AddressPoolType::Internal, 2);

        let mut b = AccountChangeSet::default();
        b.highest_used.insert(AddressPoolType::External, 3); // lower — must not overwrite
        b.highest_used.insert(AddressPoolType::Internal, 8); // higher — must win

        a.merge(b);
        assert_eq!(a.highest_used.get(&AddressPoolType::External), Some(&5));
        assert_eq!(a.highest_used.get(&AddressPoolType::Internal), Some(&8));
    }

    // Dedicated dedup test removed: `AccountChangeSet::transactions` is a
    // `BTreeMap<Txid, TransactionRecord>`, so last-write-wins on merge is
    // guaranteed by `BTreeMap::extend` — no custom dedup logic to cover.

    #[test]
    fn wallet_changeset_merge_merges_per_account_buckets() {
        let mut a = WalletChangeSet::default();
        a.account_bucket(bip44_account_0())
            .highest_used
            .insert(AddressPoolType::External, 5);

        let mut b = WalletChangeSet::default();
        b.account_bucket(bip44_account_0())
            .highest_used
            .insert(AddressPoolType::External, 8);
        b.account_bucket(bip44_account_1())
            .highest_used
            .insert(AddressPoolType::External, 2);

        a.merge(b);

        // Same bucket merged max-wins on highest_used.
        assert_eq!(
            a.per_account
                .get(&bip44_account_0())
                .unwrap()
                .highest_used
                .get(&AddressPoolType::External),
            Some(&8)
        );
        // Second bucket added.
        assert_eq!(
            a.per_account
                .get(&bip44_account_1())
                .unwrap()
                .highest_used
                .get(&AddressPoolType::External),
            Some(&2)
        );
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
