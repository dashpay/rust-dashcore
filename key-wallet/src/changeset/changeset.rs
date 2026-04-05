//! Wallet changeset types for incremental persistence.
//!
//! A [`WalletChangeSet`] captures the delta between the current wallet state
//! and the last persisted snapshot.  Sub-changesets cover individual domains
//! (chain tip, UTXOs, transactions, accounts, balances).

use std::collections::{BTreeMap, BTreeSet};

use dashcore::blockdata::transaction::OutPoint;
use dashcore::{BlockHash, ScriptBuf, Transaction, Txid};

use crate::Address;

use super::merge::Merge;

// ---------------------------------------------------------------------------
// Top-level changeset
// ---------------------------------------------------------------------------

/// Aggregated changeset covering every persistable wallet domain.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WalletChangeSet {
    /// Changes to the chain tip the wallet is tracking.
    pub chain: Option<ChainChangeSet>,
    /// UTXO additions, spends, and lock-state changes.
    pub utxos: Option<UtxoChangeSet>,
    /// New or updated transaction records.
    pub transactions: Option<TransactionChangeSet>,
    /// Account-level changes (revealed indices, address usage).
    pub accounts: Option<AccountChangeSet>,
    /// Balance deltas since last persist.
    pub balance: Option<BalanceChangeSet>,
}

impl Merge for WalletChangeSet {
    fn merge(&mut self, other: Self) {
        self.chain.merge(other.chain);
        self.utxos.merge(other.utxos);
        self.transactions.merge(other.transactions);
        self.accounts.merge(other.accounts);
        self.balance.merge(other.balance);
    }

    fn is_empty(&self) -> bool {
        self.chain.is_empty()
            && self.utxos.is_empty()
            && self.transactions.is_empty()
            && self.accounts.is_empty()
            && self.balance.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// Tracks the latest chain tip the wallet has processed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChainChangeSet {
    /// New best-known block height.
    pub height: Option<u32>,
    /// Hash of the block at `height`.
    pub block_hash: Option<BlockHash>,
}

impl Merge for ChainChangeSet {
    fn merge(&mut self, other: Self) {
        if other.height.is_some() {
            self.height = other.height;
        }
        if other.block_hash.is_some() {
            self.block_hash = other.block_hash;
        }
    }

    fn is_empty(&self) -> bool {
        self.height.is_none() && self.block_hash.is_none()
    }
}

// ---------------------------------------------------------------------------
// UTXOs
// ---------------------------------------------------------------------------

/// Incremental UTXO changes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UtxoChangeSet {
    /// Newly discovered unspent outputs.
    pub added: BTreeMap<OutPoint, UtxoEntry>,
    /// Outpoints that have been spent since last persist.
    pub spent: BTreeSet<OutPoint>,
    /// Outpoints that received an InstantSend lock.
    pub instant_locked: BTreeSet<OutPoint>,
}

impl Merge for UtxoChangeSet {
    fn merge(&mut self, other: Self) {
        self.added.merge(other.added);
        self.spent.merge(other.spent);
        self.instant_locked.merge(other.instant_locked);
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.spent.is_empty() && self.instant_locked.is_empty()
    }
}

/// A single unspent transaction output entry.
#[derive(Debug, Clone, PartialEq)]
pub struct UtxoEntry {
    /// The address this output pays to.
    pub address: Address,
    /// Value in satoshis.
    pub value: u64,
    /// The output script.
    pub script_pubkey: ScriptBuf,
    /// Whether this output has been InstantSend-locked.
    pub is_instant_locked: bool,
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// Incremental transaction record changes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TransactionChangeSet {
    /// New or updated transaction records keyed by txid.
    pub records: BTreeMap<Txid, TransactionEntry>,
}

impl Merge for TransactionChangeSet {
    fn merge(&mut self, other: Self) {
        self.records.merge(other.records);
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Full record for a single transaction relevant to the wallet.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionEntry {
    /// The raw transaction.
    pub transaction: Transaction,
    /// Block height the transaction was mined in (if confirmed).
    pub block_height: Option<u32>,
    /// Hash of the block the transaction was mined in (if confirmed).
    pub block_hash: Option<BlockHash>,
    /// Unix timestamp (seconds) when first seen or confirmed.
    pub timestamp: u64,
    /// Net satoshi change from the wallet's perspective (positive = incoming).
    pub net_amount: i64,
    /// Fee paid (if known).
    pub fee: Option<u64>,
    /// User-supplied label.
    pub label: Option<String>,
    /// Whether the transaction has an InstantSend lock.
    pub is_instant_locked: bool,
    /// Whether the transaction is covered by a ChainLock.
    pub is_chain_locked: bool,
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// Account-level changes (address pools, revealed indices).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccountChangeSet {
    /// Maps `account_index` to the new highest-revealed address index.
    pub last_revealed: BTreeMap<u32, u32>,
    /// Addresses that have been marked as used: `(account_index, address)`.
    pub addresses_used: Vec<(u32, Address)>,
}

impl Merge for AccountChangeSet {
    fn merge(&mut self, other: Self) {
        // For last_revealed, keep the higher value per account.
        for (acct, idx) in other.last_revealed {
            let entry = self.last_revealed.entry(acct).or_insert(0);
            if idx > *entry {
                *entry = idx;
            }
        }
        self.addresses_used.merge(other.addresses_used);
    }

    fn is_empty(&self) -> bool {
        self.last_revealed.is_empty() && self.addresses_used.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Balances
// ---------------------------------------------------------------------------

/// Cumulative balance deltas since the last persist.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BalanceChangeSet {
    /// Change in spendable (confirmed + InstantSend-locked) balance.
    pub spendable_delta: i64,
    /// Change in unconfirmed balance.
    pub unconfirmed_delta: i64,
    /// Change in immature (coinbase) balance.
    pub immature_delta: i64,
    /// Change in locked (frozen) balance.
    pub locked_delta: i64,
}

impl Merge for BalanceChangeSet {
    fn merge(&mut self, other: Self) {
        self.spendable_delta += other.spendable_delta;
        self.unconfirmed_delta += other.unconfirmed_delta;
        self.immature_delta += other.immature_delta;
        self.locked_delta += other.locked_delta;
    }

    fn is_empty(&self) -> bool {
        self.spendable_delta == 0
            && self.unconfirmed_delta == 0
            && self.immature_delta == 0
            && self.locked_delta == 0
    }
}
