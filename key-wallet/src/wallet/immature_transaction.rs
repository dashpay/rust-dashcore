//! Immature transaction tracking for coinbase and special transactions
//!
//! This module provides structures for tracking immature transactions
//! that require confirmations before their outputs can be spent.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use dashcore::blockdata::transaction::Transaction;
use dashcore::{BlockHash, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents an immature transaction with the accounts it affects
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImmatureTransaction {
    /// The transaction
    pub transaction: Transaction,
    /// Transaction ID
    pub txid: Txid,
    /// Block height where transaction was confirmed
    pub height: u32,
    /// Block hash where transaction was confirmed
    pub block_hash: BlockHash,
    /// Timestamp of the block
    pub timestamp: u64,
    /// Number of confirmations needed to mature (typically 100 for coinbase)
    pub maturity_confirmations: u32,
    /// Accounts affected by this transaction
    pub affected_accounts: AffectedAccounts,
    /// Total amount received by our accounts
    pub total_received: u64,
    /// Whether this is a coinbase transaction
    pub is_coinbase: bool,
}

/// Tracks which accounts are affected by an immature transaction
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AffectedAccounts {
    /// BIP44 account indices that received funds
    pub bip44_accounts: BTreeSet<u32>,
    /// BIP32 account indices that received funds
    pub bip32_accounts: BTreeSet<u32>,
    /// CoinJoin account indices that received funds
    pub coinjoin_accounts: BTreeSet<u32>,
}

impl AffectedAccounts {
    /// Create a new empty set of affected accounts
    pub fn new() -> Self {
        Self {
            bip44_accounts: BTreeSet::new(),
            bip32_accounts: BTreeSet::new(),
            coinjoin_accounts: BTreeSet::new(),
        }
    }

    /// Check if any accounts are affected
    pub fn is_empty(&self) -> bool {
        self.bip44_accounts.is_empty()
            && self.bip32_accounts.is_empty()
            && self.coinjoin_accounts.is_empty()
    }

    /// Get total number of affected accounts
    pub fn count(&self) -> usize {
        self.bip44_accounts.len() + self.bip32_accounts.len() + self.coinjoin_accounts.len()
    }

    /// Add a BIP44 account
    pub fn add_bip44(&mut self, index: u32) {
        self.bip44_accounts.insert(index);
    }

    /// Add a BIP32 account
    pub fn add_bip32(&mut self, index: u32) {
        self.bip32_accounts.insert(index);
    }

    /// Add a CoinJoin account
    pub fn add_coinjoin(&mut self, index: u32) {
        self.coinjoin_accounts.insert(index);
    }
}

impl ImmatureTransaction {
    /// Create a new immature transaction
    pub fn new(
        transaction: Transaction,
        height: u32,
        block_hash: BlockHash,
        timestamp: u64,
        maturity_confirmations: u32,
        is_coinbase: bool,
    ) -> Self {
        let txid = transaction.txid();
        Self {
            transaction,
            txid,
            height,
            block_hash,
            timestamp,
            maturity_confirmations,
            affected_accounts: AffectedAccounts::new(),
            total_received: 0,
            is_coinbase,
        }
    }

    /// Check if the transaction has matured based on current chain height
    pub fn is_mature(&self, current_height: u32) -> bool {
        if current_height < self.height {
            return false;
        }
        let confirmations = (current_height - self.height) + 1;
        confirmations >= self.maturity_confirmations
    }

    /// Get the number of confirmations
    pub fn confirmations(&self, current_height: u32) -> u32 {
        if current_height >= self.height {
            (current_height - self.height) + 1
        } else {
            0
        }
    }

    /// Get remaining confirmations until mature
    pub fn remaining_confirmations(&self, current_height: u32) -> u32 {
        let confirmations = self.confirmations(current_height);
        self.maturity_confirmations.saturating_sub(confirmations)
    }
}

/// Collection of immature transactions indexed by maturity height
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImmatureTransactionCollection {
    /// Map of maturity height to list of transactions that will mature at that height
    transactions_by_maturity_height: alloc::collections::BTreeMap<u32, Vec<ImmatureTransaction>>,
    /// Secondary index: txid to maturity height for quick lookups
    txid_to_height: alloc::collections::BTreeMap<Txid, u32>,
}

impl ImmatureTransactionCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self {
            transactions_by_maturity_height: alloc::collections::BTreeMap::new(),
            txid_to_height: alloc::collections::BTreeMap::new(),
        }
    }

    /// Add an immature transaction
    pub fn insert(&mut self, tx: ImmatureTransaction) {
        let maturity_height = tx.height + tx.maturity_confirmations;
        let txid = tx.txid;

        // Add to the maturity height index
        self.transactions_by_maturity_height.entry(maturity_height).or_default().push(tx);

        // Add to txid index
        self.txid_to_height.insert(txid, maturity_height);
    }

    /// Remove an immature transaction by txid
    pub fn remove(&mut self, txid: &Txid) -> Option<ImmatureTransaction> {
        // Find the maturity height for this txid
        if let Some(maturity_height) = self.txid_to_height.remove(txid) {
            // Find and remove from the transactions list at that height
            if let Some(transactions) =
                self.transactions_by_maturity_height.get_mut(&maturity_height)
            {
                if let Some(pos) = transactions.iter().position(|tx| tx.txid == *txid) {
                    let tx = transactions.remove(pos);

                    // If this was the last transaction at this height, remove the entry
                    if transactions.is_empty() {
                        self.transactions_by_maturity_height.remove(&maturity_height);
                    }

                    return Some(tx);
                }
            }
        }
        None
    }

    /// Get an immature transaction by txid
    pub fn get(&self, txid: &Txid) -> Option<&ImmatureTransaction> {
        if let Some(maturity_height) = self.txid_to_height.get(txid) {
            if let Some(transactions) = self.transactions_by_maturity_height.get(maturity_height) {
                return transactions.iter().find(|tx| tx.txid == *txid);
            }
        }
        None
    }

    /// Get a mutable reference to an immature transaction
    pub fn get_mut(&mut self, txid: &Txid) -> Option<&mut ImmatureTransaction> {
        if let Some(maturity_height) = self.txid_to_height.get(txid) {
            if let Some(transactions) =
                self.transactions_by_maturity_height.get_mut(maturity_height)
            {
                return transactions.iter_mut().find(|tx| tx.txid == *txid);
            }
        }
        None
    }

    /// Check if a transaction is in the collection
    pub fn contains(&self, txid: &Txid) -> bool {
        self.txid_to_height.contains_key(txid)
    }

    /// Get all transactions that have matured at or before the given height
    pub fn get_matured(&self, current_height: u32) -> Vec<&ImmatureTransaction> {
        let mut matured = Vec::new();

        // Iterate through all heights up to and including current_height
        for (_, transactions) in self.transactions_by_maturity_height.range(..=current_height) {
            matured.extend(transactions.iter());
        }

        matured
    }

    /// Remove and return all matured transactions
    pub fn remove_matured(&mut self, current_height: u32) -> Vec<ImmatureTransaction> {
        let mut matured = Vec::new();

        // Collect all maturity heights that have been reached
        let matured_heights: Vec<u32> = self
            .transactions_by_maturity_height
            .range(..=current_height)
            .map(|(height, _)| *height)
            .collect();

        // Remove all transactions at matured heights
        for height in matured_heights {
            if let Some(transactions) = self.transactions_by_maturity_height.remove(&height) {
                // Remove txids from index
                for tx in &transactions {
                    self.txid_to_height.remove(&tx.txid);
                }
                matured.extend(transactions);
            }
        }

        matured
    }

    /// Get all immature transactions
    pub fn all(&self) -> Vec<&ImmatureTransaction> {
        self.transactions_by_maturity_height.values().flat_map(|txs| txs.iter()).collect()
    }

    /// Get number of immature transactions
    pub fn len(&self) -> usize {
        self.txid_to_height.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.txid_to_height.is_empty()
    }

    /// Clear all transactions
    pub fn clear(&mut self) {
        self.transactions_by_maturity_height.clear();
        self.txid_to_height.clear();
    }

    /// Get total value of all immature transactions
    pub fn total_immature_balance(&self) -> u64 {
        self.transactions_by_maturity_height
            .values()
            .flat_map(|txs| txs.iter())
            .map(|tx| tx.total_received)
            .sum()
    }

    /// Get immature balance for BIP44 accounts
    pub fn bip44_immature_balance(&self, account_index: u32) -> u64 {
        self.transactions_by_maturity_height
            .values()
            .flat_map(|txs| txs.iter())
            .filter(|tx| tx.affected_accounts.bip44_accounts.contains(&account_index))
            .map(|tx| tx.total_received)
            .sum()
    }

    /// Get immature balance for BIP32 accounts
    pub fn bip32_immature_balance(&self, account_index: u32) -> u64 {
        self.transactions_by_maturity_height
            .values()
            .flat_map(|txs| txs.iter())
            .filter(|tx| tx.affected_accounts.bip32_accounts.contains(&account_index))
            .map(|tx| tx.total_received)
            .sum()
    }

    /// Get immature balance for CoinJoin accounts
    pub fn coinjoin_immature_balance(&self, account_index: u32) -> u64 {
        self.transactions_by_maturity_height
            .values()
            .flat_map(|txs| txs.iter())
            .filter(|tx| tx.affected_accounts.coinjoin_accounts.contains(&account_index))
            .map(|tx| tx.total_received)
            .sum()
    }

    /// Get transactions that will mature at a specific height
    pub fn at_height(&self, height: u32) -> Vec<&ImmatureTransaction> {
        self.transactions_by_maturity_height
            .get(&height)
            .map(|txs| txs.iter().collect())
            .unwrap_or_default()
    }

    /// Get the next maturity height (the lowest height where transactions will mature)
    pub fn next_maturity_height(&self) -> Option<u32> {
        self.transactions_by_maturity_height.keys().next().copied()
    }

    /// Get all maturity heights
    pub fn maturity_heights(&self) -> Vec<u32> {
        self.transactions_by_maturity_height.keys().copied().collect()
    }
}
