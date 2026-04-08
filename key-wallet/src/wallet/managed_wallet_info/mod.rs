//! Managed wallet information
//!
//! This module contains the mutable metadata and information about a wallet
//! that is managed separately from the core wallet structure.

pub mod asset_lock_builder;
pub mod coin_selection;
pub mod fee;
pub mod helpers;
pub mod managed_account_operations;
pub mod managed_accounts;
pub mod transaction_builder;
pub mod transaction_building;
pub mod wallet_info_interface;

pub use managed_account_operations::ManagedAccountOperations;

use super::balance::WalletCoreBalance;
use super::metadata::WalletMetadata;
use crate::account::ManagedAccountCollection;
use crate::changeset::{BalanceChangeSet, Merge, WalletChangeSet};
use crate::Network;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Txid;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Information about a managed wallet
///
/// This struct contains the mutable metadata and descriptive information
/// about a wallet, kept separate from the core wallet structure to maintain
/// immutability of the wallet itself.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedWalletInfo {
    /// Network this wallet info is associated with
    pub network: Network,
    /// Unique wallet ID (SHA256 hash of root public key) - should match the Wallet's wallet_id
    pub wallet_id: [u8; 32],
    /// Wallet name
    pub name: Option<String>,
    /// Wallet description
    pub description: Option<String>,
    /// Wallet metadata
    pub metadata: WalletMetadata,
    /// All managed accounts
    pub accounts: ManagedAccountCollection,
    /// Cached wallet core balance - should be updated when accounts change
    pub balance: WalletCoreBalance,
    /// Transactions that have received an InstantSend lock.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) instant_send_locks: HashSet<Txid>,
}

impl ManagedWalletInfo {
    /// Create new managed wallet info with network and wallet ID
    pub fn new(network: Network, wallet_id: [u8; 32]) -> Self {
        Self {
            network,
            wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::new(),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
        }
    }

    /// Create managed wallet info with network, wallet ID and name
    pub fn with_name(network: Network, wallet_id: [u8; 32], name: String) -> Self {
        Self {
            network,
            wallet_id,
            name: Some(name),
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::new(),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
        }
    }

    /// Create managed wallet info from a Wallet
    pub fn from_wallet(wallet: &super::super::Wallet) -> Self {
        Self {
            network: wallet.network,
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: ManagedAccountCollection::from_account_collection(&wallet.accounts),
            balance: WalletCoreBalance::default(),
            instant_send_locks: HashSet::new(),
        }
    }

    /// Create managed wallet info from a Wallet with a name
    pub fn from_wallet_with_name(wallet: &super::super::Wallet, name: String) -> Self {
        let mut info = Self::from_wallet(wallet);
        info.name = Some(name);
        info
    }

    /// Create managed wallet info with birth height
    pub fn with_birth_height(
        network: Network,
        wallet_id: [u8; 32],
        birth_height: CoreBlockHeight,
    ) -> Self {
        let mut info = Self::new(network, wallet_id);
        info.metadata.birth_height = birth_height;
        info
    }

    /// Get the network for this wallet info
    pub fn network(&self) -> Network {
        self.network
    }

    /// Return the last fully processed height of the wallet.
    pub fn synced_height(&self) -> CoreBlockHeight {
        self.metadata.synced_height
    }

    /// Get the wallet's unique ID
    pub fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    /// Get the wallet's name
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Set the wallet's name
    pub fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    /// Get the wallet's description
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Set the wallet's description
    pub fn set_description(&mut self, description: Option<String>) {
        self.description = description;
    }

    /// Get the birth height of the wallet
    pub fn birth_height(&self) -> CoreBlockHeight {
        self.metadata.birth_height
    }

    /// Set the birth height
    pub fn set_birth_height(&mut self, height: CoreBlockHeight) {
        self.metadata.birth_height = height;
    }

    /// Get the timestamp when first loaded
    pub fn first_loaded_at(&self) -> u64 {
        self.metadata.first_loaded_at
    }

    /// Set the timestamp when first loaded
    pub fn set_first_loaded_at(&mut self, timestamp: u64) {
        self.metadata.first_loaded_at = timestamp;
    }

    /// Update last synced timestamp
    pub fn update_last_synced(&mut self, timestamp: u64) {
        self.metadata.last_synced = Some(timestamp);
    }

    /// Get accounts (mutable)
    pub fn accounts_mut(&mut self) -> &mut ManagedAccountCollection {
        &mut self.accounts
    }

    /// Get accounts (immutable)
    pub fn accounts(&self) -> &ManagedAccountCollection {
        &self.accounts
    }

    /// Get the wallet balance
    pub fn balance(&self) -> WalletCoreBalance {
        self.balance
    }

    /// Update the wallet balance from account state.
    pub fn update_balance(&mut self) {
        let mut balance = WalletCoreBalance::default();
        let synced_height = self.synced_height();
        for account in self.accounts.all_accounts_mut() {
            let _balance_cs = account.update_balance(synced_height);
            balance += account.balance;
        }
        self.balance = balance;
    }

    /// Get all UTXOs for the wallet
    pub fn utxos(&self) -> std::collections::BTreeSet<&Utxo> {
        let mut utxos = std::collections::BTreeSet::new();
        for account in self.accounts.all_accounts() {
            utxos.extend(account.utxos.values());
        }
        utxos
    }

    /// Get spendable UTXOs (confirmed and not locked)
    pub fn get_spendable_utxos(&self) -> std::collections::BTreeSet<&Utxo> {
        self.utxos().into_iter().filter(|utxo| utxo.is_spendable(self.synced_height())).collect()
    }

    /// Get all monitored addresses
    pub fn monitored_addresses(&self) -> Vec<dashcore::Address> {
        let mut addresses = Vec::new();
        for account in self.accounts.all_accounts() {
            addresses.extend(account.all_addresses());
        }
        addresses
    }

    /// Get transaction history
    pub fn transaction_history(&self) -> Vec<&TransactionRecord> {
        let mut transactions = Vec::new();
        for account in self.accounts.all_accounts() {
            transactions.extend(account.transactions.values());
        }
        transactions
    }

    /// Get immature transactions
    pub fn immature_transactions(&self) -> Vec<dashcore::Transaction> {
        let mut immature_txids: std::collections::BTreeSet<dashcore::Txid> =
            std::collections::BTreeSet::new();

        // Find txids of immature coinbase UTXOs
        for account in self.accounts.all_accounts() {
            for utxo in account.utxos.values() {
                if utxo.is_coinbase && !utxo.is_mature(self.synced_height()) {
                    immature_txids.insert(utxo.outpoint.txid);
                }
            }
        }

        // Get the actual transactions
        let mut transactions = Vec::new();
        for account in self.accounts.all_accounts() {
            for (txid, record) in &account.transactions {
                if immature_txids.contains(txid) {
                    transactions.push(record.transaction.clone());
                }
            }
        }
        transactions
    }

    /// Update chain state and process any matured transactions.
    /// This should be called when the chain tip advances to a new height.
    pub fn update_synced_height(&mut self, current_height: u32) {
        self.metadata.synced_height = current_height;
        // Update cached balance
        self.update_balance();
    }

    /// Mark UTXOs for a transaction as InstantSend-locked across all accounts.
    /// Returns `(changed, utxo_changeset)` where `changed` indicates if any
    /// UTXO was newly marked, and `utxo_changeset` captures the IS-lock deltas
    /// for persistence.
    pub fn mark_instant_send_utxos(
        &mut self,
        txid: &dashcore::Txid,
    ) -> (bool, crate::changeset::UtxoChangeSet) {
        use crate::changeset::Merge;

        if !self.instant_send_locks.insert(*txid) {
            return (false, crate::changeset::UtxoChangeSet::default());
        }
        let mut any_changed = false;
        let mut combined_utxo_cs = crate::changeset::UtxoChangeSet::default();
        for account in self.accounts.all_accounts_mut() {
            let (changed, utxo_cs) = account.mark_utxos_instant_send(txid);
            if changed {
                any_changed = true;
            }
            combined_utxo_cs.merge(utxo_cs);
        }
        if any_changed {
            self.update_balance();
        }
        (any_changed, combined_utxo_cs)
    }

    /// Return the aggregated monitor revision across all accounts.
    /// Increments whenever the monitored address set changes.
    pub fn monitor_revision(&self) -> u64 {
        self.accounts.all_accounts().iter().map(|a| a.monitor_revision()).sum()
    }

    /// Increment the transaction count
    pub fn increment_transactions(&mut self) {
        self.metadata.total_transactions += 1;
    }

    /// Update the wallet balance and return a `BalanceChangeSet` capturing the aggregate delta.
    pub fn update_balance_with_changeset(&mut self) -> BalanceChangeSet {
        let mut balance = WalletCoreBalance::default();
        let synced_height = self.metadata.synced_height;
        let mut combined = BalanceChangeSet::default();
        for account in self.accounts.all_accounts_mut() {
            let acct_cs = account.update_balance(synced_height);
            balance += account.balance;
            combined.merge(acct_cs);
        }
        self.balance = balance;
        combined
    }

    /// Apply a [`WalletChangeSet`] to this wallet info, updating all relevant
    /// state in place.
    ///
    /// Each sub-changeset is applied independently when present:
    /// - **chain**: updates `synced_height` and related metadata.
    /// - **utxos**: adds, removes, and IS-locks UTXOs in the owning accounts.
    /// - **transactions**: inserts transaction records into owning accounts.
    /// - **accounts**: advances revealed indices and marks addresses as used.
    /// - **balance**: applies signed deltas to the cached wallet balance.
    pub fn apply(&mut self, changeset: &WalletChangeSet) {
        // 1. Chain ----------------------------------------------------------
        if let Some(chain) = &changeset.chain {
            if let Some(height) = chain.height {
                self.metadata.synced_height = height;
            }
        }

        // 2. UTXOs ----------------------------------------------------------
        if let Some(utxos) = &changeset.utxos {
            // 2a. Added UTXOs – find owning account by address and insert.
            for (outpoint, entry) in &utxos.added {
                if let Some(account) = self
                    .accounts
                    .all_accounts_mut()
                    .into_iter()
                    .find(|a| a.contains_address(&entry.address))
                {
                    let utxo = Utxo::new(
                        *outpoint,
                        TxOut {
                            value: entry.value,
                            script_pubkey: entry.script_pubkey.clone(),
                        },
                        entry.address.clone(),
                        self.metadata.synced_height,
                        false, // not coinbase – changeset doesn't carry this info
                    );
                    // Propagate the IS-lock flag from the entry.
                    let mut utxo = utxo;
                    utxo.is_instantlocked = entry.is_instant_locked;
                    account.utxos.insert(*outpoint, utxo);
                }
            }

            // 2b. Spent UTXOs – remove from whichever account holds them.
            for outpoint in &utxos.spent {
                for account in self.accounts.all_accounts_mut() {
                    if account.utxos.remove(outpoint).is_some() {
                        break;
                    }
                }
            }

            // 2c. InstantSend-locked UTXOs – mark existing UTXOs.
            for outpoint in &utxos.instant_locked {
                for account in self.accounts.all_accounts_mut() {
                    if let Some(utxo) = account.utxos.get_mut(outpoint) {
                        utxo.is_instantlocked = true;
                        break;
                    }
                }
            }
        }

        // 3. Transactions ---------------------------------------------------
        if let Some(tx_cs) = &changeset.transactions {
            use crate::managed_account::transaction_record::{TransactionDirection, TransactionRecord};
            use crate::transaction_checking::transaction_router::TransactionType;
            use crate::transaction_checking::TransactionContext;

            for (txid, entry) in &tx_cs.records {
                // Build a TransactionContext from the entry's block info.
                let context = match (entry.block_height, entry.block_hash) {
                    (Some(h), Some(bh)) => {
                        use crate::transaction_checking::BlockInfo;
                        let block_info = BlockInfo::new(h, bh, entry.timestamp as u32);
                        if entry.is_chain_locked {
                            TransactionContext::InChainLockedBlock(block_info)
                        } else {
                            TransactionContext::InBlock(block_info)
                        }
                    }
                    _ => {
                        if entry.is_instant_locked {
                            TransactionContext::InstantSend
                        } else {
                            TransactionContext::Mempool
                        }
                    }
                };

                let direction = if entry.net_amount >= 0 {
                    TransactionDirection::Incoming
                } else {
                    TransactionDirection::Outgoing
                };

                let record = TransactionRecord::new(
                    entry.transaction.clone(),
                    context,
                    TransactionType::Standard, // best-effort default
                    direction,
                    Vec::new(), // input_details – not available from changeset
                    Vec::new(), // output_details – not available from changeset
                    entry.net_amount,
                );

                // Try to find the account that owns an address in this
                // transaction's outputs, and insert the record there.
                let mut inserted = false;
                for account in self.accounts.all_accounts_mut() {
                    for output in &entry.transaction.output {
                        if let Ok(addr) = crate::Address::from_script(
                            &output.script_pubkey,
                            self.network,
                        ) {
                            if account.contains_address(&addr) {
                                account.transactions.insert(*txid, record.clone());
                                inserted = true;
                                break;
                            }
                        }
                    }
                    if inserted {
                        break;
                    }
                }

                // Fallback: if no account matched via outputs, try inputs or
                // just insert into the first standard account.
                if !inserted {
                    if let Some(account) = self
                        .accounts
                        .standard_bip44_accounts
                        .values_mut()
                        .next()
                    {
                        account.transactions.insert(*txid, record);
                    }
                }
            }
        }

        // 4. Accounts -------------------------------------------------------
        if let Some(acct_cs) = &changeset.accounts {
            // 4a. last_revealed – advance the highest_generated index on
            // address pools for the given account indices.
            for (&account_index, &new_index) in &acct_cs.last_revealed {
                if let Some(account) = self
                    .accounts
                    .standard_bip44_accounts
                    .get_mut(&account_index)
                {
                    for pool in account.account_type.address_pools_mut() {
                        if let Some(current) = pool.highest_generated {
                            if new_index > current {
                                pool.highest_generated = Some(new_index);
                            }
                        } else {
                            pool.highest_generated = Some(new_index);
                        }
                    }
                }
            }

            // 4b. addresses_used – mark each address as used in its account.
            for (_, address) in &acct_cs.addresses_used {
                for account in self.accounts.all_accounts_mut() {
                    if account.contains_address(address) {
                        account.account_type.mark_address_used(address);
                        break;
                    }
                }
            }
        }

        // 5. Balance --------------------------------------------------------
        if let Some(balance_cs) = &changeset.balance {
            self.balance.apply_delta(balance_cs);
        }
    }
}

/// Re-export types from account module for convenience
pub use crate::account::TransactionRecord;
pub use crate::utxo::Utxo;
