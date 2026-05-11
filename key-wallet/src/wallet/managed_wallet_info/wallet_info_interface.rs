//! Trait defining the interface for wallet info types
//!
//! This trait allows WalletManager to work with different wallet info implementations

use std::collections::{BTreeMap, BTreeSet};

use super::managed_account_operations::ManagedAccountOperations;
use crate::account::{AccountType, ManagedAccountTrait};
use crate::managed_account::managed_account_collection::ManagedAccountCollection;
use crate::managed_account::managed_account_ref::ManagedAccountRefMut;
use crate::transaction_checking::TransactionContext;
use crate::transaction_checking::WalletTransactionChecker;
use crate::wallet::managed_wallet_info::TransactionRecord;
use crate::wallet::ManagedWalletInfo;
use crate::{Network, Utxo, Wallet, WalletCoreBalance};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address as DashAddress, Transaction, Txid};

/// Trait that wallet info types must implement to work with WalletManager
pub trait WalletInfoInterface: Sized + WalletTransactionChecker + ManagedAccountOperations {
    /// Create a wallet info from an existing wallet, seeding the sync checkpoint at
    /// `birth_height`.
    ///
    /// Both `synced_height` and `last_processed_height` are seeded to
    /// `birth_height.saturating_sub(1)` so the next block to scan is `birth_height`.
    /// Taking `birth_height` at construction makes the sync checkpoint a required
    /// invariant of the type rather than something callers have to remember to set.
    fn from_wallet(wallet: &Wallet, birth_height: CoreBlockHeight) -> Self;

    /// Create a wallet info with a name, seeding the sync checkpoint at `birth_height`
    /// (see `from_wallet` for details).
    fn from_wallet_with_name(wallet: &Wallet, name: String, birth_height: CoreBlockHeight) -> Self;

    /// Get the wallet's network
    fn network(&self) -> Network;

    /// Get the wallet's unique ID
    fn wallet_id(&self) -> [u8; 32];

    /// Get the wallet's name
    fn name(&self) -> Option<&str>;

    /// Set the wallet's name
    fn set_name(&mut self, name: String);

    /// Get the wallet's description
    fn description(&self) -> Option<&str>;

    /// Set the wallet's description
    fn set_description(&mut self, description: Option<String>);

    /// Get the birth height of the wallet
    fn birth_height(&self) -> CoreBlockHeight;

    /// Update last synced timestamp
    fn update_last_synced(&mut self, timestamp: u64);

    /// Get all monitored addresses
    fn monitored_addresses(&self) -> Vec<DashAddress>;

    /// Get all UTXOs for the wallet
    fn utxos(&self) -> BTreeSet<&Utxo>;

    /// Get spendable UTXOs (confirmed and not locked)
    fn get_spendable_utxos(&self) -> BTreeSet<&Utxo>;

    /// Get the wallet balance
    fn balance(&self) -> WalletCoreBalance;

    /// Update the wallet balance
    fn update_balance(&mut self);

    /// Per-account balances keyed by `AccountType`.
    ///
    /// Only funds-bearing accounts (Standard, CoinJoin, DashPay) carry a
    /// balance — keys-only accounts (identity, asset-lock, provider) are
    /// excluded from the result entirely rather than reported with a zero
    /// balance.
    fn account_balances(&self) -> BTreeMap<AccountType, WalletCoreBalance> {
        self.accounts()
            .all_funding_accounts()
            .iter()
            .map(|funds| (funds.managed_account_type().to_account_type(), funds.balance))
            .collect()
    }

    /// Get transaction history
    fn transaction_history(&self) -> Vec<&TransactionRecord>;

    /// Get accounts (mutable)
    fn accounts_mut(&mut self) -> &mut ManagedAccountCollection;

    /// Get accounts (immutable)
    fn accounts(&self) -> &ManagedAccountCollection;

    /// Get immature transactions
    fn immature_transactions(&self) -> Vec<Transaction>;

    /// Return the last fully processed height of the wallet.
    fn last_processed_height(&self) -> CoreBlockHeight;

    /// Return the durable wallet sync checkpoint height.
    fn synced_height(&self) -> CoreBlockHeight;

    /// Return the highest chainlock that has been applied to this
    /// wallet, retaining the signing proof. Blocks at or below
    /// `chain_lock.block_height` are considered chainlock-finalized
    /// for this wallet. `None` until the first chainlock arrives.
    fn last_applied_chain_lock(&self) -> Option<&ChainLock> {
        None
    }

    /// Promote every `InBlock` transaction record across this wallet's
    /// accounts whose block height is `<= chain_lock.block_height` to
    /// `TransactionContext::InChainLockedBlock`, advance the wallet's
    /// `last_applied_chain_lock` to `chain_lock` (clamped forward by
    /// height), and return the per-account promotion result.
    ///
    /// Accounts with no net-new promotions are omitted from the map.
    /// Under the default `keep-finalized-transactions=OFF` feature the
    /// promoted records are dropped and only their txids are retained —
    /// the txids are still surfaced here so the caller can emit a single
    /// `TransactionsChainlocked` event before the records disappear.
    ///
    /// `last_applied_chain_lock` advances even when no records were
    /// promoted: a chainlock that lands above a wallet's currently
    /// recorded history still establishes the finality boundary for
    /// any future blocks that arrive in that range via the late-block
    /// path in block processing.
    fn apply_chain_lock(&mut self, _chain_lock: ChainLock) -> BTreeMap<AccountType, Vec<Txid>> {
        BTreeMap::new()
    }

    /// Update chain state and process any matured transactions
    /// This should be called when the chain tip advances to a new height
    fn update_last_processed_height(&mut self, current_height: u32);

    /// Record that the durable wallet sync checkpoint has advanced to `current_height`.
    fn update_synced_height(&mut self, current_height: u32);

    /// Records whose coinbase maturity threshold lies in
    /// `(old_height, new_height]`, i.e. coinbase records that just matured
    /// during the height advance from `old_height` to `new_height`.
    ///
    /// Returns clones of the matured records so the caller can include them
    /// in atomic events without mutating wallet state.
    fn matured_coinbase_records(
        &self,
        old_height: CoreBlockHeight,
        new_height: CoreBlockHeight,
    ) -> Vec<TransactionRecord>;

    /// Mark UTXOs for a transaction as InstantSend-locked across all accounts
    /// and update the corresponding transaction record context.
    /// Returns `true` if any UTXO was newly marked.
    fn mark_instant_send_utxos(&mut self, txid: &Txid, lock: &InstantLock) -> bool;

    /// Return the aggregated monitor revision across all accounts.
    /// Increments whenever the monitored address set changes.
    fn monitor_revision(&self) -> u64 {
        0
    }
}

/// Default implementation for ManagedWalletInfo
impl WalletInfoInterface for ManagedWalletInfo {
    fn from_wallet(wallet: &Wallet, birth_height: CoreBlockHeight) -> Self {
        Self::from_wallet(wallet, birth_height)
    }

    fn from_wallet_with_name(wallet: &Wallet, name: String, birth_height: CoreBlockHeight) -> Self {
        Self::from_wallet_with_name(wallet, name, birth_height)
    }

    fn network(&self) -> Network {
        self.network
    }

    fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn set_description(&mut self, description: Option<String>) {
        self.description = description;
    }

    fn birth_height(&self) -> CoreBlockHeight {
        self.metadata.birth_height
    }

    fn last_processed_height(&self) -> CoreBlockHeight {
        self.metadata.last_processed_height
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.metadata.synced_height
    }

    fn last_applied_chain_lock(&self) -> Option<&ChainLock> {
        self.metadata.last_applied_chain_lock.as_ref()
    }

    fn apply_chain_lock(&mut self, chain_lock: ChainLock) -> BTreeMap<AccountType, Vec<Txid>> {
        let cl_height = chain_lock.block_height;
        let mut per_account: BTreeMap<AccountType, Vec<Txid>> = BTreeMap::new();

        // Promote across every account: funds-bearing (Standard,
        // CoinJoin, DashPay) and keys-only (identity, asset-lock,
        // provider, platform-payment). Keys-only accounts hold
        // transactions such as identity registrations and asset locks
        // that under the default `keep-finalized-transactions=false`
        // feature must be dropped to bound memory once chainlocked,
        // exactly like funds-account txs.
        for account in self.accounts.all_accounts_mut() {
            let (account_type, finalized_txids) = match account {
                ManagedAccountRefMut::Funds(funds) => (
                    funds.managed_account_type().to_account_type(),
                    funds.apply_chain_lock(cl_height),
                ),
                ManagedAccountRefMut::Keys(keys) => (
                    keys.managed_account_type().to_account_type(),
                    keys.apply_chain_lock(cl_height),
                ),
            };
            if !finalized_txids.is_empty() {
                per_account.insert(account_type, finalized_txids);
            }
        }

        let advance = self
            .metadata
            .last_applied_chain_lock
            .as_ref()
            .is_none_or(|existing| cl_height > existing.block_height);
        if advance {
            self.metadata.last_applied_chain_lock = Some(chain_lock);
        }

        per_account
    }

    fn update_last_synced(&mut self, timestamp: u64) {
        self.metadata.last_synced = Some(timestamp);
    }

    fn monitored_addresses(&self) -> Vec<DashAddress> {
        let mut addresses = Vec::new();
        for account in self.accounts.all_accounts() {
            addresses.extend(account.all_addresses());
        }
        addresses
    }

    fn utxos(&self) -> BTreeSet<&Utxo> {
        let mut utxos = BTreeSet::new();
        for account in self.accounts.all_funding_accounts() {
            utxos.extend(account.utxos.values());
        }
        utxos
    }
    fn get_spendable_utxos(&self) -> BTreeSet<&Utxo> {
        self.utxos()
            .into_iter()
            .filter(|utxo| utxo.is_spendable(self.last_processed_height()))
            .collect()
    }

    fn balance(&self) -> WalletCoreBalance {
        self.balance
    }

    fn update_balance(&mut self) {
        // Only funds-bearing accounts contribute to the wallet balance.
        let mut balance = WalletCoreBalance::default();
        let last_processed_height = self.last_processed_height();
        for funds in self.accounts.all_funding_accounts_mut() {
            funds.update_balance(last_processed_height);
            balance += funds.balance;
        }
        self.balance = balance;
    }

    fn transaction_history(&self) -> Vec<&TransactionRecord> {
        let mut transactions = Vec::new();
        for account in self.accounts.all_accounts() {
            transactions.extend(account.transactions().values());
        }
        transactions
    }

    fn accounts_mut(&mut self) -> &mut ManagedAccountCollection {
        &mut self.accounts
    }

    fn accounts(&self) -> &ManagedAccountCollection {
        &self.accounts
    }

    fn immature_transactions(&self) -> Vec<Transaction> {
        // Coinbase UTXOs only live on funds-bearing accounts.
        let mut immature_txids: BTreeSet<Txid> = BTreeSet::new();
        for account in self.accounts.all_funding_accounts() {
            for utxo in account.utxos.values() {
                if utxo.is_coinbase && !utxo.is_mature(self.last_processed_height()) {
                    immature_txids.insert(utxo.outpoint.txid);
                }
            }
        }

        // Look up the matching transaction records on the same funds accounts.
        let mut transactions = Vec::new();
        for account in self.accounts.all_funding_accounts() {
            for (txid, record) in account.transactions() {
                if immature_txids.contains(txid) {
                    transactions.push(record.transaction.clone());
                }
            }
        }
        transactions
    }

    fn update_last_processed_height(&mut self, current_height: u32) {
        self.metadata.last_processed_height = current_height;
        // Update cached balance
        self.update_balance();
    }

    fn update_synced_height(&mut self, current_height: u32) {
        self.metadata.synced_height = current_height;
    }

    fn matured_coinbase_records(
        &self,
        old_height: CoreBlockHeight,
        new_height: CoreBlockHeight,
    ) -> Vec<TransactionRecord> {
        if new_height <= old_height {
            return Vec::new();
        }
        // Coinbase records only land on funds-bearing accounts.
        let mut matured = Vec::new();
        for account in self.accounts.all_funding_accounts() {
            for record in account.transactions().values() {
                if !record.transaction.is_coin_base() {
                    continue;
                }
                let Some(record_height) = record.height() else {
                    continue;
                };
                let maturity_height = record_height.saturating_add(100);
                if maturity_height > old_height && maturity_height <= new_height {
                    matured.push(record.clone());
                }
            }
        }
        matured
    }

    fn mark_instant_send_utxos(&mut self, txid: &Txid, lock: &InstantLock) -> bool {
        if !self.instant_send_locks.insert(*txid) {
            return false;
        }
        let mut any_changed = false;
        for mut account in self.accounts.all_accounts_mut() {
            if account.mark_utxos_instant_send(txid) {
                any_changed = true;
            }
            if let Some(record) = account.transactions_mut().get_mut(txid) {
                record.update_context(TransactionContext::InstantSend(lock.clone()));
            }
        }
        if any_changed {
            self.update_balance();
        }
        any_changed
    }

    fn monitor_revision(&self) -> u64 {
        self.accounts.all_accounts().iter().map(|a| a.monitor_revision()).sum()
    }
}
