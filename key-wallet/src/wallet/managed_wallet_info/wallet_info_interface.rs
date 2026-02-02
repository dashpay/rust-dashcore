//! Trait defining the interface for wallet info types
//!
//! This trait allows WalletManager to work with different wallet info implementations

use super::managed_account_operations::ManagedAccountOperations;
use crate::account::ManagedAccountTrait;
use crate::managed_account::managed_account_collection::ManagedAccountCollection;
use crate::transaction_checking::WalletTransactionChecker;
use crate::wallet::managed_wallet_info::fee::FeeLevel;
use crate::wallet::managed_wallet_info::transaction_building::{
    AccountTypePreference, TransactionError,
};
use crate::wallet::managed_wallet_info::TransactionRecord;
use crate::wallet::ManagedWalletInfo;
use crate::{Network, Utxo, Wallet, WalletCoreBalance};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address as DashAddress, Address, Transaction, Txid};

/// Trait that wallet info types must implement to work with WalletManager
pub trait WalletInfoInterface: Sized + WalletTransactionChecker + ManagedAccountOperations {
    /// Create a wallet info from an existing wallet
    /// This properly initializes the wallet info from the wallet's state
    fn from_wallet(wallet: &Wallet) -> Self;

    /// Create a wallet info from an existing wallet with proper account initialization
    /// Default implementation just uses with_name (backward compatibility)
    fn from_wallet_with_name(wallet: &Wallet, name: String) -> Self;

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

    /// Set the birth height
    fn set_birth_height(&mut self, height: CoreBlockHeight);

    /// Get the timestamp when first loaded
    fn first_loaded_at(&self) -> u64;

    /// Set the timestamp when first loaded
    fn set_first_loaded_at(&mut self, timestamp: u64);

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

    /// Get transaction history
    fn transaction_history(&self) -> Vec<&TransactionRecord>;

    /// Get accounts (mutable)
    fn accounts_mut(&mut self) -> &mut ManagedAccountCollection;

    /// Get accounts (immutable)
    fn accounts(&self) -> &ManagedAccountCollection;

    /// Get immature transactions
    fn immature_transactions(&self) -> Vec<Transaction>;

    /// Create an unsigned payment transaction
    #[allow(clippy::too_many_arguments)]
    fn create_unsigned_payment_transaction(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, TransactionError>;

    /// Return the last fully processed height of the wallet.
    fn synced_height(&self) -> CoreBlockHeight;

    /// Update chain state and process any matured transactions
    /// This should be called when the chain tip advances to a new height
    fn update_synced_height(&mut self, current_height: u32);
}

/// Default implementation for ManagedWalletInfo
impl WalletInfoInterface for ManagedWalletInfo {
    fn from_wallet(wallet: &Wallet) -> Self {
        Self::from_wallet_with_name(wallet, String::new())
    }

    fn from_wallet_with_name(wallet: &Wallet, name: String) -> Self {
        Self::from_wallet_with_name(wallet, name)
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

    fn set_birth_height(&mut self, height: CoreBlockHeight) {
        self.metadata.birth_height = height;
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.metadata.synced_height
    }

    fn first_loaded_at(&self) -> u64 {
        self.metadata.first_loaded_at
    }

    fn set_first_loaded_at(&mut self, timestamp: u64) {
        self.metadata.first_loaded_at = timestamp;
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
        for account in self.accounts.all_accounts() {
            utxos.extend(account.utxos.values());
        }
        utxos
    }
    fn get_spendable_utxos(&self) -> BTreeSet<&Utxo> {
        self.utxos().into_iter().filter(|utxo| utxo.is_spendable(self.synced_height())).collect()
    }

    fn balance(&self) -> WalletCoreBalance {
        self.balance
    }

    fn update_balance(&mut self) {
        let mut balance = WalletCoreBalance::default();
        let synced_height = self.synced_height();
        for account in self.accounts.all_accounts_mut() {
            account.update_balance(synced_height);
            balance += *account.balance();
        }
        self.balance = balance;
    }

    fn transaction_history(&self) -> Vec<&TransactionRecord> {
        let mut transactions = Vec::new();
        for account in self.accounts.all_accounts() {
            transactions.extend(account.transactions.values());
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
        let mut immature_txids: BTreeSet<Txid> = BTreeSet::new();

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

    fn create_unsigned_payment_transaction(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, TransactionError> {
        self.create_unsigned_payment_transaction_internal(
            wallet,
            self.network,
            account_index,
            account_type_pref,
            recipients,
            fee_level,
            current_block_height,
        )
    }

    fn update_synced_height(&mut self, current_height: u32) {
        self.metadata.synced_height = current_height;
        // Update cached balance
        self.update_balance();
    }
}
