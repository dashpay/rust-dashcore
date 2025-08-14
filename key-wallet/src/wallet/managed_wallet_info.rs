//! Managed wallet information
//!
//! This module contains the mutable metadata and information about a wallet
//! that is managed separately from the core wallet structure.

use super::balance::WalletBalance;
use super::immature_transaction::ImmatureTransactionCollection;
use super::metadata::WalletMetadata;
use crate::account::{ManagedAccount, ManagedAccountCollection};
use crate::{Address, Network};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Information about a managed wallet
///
/// This struct contains the mutable metadata and descriptive information
/// about a wallet, kept separate from the core wallet structure to maintain
/// immutability of the wallet itself.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedWalletInfo {
    /// Unique wallet ID (SHA256 hash of root public key) - should match the Wallet's wallet_id
    pub wallet_id: [u8; 32],
    /// Wallet name
    pub name: Option<String>,
    /// Wallet description  
    pub description: Option<String>,
    /// Wallet metadata
    pub metadata: WalletMetadata,
    /// All managed accounts organized by network
    pub accounts: BTreeMap<Network, ManagedAccountCollection>,
    /// Immature transactions organized by network
    pub immature_transactions: BTreeMap<Network, ImmatureTransactionCollection>,
    /// Cached wallet balance - should be updated when accounts change
    pub balance: WalletBalance,
}

impl ManagedWalletInfo {
    /// Create new managed wallet info with wallet ID
    pub fn new(wallet_id: [u8; 32]) -> Self {
        Self {
            wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: BTreeMap::new(),
            immature_transactions: BTreeMap::new(),
            balance: WalletBalance::default(),
        }
    }

    /// Create managed wallet info with wallet ID and name
    pub fn with_name(wallet_id: [u8; 32], name: String) -> Self {
        Self {
            wallet_id,
            name: Some(name),
            description: None,
            metadata: WalletMetadata::default(),
            accounts: BTreeMap::new(),
            immature_transactions: BTreeMap::new(),
            balance: WalletBalance::default(),
        }
    }

    /// Create managed wallet info from a Wallet
    pub fn from_wallet(wallet: &super::super::Wallet) -> Self {
        Self {
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: BTreeMap::new(),
            immature_transactions: BTreeMap::new(),
            balance: WalletBalance::default(),
        }
    }

    /// Create managed wallet info with birth height
    pub fn with_birth_height(wallet_id: [u8; 32], birth_height: Option<u32>) -> Self {
        let mut info = Self::new(wallet_id);
        info.metadata.birth_height = birth_height;
        info
    }

    /// Set the wallet name
    pub fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    /// Set the wallet description
    pub fn set_description(&mut self, description: String) {
        self.description = Some(description);
    }

    /// Update the last synced timestamp
    pub fn update_last_synced(&mut self, timestamp: u64) {
        self.metadata.last_synced = Some(timestamp);
    }

    /// Increment the transaction count
    pub fn increment_transactions(&mut self) {
        self.metadata.total_transactions += 1;
    }

    /// Get a managed account by network and index
    pub fn get_account(&self, network: Network, index: u32) -> Option<&ManagedAccount> {
        self.accounts.get(&network).and_then(|collection| collection.get(index))
    }

    /// Get a mutable managed account by network and index
    pub fn get_account_mut(&mut self, network: Network, index: u32) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network).and_then(|collection| collection.get_mut(index))
    }

    /// Update the cached wallet balance by summing all accounts
    pub fn update_balance(&mut self) {
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        let mut locked = 0u64;
        
        // Sum balances from all accounts across all networks
        for collection in self.accounts.values() {
            for account in collection.all_accounts() {
                for utxo in account.utxos.values() {
                    let value = utxo.txout.value;
                    if utxo.is_locked {
                        locked += value;
                    } else if utxo.height.is_some() {
                        confirmed += value;
                    } else {
                        unconfirmed += value;
                    }
                }
            }
        }
        
        // Update balance, ignoring overflow errors as we're recalculating from scratch
        self.balance = WalletBalance::new(confirmed, unconfirmed, locked)
            .unwrap_or_else(|_| WalletBalance::default());
    }
    
    /// Get the cached wallet balance
    pub fn get_balance(&self) -> WalletBalance {
        self.balance
    }
    
    /// Get total wallet balance by recalculating from all accounts (for verification)
    pub fn calculate_balance(&self) -> WalletBalance {
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        let mut locked = 0u64;
        
        // Sum balances from all accounts across all networks
        for collection in self.accounts.values() {
            for account in collection.all_accounts() {
                for utxo in account.utxos.values() {
                    let value = utxo.txout.value;
                    if utxo.is_locked {
                        locked += value;
                    } else if utxo.height.is_some() {
                        confirmed += value;
                    } else {
                        unconfirmed += value;
                    }
                }
            }
        }
        
        WalletBalance::new(confirmed, unconfirmed, locked)
            .unwrap_or_else(|_| WalletBalance::default())
    }
    
    /// Add a monitored address
    pub fn add_monitored_address(&mut self, _address: Address) {
        // Find the account that should own this address
        // For now, we'll store it at the wallet level for simplicity
        // In a full implementation, this would delegate to the appropriate account
    }
    
    /// Add a transaction record to the appropriate account
    pub fn add_transaction(&mut self, _transaction: TransactionRecord) {
        // This would need to determine which account owns the transaction
        // For now, this is a placeholder
    }
    
    /// Get all transaction history across all accounts
    pub fn get_transaction_history(&self) -> Vec<&TransactionRecord> {
        let mut transactions = Vec::new();
        
        // Collect transactions from all accounts across all networks
        for collection in self.accounts.values() {
            for account in collection.all_accounts() {
                transactions.extend(account.transactions.values());
            }
        }
        
        transactions
    }
    
    /// Add a UTXO to the appropriate account
    pub fn add_utxo(&mut self, _utxo: Utxo) {
        // This would need to determine which account owns the UTXO
        // For now, this is a placeholder
    }
    
    /// Get all UTXOs across all accounts
    pub fn get_utxos(&self) -> Vec<&Utxo> {
        let mut utxos = Vec::new();
        
        // Collect UTXOs from all accounts across all networks
        for collection in self.accounts.values() {
            for account in collection.all_accounts() {
                utxos.extend(account.utxos.values());
            }
        }
        
        utxos
    }
    
    /// Get spendable UTXOs (confirmed and not locked)
    pub fn get_spendable_utxos(&self) -> Vec<&Utxo> {
        self.get_utxos()
            .into_iter()
            .filter(|utxo| !utxo.is_locked && utxo.height.is_some())
            .collect()
    }

    /// Add an immature transaction
    pub fn add_immature_transaction(&mut self, network: Network, tx: super::immature_transaction::ImmatureTransaction) {
        self.immature_transactions
            .entry(network)
            .or_insert_with(ImmatureTransactionCollection::new)
            .insert(tx);
    }

    /// Process matured transactions for a given chain height
    pub fn process_matured_transactions(&mut self, network: Network, current_height: u32) -> Vec<super::immature_transaction::ImmatureTransaction> {
        if let Some(collection) = self.immature_transactions.get_mut(&network) {
            let matured = collection.remove_matured(current_height);
            
            // Update accounts with matured transactions
            if let Some(account_collection) = self.accounts.get_mut(&network) {
                for tx in &matured {
                    // Process BIP44 accounts
                    for &index in &tx.affected_accounts.bip44_accounts {
                        if let Some(account) = account_collection.standard_bip44_accounts.get_mut(&index) {
                            // Add transaction record as confirmed
                            let tx_record = crate::account::TransactionRecord::new_confirmed(
                                tx.transaction.clone(),
                                tx.height,
                                tx.block_hash,
                                tx.timestamp,
                                tx.total_received as i64,
                                false, // Not ours (we received)
                            );
                            account.transactions.insert(tx.txid, tx_record);
                        }
                    }
                    
                    // Process BIP32 accounts
                    for &index in &tx.affected_accounts.bip32_accounts {
                        if let Some(account) = account_collection.standard_bip32_accounts.get_mut(&index) {
                            let tx_record = crate::account::TransactionRecord::new_confirmed(
                                tx.transaction.clone(),
                                tx.height,
                                tx.block_hash,
                                tx.timestamp,
                                tx.total_received as i64,
                                false,
                            );
                            account.transactions.insert(tx.txid, tx_record);
                        }
                    }
                    
                    // Process CoinJoin accounts
                    for &index in &tx.affected_accounts.coinjoin_accounts {
                        if let Some(account) = account_collection.coinjoin_accounts.get_mut(&index) {
                            let tx_record = crate::account::TransactionRecord::new_confirmed(
                                tx.transaction.clone(),
                                tx.height,
                                tx.block_hash,
                                tx.timestamp,
                                tx.total_received as i64,
                                false,
                            );
                            account.transactions.insert(tx.txid, tx_record);
                        }
                    }
                }
            }
            
            // Update balance after processing matured transactions
            self.update_balance();
            
            matured
        } else {
            Vec::new()
        }
    }

    /// Get immature transactions for a network
    pub fn get_immature_transactions(&self, network: Network) -> Option<&ImmatureTransactionCollection> {
        self.immature_transactions.get(&network)
    }

    /// Get total immature balance across all networks
    pub fn total_immature_balance(&self) -> u64 {
        self.immature_transactions
            .values()
            .map(|collection| collection.total_immature_balance())
            .sum()
    }

    /// Get immature balance for a specific network
    pub fn network_immature_balance(&self, network: Network) -> u64 {
        self.immature_transactions
            .get(&network)
            .map(|collection| collection.total_immature_balance())
            .unwrap_or(0)
    }
}

/// Re-export types from account module for convenience
pub use crate::account::{TransactionRecord, Utxo};

