//! High-level wallet management
//!
//! This module provides a high-level interface for wallet operations,
//! coordinating between key-wallet primitives and dashcore types.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use dashcore::blockdata::transaction::Transaction;
use dashcore_hashes::Hash;
use key_wallet::{
    Wallet, WalletConfig, Account, Address, Mnemonic, AccountType,
};

use crate::utxo::{Utxo, UtxoSet};
use crate::transaction_builder::{TransactionBuilder, BuilderError};
use crate::coin_selection::SelectionStrategy;
use crate::fee::FeeLevel;

/// High-level wallet manager
pub struct WalletManager {
    /// The underlying wallet
    wallet: Wallet,
    /// UTXO set
    utxo_set: UtxoSet,
    /// Transaction history
    transactions: BTreeMap<[u8; 32], TransactionRecord>,
    /// Current block height
    current_height: u32,
}

/// Transaction record
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    /// The transaction
    pub transaction: Transaction,
    /// Block height (if confirmed)
    pub height: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
    /// Net amount for wallet
    pub net_amount: i64,
    /// Fee paid (if known)
    pub fee: Option<u64>,
    /// Transaction label
    pub label: Option<String>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub fn new(config: WalletConfig) -> Result<Self, WalletError> {
        let wallet = Wallet::new(config)
            .map_err(|e| WalletError::Creation(e.to_string()))?;
        
        Ok(Self {
            wallet,
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
            current_height: 0,
        })
    }

    /// Create from a mnemonic
    pub fn from_mnemonic(mnemonic: Mnemonic, config: WalletConfig) -> Result<Self, WalletError> {
        let wallet = Wallet::from_mnemonic(mnemonic, config)
            .map_err(|e| WalletError::Creation(e.to_string()))?;
        
        Ok(Self {
            wallet,
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
            current_height: 0,
        })
    }

    /// Get the wallet's mnemonic (if available)
    /// Note: mnemonic field is private in the current implementation
    pub fn mnemonic(&self) -> Option<&Mnemonic> {
        // Mnemonic is stored privately and cannot be accessed directly
        // This would require adding a getter method to Wallet
        None // TODO: Add public getter to key-wallet
    }

    /// Create an account
    pub fn create_account(&mut self, index: u32, account_type: AccountType) -> Result<&Account, WalletError> {
        self.wallet.create_account(index, account_type)
            .map_err(|e| WalletError::AccountCreation(e.to_string()))
    }

    /// Get an account by index
    pub fn get_account(&self, index: u32) -> Option<&Account> {
        self.wallet.get_account(index)
    }

    /// Get all accounts
    pub fn accounts(&self) -> Vec<&Account> {
        self.wallet.all_accounts()
    }

    /// Get a new receive address for an account
    pub fn get_receive_address(&mut self, account_index: u32) -> Result<Address, WalletError> {
        let account = self.wallet.get_account_mut(account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;
        
        account.get_next_receive_address()
            .map_err(|e| WalletError::AddressGeneration(e.to_string()))
    }

    /// Get a new change address for an account
    pub fn get_change_address(&mut self, account_index: u32) -> Result<Address, WalletError> {
        let account = self.wallet.get_account_mut(account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;
        
        account.get_next_change_address()
            .map_err(|e| WalletError::AddressGeneration(e.to_string()))
    }

    /// Add a UTXO to the wallet
    pub fn add_utxo(&mut self, utxo: Utxo) {
        self.utxo_set.add(utxo);
    }

    /// Remove a UTXO (when spent)
    pub fn remove_utxo(&mut self, outpoint: &dashcore::blockdata::transaction::OutPoint) -> Option<Utxo> {
        self.utxo_set.remove(outpoint)
    }

    /// Get the UTXO set
    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxo_set
    }

    /// Get mutable UTXO set
    pub fn utxo_set_mut(&mut self) -> &mut UtxoSet {
        &mut self.utxo_set
    }

    /// Update current block height
    pub fn set_block_height(&mut self, height: u32) {
        self.current_height = height;
    }

    /// Get current block height
    pub fn block_height(&self) -> u32 {
        self.current_height
    }

    /// Create a transaction
    pub fn create_transaction(
        &mut self,
        account_index: u32,
        destination: &Address,
        amount: u64,
        fee_level: FeeLevel,
        selection_strategy: SelectionStrategy,
    ) -> Result<Transaction, WalletError> {
        // Get change address first
        let change_address = self.get_change_address(account_index)?;
        
        // Get the account and its addresses
        let account = self.wallet.get_account(account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;
        let account_addresses: Vec<Address> = account.get_all_addresses();
        let available_utxos: Vec<Utxo> = self.utxo_set
            .all()
            .iter()
            .filter(|u| account_addresses.contains(&u.address))
            .map(|u| (*u).clone())
            .collect();
        
        if available_utxos.is_empty() {
            return Err(WalletError::NoUtxos);
        }
        
        // Build the transaction
        let tx = TransactionBuilder::new(self.wallet.config.network)
            .select_inputs(
                &available_utxos,
                amount,
                selection_strategy,
                self.current_height,
                |_utxo| None, // Keys would be derived here
            )?
            .add_output(destination, amount)?
            .set_change_address(change_address)
            .set_fee_level(fee_level)
            .build()
            .map_err(WalletError::TransactionBuilder)?;
        
        Ok(tx)
    }

    /// Get total balance across all accounts
    pub fn total_balance(&self) -> WalletBalance {
        WalletBalance {
            confirmed: self.utxo_set.confirmed_balance(),
            unconfirmed: self.utxo_set.unconfirmed_balance(),
            locked: self.utxo_set.locked_balance(),
            total: self.utxo_set.total_balance(),
        }
    }

    /// Get balance for a specific account
    pub fn account_balance(&self, account_index: u32) -> WalletBalance {
        let account = match self.wallet.get_account(account_index) {
            Some(acc) => acc,
            None => return WalletBalance::default(),
        };
        
        let account_addresses: Vec<Address> = account.get_all_addresses();
        
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        let mut locked = 0u64;
        
        for utxo in self.utxo_set.all() {
            if account_addresses.contains(&utxo.address) {
                let value = utxo.value();
                if utxo.is_confirmed || utxo.is_instantlocked {
                    confirmed += value;
                } else {
                    unconfirmed += value;
                }
                if utxo.is_locked {
                    locked += value;
                }
            }
        }
        
        WalletBalance {
            confirmed,
            unconfirmed,
            locked,
            total: confirmed + unconfirmed,
        }
    }

    /// Add a transaction to history
    pub fn add_transaction(&mut self, tx: Transaction, height: Option<u32>, net_amount: i64) {
        let txid = tx.txid();
        let record = TransactionRecord {
            transaction: tx,
            height,
            timestamp: 0, // Would use actual timestamp
            net_amount,
            fee: None,
            label: None,
        };
        
        self.transactions.insert(*txid.as_byte_array(), record);
    }

    /// Get transaction history
    pub fn transactions(&self) -> Vec<&TransactionRecord> {
        self.transactions.values().collect()
    }

    /// Scan for address usage
    pub fn scan_for_activity<F>(&mut self, account_index: u32, check_fn: F) -> Result<usize, WalletError>
    where
        F: Fn(&Address) -> bool + Clone,
    {
        let account = self.wallet.get_account_mut(account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;
        
        let result = account.scan_for_activity(check_fn);
        Ok(result.total_found)
    }
}

/// Wallet balance information
#[derive(Debug, Clone, Default)]
pub struct WalletBalance {
    /// Confirmed balance
    pub confirmed: u64,
    /// Unconfirmed balance
    pub unconfirmed: u64,
    /// Locked balance
    pub locked: u64,
    /// Total balance
    pub total: u64,
}

/// Wallet errors
#[derive(Debug, Clone)]
pub enum WalletError {
    /// Wallet creation failed
    Creation(String),
    /// Account creation failed
    AccountCreation(String),
    /// Account not found
    AccountNotFound(u32),
    /// Address generation failed
    AddressGeneration(String),
    /// No UTXOs available
    NoUtxos,
    /// Transaction builder error
    TransactionBuilder(BuilderError),
}

impl From<BuilderError> for WalletError {
    fn from(err: BuilderError) -> Self {
        WalletError::TransactionBuilder(err)
    }
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Creation(msg) => write!(f, "Wallet creation failed: {}", msg),
            Self::AccountCreation(msg) => write!(f, "Account creation failed: {}", msg),
            Self::AccountNotFound(index) => write!(f, "Account {} not found", index),
            Self::AddressGeneration(msg) => write!(f, "Address generation failed: {}", msg),
            Self::NoUtxos => write!(f, "No UTXOs available"),
            Self::TransactionBuilder(err) => write!(f, "Transaction builder error: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WalletError {}