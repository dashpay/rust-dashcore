//! Trait defining the interface for wallet info types
//!
//! This trait allows WalletManager to work with different wallet info implementations

use crate::account::managed_account_collection::ManagedAccountCollection;
use crate::transaction_checking::WalletTransactionChecker;
use crate::wallet::managed_wallet_info::fee::FeeLevel;
use crate::wallet::managed_wallet_info::transaction_building::{
    AccountTypePreference, TransactionError,
};
use crate::wallet::managed_wallet_info::TransactionRecord;
use crate::wallet::ManagedWalletInfo;
use crate::{Address, Network, Utxo, Wallet, WalletBalance};
use dashcore::blockdata::transaction::Transaction;
use dashcore::Address as DashAddress;

/// Trait that wallet info types must implement to work with WalletManager
pub trait WalletInfoInterface: Sized + WalletTransactionChecker {
    /// Create a new wallet info with the given ID and name
    fn with_name(wallet_id: [u8; 32], name: String) -> Self;
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

    /// Get the birth height for tracking
    fn birth_height(&self) -> Option<u32>;

    /// Set the birth height
    fn set_birth_height(&mut self, height: Option<u32>);

    /// Get the timestamp when first loaded
    fn first_loaded_at(&self) -> u64;

    /// Set the timestamp when first loaded
    fn set_first_loaded_at(&mut self, timestamp: u64);

    /// Update last synced timestamp
    fn update_last_synced(&mut self, timestamp: u64);

    /// Get all monitored addresses for a network
    fn monitored_addresses(&self, network: Network) -> Vec<DashAddress>;

    /// Get all UTXOs for the wallet
    fn get_utxos(&self) -> Vec<Utxo>;

    /// Get the wallet balance
    fn get_balance(&self) -> WalletBalance;

    /// Update the wallet balance
    fn update_balance(&mut self);

    /// Get transaction history
    fn get_transaction_history(&self) -> Vec<&TransactionRecord>;

    /// Get accounts for a network (mutable)
    fn accounts_mut(&mut self, network: Network) -> Option<&mut ManagedAccountCollection>;

    /// Get accounts for a network (immutable)
    fn accounts(&self, network: Network) -> Option<&ManagedAccountCollection>;

    /// Create an unsigned payment transaction
    #[allow(clippy::too_many_arguments)]
    fn create_unsigned_payment_transaction(
        &mut self,
        wallet: &Wallet,
        network: Network,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, TransactionError>;
}

/// Default implementation for ManagedWalletInfo
impl WalletInfoInterface for ManagedWalletInfo {
    fn with_name(wallet_id: [u8; 32], name: String) -> Self {
        Self::with_name(wallet_id, name)
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

    fn birth_height(&self) -> Option<u32> {
        self.metadata.birth_height
    }

    fn set_birth_height(&mut self, height: Option<u32>) {
        self.metadata.birth_height = height;
    }

    fn first_loaded_at(&self) -> u64 {
        self.metadata.first_loaded_at
    }

    fn set_first_loaded_at(&mut self, timestamp: u64) {
        self.metadata.first_loaded_at = timestamp;
    }

    fn update_last_synced(&mut self, timestamp: u64) {
        self.update_last_synced(timestamp);
    }

    fn monitored_addresses(&self, network: Network) -> Vec<DashAddress> {
        self.monitored_addresses(network).into_iter().collect()
    }

    fn get_utxos(&self) -> Vec<Utxo> {
        self.get_utxos().into_iter().cloned().collect()
    }

    fn get_balance(&self) -> WalletBalance {
        self.get_balance()
    }

    fn update_balance(&mut self) {
        self.update_balance();
    }

    fn get_transaction_history(&self) -> Vec<&TransactionRecord> {
        self.get_transaction_history()
    }

    fn accounts_mut(&mut self, network: Network) -> Option<&mut ManagedAccountCollection> {
        self.accounts.get_mut(&network)
    }

    fn accounts(&self, network: Network) -> Option<&ManagedAccountCollection> {
        self.accounts.get(&network)
    }

    fn create_unsigned_payment_transaction(
        &mut self,
        wallet: &Wallet,
        network: Network,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, TransactionError> {
        self.create_unsigned_payment_transaction(
            wallet,
            network,
            account_index,
            account_type_pref,
            recipients,
            fee_level,
            current_block_height,
        )
    }
}
