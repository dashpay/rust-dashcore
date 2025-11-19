//! Managed wallet information
//!
//! This module contains the mutable metadata and information about a wallet
//! that is managed separately from the core wallet structure.

pub mod coin_selection;
pub mod fee;
pub mod helpers;
pub mod managed_account_operations;
pub mod managed_accounts;
pub mod transaction_builder;
pub mod transaction_building;
pub mod utxo;
pub mod wallet_info_interface;

pub use managed_account_operations::ManagedAccountOperations;

use super::balance::WalletBalance;
use super::immature_transaction::ImmatureTransactionCollection;
use super::metadata::WalletMetadata;
use crate::account::ManagedAccountCollection;
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::string::String;
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
        let mut managed_accounts = BTreeMap::new();

        // Initialize ManagedAccountCollection for each network that has accounts
        for (network, account_collection) in &wallet.accounts {
            let managed_collection =
                ManagedAccountCollection::from_account_collection(account_collection);
            managed_accounts.insert(*network, managed_collection);
        }

        Self {
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            accounts: managed_accounts,
            immature_transactions: BTreeMap::new(),
            balance: WalletBalance::default(),
        }
    }

    /// Create managed wallet info from a Wallet with a name
    pub fn from_wallet_with_name(wallet: &super::super::Wallet, name: String) -> Self {
        let mut info = Self::from_wallet(wallet);
        info.name = Some(name);
        info
    }

    /// Create managed wallet info with birth height
    pub fn with_birth_height(wallet_id: [u8; 32], birth_height: Option<u32>) -> Self {
        let mut info = Self::new(wallet_id);
        info.metadata.birth_height = birth_height;
        info
    }

    /// Increment the transaction count
    pub fn increment_transactions(&mut self) {
        self.metadata.total_transactions += 1;
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
                    } else if utxo.is_confirmed {
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
}

/// Re-export types from account module for convenience
pub use crate::account::TransactionRecord;
pub use crate::utxo::Utxo;
