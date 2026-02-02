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
pub mod wallet_info_interface;

pub use managed_account_operations::ManagedAccountOperations;

use super::balance::WalletCoreBalance;
use super::metadata::WalletMetadata;
use crate::account::ManagedAccountCollection;
use crate::Network;
use alloc::string::String;
use dashcore::prelude::CoreBlockHeight;
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

    /// Increment the transaction count
    pub fn increment_transactions(&mut self) {
        self.metadata.total_transactions += 1;
    }
}

/// Re-export types from account module for convenience
pub use crate::account::TransactionRecord;
pub use crate::utxo::Utxo;
