//! Managed wallet information
//!
//! This module contains the mutable metadata and information about a wallet
//! that is managed separately from the core wallet structure.

use super::metadata::WalletMetadata;
use crate::account::{ManagedAccount, ManagedAccountCollection};
use crate::Network;
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
    /// Standard BIP44 managed accounts organized by network
    pub standard_accounts: ManagedAccountCollection,
    /// CoinJoin managed accounts organized by network
    pub coinjoin_accounts: ManagedAccountCollection,
    /// Special purpose managed accounts organized by network
    pub special_accounts: BTreeMap<Network, Vec<ManagedAccount>>,
}

impl ManagedWalletInfo {
    /// Create new managed wallet info with wallet ID
    pub fn new(wallet_id: [u8; 32]) -> Self {
        Self {
            wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            standard_accounts: ManagedAccountCollection::new(),
            coinjoin_accounts: ManagedAccountCollection::new(),
            special_accounts: BTreeMap::new(),
        }
    }

    /// Create managed wallet info with wallet ID and name
    pub fn with_name(wallet_id: [u8; 32], name: String) -> Self {
        Self {
            wallet_id,
            name: Some(name),
            description: None,
            metadata: WalletMetadata::default(),
            standard_accounts: ManagedAccountCollection::new(),
            coinjoin_accounts: ManagedAccountCollection::new(),
            special_accounts: BTreeMap::new(),
        }
    }

    /// Create managed wallet info from a Wallet
    pub fn from_wallet(wallet: &super::super::Wallet) -> Self {
        Self {
            wallet_id: wallet.wallet_id,
            name: None,
            description: None,
            metadata: WalletMetadata::default(),
            standard_accounts: ManagedAccountCollection::new(),
            coinjoin_accounts: ManagedAccountCollection::new(),
            special_accounts: BTreeMap::new(),
        }
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
}
