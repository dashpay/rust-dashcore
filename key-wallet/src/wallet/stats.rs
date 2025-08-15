//! Wallet statistics types and functionality
//!
//! This module contains statistics-related structures and methods for wallets.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::Wallet;

/// Wallet statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletStats {
    /// Total number of accounts
    pub total_accounts: usize,
    /// Total addresses generated
    pub total_addresses: usize,
    /// Used addresses
    pub used_addresses: usize,
    /// Unused addresses
    pub unused_addresses: usize,
    /// Accounts with CoinJoin enabled
    pub coinjoin_enabled_accounts: usize,
    /// Whether this is watch-only
    pub is_watch_only: bool,
}

impl Wallet {
    /// Get wallet statistics
    /// Note: Address statistics would need to be implemented using ManagedAccounts
    pub fn stats(&self) -> WalletStats {
        let total_accounts: usize =
            self.accounts.values().map(|collection| collection.count()).sum();

        let coinjoin_enabled_accounts: usize =
            self.accounts.values().map(|collection| collection.coinjoin_accounts.len()).sum();

        // Address statistics would need to be retrieved from ManagedAccountCollection
        // For now, we return basic stats based on account counts
        WalletStats {
            total_accounts,
            total_addresses: 0,  // Would need ManagedAccounts
            used_addresses: 0,   // Would need ManagedAccounts
            unused_addresses: 0, // Would need ManagedAccounts
            coinjoin_enabled_accounts,
            is_watch_only: self.is_watch_only(),
        }
    }
}
