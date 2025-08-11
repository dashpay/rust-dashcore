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
    pub fn stats(&self) -> WalletStats {
        let total_accounts =
            self.standard_accounts.total_count() + self.coinjoin_accounts.total_count();
        let mut total_addresses = 0;
        let mut used_addresses = 0;
        let mut coinjoin_enabled = 0;

        for account in self.standard_accounts.all_accounts() {
            total_addresses += account.get_all_addresses().len();
            used_addresses += account.get_used_addresses().len();
            if account.coinjoin_addresses.is_some() {
                coinjoin_enabled += 1;
            }
        }

        for account in self.coinjoin_accounts.all_accounts() {
            total_addresses += account.get_all_addresses().len();
            used_addresses += account.get_used_addresses().len();
            if account.coinjoin_addresses.is_some() {
                coinjoin_enabled += 1;
            }
        }

        WalletStats {
            total_accounts,
            total_addresses,
            used_addresses,
            unused_addresses: total_addresses - used_addresses,
            coinjoin_enabled_accounts: coinjoin_enabled,
            is_watch_only: self.is_watch_only(),
        }
    }
}
