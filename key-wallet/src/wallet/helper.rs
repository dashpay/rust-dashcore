//! Wallet helper methods
//!
//! This module contains helper methods and utility functions for wallets.

use super::balance::WalletBalance;
use super::root_extended_keys::RootExtendedPrivKey;
use super::{Wallet, WalletScanResult, WalletType};
use crate::account::Account;
use crate::error::{Error, Result};
use crate::Network;
use dashcore::Address;

impl Wallet {
    /// Get an account by network and index (searches both standard and coinjoin accounts)
    pub fn get_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.standard_accounts
            .get(network, index)
            .or_else(|| self.coinjoin_accounts.get(network, index))
    }

    /// Get a standard account by network and index
    pub fn get_standard_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.standard_accounts.get(network, index)
    }

    /// Get a coinjoin account by network and index
    pub fn get_coinjoin_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.coinjoin_accounts.get(network, index)
    }

    /// Get a mutable account by network and index (searches both standard and coinjoin accounts)
    pub fn get_account_mut(&mut self, network: Network, index: u32) -> Option<&mut Account> {
        if self.standard_accounts.contains_key(network, index) {
            self.standard_accounts.get_mut(network, index)
        } else {
            self.coinjoin_accounts.get_mut(network, index)
        }
    }

    /// Get a mutable standard account by network and index
    pub fn get_standard_account_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut Account> {
        self.standard_accounts.get_mut(network, index)
    }

    /// Get a mutable coinjoin account by network and index
    pub fn get_coinjoin_account_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut Account> {
        self.coinjoin_accounts.get_mut(network, index)
    }

    /// Get the default account (index 0, searches standard accounts first)
    pub fn default_account(&self, network: Network) -> Option<&Account> {
        self.standard_accounts.get(network, 0).or_else(|| self.coinjoin_accounts.get(network, 0))
    }

    /// Get the default account mutably
    pub fn default_account_mut(&mut self, network: Network) -> Option<&mut Account> {
        if self.standard_accounts.contains_key(network, 0) {
            self.standard_accounts.get_mut(network, 0)
        } else {
            self.coinjoin_accounts.get_mut(network, 0)
        }
    }

    /// Get all accounts (both standard and coinjoin)
    pub fn all_accounts(&self) -> Vec<&Account> {
        let mut accounts = Vec::new();
        accounts.extend(self.standard_accounts.all_accounts());
        accounts.extend(self.coinjoin_accounts.all_accounts());
        accounts
    }

    /// Get the count of accounts (both standard and coinjoin)
    pub fn account_count(&self) -> usize {
        self.standard_accounts.total_count() + self.coinjoin_accounts.total_count()
    }

    /// Get all account indices for a network (both standard and coinjoin)
    pub fn account_indices(&self, network: Network) -> Vec<u32> {
        let mut indices = Vec::new();
        indices.extend(self.standard_accounts.network_indices(network));
        indices.extend(self.coinjoin_accounts.network_indices(network));
        indices.sort();
        indices
    }

    /// Get total balance across all accounts
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn total_balance(&self) -> WalletBalance {
        // This would need to be implemented with ManagedAccountCollection
        // For now, returning default as balances are tracked in ManagedAccount
        WalletBalance::default()
    }

    /// Get all addresses across all accounts
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn all_addresses(&self) -> Vec<Address> {
        // This would need to be implemented with ManagedAccountCollection
        // For now, returning empty as addresses are tracked in ManagedAccount
        Vec::new()
    }

    /// Find which account an address belongs to
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn find_account_for_address(&self, _address: &Address) -> Option<(&Account, Network, u32)> {
        // This would need to be implemented with ManagedAccountCollection
        None
    }

    /// Mark an address as used across all accounts
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn mark_address_used(&mut self, _address: &Address) -> bool {
        // This would need to be implemented with ManagedAccountCollection
        false
    }

    /// Scan all accounts for address activity
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn scan_for_activity<F>(&mut self, _check_fn: F) -> WalletScanResult
    where
        F: Fn(&Address) -> bool + Clone,
    {
        // This would need to be implemented with ManagedAccountCollection
        WalletScanResult::default()
    }

    /// Get the next receive address for the default account
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn get_next_receive_address(&mut self, _network: Network) -> Result<Address> {
        Err(Error::InvalidParameter("Address generation needs ManagedAccount".into()))
    }

    /// Get the next change address for the default account
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn get_next_change_address(&mut self, _network: Network) -> Result<Address> {
        Err(Error::InvalidParameter("Address generation needs ManagedAccount".into()))
    }

    /// Enable CoinJoin for an account
    /// Note: This would need to be implemented using ManagedAccounts
    pub fn enable_coinjoin_for_account(
        &mut self,
        _network: Network,
        _account_index: u32,
    ) -> Result<()> {
        Err(Error::InvalidParameter("CoinJoin enabling needs ManagedAccount".into()))
    }

    /// Export wallet as watch-only
    pub fn to_watch_only(&self) -> Self {
        let mut watch_only = self.clone();

        // Get the root public key
        let root_pub_key = if let Ok(root_key) = self.root_extended_priv_key() {
            root_key.to_root_extended_pub_key()
        } else {
            // For already watch-only wallets, keep the existing public key
            match &self.wallet_type {
                WalletType::WatchOnly(pub_key) | WalletType::ExternalSignable(pub_key) => {
                    pub_key.clone()
                }
                WalletType::MnemonicWithPassphrase {
                    root_extended_public_key,
                    ..
                } => root_extended_public_key.clone(),
                _ => {
                    // Fallback - create a dummy key
                    let dummy_priv = RootExtendedPrivKey::new_master(&[0u8; 64]).unwrap();
                    dummy_priv.to_root_extended_pub_key()
                }
            }
        };

        watch_only.wallet_type = WalletType::WatchOnly(root_pub_key);

        // Convert all accounts to watch-only
        for account in watch_only.standard_accounts.all_accounts_mut() {
            *account = account.to_watch_only();
        }
        for account in watch_only.coinjoin_accounts.all_accounts_mut() {
            *account = account.to_watch_only();
        }

        watch_only
    }

    /// Check if wallet has a mnemonic
    pub fn has_mnemonic(&self) -> bool {
        matches!(
            self.wallet_type,
            WalletType::Mnemonic { .. } | WalletType::MnemonicWithPassphrase { .. }
        )
    }

    /// Check if wallet is watch-only
    pub fn is_watch_only(&self) -> bool {
        matches!(self.wallet_type, WalletType::WatchOnly(_))
    }

    /// Check if wallet supports external signing
    pub fn is_external_signable(&self) -> bool {
        matches!(self.wallet_type, WalletType::ExternalSignable(_))
    }

    /// Check if wallet can sign transactions (has private keys or can get them)
    pub fn can_sign(&self) -> bool {
        !matches!(self.wallet_type, WalletType::WatchOnly(_))
    }

    /// Check if wallet needs a passphrase for signing
    pub fn needs_passphrase(&self) -> bool {
        matches!(self.wallet_type, WalletType::MnemonicWithPassphrase { .. })
    }

    /// Check if wallet has a seed
    pub fn has_seed(&self) -> bool {
        matches!(self.wallet_type, WalletType::Seed { .. })
    }
}

use alloc::vec::Vec;
