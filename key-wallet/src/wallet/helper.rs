//! Wallet helper methods
//!
//! This module contains helper methods and utility functions for wallets.

use super::balance::WalletBalance;
use super::root_extended_keys::RootExtendedPrivKey;
use super::{Wallet, WalletScanResult, WalletType};
use crate::account::Account;
use crate::error::{Error, Result};
use crate::mnemonic::Mnemonic;
use crate::{Address, Network};

impl Wallet {
    /// Get the root extended private key from the wallet type
    pub(crate) fn root_extended_priv_key(&self) -> Result<&RootExtendedPrivKey> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key),
            WalletType::MnemonicWithPassphrase {
                ..
            } => Err(Error::InvalidParameter(
                "Mnemonic with passphrase requires passphrase to derive private key".into(),
            )),
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key),
            WalletType::ExtendedPrivKey(key) => Ok(key),
            WalletType::ExternalSignable(_) => {
                Err(Error::InvalidParameter("External signable wallet has no private key".into()))
            }
            WalletType::WatchOnly(_) => {
                Err(Error::InvalidParameter("Watch-only wallet has no private key".into()))
            }
        }
    }

    /// Get the root extended private key with passphrase callback for MnemonicWithPassphrase
    pub fn root_extended_priv_key_with_callback<F>(
        &self,
        network: Network,
        passphrase_callback: F,
    ) -> Result<RootExtendedPrivKey>
    where
        F: FnOnce() -> Result<String>,
    {
        match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key.clone()),
            WalletType::MnemonicWithPassphrase {
                mnemonic,
                ..
            } => {
                // Request passphrase via callback
                let passphrase = passphrase_callback()?;
                let seed = mnemonic.to_seed(&passphrase);
                Ok(RootExtendedPrivKey::new_master(&seed)?)
            }
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => Ok(root_extended_private_key.clone()),
            WalletType::ExtendedPrivKey(key) => Ok(key.clone()),
            WalletType::ExternalSignable(_) => {
                Err(Error::InvalidParameter("External signable wallet has no private key".into()))
            }
            WalletType::WatchOnly(_) => {
                Err(Error::InvalidParameter("Watch-only wallet has no private key".into()))
            }
        }
    }

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
    pub fn total_balance(&self) -> WalletBalance {
        let mut total = WalletBalance::default();

        for account in self.standard_accounts.all_accounts() {
            total.confirmed += account.balance.confirmed;
            total.unconfirmed += account.balance.unconfirmed;
            total.immature += account.balance.immature;
            total.total += account.balance.total;
        }

        for account in self.coinjoin_accounts.all_accounts() {
            total.confirmed += account.balance.confirmed;
            total.unconfirmed += account.balance.unconfirmed;
            total.immature += account.balance.immature;
            total.total += account.balance.total;
        }

        total
    }

    /// Get all addresses across all accounts
    pub fn all_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        for account in self.standard_accounts.all_accounts() {
            addresses.extend(account.get_all_addresses());
        }
        for account in self.coinjoin_accounts.all_accounts() {
            addresses.extend(account.get_all_addresses());
        }
        addresses
    }

    /// Find which account an address belongs to
    pub fn find_account_for_address(&self, address: &Address) -> Option<(&Account, Network, u32)> {
        for (network, index) in self.standard_accounts.all_indices() {
            if let Some(account) = self.standard_accounts.get(network, index) {
                if account.contains_address(address) {
                    return Some((account, network, index));
                }
            }
        }
        for (network, index) in self.coinjoin_accounts.all_indices() {
            if let Some(account) = self.coinjoin_accounts.get(network, index) {
                if account.contains_address(address) {
                    return Some((account, network, index));
                }
            }
        }
        None
    }

    /// Mark an address as used across all accounts
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        for account in self.standard_accounts.all_accounts_mut() {
            if account.mark_address_used(address) {
                self.metadata.last_synced = Some(0);
                return true;
            }
        }
        for account in self.coinjoin_accounts.all_accounts_mut() {
            if account.mark_address_used(address) {
                self.metadata.last_synced = Some(0);
                return true;
            }
        }
        false
    }

    /// Scan all accounts for address activity
    pub fn scan_for_activity<F>(&mut self, check_fn: F) -> WalletScanResult
    where
        F: Fn(&Address) -> bool + Clone,
    {
        let mut result = WalletScanResult::default();

        for (network, index) in self.standard_accounts.all_indices() {
            if let Some(account) = self.standard_accounts.get_mut(network, index) {
                let scan_result = account.scan_for_activity(check_fn.clone());
                if scan_result.total_found > 0 {
                    result.accounts_with_activity.push(index);
                    result.total_addresses_found += scan_result.total_found;
                }
            }
        }

        for (network, index) in self.coinjoin_accounts.all_indices() {
            if let Some(account) = self.coinjoin_accounts.get_mut(network, index) {
                let scan_result = account.scan_for_activity(check_fn.clone());
                if scan_result.total_found > 0 {
                    result.accounts_with_activity.push(index);
                    result.total_addresses_found += scan_result.total_found;
                }
            }
        }

        if result.total_addresses_found > 0 {
            self.metadata.last_synced = Some(0);
        }

        result
    }

    /// Get the next receive address for the default account
    pub fn get_next_receive_address(&mut self, network: Network) -> Result<Address> {
        self.default_account_mut(network)
            .ok_or(Error::InvalidParameter("No default account".into()))?
            .get_next_receive_address()
    }

    /// Get the next change address for the default account
    pub fn get_next_change_address(&mut self, network: Network) -> Result<Address> {
        self.default_account_mut(network)
            .ok_or(Error::InvalidParameter("No default account".into()))?
            .get_next_change_address()
    }

    /// Enable CoinJoin for an account
    pub fn enable_coinjoin_for_account(
        &mut self,
        network: Network,
        account_index: u32,
    ) -> Result<()> {
        let account = self
            .standard_accounts
            .get_mut(network, account_index)
            .or_else(|| self.coinjoin_accounts.get_mut(network, account_index))
            .ok_or(Error::InvalidParameter(format!(
                "Account {} not found for network {:?}",
                account_index, network
            )))?;
        account.enable_coinjoin(self.config.coinjoin_gap_limit)
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

    /// Get the mnemonic if available (for testing)
    #[cfg(test)]
    pub(crate) fn test_get_mnemonic(&self) -> Option<&Mnemonic> {
        match &self.wallet_type {
            WalletType::Mnemonic {
                mnemonic,
                ..
            } => Some(mnemonic),
            WalletType::MnemonicWithPassphrase {
                mnemonic,
                ..
            } => Some(mnemonic),
            _ => None,
        }
    }

    /// Update last sync timestamp
    pub fn update_sync_timestamp(&mut self, timestamp: u64) {
        self.metadata.last_synced = Some(timestamp);
    }
}

use alloc::vec::Vec;
