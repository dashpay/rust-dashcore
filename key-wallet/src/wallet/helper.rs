//! Wallet helper methods
//!
//! This module contains helper methods and utility functions for wallets.

use super::balance::WalletBalance;
use super::initialization::WalletAccountCreationOptions;
use super::root_extended_keys::RootExtendedPrivKey;
use super::{Wallet, WalletScanResult, WalletType};
use crate::account::{Account, AccountType, StandardAccountType};
use crate::error::{Error, Result};
use crate::Network;
use alloc::vec::Vec;
use dashcore::Address;

impl Wallet {
    /// Get an account by network and index (searches both standard and coinjoin accounts)
    pub fn get_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts.get(&network).and_then(|collection| collection.get(index))
    }

    /// Get a standard account by network and index
    pub fn get_standard_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts.get(&network).and_then(|collection| {
            collection
                .standard_bip44_accounts
                .get(&index)
                .or_else(|| collection.standard_bip32_accounts.get(&index))
        })
    }

    /// Get a coinjoin account by network and index
    pub fn get_coinjoin_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts.get(&network).and_then(|collection| collection.coinjoin_accounts.get(&index))
    }

    /// Get a mutable account by network and index (searches both standard and coinjoin accounts)
    pub fn get_account_mut(&mut self, network: Network, index: u32) -> Option<&mut Account> {
        self.accounts.get_mut(&network).and_then(|collection| collection.get_mut(index))
    }

    /// Get a mutable standard account by network and index
    pub fn get_standard_account_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut Account> {
        self.accounts.get_mut(&network).and_then(|collection| {
            if collection.standard_bip44_accounts.contains_key(&index) {
                collection.standard_bip44_accounts.get_mut(&index)
            } else {
                collection.standard_bip32_accounts.get_mut(&index)
            }
        })
    }

    /// Get a mutable coinjoin account by network and index
    pub fn get_coinjoin_account_mut(
        &mut self,
        network: Network,
        index: u32,
    ) -> Option<&mut Account> {
        self.accounts
            .get_mut(&network)
            .and_then(|collection| collection.coinjoin_accounts.get_mut(&index))
    }

    /// Get the default account (index 0, searches standard accounts first)
    pub fn default_account(&self, network: Network) -> Option<&Account> {
        self.accounts.get(&network).and_then(|collection| {
            collection
                .standard_bip44_accounts
                .get(&0)
                .or_else(|| collection.standard_bip32_accounts.get(&0))
                .or_else(|| collection.coinjoin_accounts.get(&0))
        })
    }

    /// Get the default account mutably
    pub fn default_account_mut(&mut self, network: Network) -> Option<&mut Account> {
        self.accounts.get_mut(&network).and_then(|collection| {
            if collection.standard_bip44_accounts.contains_key(&0) {
                collection.standard_bip44_accounts.get_mut(&0)
            } else if collection.standard_bip32_accounts.contains_key(&0) {
                collection.standard_bip32_accounts.get_mut(&0)
            } else {
                collection.coinjoin_accounts.get_mut(&0)
            }
        })
    }

    /// Get all accounts (both standard and coinjoin)
    pub fn all_accounts(&self) -> Vec<&Account> {
        let mut accounts = Vec::new();
        for collection in self.accounts.values() {
            accounts.extend(collection.all_accounts());
        }
        accounts
    }

    /// Get the count of accounts (both standard and coinjoin)
    pub fn account_count(&self) -> usize {
        self.accounts.values().map(|collection| collection.count()).sum()
    }

    /// Get all account indices for a network (both standard and coinjoin)
    pub fn account_indices(&self, network: Network) -> Vec<u32> {
        let mut indices = Vec::new();
        if let Some(collection) = self.accounts.get(&network) {
            indices.extend(collection.all_indices());
        }
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
        for collection in watch_only.accounts.values_mut() {
            for account in collection.all_accounts_mut() {
                *account = account.to_watch_only();
            }
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

    /// Create accounts based on the provided creation options
    pub(crate) fn create_accounts_from_options(
        &mut self,
        options: WalletAccountCreationOptions,
        network: Network,
    ) -> Result<()> {
        match options {
            WalletAccountCreationOptions::Default => {
                // Create default BIP44 account 0
                self.add_account(
                    AccountType::Standard {
                        index: 0,
                        standard_account_type: StandardAccountType::BIP44Account,
                    },
                    network,
                    None,
                )?;

                // Create default CoinJoin account 0
                self.add_account(
                    AccountType::CoinJoin {
                        index: 0,
                    },
                    network,
                    None,
                )?;

                // Create all special purpose accounts
                self.create_special_purpose_accounts(network)?;
            }

            WalletAccountCreationOptions::AllAccounts(bip44_indices, coinjoin_indices) => {
                // Create specified BIP44 accounts
                for index in bip44_indices {
                    self.add_account(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP44Account,
                        },
                        network,
                        None,
                    )?;
                }

                // Create specified CoinJoin accounts
                for index in coinjoin_indices {
                    self.add_account(
                        AccountType::CoinJoin {
                            index,
                        },
                        network,
                        None,
                    )?;
                }

                // Create all special purpose accounts
                self.create_special_purpose_accounts(network)?;
            }

            WalletAccountCreationOptions::BIP44AccountsOnly(topup_indices) => {
                // Create BIP44 account 0 if not exists
                if !self
                    .accounts
                    .get(&network)
                    .map(|c| c.standard_bip44_accounts.contains_key(&0))
                    .unwrap_or(false)
                {
                    self.add_account(
                        AccountType::Standard {
                            index: 0,
                            standard_account_type: StandardAccountType::BIP44Account,
                        },
                        network,
                        None,
                    )?;
                }

                // Create identity top-up accounts for specified registrations
                for registration_index in topup_indices {
                    self.add_account(
                        AccountType::IdentityTopUp {
                            registration_index,
                        },
                        network,
                        None,
                    )?;
                }
            }

            WalletAccountCreationOptions::SpecificAccounts(
                bip44_indices,
                coinjoin_indices,
                topup_indices,
                special_accounts,
            ) => {
                // Create specified BIP44 accounts
                for index in bip44_indices {
                    self.add_account(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP44Account,
                        },
                        network,
                        None,
                    )?;
                }

                // Create specified CoinJoin accounts
                for index in coinjoin_indices {
                    self.add_account(
                        AccountType::CoinJoin {
                            index,
                        },
                        network,
                        None,
                    )?;
                }

                // Create identity top-up accounts
                for registration_index in topup_indices {
                    self.add_account(
                        AccountType::IdentityTopUp {
                            registration_index,
                        },
                        network,
                        None,
                    )?;
                }

                // Create any additional special accounts if provided
                if let Some(special_types) = special_accounts {
                    for account_type in special_types {
                        self.add_account(account_type, network, None)?;
                    }
                }
            }

            WalletAccountCreationOptions::None => {
                // Don't create any accounts - useful for tests
            }
        }

        Ok(())
    }

    /// Create all special purpose accounts
    fn create_special_purpose_accounts(&mut self, network: Network) -> Result<()> {
        // Identity registration account
        self.add_account(AccountType::IdentityRegistration, network, None)?;

        // Identity invitation account
        self.add_account(AccountType::IdentityInvitation, network, None)?;

        // Identity top-up not bound to identity
        self.add_account(AccountType::IdentityTopUpNotBoundToIdentity, network, None)?;

        // Provider keys accounts
        self.add_account(AccountType::ProviderVotingKeys, network, None)?;
        self.add_account(AccountType::ProviderOwnerKeys, network, None)?;
        self.add_account(AccountType::ProviderOperatorKeys, network, None)?;
        self.add_account(AccountType::ProviderPlatformKeys, network, None)?;

        Ok(())
    }
}
