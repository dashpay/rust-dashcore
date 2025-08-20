//! Wallet helper methods
//!
//! This module contains helper methods and utility functions for wallets.

use super::initialization::WalletAccountCreationOptions;
use super::root_extended_keys::RootExtendedPrivKey;
use super::{Wallet, WalletType};
use crate::account::{Account, AccountType, StandardAccountType};
use crate::error::Result;
use crate::{Error, Network};
use alloc::vec::Vec;

impl Wallet {
    /// Get a bip44 account by network and index
    pub fn get_bip44_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts
            .get(&network)
            .and_then(|collection| collection.standard_bip44_accounts.get(&index))
    }

    /// Get a bip32 account by network and index
    pub fn get_bip32_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts
            .get(&network)
            .and_then(|collection| collection.standard_bip32_accounts.get(&index))
    }

    /// Get a coinjoin account by network and index
    pub fn get_coinjoin_account(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts.get(&network).and_then(|collection| collection.coinjoin_accounts.get(&index))
    }

    /// Get a mutable bip44 account by network and index
    pub fn get_bip44_account_mut(&mut self, network: Network, index: u32) -> Option<&mut Account> {
        self.accounts
            .get_mut(&network)
            .and_then(|collection| collection.standard_bip44_accounts.get_mut(&index))
    }

    /// Get a mutable bip32 account by network and index
    pub fn get_bip32_account_mut(&mut self, network: Network, index: u32) -> Option<&mut Account> {
        self.accounts
            .get_mut(&network)
            .and_then(|collection| collection.standard_bip32_accounts.get_mut(&index))
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
        matches!(self.wallet_type, WalletType::Seed { .. } | WalletType::Mnemonic { .. })
    }

    /// Create accounts based on the provided creation options
    pub(crate) fn create_accounts_from_options(
        &mut self,
        options: WalletAccountCreationOptions,
        network: Network,
    ) -> Result<()> {
        if matches!(self.wallet_type, WalletType::MnemonicWithPassphrase { .. }) {
            return Err(Error::InvalidParameter(
                "create_accounts_from_options can not be used on wallets with a mnemonic and a passphrase".to_string()
            ));
        }
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

            WalletAccountCreationOptions::AllAccounts(
                bip44_indices,
                bip32_indices,
                coinjoin_indices,
                top_up_accounts,
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

                // Create specified BIP44 accounts
                for index in bip32_indices {
                    self.add_account(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP32Account,
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

                // Create specified CoinJoin accounts
                for registration_index in top_up_accounts {
                    self.add_account(
                        AccountType::IdentityTopUp {
                            registration_index,
                        },
                        network,
                        None,
                    )?;
                }

                // Create all special purpose accounts
                self.create_special_purpose_accounts(network)?;
            }

            WalletAccountCreationOptions::BIP44AccountsOnly(bip44_indices) => {
                // Create BIP44 account 0 if not exists
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

    /// Create accounts based on the provided creation options with passphrase
    pub fn create_accounts_with_passphrase_from_options(
        &mut self,
        options: WalletAccountCreationOptions,
        passphrase: &str,
        network: Network,
    ) -> Result<()> {
        if !matches!(self.wallet_type, WalletType::MnemonicWithPassphrase { .. }) {
            return Err(Error::InvalidParameter(
                "create_accounts_with_passphrase_from_options can only be used with wallets created with a passphrase".to_string()
            ));
        }
        match options {
            WalletAccountCreationOptions::Default => {
                // Create default BIP44 account 0
                self.add_account_with_passphrase(
                    AccountType::Standard {
                        index: 0,
                        standard_account_type: StandardAccountType::BIP44Account,
                    },
                    network,
                    passphrase,
                )?;

                // Create default CoinJoin account 0
                self.add_account_with_passphrase(
                    AccountType::CoinJoin {
                        index: 0,
                    },
                    network,
                    passphrase,
                )?;

                // Create all special purpose accounts
                self.create_special_purpose_accounts_with_passphrase(passphrase, network)?;
            }

            WalletAccountCreationOptions::AllAccounts(
                bip44_indices,
                bip32_indices,
                coinjoin_indices,
                top_up_accounts,
            ) => {
                // Create specified BIP44 accounts
                for index in bip44_indices {
                    self.add_account_with_passphrase(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP44Account,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create specified BIP32 accounts
                for index in bip32_indices {
                    self.add_account_with_passphrase(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP32Account,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create specified CoinJoin accounts
                for index in coinjoin_indices {
                    self.add_account_with_passphrase(
                        AccountType::CoinJoin {
                            index,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create specified CoinJoin accounts
                for registration_index in top_up_accounts {
                    self.add_account_with_passphrase(
                        AccountType::IdentityTopUp {
                            registration_index,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create all special purpose accounts
                self.create_special_purpose_accounts_with_passphrase(passphrase, network)?;
            }

            WalletAccountCreationOptions::BIP44AccountsOnly(bip44_indices) => {
                // Create BIP44 account 0 if not exists
                for index in bip44_indices {
                    self.add_account_with_passphrase(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP44Account,
                        },
                        network,
                        passphrase,
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
                    self.add_account_with_passphrase(
                        AccountType::Standard {
                            index,
                            standard_account_type: StandardAccountType::BIP44Account,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create specified CoinJoin accounts
                for index in coinjoin_indices {
                    self.add_account_with_passphrase(
                        AccountType::CoinJoin {
                            index,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create identity top-up accounts
                for registration_index in topup_indices {
                    self.add_account_with_passphrase(
                        AccountType::IdentityTopUp {
                            registration_index,
                        },
                        network,
                        passphrase,
                    )?;
                }

                // Create any additional special accounts if provided
                if let Some(special_types) = special_accounts {
                    for account_type in special_types {
                        self.add_account_with_passphrase(account_type, network, passphrase)?;
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

    /// Create all special purpose accounts
    fn create_special_purpose_accounts_with_passphrase(
        &mut self,
        passphrase: &str,
        network: Network,
    ) -> Result<()> {
        // Identity registration account
        self.add_account_with_passphrase(AccountType::IdentityRegistration, network, passphrase)?;

        // Identity invitation account
        self.add_account_with_passphrase(AccountType::IdentityInvitation, network, passphrase)?;

        // Identity top-up not bound to identity
        self.add_account_with_passphrase(
            AccountType::IdentityTopUpNotBoundToIdentity,
            network,
            passphrase,
        )?;

        // Provider keys accounts
        self.add_account_with_passphrase(AccountType::ProviderVotingKeys, network, passphrase)?;
        self.add_account_with_passphrase(AccountType::ProviderOwnerKeys, network, passphrase)?;
        self.add_account_with_passphrase(AccountType::ProviderOperatorKeys, network, passphrase)?;
        self.add_account_with_passphrase(AccountType::ProviderPlatformKeys, network, passphrase)?;

        Ok(())
    }
}
