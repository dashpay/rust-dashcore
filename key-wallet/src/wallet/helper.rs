//! Wallet helper methods
//!
//! This module contains helper methods and utility functions for wallets.

use super::initialization::WalletAccountCreationOptions;
use super::root_extended_keys::RootExtendedPrivKey;
use super::{Wallet, WalletType};
use crate::account::{Account, AccountType, StandardAccountType};
use crate::error::Result;
use crate::{AccountCollection, Error, Network};
use alloc::vec::Vec;
use hex;

impl Wallet {
    /// Get the networks supported for the wallet
    pub fn networks_supported(&self) -> Vec<Network> {
        self.accounts.keys().cloned().collect()
    }
    /// Get the collection of accounts on a network
    pub fn accounts_on_network(&self, network: Network) -> Option<&AccountCollection> {
        self.accounts.get(&network)
    }
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
                // Create default BIP32 account 0
                self.add_account(
                    AccountType::Standard {
                        index: 0,
                        standard_account_type: StandardAccountType::BIP32Account,
                    },
                    network,
                    None,
                )?;

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
                bip32_indices,
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

                // Create specified BIP32 accounts
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
                // Create default BIP32 account 0
                self.add_account_with_passphrase(
                    AccountType::Standard {
                        index: 0,
                        standard_account_type: StandardAccountType::BIP32Account,
                    },
                    network,
                    passphrase,
                )?;

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
                bip32_indices,
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
        #[cfg(feature = "bls")]
        self.add_bls_account(AccountType::ProviderOperatorKeys, network, None)?;
        #[cfg(feature = "eddsa")]
        self.add_eddsa_account(AccountType::ProviderPlatformKeys, network, None)?;

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
        #[cfg(feature = "bls")]
        self.add_bls_account_with_passphrase(
            AccountType::ProviderOperatorKeys,
            network,
            passphrase,
        )?;
        #[cfg(feature = "eddsa")]
        self.add_eddsa_account_with_passphrase(
            AccountType::ProviderPlatformKeys,
            network,
            passphrase,
        )?;

        Ok(())
    }

    /// Derive an extended private key at a specific derivation path
    ///
    /// This will return the extended private key for the given derivation path.
    /// Only works for wallets that have access to the private keys (not watch-only).
    /// For MnemonicWithPassphrase wallets, you must provide the passphrase.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    /// * `passphrase` - Optional passphrase for MnemonicWithPassphrase wallets
    ///
    /// # Returns
    /// The extended private key, or an error if the wallet is watch-only or path is invalid
    pub fn derive_extended_private_key_with_passphrase(
        &self,
        network: Network,
        path: &crate::DerivationPath,
        passphrase: Option<&str>,
    ) -> Result<crate::bip32::ExtendedPrivKey> {
        use crate::bip32::ExtendedPrivKey;
        use secp256k1::Secp256k1;

        // Get the master private key based on wallet type
        let master = match &self.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.to_extended_priv_key(network),
            WalletType::MnemonicWithPassphrase {
                mnemonic,
                ..
            } => {
                let pass = passphrase.ok_or(Error::InvalidParameter(
                    "Passphrase required for this wallet type".to_string(),
                ))?;
                let seed = mnemonic.to_seed(pass);
                ExtendedPrivKey::new_master(network, &seed)?
            }
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => root_extended_private_key.to_extended_priv_key(network),
            WalletType::ExtendedPrivKey(root_priv) => root_priv.to_extended_priv_key(network),
            WalletType::ExternalSignable(_) | WalletType::WatchOnly(_) => {
                return Err(Error::InvalidParameter(
                    "Cannot derive private keys from watch-only wallet".to_string(),
                ));
            }
        };

        // Derive the private key at the specified path
        let secp = Secp256k1::new();
        master.derive_priv(&secp, path).map_err(|e| e.into())
    }

    /// Derive an extended private key at a specific derivation path
    ///
    /// This will return the extended private key for the given derivation path.
    /// Only works for wallets that have access to the private keys (not watch-only).
    /// For MnemonicWithPassphrase wallets, this will fail.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    ///
    /// # Returns
    /// The extended private key, or an error if the wallet is watch-only or path is invalid
    pub fn derive_extended_private_key(
        &self,
        network: Network,
        path: &crate::DerivationPath,
    ) -> Result<crate::bip32::ExtendedPrivKey> {
        self.derive_extended_private_key_with_passphrase(network, path, None)
    }

    /// Derive a private key at a specific derivation path
    ///
    /// This will return the private key (SecretKey) for the given derivation path.
    /// Only works for wallets that have access to the private keys (not watch-only).
    /// For MnemonicWithPassphrase wallets, this will fail.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    ///
    /// # Returns
    /// The private key (SecretKey), or an error if the wallet is watch-only or path is invalid
    pub fn derive_private_key(
        &self,
        network: Network,
        path: &crate::DerivationPath,
    ) -> Result<secp256k1::SecretKey> {
        let extended = self.derive_extended_private_key(network, path)?;
        Ok(extended.private_key)
    }

    /// Derive a private key at a specific derivation path and return as WIF
    ///
    /// This will return the private key in WIF format for the given derivation path.
    /// Only works for wallets that have access to the private keys (not watch-only).
    /// For MnemonicWithPassphrase wallets, this will fail.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    ///
    /// # Returns
    /// The private key in WIF format, or an error if the wallet is watch-only or path is invalid
    pub fn derive_private_key_as_wif(
        &self,
        network: Network,
        path: &crate::DerivationPath,
    ) -> Result<String> {
        let private_key = self.derive_private_key(network, path)?;

        // Convert to WIF format
        use dashcore::PrivateKey as DashPrivateKey;
        let dash_key = DashPrivateKey {
            compressed: true,
            network,
            inner: private_key,
        };
        Ok(dash_key.to_wif())
    }

    /// Derive an extended public key at a specific derivation path
    ///
    /// For hardened derivation paths, this requires private key access.
    /// For non-hardened paths, this works with watch-only wallets.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    ///
    /// # Returns
    /// The extended public key, or an error if the path is invalid
    pub fn derive_extended_public_key(
        &self,
        network: Network,
        path: &crate::DerivationPath,
    ) -> Result<crate::bip32::ExtendedPubKey> {
        use secp256k1::Secp256k1;

        // Check if the path contains hardened derivation
        let has_hardened = path.into_iter().any(|child| child.is_hardened());

        if has_hardened && !self.can_sign() {
            return Err(Error::InvalidParameter(
                "Cannot derive hardened extended public keys from watch-only wallet".to_string(),
            ));
        }

        if has_hardened {
            // For hardened paths, derive the extended private key first, then get extended public key
            let extended_private = self.derive_extended_private_key(network, path)?;
            use crate::bip32::ExtendedPubKey;
            let secp = Secp256k1::new();
            Ok(ExtendedPubKey::from_priv(&secp, &extended_private))
        } else {
            // For non-hardened paths, derive directly from public key
            let secp = Secp256k1::new();
            let xpub = self.root_extended_pub_key().to_extended_pub_key(network);
            xpub.derive_pub(&secp, path).map_err(|e| e.into())
        }
    }

    /// Derive a public key at a specific derivation path
    ///
    /// For hardened derivation paths, this requires private key access.
    /// For non-hardened paths, this works with watch-only wallets.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    ///
    /// # Returns
    /// The public key (secp256k1::PublicKey), or an error if the path is invalid
    pub fn derive_public_key(
        &self,
        network: Network,
        path: &crate::DerivationPath,
    ) -> Result<secp256k1::PublicKey> {
        // Check if the path contains hardened derivation
        let has_hardened = path.into_iter().any(|child| child.is_hardened());

        if has_hardened && !self.can_sign() {
            return Err(Error::InvalidParameter(
                "Cannot derive hardened public keys from watch-only wallet".to_string(),
            ));
        }

        if has_hardened {
            // For hardened paths, derive the private key first, then get public key
            let private_key = self.derive_private_key(network, path)?;
            use secp256k1::Secp256k1;
            let secp = Secp256k1::new();
            Ok(secp256k1::PublicKey::from_secret_key(&secp, &private_key))
        } else {
            // For non-hardened paths, derive directly from public key
            let extended = self.derive_extended_public_key(network, path)?;
            Ok(extended.public_key)
        }
    }

    /// Derive a public key at a specific derivation path and return as hex string
    ///
    /// For hardened derivation paths, this requires private key access.
    /// For non-hardened paths, this works with watch-only wallets.
    ///
    /// # Arguments
    /// * `network` - The network to derive for
    /// * `path` - The derivation path (e.g., "m/44'/5'/0'/0/0")
    ///
    /// # Returns
    /// The public key as hex string, or an error if the path is invalid
    pub fn derive_public_key_as_hex(
        &self,
        network: Network,
        path: &crate::DerivationPath,
    ) -> Result<String> {
        let public_key = self.derive_public_key(network, path)?;

        // Return as hex string
        let serialized = public_key.serialize(); // compressed
        Ok(hex::encode(serialized))
    }

    /// Get the extended public key for a specific account type
    ///
    /// This helper method retrieves the extended public key for a given account type
    /// from the wallet's account collection.
    ///
    /// # Arguments
    /// * `account_type` - The type of account to get the xpub for
    /// * `account_index` - The account index for indexed account types
    /// * `network` - The network to look up accounts for
    ///
    /// # Returns
    /// The extended public key for the account, or None if not found
    pub fn extended_public_key_for_account_type(
        &self,
        account_type: &crate::transaction_checking::transaction_router::AccountTypeToCheck,
        account_index: Option<u32>,
        network: Network,
    ) -> Option<crate::bip32::ExtendedPubKey> {
        self.accounts.get(&network).and_then(|coll| {
            match account_type {
                crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP44 => {
                    account_index.and_then(|idx| coll.standard_bip44_accounts.get(&idx).map(|a| a.account_xpub))
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::StandardBIP32 => {
                    account_index.and_then(|idx| coll.standard_bip32_accounts.get(&idx).map(|a| a.account_xpub))
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::CoinJoin => {
                    account_index.and_then(|idx| coll.coinjoin_accounts.get(&idx).map(|a| a.account_xpub))
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::IdentityRegistration => {
                    coll.identity_registration.as_ref().map(|a| a.account_xpub)
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::IdentityTopUp => {
                    account_index.and_then(|idx| coll.identity_topup.get(&idx).map(|a| a.account_xpub))
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::IdentityTopUpNotBound => {
                    coll.identity_topup_not_bound.as_ref().map(|a| a.account_xpub)
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::IdentityInvitation => {
                    coll.identity_invitation.as_ref().map(|a| a.account_xpub)
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderVotingKeys => {
                    coll.provider_voting_keys.as_ref().map(|a| a.account_xpub)
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOwnerKeys => {
                    coll.provider_owner_keys.as_ref().map(|a| a.account_xpub)
                }
                crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderOperatorKeys |
                crate::transaction_checking::transaction_router::AccountTypeToCheck::ProviderPlatformKeys => {
                    // These use BLS/EdDSA keys, not regular xpubs
                    None
                }
            }
        })
    }
}
