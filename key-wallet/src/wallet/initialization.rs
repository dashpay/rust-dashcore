//! Wallet initialization methods
//!
//! This module contains all methods for creating and initializing wallets.

use alloc::collections::BTreeMap;
use alloc::string::String;

use super::config::WalletConfig;
use super::root_extended_keys::{RootExtendedPrivKey, RootExtendedPubKey};
use super::{Wallet, WalletType};
use crate::account::account_collection::AccountCollection;
use crate::account::{Account, AccountType};
use crate::bip32::{ExtendedPrivKey, ExtendedPubKey};
use crate::error::Result;
use crate::mnemonic::{Language, Mnemonic};
use crate::seed::Seed;
use crate::Network;

impl Wallet {
    /// Create a new wallet with a randomly generated mnemonic
    pub fn new_random(config: WalletConfig, network: Network) -> Result<Self> {
        let mnemonic = Mnemonic::generate(12, Language::English)?;
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        Self::from_wallet_type(
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            },
            config,
            network,
        )
    }

    /// Create a wallet from a specific wallet type
    pub fn from_wallet_type(
        wallet_type: WalletType,
        config: WalletConfig,
        network: Network,
    ) -> Result<Self> {
        let is_watch_only = matches!(
            wallet_type,
            WalletType::WatchOnly(_)
                | WalletType::ExternalSignable(_)
                | WalletType::MnemonicWithPassphrase { .. }
        );

        // Compute wallet ID from root public key
        let root_pub_key = match &wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            }
            | WalletType::Seed {
                root_extended_private_key,
                ..
            }
            | WalletType::ExtendedPrivKey(root_extended_private_key) => {
                root_extended_private_key.to_root_extended_pub_key()
            }
            WalletType::MnemonicWithPassphrase {
                root_extended_public_key,
                ..
            }
            | WalletType::ExternalSignable(root_extended_public_key)
            | WalletType::WatchOnly(root_extended_public_key) => root_extended_public_key.clone(),
        };
        let wallet_id = Self::compute_wallet_id(&root_pub_key);

        let mut wallet = Self {
            wallet_id,
            config: config.clone(),
            wallet_type,
            accounts: BTreeMap::new(),
        };

        // Generate initial account
        if !is_watch_only {
            wallet.add_account(
                0,
                AccountType::Standard {
                    index: 0,
                    standard_account_type: crate::account::StandardAccountType::BIP44Account,
                },
                network,
            )?;
        } else {
            // For watch-only, external signable, and mnemonic with passphrase wallets, create account with the provided xpub
            let xpub = match &wallet.wallet_type {
                WalletType::WatchOnly(root_pub) | WalletType::ExternalSignable(root_pub) => {
                    root_pub.to_extended_pub_key(network)
                }
                WalletType::MnemonicWithPassphrase {
                    root_extended_public_key,
                    ..
                } => root_extended_public_key.to_extended_pub_key(network),
                _ => unreachable!("Already checked is_watch_only"),
            };

            let account = Account::from_xpub(
                None,
                AccountType::Standard {
                    index: 0,
                    standard_account_type: crate::account::StandardAccountType::BIP44Account,
                },
                xpub,
                network,
            )?;
            let collection = wallet.accounts.entry(network).or_insert_with(AccountCollection::new);
            collection.insert(account);
        }

        Ok(wallet)
    }

    /// Create a wallet from a mnemonic phrase
    pub fn from_mnemonic(
        mnemonic: Mnemonic,
        config: WalletConfig,
        network: Network,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        Self::from_wallet_type(
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            },
            config,
            network,
        )
    }

    /// Create a wallet from a mnemonic phrase with passphrase
    /// The passphrase is used only to derive the master public key, then discarded
    pub fn from_mnemonic_with_passphrase(
        mnemonic: Mnemonic,
        passphrase: String,
        config: WalletConfig,
        network: Network,
        add_account_types: Vec<AccountType>,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed(&passphrase);
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;
        let root_extended_public_key = root_extended_private_key.to_root_extended_pub_key();

        // Store only mnemonic and public key, not the passphrase or private key
        let mut wallet = Self::from_wallet_type(
            WalletType::MnemonicWithPassphrase {
                mnemonic,
                root_extended_public_key,
            },
            config,
            network,
        )?;

        // Add requested account types
        for account_type in add_account_types {
            // Get the account index from the account type
            let account_index = match &account_type {
                AccountType::Standard {
                    index,
                    ..
                } => *index,
                AccountType::CoinJoin {
                    index,
                } => *index,
                AccountType::IdentityTopUp {
                    registration_index,
                } => *registration_index,
                // For other types without an index, use 0
                _ => 0,
            };

            wallet.add_account(account_index, account_type, network)?;
        }

        Ok(wallet)
    }

    /// Create a watch-only wallet from extended public key
    pub fn from_xpub(
        master_xpub: ExtendedPubKey,
        config: WalletConfig,
        network: Network,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        Self::from_wallet_type(WalletType::WatchOnly(root_extended_public_key), config, network)
    }

    /// Create an external signable wallet from extended public key
    /// This wallet type allows for external signing of transactions
    pub fn from_external_signable(
        master_xpub: ExtendedPubKey,
        config: WalletConfig,
        network: Network,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        Self::from_wallet_type(
            WalletType::ExternalSignable(root_extended_public_key),
            config,
            network,
        )
    }

    /// Create a wallet from seed bytes
    pub fn from_seed(seed: Seed, config: WalletConfig, network: Network) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::new_master(seed.as_slice())?;

        Self::from_wallet_type(
            WalletType::Seed {
                seed,
                root_extended_private_key,
            },
            config,
            network,
        )
    }

    /// Create a wallet from seed bytes array
    pub fn from_seed_bytes(
        seed_bytes: [u8; 64],
        config: WalletConfig,
        network: Network,
    ) -> Result<Self> {
        Self::from_seed(Seed::new(seed_bytes), config, network)
    }

    /// Create a wallet from an extended private key
    pub fn from_extended_key(
        master_key: ExtendedPrivKey,
        config: WalletConfig,
        network: Network,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::from_extended_priv_key(&master_key);
        Self::from_wallet_type(
            WalletType::ExtendedPrivKey(root_extended_private_key),
            config,
            network,
        )
    }
}
