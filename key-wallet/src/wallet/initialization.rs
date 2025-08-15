//! Wallet initialization methods
//!
//! This module contains all methods for creating and initializing wallets.

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
use alloc::collections::BTreeMap;
use alloc::string::String;
use std::collections::BTreeSet;

/// Set of BIP44 account indices to create
pub type WalletAccountCreationBIP44Accounts = BTreeSet<u32>;

/// Set of CoinJoin account indices to create
pub type WalletAccountCreationCoinjoinAccounts = BTreeSet<u32>;

/// Set of identity top-up account registration indices to create
pub type WalletAccountCreationTopUpAccounts = BTreeSet<u32>;

/// Options for specifying which accounts to create when initializing a wallet
#[derive(Debug, Clone)]
pub enum WalletAccountCreationOptions {
    /// Default account creation: Creates account 0 for BIP44, account 0 for CoinJoin,
    /// and all special purpose accounts (Identity Registration, Identity Invitation,
    /// Provider keys, etc.)
    Default,

    /// Create all specified BIP44 and CoinJoin accounts plus all special purpose accounts
    ///
    /// # Arguments
    /// * First parameter: Set of BIP44 account indices to create
    /// * Second parameter: Set of CoinJoin account indices to create
    AllAccounts(WalletAccountCreationBIP44Accounts, WalletAccountCreationCoinjoinAccounts),

    /// Create only BIP44 accounts (no CoinJoin or special accounts), with optional
    /// identity top-up accounts for specific registrations
    ///
    /// # Arguments
    /// * Set of identity top-up registration indices (can be empty)
    BIP44AccountsOnly(WalletAccountCreationTopUpAccounts),

    /// Create specific accounts with full control over what gets created
    ///
    /// # Arguments
    /// * First: Set of BIP44 account indices
    /// * Second: Set of CoinJoin account indices  
    /// * Third: Set of identity top-up registration indices
    /// * Fourth: Additional special account type to create (e.g., IdentityRegistration)
    SpecificAccounts(
        WalletAccountCreationBIP44Accounts,
        WalletAccountCreationCoinjoinAccounts,
        WalletAccountCreationTopUpAccounts,
        Option<Vec<AccountType>>,
    ),

    /// Create no accounts at all - useful for tests that want to manually control account creation
    None,
}

impl Wallet {
    /// Create a new wallet with a randomly generated mnemonic
    ///
    /// # Arguments
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn new_random(
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let mnemonic = Mnemonic::generate(12, Language::English)?;
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        let mut wallet = Self::from_wallet_type(
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            },
            config,
            network,
        )?;

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
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

        let wallet = Self {
            wallet_id,
            config: config.clone(),
            wallet_type,
            accounts: BTreeMap::new(),
        };

        // Don't create any accounts here - let the WalletAccountCreationOptions handle it
        Ok(wallet)
    }

    /// Create a wallet from a mnemonic phrase
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_mnemonic(
        mnemonic: Mnemonic,
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        let mut wallet = Self::from_wallet_type(
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            },
            config,
            network,
        )?;

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }

    /// Create a wallet from a mnemonic phrase with passphrase
    /// The passphrase is used only to derive the master public key, then discarded
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase
    /// * `passphrase` - The BIP39 passphrase
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_mnemonic_with_passphrase(
        mnemonic: Mnemonic,
        passphrase: String,
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
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

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }

    /// Create a watch-only wallet from extended public key
    ///
    /// # Arguments
    /// * `master_xpub` - The extended public key
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    ///
    /// Note: Watch-only wallets can only create accounts if the extended public keys are provided
    pub fn from_xpub(
        master_xpub: ExtendedPubKey,
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let wallet = Self::from_wallet_type(
            WalletType::WatchOnly(root_extended_public_key),
            config,
            network,
        )?;

        // For watch-only wallets, we can only create accounts if we have the xpubs
        // The Default option won't work as it tries to derive keys
        match account_creation_options {
            WalletAccountCreationOptions::Default | WalletAccountCreationOptions::None => {
                // For watch-only, we can't derive keys, so skip default account creation
            }
            _ => {
                // Other options would need explicit xpubs provided
                return Err(crate::error::Error::InvalidParameter(
                    "Watch-only wallets require explicit extended public keys for account creation"
                        .to_string(),
                ));
            }
        }

        Ok(wallet)
    }

    /// Create an external signable wallet from extended public key
    /// This wallet type allows for external signing of transactions
    ///
    /// # Arguments
    /// * `master_xpub` - The extended public key
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    ///
    /// Note: External signable wallets can only create accounts if the extended public keys are provided
    pub fn from_external_signable(
        master_xpub: ExtendedPubKey,
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let wallet = Self::from_wallet_type(
            WalletType::ExternalSignable(root_extended_public_key),
            config,
            network,
        )?;

        // For externally signable wallets, we can only create accounts if we have the xpubs
        match account_creation_options {
            WalletAccountCreationOptions::Default | WalletAccountCreationOptions::None => {
                // For externally signable, we can't derive keys, so skip default account creation
            }
            _ => {
                // Other options would need explicit xpubs provided
                return Err(crate::error::Error::InvalidParameter(
                    "Externally signable wallets require explicit extended public keys for account creation".to_string()
                ));
            }
        }

        Ok(wallet)
    }

    /// Create a wallet from seed bytes
    ///
    /// # Arguments
    /// * `seed` - The seed bytes
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_seed(
        seed: Seed,
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::new_master(seed.as_slice())?;

        let mut wallet = Self::from_wallet_type(
            WalletType::Seed {
                seed,
                root_extended_private_key,
            },
            config,
            network,
        )?;

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }

    /// Create a wallet from seed bytes array
    ///
    /// # Arguments
    /// * `seed_bytes` - The seed bytes array
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_seed_bytes(
        seed_bytes: [u8; 64],
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        Self::from_seed(Seed::new(seed_bytes), config, network, account_creation_options)
    }

    /// Create a wallet from an extended private key
    ///
    /// # Arguments
    /// * `master_key` - The extended private key
    /// * `config` - Wallet configuration
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_extended_key(
        master_key: ExtendedPrivKey,
        config: WalletConfig,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::from_extended_priv_key(&master_key);
        let mut wallet = Self::from_wallet_type(
            WalletType::ExtendedPrivKey(root_extended_private_key),
            config,
            network,
        )?;

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }
}
