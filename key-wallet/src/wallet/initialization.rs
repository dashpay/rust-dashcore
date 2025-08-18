//! Wallet initialization methods
//!
//! This module contains all methods for creating and initializing wallets.

use super::config::WalletConfig;
use super::root_extended_keys::{RootExtendedPrivKey, RootExtendedPubKey};
use super::{Wallet, WalletType};
use crate::account::account_collection::AccountCollection;
use crate::account::AccountType;
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

/// Set of BIP32 account indices to create
pub type WalletAccountCreationBIP32Accounts = BTreeSet<u32>;

/// Set of CoinJoin account indices to create
pub type WalletAccountCreationCoinjoinAccounts = BTreeSet<u32>;

/// Set of identity top-up account registration indices to create
pub type WalletAccountCreationTopUpAccounts = BTreeSet<u32>;

/// Options for specifying which accounts to create when initializing a wallet
#[derive(Debug, Clone, Default)]
pub enum WalletAccountCreationOptions {
    /// Default account creation: Creates account 0 for BIP44, account 0 for CoinJoin,
    /// and all special purpose accounts (Identity Registration, Identity Invitation,
    /// Provider keys, etc.)
    #[default]
    Default,

    /// Create all specified BIP44 and CoinJoin accounts plus all special purpose accounts
    ///
    /// # Arguments
    /// * First parameter: Set of BIP44 account indices to create
    /// * Second parameter: Set of CoinJoin account indices to create
    AllAccounts(
        WalletAccountCreationBIP44Accounts,
        WalletAccountCreationBIP32Accounts,
        WalletAccountCreationCoinjoinAccounts,
        WalletAccountCreationTopUpAccounts,
    ),

    /// Create only BIP44 accounts (no CoinJoin or special accounts), with optional
    /// identity top-up accounts for specific registrations
    ///
    /// # Arguments
    /// * Set of identity top-up registration indices (can be empty)
    BIP44AccountsOnly(WalletAccountCreationBIP44Accounts),

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
        );

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }

    /// Create a wallet from a specific wallet type with no accounts
    pub fn from_wallet_type(wallet_type: WalletType, config: WalletConfig) -> Self {
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

        wallet
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
        );

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
        );

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }

    /// Create a watch-only wallet from extended public key
    ///
    /// Watch-only wallets can generate addresses and monitor transactions but cannot sign.
    /// This is useful for cold storage setups where the private keys are kept offline.
    ///
    /// # Arguments
    /// * `master_xpub` - The master extended public key for the wallet
    /// * `config` - Optional wallet configuration (uses default if None)
    /// * `accounts` - Pre-created account collections mapped by network. Since watch-only wallets
    ///                cannot derive private keys, all accounts must be provided with their extended
    ///                public keys already initialized.
    ///
    /// # Returns
    /// A new watch-only wallet instance
    ///
    /// # Example
    /// ```ignore
    /// let accounts = BTreeMap::from([
    ///     (Network::Mainnet, account_collection),
    /// ]);
    /// let wallet = Wallet::from_xpub(master_xpub, None, accounts)?;
    /// ```
    pub fn from_xpub(
        master_xpub: ExtendedPubKey,
        config: Option<WalletConfig>,
        accounts: BTreeMap<Network, AccountCollection>,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let mut wallet = Self::from_wallet_type(
            WalletType::WatchOnly(root_extended_public_key),
            config.unwrap_or_default(),
        );

        wallet.accounts = accounts;

        Ok(wallet)
    }

    /// Create an external signable wallet from extended public key
    ///
    /// External signable wallets support transaction signing through external devices or services.
    /// Unlike watch-only wallets which cannot sign at all, these wallets delegate signing to
    /// hardware wallets, remote signing services, or other external signing mechanisms.
    ///
    /// # Arguments
    /// * `master_xpub` - The master extended public key from the external signing device
    /// * `config` - Optional wallet configuration (uses default if None)
    /// * `accounts` - Pre-created account collections mapped by network. Since external signable
    ///                wallets cannot derive private keys, all accounts must be provided with their
    ///                extended public keys already initialized from the external device.
    ///
    /// # Returns
    /// A new external signable wallet instance that can create transactions but requires
    /// the external device/service for signing
    ///
    /// # Example
    /// ```ignore
    /// // Get master xpub from hardware wallet
    /// let master_xpub = hardware_wallet.get_master_xpub()?;
    ///
    /// // Create accounts with xpubs from hardware wallet
    /// let accounts = create_accounts_from_hardware_wallet(&hardware_wallet)?;
    ///
    /// let wallet = Wallet::from_external_signable(master_xpub, None, accounts)?;
    ///
    /// // Later, when signing is needed:
    /// // let signature = hardware_wallet.sign_transaction(&tx)?;
    /// ```
    pub fn from_external_signable(
        master_xpub: ExtendedPubKey,
        config: Option<WalletConfig>,
        accounts: BTreeMap<Network, AccountCollection>,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let mut wallet = Self::from_wallet_type(
            WalletType::ExternalSignable(root_extended_public_key),
            config.unwrap_or_default(),
        );

        wallet.accounts = accounts;

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
        );

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
        let mut wallet =
            Self::from_wallet_type(WalletType::ExtendedPrivKey(root_extended_private_key), config);

        // Create accounts based on options
        wallet.create_accounts_from_options(account_creation_options, network)?;

        Ok(wallet)
    }
}
