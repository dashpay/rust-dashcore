//! Wallet initialization methods
//!
//! This module contains all methods for creating and initializing wallets.

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
    /// Default account creation: Creates account 0 for BIP32, BIP44, account 0 for CoinJoin,
    /// and all special purpose accounts (Identity Registration, Identity Invitation,
    /// Provider keys, etc.)
    #[default]
    Default,

    /// Create all specified BIP44, BIP32, and CoinJoin accounts plus all special purpose accounts
    ///
    /// # Arguments
    /// * First parameter: Set of BIP44 account indices to create
    /// * Second parameter: Set of BIP32 account indices to create
    /// * Third parameter: Set of CoinJoin account indices to create
    /// * Fourth parameter: Set of identity top-up registration indices to create
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
    /// * Second: Set of BIP32 account indices
    /// * Third: Set of CoinJoin account indices  
    /// * Fourth: Set of identity top-up registration indices
    /// * Fifth: Additional special account type to create (e.g., IdentityRegistration)
    SpecificAccounts(
        WalletAccountCreationBIP44Accounts,
        WalletAccountCreationBIP32Accounts,
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
    /// * `networks` - List of networks to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn new_random(
        networks: &[Network],
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let mnemonic = Mnemonic::generate(12, Language::English)?;
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        let mut wallet = Self::from_wallet_type(WalletType::Mnemonic {
            mnemonic,
            root_extended_private_key,
        });

        // Create accounts for each network
        for network in networks {
            wallet.create_accounts_from_options(account_creation_options.clone(), *network)?;
        }

        Ok(wallet)
    }

    /// Create a wallet from a specific wallet type with no accounts
    pub fn from_wallet_type(wallet_type: WalletType) -> Self {
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
        let wallet_id = Self::compute_wallet_id_from_root_extended_pub_key(&root_pub_key);

        Self {
            wallet_id,
            wallet_type,
            accounts: BTreeMap::new(),
        }
    }

    /// Create a wallet from a mnemonic phrase
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase
    /// * `networks` - List of networks to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_mnemonic(
        mnemonic: Mnemonic,
        networks: &[Network],
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        let mut wallet = Self::from_wallet_type(WalletType::Mnemonic {
            mnemonic,
            root_extended_private_key,
        });

        // Create accounts for each network
        for network in networks {
            wallet.create_accounts_from_options(account_creation_options.clone(), *network)?;
        }

        Ok(wallet)
    }

    /// Create a wallet from a mnemonic phrase with passphrase
    /// The passphrase is used only to derive the master public key, then discarded
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase
    /// * `passphrase` - The BIP39 passphrase
    /// * `networks` - List of networks to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_mnemonic_with_passphrase(
        mnemonic: Mnemonic,
        passphrase: String,
        networks: &[Network],
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed(&passphrase);
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;
        let root_extended_public_key = root_extended_private_key.to_root_extended_pub_key();

        // Store only mnemonic and public key, not the passphrase or private key
        let mut wallet = Self::from_wallet_type(WalletType::MnemonicWithPassphrase {
            mnemonic,
            root_extended_public_key,
        });

        // Create accounts for each network
        for network in networks {
            wallet.create_accounts_with_passphrase_from_options(
                account_creation_options.clone(),
                passphrase.as_str(),
                *network,
            )?;
        }

        Ok(wallet)
    }

    /// Create a watch-only or externally signable wallet from extended public key
    ///
    /// Watch-only wallets can generate addresses and monitor transactions but cannot sign.
    /// Externally signable wallets can also create unsigned transactions that can be signed by
    /// external devices (hardware wallets, remote signing services, etc.).
    ///
    /// # Arguments
    /// * `master_xpub` - The master extended public key for the wallet
    /// * `accounts` - Pre-created account collections mapped by network. Since watch-only wallets
    ///   cannot derive private keys, all accounts must be provided with their extended
    ///   public keys already initialized.
    /// * `can_sign_externally` - If true, creates an externally signable wallet that supports
    ///   transaction creation for external signing. If false, creates a pure watch-only wallet.
    ///
    /// # Returns
    /// A new watch-only or externally signable wallet instance
    ///
    /// # Example
    /// ```ignore
    /// let accounts = BTreeMap::from([
    ///     (Network::Mainnet, account_collection),
    /// ]);
    /// // Create a pure watch-only wallet
    /// let watch_wallet = Wallet::from_xpub(master_xpub, accounts.clone(), false)?;
    ///
    /// // Create an externally signable wallet (e.g., for hardware wallet)
    /// let hw_wallet = Wallet::from_xpub(master_xpub, accounts, true)?;
    /// ```
    pub fn from_xpub(
        master_xpub: ExtendedPubKey,
        accounts: BTreeMap<Network, AccountCollection>,
        can_sign_externally: bool,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let wallet_type = if can_sign_externally {
            WalletType::ExternalSignable(root_extended_public_key)
        } else {
            WalletType::WatchOnly(root_extended_public_key)
        };
        let mut wallet = Self::from_wallet_type(wallet_type);

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
    ///   wallets cannot derive private keys, all accounts must be provided with their
    ///   extended public keys already initialized from the external device.
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
        accounts: BTreeMap<Network, AccountCollection>,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let mut wallet =
            Self::from_wallet_type(WalletType::ExternalSignable(root_extended_public_key));

        wallet.accounts = accounts;

        Ok(wallet)
    }

    /// Create a wallet from seed bytes
    ///
    /// # Arguments
    /// * `seed` - The seed bytes
    /// * `networks` - List of networks to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_seed(
        seed: Seed,
        networks: &[Network],
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::new_master(seed.as_slice())?;

        let mut wallet = Self::from_wallet_type(WalletType::Seed {
            seed,
            root_extended_private_key,
        });

        // Create accounts for each network
        for network in networks {
            wallet.create_accounts_from_options(account_creation_options.clone(), *network)?;
        }

        Ok(wallet)
    }

    /// Create a wallet from seed bytes array
    ///
    /// # Arguments
    /// * `seed_bytes` - The seed bytes array
    /// * `networks` - List of networks to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_seed_bytes(
        seed_bytes: [u8; 64],
        networks: &[Network],
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        Self::from_seed(Seed::new(seed_bytes), networks, account_creation_options)
    }

    /// Create a wallet from an extended private key
    ///
    /// # Arguments
    /// * `master_key` - The extended private key
    /// * `networks` - List of networks to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_extended_key(
        master_key: ExtendedPrivKey,
        networks: &[Network],
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::from_extended_priv_key(&master_key);
        let mut wallet =
            Self::from_wallet_type(WalletType::ExtendedPrivKey(root_extended_private_key));

        // Create accounts for each network
        for network in networks {
            wallet.create_accounts_from_options(account_creation_options.clone(), *network)?;
        }

        Ok(wallet)
    }
}
