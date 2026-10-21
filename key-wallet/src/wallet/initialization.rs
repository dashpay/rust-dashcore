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
use std::collections::BTreeSet;

/// Set of BIP44 account indices to create
pub type WalletAccountCreationBIP44Accounts = BTreeSet<u32>;

/// Set of BIP32 account indices to create
pub type WalletAccountCreationBIP32Accounts = BTreeSet<u32>;

/// Set of CoinJoin account indices to create
pub type WalletAccountCreationCoinjoinAccounts = BTreeSet<u32>;

/// Set of identity top-up account registration indices to create
pub type WalletAccountCreationTopUpAccounts = BTreeSet<u32>;

/// Specification for a PlatformPayment account to create
///
/// PlatformPayment accounts (DIP-17) use the derivation path:
/// `m/9'/coin_type'/17'/account'/key_class'/index`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlatformPaymentAccountSpec {
    /// Account index (hardened) - the account' level in the derivation path
    pub account: u32,
    /// Key class (hardened) - defaults to 0', 1' is reserved for change-like segregation
    pub key_class: u32,
}

/// Set of PlatformPayment account specs to create
pub type WalletAccountCreationPlatformPaymentAccounts = BTreeSet<PlatformPaymentAccountSpec>;

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
    /// * Fifth parameter: Set of PlatformPayment account specs to create
    AllAccounts(
        WalletAccountCreationBIP44Accounts,
        WalletAccountCreationBIP32Accounts,
        WalletAccountCreationCoinjoinAccounts,
        WalletAccountCreationTopUpAccounts,
        WalletAccountCreationPlatformPaymentAccounts,
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
    /// * Fifth: Set of PlatformPayment account specs to create
    /// * Sixth: Additional special account types to create (e.g., IdentityRegistration)
    SpecificAccounts(
        WalletAccountCreationBIP44Accounts,
        WalletAccountCreationBIP32Accounts,
        WalletAccountCreationCoinjoinAccounts,
        WalletAccountCreationTopUpAccounts,
        WalletAccountCreationPlatformPaymentAccounts,
        Option<Vec<AccountType>>,
    ),

    /// Create no accounts at all - useful for tests that want to manually control account creation
    None,
}

impl Wallet {
    /// Create a new wallet with a randomly generated mnemonic
    ///
    /// # Arguments
    /// * `network` - Network to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn new_random(
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let mnemonic = Mnemonic::generate(12, Language::English)?;
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        let mut wallet = Self::from_wallet_type(
            network,
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            },
        );

        wallet.create_accounts_from_options(account_creation_options.clone())?;

        Ok(wallet)
    }

    /// Create a wallet from a signing wallet type with no accounts.
    ///
    /// This derives the wallet id from the root public key carried by the
    /// variant. The [`WalletType::WatchOnly`] and [`WalletType::ExternalSignable`]
    /// unit variants have no root key to derive from — use
    /// [`Wallet::new_watch_only`] or [`Wallet::new_external_signable`] for those.
    ///
    /// # Panics
    /// Panics if `wallet_type` is `WalletType::WatchOnly` or
    /// `WalletType::ExternalSignable`.
    pub fn from_wallet_type(network: Network, wallet_type: WalletType) -> Self {
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
            WalletType::ExternalSignable | WalletType::WatchOnly => {
                panic!(
                    "Wallet::from_wallet_type cannot be used with WalletType::WatchOnly or \
                     WalletType::ExternalSignable — use Wallet::new_watch_only or \
                     Wallet::new_external_signable instead"
                );
            }
        };
        let wallet_id =
            Self::compute_wallet_id_from_root_extended_pub_key(&root_pub_key, Some(network));

        Self {
            network,
            wallet_id,
            wallet_type,
            accounts: AccountCollection::new(),
        }
    }

    /// Build a watch-only wallet from its known id + pre-built accounts.
    ///
    /// Watch-only wallets carry no root key material. Every Dash derivation path
    /// (BIP44, DIP-9 identity, DIP-15 DashPay, DIP-17 platform payment) hits a
    /// hardened level before the account index, so a host-side root xpub cannot
    /// be used to expand account coverage. Supply the accounts you want to track
    /// directly via `accounts`.
    ///
    /// `wallet_id` is the stable identifier for this wallet (typically a hash
    /// derived when the wallet was first created, persisted by the caller, and
    /// fed back in at restore time).
    pub fn new_watch_only(
        network: Network,
        wallet_id: [u8; 32],
        accounts: AccountCollection,
    ) -> Self {
        Self {
            network,
            wallet_id,
            wallet_type: WalletType::WatchOnly,
            accounts,
        }
    }

    /// Build an external-signable wallet from its known id + pre-built accounts.
    ///
    /// The external device (hardware wallet, remote signer, …) holds all key
    /// material. The host only needs per-account xpubs (for address generation)
    /// and derivation paths (to request signatures). Both are carried by
    /// `accounts`.
    ///
    /// `wallet_id` is the stable identifier for this wallet (typically a hash
    /// derived when the wallet was first created, persisted by the caller, and
    /// fed back in at restore time).
    pub fn new_external_signable(
        network: Network,
        wallet_id: [u8; 32],
        accounts: AccountCollection,
    ) -> Self {
        Self {
            network,
            wallet_id,
            wallet_type: WalletType::ExternalSignable,
            accounts,
        }
    }

    /// Create a wallet from a mnemonic phrase
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase
    /// * `network` - Network to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_mnemonic(
        mnemonic: Mnemonic,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let seed = mnemonic.to_seed("");
        let root_extended_private_key = RootExtendedPrivKey::new_master(&seed)?;

        let mut wallet = Self::from_wallet_type(
            network,
            WalletType::Mnemonic {
                mnemonic,
                root_extended_private_key,
            },
        );

        wallet.create_accounts_from_options(account_creation_options.clone())?;

        Ok(wallet)
    }

    /// Create a watch-only or externally signable wallet from an extended public key.
    ///
    /// This is a thin adapter that hashes `master_xpub` into a stable wallet id
    /// and delegates to [`Wallet::new_watch_only`] or
    /// [`Wallet::new_external_signable`]. The xpub itself is **not** retained on
    /// the wallet — watch-only and external-signable wallets do not need a root
    /// key at rest (see the rationale on [`WalletType::WatchOnly`]).
    ///
    /// Prefer the new `new_*` constructors when you already know the wallet id
    /// (e.g. restoring from persistence).
    ///
    /// # Arguments
    /// * `master_xpub` - The master extended public key. Used only to derive the
    ///   wallet id; not retained.
    /// * `accounts` - Pre-created account collections. Since these wallet types
    ///   cannot derive private keys, all accounts must be provided with their
    ///   extended public keys already initialized.
    /// * `can_sign_externally` - If true, builds an externally signable wallet
    ///   (signing delegated to a hardware device or remote signer). If false,
    ///   builds a pure watch-only wallet.
    pub fn from_xpub(
        master_xpub: ExtendedPubKey,
        accounts: AccountCollection,
        can_sign_externally: bool,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let wallet_id = Self::compute_wallet_id_from_root_extended_pub_key(
            &root_extended_public_key,
            Some(master_xpub.network),
        );
        let wallet = if can_sign_externally {
            Self::new_external_signable(master_xpub.network, wallet_id, accounts)
        } else {
            Self::new_watch_only(master_xpub.network, wallet_id, accounts)
        };
        Ok(wallet)
    }

    /// Create an external signable wallet from an extended public key.
    ///
    /// Thin adapter around [`Wallet::new_external_signable`] that derives the
    /// wallet id from `master_xpub`. The xpub itself is not retained.
    ///
    /// # Arguments
    /// * `master_xpub` - The master extended public key. Used only to derive the
    ///   wallet id; not retained.
    /// * `accounts` - Pre-created account collections with xpubs from the
    ///   external signing device.
    pub fn from_external_signable(
        master_xpub: ExtendedPubKey,
        accounts: AccountCollection,
    ) -> Result<Self> {
        let root_extended_public_key = RootExtendedPubKey::from_extended_pub_key(&master_xpub);
        let wallet_id = Self::compute_wallet_id_from_root_extended_pub_key(
            &root_extended_public_key,
            Some(master_xpub.network),
        );
        Ok(Self::new_external_signable(master_xpub.network, wallet_id, accounts))
    }

    /// Create a wallet from seed bytes
    ///
    /// # Arguments
    /// * `seed` - The seed bytes
    /// * `network` - Network to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_seed(
        seed: Seed,
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::new_master(seed.as_slice())?;

        let mut wallet = Self::from_wallet_type(
            network,
            WalletType::Seed {
                seed,
                root_extended_private_key,
            },
        );

        wallet.create_accounts_from_options(account_creation_options.clone())?;

        Ok(wallet)
    }

    /// Create a wallet from seed bytes array
    ///
    /// # Arguments
    /// * `seed_bytes` - The seed bytes array
    /// * `network` - Network to create accounts for
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_seed_bytes(
        seed_bytes: [u8; 64],
        network: Network,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        Self::from_seed(Seed::new(seed_bytes), network, account_creation_options)
    }

    /// Create a wallet from an extended private key
    ///
    /// # Arguments
    /// * `master_key` - The extended private key
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    pub fn from_extended_key(
        master_key: ExtendedPrivKey,
        account_creation_options: WalletAccountCreationOptions,
    ) -> Result<Self> {
        let root_extended_private_key = RootExtendedPrivKey::from_extended_priv_key(&master_key);
        let mut wallet = Self::from_wallet_type(
            master_key.network,
            WalletType::ExtendedPrivKey(root_extended_private_key),
        );

        wallet.create_accounts_from_options(account_creation_options.clone())?;

        Ok(wallet)
    }
}
