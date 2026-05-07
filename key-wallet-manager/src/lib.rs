/// Re-export key-wallet so consumers can access wallet primitives through this crate.
pub use key_wallet;

/// High-level wallet management for Dash
///
/// This module provides high-level wallet functionality that builds on top of
/// the low-level primitives in `key-wallet`
///
/// ## Features
///
/// - Multiple wallet management
/// - BIP 157/158 compact block filter support
/// - Address generation and gap limit handling
/// - Blockchain synchronization
mod accessors;
mod error;
mod events;
mod matching;
mod process_block;
mod wallet_interface;

pub use error::WalletError;
pub use events::{DerivedAddress, WalletEvent};
pub use matching::{check_compact_filters_for_addresses, FilterMatchKey};
pub use wallet_interface::{BlockProcessingResult, MempoolTransactionResult, WalletInterface};

use dashcore::blockdata::transaction::Transaction;
use dashcore::prelude::CoreBlockHeight;
use key_wallet::account::AccountCollection;
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::transaction_checking::{DerivedAddressInfo, TransactionContext};
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{AccountType, Address, ExtendedPrivKey, Mnemonic, Network, Wallet};
use key_wallet::{ExtendedPubKey, WalletCoreBalance};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use dashcore::address::NetworkUnchecked;
use key_wallet::wallet::managed_wallet_info::fee::FeeRate;
use tokio::sync::broadcast;

/// Default capacity for the wallet event bus.
const DEFAULT_WALLET_EVENT_CAPACITY: usize = 1000;

/// Unique identifier for a wallet (32-byte hash)
pub type WalletId = [u8; 32];

/// Unique identifier for an account within a wallet
pub type AccountId = u32;

/// The actual account type that was used for address generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountTypeUsed {
    /// BIP44 account was used
    BIP44,
    /// BIP32 account was used
    BIP32,
}

/// Result of address generation
#[derive(Debug, Clone)]
pub struct AddressGenerationResult {
    /// The generated address, if successful
    pub address: Option<Address>,
    /// The account type that was used (if an address was generated)
    pub account_type_used: Option<AccountTypeUsed>,
}

/// Result of checking a transaction against all wallets
#[derive(Debug, Clone, Default)]
pub struct CheckTransactionsResult {
    /// Wallets that found the transaction relevant
    pub affected_wallets: Vec<WalletId>,
    /// Set to false if the transaction was already stored and is being re-processed (e.g., during rescan)
    pub is_new_transaction: bool,
    /// Addresses derived during gap-limit maintenance, attributed to the
    /// wallet that produced them. Each entry carries the originating
    /// account type, pool type, and full
    /// [`AddressInfo`](key_wallet::managed_account::address_pool::AddressInfo)
    /// so downstream emitters can attribute the derivation precisely without
    /// re-deriving.
    pub new_addresses: BTreeMap<WalletId, Vec<DerivedAddressInfo>>,
    /// Total value received across all wallets
    pub total_received: u64,
    /// Total value sent across all wallets
    pub total_sent: u64,
    /// Addresses involved across all wallets
    pub involved_addresses: Vec<Address>,
    /// Records newly recorded by this check, grouped by wallet.
    pub per_wallet_new_records: BTreeMap<WalletId, Vec<TransactionRecord>>,
    /// Records whose state was updated by this check (confirmation or
    /// InstantSend lock on a previously stored record), grouped by wallet.
    pub per_wallet_updated_records: BTreeMap<WalletId, Vec<TransactionRecord>>,
}

impl CheckTransactionsResult {
    /// Iterate over every newly derived [`DerivedAddressInfo`] regardless of
    /// wallet attribution.
    pub(crate) fn all_new_address_infos(&self) -> impl Iterator<Item = &DerivedAddressInfo> {
        self.new_addresses.values().flatten()
    }

    /// Iterate over every newly derived address regardless of wallet
    /// attribution. The richer [`DerivedAddressInfo`] is available via
    /// [`Self::all_new_address_infos`].
    pub(crate) fn all_new_addresses(&self) -> impl Iterator<Item = &Address> {
        self.all_new_address_infos().map(|d| &d.info.address)
    }
}

/// High-level wallet manager that manages multiple wallets
///
/// Each wallet can contain multiple accounts following BIP44 standard.
/// This is the main entry point for wallet operations.
#[derive(Debug)]
pub struct WalletManager<T: WalletInfoInterface + Send + Sync + 'static = ManagedWalletInfo> {
    /// Network the managed wallets are used for
    network: Network,
    /// Immutable wallets indexed by wallet ID
    wallets: BTreeMap<WalletId, Wallet>,
    /// Mutable wallet info indexed by wallet ID
    wallet_infos: BTreeMap<WalletId, T>,
    /// Structural revision counter incremented when wallets or accounts are
    /// added/removed. Combined with per-wallet account-level revisions to
    /// produce the total monitor revision.
    structural_revision: u64,
    /// Event sender for wallet events
    event_sender: broadcast::Sender<WalletEvent>,
}

impl<T: WalletInfoInterface + Send + Sync + 'static> WalletManager<T> {
    /// Create a new wallet manager
    pub fn new(network: Network) -> Self {
        Self {
            network,
            wallets: BTreeMap::new(),
            wallet_infos: BTreeMap::new(),
            structural_revision: 0,
            event_sender: broadcast::Sender::new(DEFAULT_WALLET_EVENT_CAPACITY),
        }
    }

    /// Increment the structural revision for wallet/account additions or removals.
    fn bump_structural_revision(&mut self) {
        self.structural_revision += 1;
    }

    /// Create a new wallet from mnemonic and add it to the manager
    /// Returns the computed wallet ID
    pub fn create_wallet_from_mnemonic(
        &mut self,
        mnemonic: &str,
        passphrase: &str,
        birth_height: CoreBlockHeight,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
    ) -> Result<WalletId, WalletError> {
        let mnemonic_obj = Mnemonic::from_phrase(mnemonic, key_wallet::mnemonic::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        // Use appropriate wallet creation method based on whether a passphrase is provided
        let wallet = if passphrase.is_empty() {
            Wallet::from_mnemonic(mnemonic_obj, self.network, account_creation_options)
                .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        } else {
            // For wallets with passphrase, use the provided options
            Wallet::from_mnemonic_with_passphrase(
                mnemonic_obj,
                passphrase.to_string(),
                self.network,
                account_creation_options,
            )
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        };

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info from the wallet to properly initialize accounts
        // This ensures the ManagedAccountCollection is synchronized with the Wallet's accounts
        let managed_info = T::from_wallet(&wallet, birth_height);

        // The wallet already has accounts created according to the provided options
        // No need to manually add accounts here since that's handled by from_mnemonic/from_mnemonic_with_passphrase
        let wallet_mut = wallet.clone();

        // Add the account to managed info and generate initial addresses
        // Note: Address generation would need to be done through proper derivation from the account's xpub
        // For now, we'll just store the wallet with the account ready

        self.wallets.insert(wallet_id, wallet_mut);
        self.wallet_infos.insert(wallet_id, managed_info);
        self.bump_structural_revision();
        Ok(wallet_id)
    }

    /// Create a wallet from mnemonic and return it as serialized bytes
    ///
    /// This function creates a wallet from a mnemonic phrase and returns it as bincode-serialized bytes.
    /// It supports downgrading to a public-key-only wallet for security purposes.
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase
    /// * `passphrase` - Optional BIP39 passphrase (empty string for no passphrase)
    /// * `birth_height` - Birth height for wallet scanning (0 to sync from genesis)
    /// * `account_creation_options` - Which accounts to create initially
    /// * `downgrade_to_pubkey_wallet` - If true, creates a wallet without private keys
    /// * `allow_external_signing` - If true and downgraded, creates an externally signable wallet (e.g., for hardware wallets)
    ///
    /// # Returns
    /// A tuple containing:
    /// * The serialized wallet bytes
    /// * The wallet ID
    ///
    /// # Security Note
    /// When `downgrade_to_pubkey_wallet` is true, the returned wallet contains NO private key material,
    /// making it safe to use on potentially compromised systems or for creating watch-only wallets.
    #[cfg(feature = "bincode")]
    #[allow(clippy::too_many_arguments)]
    pub fn create_wallet_from_mnemonic_return_serialized_bytes(
        &mut self,
        mnemonic: &str,
        passphrase: &str,
        birth_height: CoreBlockHeight,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
        downgrade_to_pubkey_wallet: bool,
        allow_external_signing: bool,
    ) -> Result<(Vec<u8>, WalletId), WalletError> {
        use zeroize::Zeroize;

        let mnemonic_obj = Mnemonic::from_phrase(mnemonic, key_wallet::mnemonic::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        // Create the initial wallet from mnemonic
        let mut wallet = if passphrase.is_empty() {
            Wallet::from_mnemonic(mnemonic_obj, self.network, account_creation_options)
                .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        } else {
            Wallet::from_mnemonic_with_passphrase(
                mnemonic_obj,
                passphrase.to_string(),
                self.network,
                account_creation_options,
            )
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        };

        // Downgrade to pubkey-only wallet if requested
        let final_wallet = if downgrade_to_pubkey_wallet {
            // Carry over the wallet id and accounts (watch-only variants do not
            // need the root xpub — per-account xpubs in `accounts` plus derivation
            // paths are enough for address generation and signing routing).
            let wallet_id = wallet.wallet_id;
            let accounts = wallet.accounts.clone();
            let network = wallet.network;

            // Zeroize the wallet containing private keys before dropping
            wallet.zeroize();
            drop(wallet);

            if allow_external_signing {
                Wallet::new_external_signable(network, wallet_id, accounts)
            } else {
                Wallet::new_watch_only(network, wallet_id, accounts)
            }
        } else {
            wallet
        };

        // Compute wallet ID
        let wallet_id = final_wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Serialize the wallet to bytes
        let serialized_bytes = bincode::encode_to_vec(&final_wallet, bincode::config::standard())
            .map_err(|e| {
            WalletError::InvalidParameter(format!("Failed to serialize wallet: {}", e))
        })?;

        // Add the wallet to the manager
        let managed_info = T::from_wallet(&final_wallet, birth_height);

        self.wallets.insert(wallet_id, final_wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        self.bump_structural_revision();

        Ok((serialized_bytes, wallet_id))
    }

    /// Create a new wallet with a random mnemonic and add it to the manager
    /// Returns the generated wallet ID
    pub fn create_wallet_with_random_mnemonic(
        &mut self,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
    ) -> Result<WalletId, WalletError> {
        // Generate a random mnemonic (24 words for maximum security)
        let mnemonic =
            Mnemonic::generate(24, key_wallet::mnemonic::Language::English).map_err(|e| {
                WalletError::WalletCreation(format!("Failed to generate mnemonic: {}", e))
            })?;

        let wallet = Wallet::from_mnemonic(mnemonic, self.network, account_creation_options)
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info
        let managed_info = T::from_wallet(&wallet, self.last_processed_height());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        self.bump_structural_revision();
        Ok(wallet_id)
    }

    /// Import a wallet from an extended private key and add it to the manager
    ///
    /// # Arguments
    /// * `xprv` - The extended private key string (base58check encoded)
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    ///
    /// # Returns
    /// * `Ok(WalletId)` - The computed wallet ID
    /// * `Err(WalletError)` - If the wallet already exists or creation fails
    pub fn import_wallet_from_extended_priv_key(
        &mut self,
        xprv: &str,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
    ) -> Result<WalletId, WalletError> {
        // Parse the extended private key
        let extended_priv_key = ExtendedPrivKey::from_str(xprv)
            .map_err(|e| WalletError::InvalidParameter(format!("Invalid xprv: {}", e)))?;

        // Create wallet from extended private key
        let wallet = Wallet::from_extended_key(extended_priv_key, account_creation_options)
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info
        let managed_info = T::from_wallet(&wallet, self.last_processed_height());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        self.bump_structural_revision();
        Ok(wallet_id)
    }

    /// Import a wallet from an extended public key and add it to the manager
    ///
    /// This creates a watch-only wallet that can monitor addresses and transactions
    /// but cannot sign them.
    ///
    /// # Arguments
    /// * `xpub` - The extended public key string (base58check encoded)
    /// * `can_sign_externally` - If true, creates an externally signable wallet (e.g., for hardware wallets).
    ///   If false, creates a pure watch-only wallet.
    ///
    /// # Returns
    /// * `Ok(WalletId)` - The computed wallet ID
    /// * `Err(WalletError)` - If the wallet already exists or creation fails
    pub fn import_wallet_from_xpub(
        &mut self,
        xpub: &str,
        can_sign_externally: bool,
    ) -> Result<WalletId, WalletError> {
        // Parse the extended public key
        let extended_pub_key = ExtendedPubKey::from_str(xpub)
            .map_err(|e| WalletError::InvalidParameter(format!("Invalid xpub: {}", e)))?;

        // Create an empty account collection for the watch-only wallet
        let accounts = AccountCollection::default();

        // Create watch-only or externally signable wallet from extended public key
        let wallet = Wallet::from_xpub(extended_pub_key, accounts, can_sign_externally)
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info
        let managed_info = T::from_wallet(&wallet, self.last_processed_height());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        self.bump_structural_revision();
        Ok(wallet_id)
    }

    /// Import a wallet from serialized bytes
    ///
    /// Deserializes a wallet from bincode-encoded bytes and adds it to the manager.
    /// This is useful for restoring wallets from backups or transferring wallets
    /// between systems.
    ///
    /// # Arguments
    /// * `wallet_bytes` - The bincode-serialized wallet bytes
    ///
    /// # Returns
    /// * `Ok(WalletId)` - The computed wallet ID of the imported wallet
    /// * `Err(WalletError)` - If deserialization fails or the wallet already exists
    #[cfg(feature = "bincode")]
    pub fn import_wallet_from_bytes(
        &mut self,
        wallet_bytes: &[u8],
    ) -> Result<WalletId, WalletError> {
        // Deserialize the wallet from bincode
        let wallet: Wallet = bincode::decode_from_slice(wallet_bytes, bincode::config::standard())
            .map_err(|e| {
                WalletError::InvalidParameter(format!("Failed to deserialize wallet: {}", e))
            })?
            .0;

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info from the imported wallet, using the manager's
        // current aggregated last-processed height as the fallback birth height
        // since the serialized form does not preserve it.
        let managed_info = T::from_wallet(&wallet, self.last_processed_height());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        self.bump_structural_revision();
        Ok(wallet_id)
    }

    /// Check a transaction against all wallets and update their states if relevant.
    ///
    /// Collects — but does not emit — the per-wallet records affected by the
    /// check. Callers are responsible for emitting the appropriate
    /// `WalletEvent` *after* refreshing wallet balances so events never
    /// carry a stale balance.
    pub async fn check_transaction_in_all_wallets(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        update_state_if_found: bool,
        update_balance: bool,
    ) -> CheckTransactionsResult {
        let wallet_ids: BTreeSet<WalletId> = self.wallets.keys().cloned().collect();
        self.check_transaction_in_wallets(
            tx,
            context,
            &wallet_ids,
            update_state_if_found,
            update_balance,
        )
        .await
    }

    /// Check a transaction against the given subset of wallets and update their states if relevant.
    pub(crate) async fn check_transaction_in_wallets(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        wallet_ids: &BTreeSet<WalletId>,
        update_state_if_found: bool,
        update_balance: bool,
    ) -> CheckTransactionsResult {
        let mut result = CheckTransactionsResult::default();

        for wallet_id in wallet_ids {
            // Get mutable references to both wallet and wallet_info
            // We need to use split borrowing to get around Rust's borrow checker
            let wallet_opt = self.wallets.get_mut(wallet_id);
            let wallet_info_opt = self.wallet_infos.get_mut(wallet_id);

            if let (Some(wallet), Some(wallet_info)) = (wallet_opt, wallet_info_opt) {
                let check_result = wallet_info
                    .check_core_transaction(
                        tx,
                        context.clone(),
                        wallet,
                        update_state_if_found,
                        update_balance,
                    )
                    .await;

                if check_result.is_relevant {
                    result.affected_wallets.push(*wallet_id);
                    if check_result.is_new_transaction {
                        result.is_new_transaction = true;
                    }

                    result.total_received =
                        result.total_received.saturating_add(check_result.total_received);
                    result.total_sent = result.total_sent.saturating_add(check_result.total_sent);
                    for account_match in &check_result.affected_accounts {
                        for addr_info in account_match.account_type_match.all_involved_addresses() {
                            result.involved_addresses.push(addr_info.address);
                        }
                    }

                    if !check_result.new_records.is_empty() {
                        result
                            .per_wallet_new_records
                            .entry(*wallet_id)
                            .or_default()
                            .extend(check_result.new_records);
                    }
                    if !check_result.updated_records.is_empty() {
                        result
                            .per_wallet_updated_records
                            .entry(*wallet_id)
                            .or_default()
                            .extend(check_result.updated_records);
                    }
                }

                if !check_result.new_addresses.is_empty() {
                    result
                        .new_addresses
                        .entry(*wallet_id)
                        .or_default()
                        .extend(check_result.new_addresses);
                }
            }
        }

        result
    }

    /// Create an account in a specific wallet
    /// Note: The index parameter is kept for convenience, even though AccountType contains it
    pub fn create_account(
        &mut self,
        wallet_id: &WalletId,
        account_type: AccountType,
        account_xpub: Option<ExtendedPubKey>,
    ) -> Result<(), WalletError> {
        let wallet =
            self.wallets.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        wallet
            .add_account(account_type, account_xpub)
            .map_err(|e| WalletError::AccountCreation(e.to_string()))?;

        self.bump_structural_revision();
        Ok(())
    }
}

impl WalletManager<ManagedWalletInfo> {
    /// Get receive address from a specific wallet and account
    pub fn next_receive_address(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Option<Address> {
        // Get the wallet account to access the xpub
        let (wallet, managed_info) = self.get_wallet_and_info_mut(wallet_id)?;

        managed_info.next_receive_address(wallet, account_index, account_type_pref, mark_as_used)
    }

    /// Get change address from a specific wallet and account
    pub fn next_change_address(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Option<Address> {
        // Get the wallet account to access the xpub
        let (wallet, managed_info) = self.get_wallet_and_info_mut(wallet_id)?;

        managed_info.next_change_address(wallet, account_index, account_type_pref, mark_as_used)
    }

    pub async fn build_and_sign_transaction(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
    ) -> Result<(Transaction, u64), WalletError> {
        // Get the managed account for UTXOs and signing data
        let (wallet, managed_wallet) = self
            .get_wallet_and_info_mut(wallet_id)
            .ok_or(WalletError::WalletNotFound(*wallet_id))?;

        managed_wallet
            .build_and_sign_transaction(wallet, account_index, outputs, fee_rate)
            .await
            .map_err(|e| WalletError::TransactionBuild(e.to_string()))
    }
}

/// Helper function for getting current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod event_tests;
#[cfg(test)]
mod test_helpers;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
