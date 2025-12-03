//! High-level wallet management
//!
//! This module provides a high-level interface for managing multiple wallets,
//! each of which can have multiple accounts. This follows the architecture
//! pattern where a manager oversees multiple distinct wallets.

mod process_block;
mod transaction_building;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use dashcore::blockdata::transaction::Transaction;
use dashcore::{BlockHash, Txid};
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::{ManagedWalletInfo, TransactionRecord};
use key_wallet::wallet::WalletType;
use key_wallet::{Account, AccountType, Address, ExtendedPrivKey, Mnemonic, Network, Wallet};
use key_wallet::{ExtendedPubKey, WalletBalance};
use key_wallet::{Utxo, UtxoSet};
use std::collections::BTreeSet;
use std::str::FromStr;
use zeroize::Zeroize;

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

/// Network-specific state for the wallet manager
#[derive(Debug)]
pub struct NetworkState {
    /// UTXO set for this network
    pub utxo_set: UtxoSet,
    /// Transaction history for this network
    pub transactions: BTreeMap<Txid, TransactionRecord>,
    /// Current block height for this network
    pub current_height: u32,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkState {
    /// Create a new network state
    pub fn new() -> Self {
        Self {
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
            current_height: 0,
        }
    }
}

/// High-level wallet manager that manages multiple wallets
///
/// Each wallet can contain multiple accounts following BIP44 standard.
/// This is the main entry point for wallet operations.
#[derive(Debug)]
pub struct WalletManager<T: WalletInfoInterface = ManagedWalletInfo> {
    /// Immutable wallets indexed by wallet ID
    pub(crate) wallets: BTreeMap<WalletId, Wallet>,
    /// Mutable wallet info indexed by wallet ID
    pub(crate) wallet_infos: BTreeMap<WalletId, T>,
    /// Network-specific state (UTXO sets, transactions, heights)
    network_states: BTreeMap<Network, NetworkState>,
    /// Filter match cache (per network) - caches whether a filter matched
    /// This is used for SPV operations to avoid rechecking filters
    filter_matches: BTreeMap<Network, BTreeMap<BlockHash, Vec<[u8; 32]>>>,
}

impl<T: WalletInfoInterface> Default for WalletManager<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: WalletInfoInterface> WalletManager<T> {
    /// Create a new wallet manager
    pub fn new() -> Self {
        Self {
            wallets: BTreeMap::new(),
            wallet_infos: BTreeMap::new(),
            network_states: BTreeMap::new(),
            filter_matches: BTreeMap::new(),
        }
    }

    /// Create a new wallet from mnemonic and add it to the manager
    /// Returns the computed wallet ID
    pub fn create_wallet_from_mnemonic(
        &mut self,
        mnemonic: &str,
        passphrase: &str,
        networks: &[Network],
        birth_height: Option<u32>,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
    ) -> Result<WalletId, WalletError> {
        let mnemonic_obj = Mnemonic::from_phrase(mnemonic, key_wallet::mnemonic::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        // Use appropriate wallet creation method based on whether a passphrase is provided
        let wallet = if passphrase.is_empty() {
            Wallet::from_mnemonic(mnemonic_obj, networks, account_creation_options)
                .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        } else {
            // For wallets with passphrase, use the provided options
            Wallet::from_mnemonic_with_passphrase(
                mnemonic_obj,
                passphrase.to_string(),
                networks,
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
        let mut managed_info = T::from_wallet(&wallet);
        managed_info.set_birth_height(birth_height);
        managed_info.set_first_loaded_at(current_timestamp());

        // The wallet already has accounts created according to the provided options
        // No need to manually add accounts here since that's handled by from_mnemonic/from_mnemonic_with_passphrase
        let wallet_mut = wallet.clone();

        // Add the account to managed info and generate initial addresses
        // Note: Address generation would need to be done through proper derivation from the account's xpub
        // For now, we'll just store the wallet with the account ready

        self.wallets.insert(wallet_id, wallet_mut);
        self.wallet_infos.insert(wallet_id, managed_info);
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
    /// * `networks` - The networks for the wallet
    /// * `birth_height` - Optional birth height for wallet scanning
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
        networks: &[Network],
        birth_height: Option<u32>,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
        downgrade_to_pubkey_wallet: bool,
        allow_external_signing: bool,
    ) -> Result<(Vec<u8>, WalletId), WalletError> {
        let mnemonic_obj = Mnemonic::from_phrase(mnemonic, key_wallet::mnemonic::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        // Create the initial wallet from mnemonic
        let mut wallet = if passphrase.is_empty() {
            Wallet::from_mnemonic(mnemonic_obj, networks, account_creation_options)
                .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        } else {
            Wallet::from_mnemonic_with_passphrase(
                mnemonic_obj,
                passphrase.to_string(),
                networks,
                account_creation_options,
            )
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        };

        // Downgrade to pubkey-only wallet if requested
        let final_wallet = if downgrade_to_pubkey_wallet {
            // Extract the public key and accounts from the full wallet
            let root_xpub = wallet.root_extended_pub_key();

            // Copy the accounts structure (but without private keys)
            let accounts = wallet.accounts.clone();

            let wallet_type = if allow_external_signing {
                WalletType::ExternalSignable(root_xpub)
            } else {
                WalletType::WatchOnly(root_xpub)
            };
            // Create a new wallet with only public keys
            let pubkey_wallet = Wallet {
                wallet_id: wallet.wallet_id,
                wallet_type,
                accounts,
            };

            // Zeroize the wallet containing private keys before dropping
            wallet.zeroize();
            drop(wallet);

            pubkey_wallet
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
        let mut managed_info = T::from_wallet(&final_wallet);
        managed_info.set_birth_height(birth_height);
        managed_info.set_first_loaded_at(current_timestamp());

        self.wallets.insert(wallet_id, final_wallet);
        self.wallet_infos.insert(wallet_id, managed_info);

        Ok((serialized_bytes, wallet_id))
    }

    /// Create a new wallet with a random mnemonic and add it to the manager
    /// Returns the generated wallet ID
    pub fn create_wallet_with_random_mnemonic(
        &mut self,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
        network: Network,
    ) -> Result<WalletId, WalletError> {
        // Generate a random mnemonic (24 words for maximum security)
        let mnemonic =
            Mnemonic::generate(24, key_wallet::mnemonic::Language::English).map_err(|e| {
                WalletError::WalletCreation(format!("Failed to generate mnemonic: {}", e))
            })?;

        let wallet = Wallet::from_mnemonic(mnemonic, &[network], account_creation_options)
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info
        let mut managed_info = T::from_wallet(&wallet);
        let network_state = self.get_or_create_network_state(network);
        managed_info.set_birth_height(Some(network_state.current_height));
        managed_info.set_first_loaded_at(current_timestamp());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        Ok(wallet_id)
    }

    /// Get a wallet by ID
    pub fn get_wallet(&self, wallet_id: &WalletId) -> Option<&Wallet> {
        self.wallets.get(wallet_id)
    }

    /// Get wallet info by ID
    pub fn get_wallet_info(&self, wallet_id: &WalletId) -> Option<&T> {
        self.wallet_infos.get(wallet_id)
    }

    /// Get mutable wallet info by ID
    pub fn get_wallet_info_mut(&mut self, wallet_id: &WalletId) -> Option<&mut T> {
        self.wallet_infos.get_mut(wallet_id)
    }

    /// Get both wallet and info by ID
    pub fn get_wallet_and_info(&self, wallet_id: &WalletId) -> Option<(&Wallet, &T)> {
        match (self.wallets.get(wallet_id), self.wallet_infos.get(wallet_id)) {
            (Some(wallet), Some(info)) => Some((wallet, info)),
            _ => None,
        }
    }

    /// Remove a wallet
    pub fn remove_wallet(&mut self, wallet_id: &WalletId) -> Result<(Wallet, T), WalletError> {
        let wallet =
            self.wallets.remove(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let info =
            self.wallet_infos.remove(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        Ok((wallet, info))
    }

    /// List all wallet IDs
    pub fn list_wallets(&self) -> Vec<&WalletId> {
        self.wallets.keys().collect()
    }

    /// Get all wallets
    pub fn get_all_wallets(&self) -> &BTreeMap<WalletId, Wallet> {
        &self.wallets
    }

    /// Get all wallet infos
    pub fn get_all_wallet_infos(&self) -> &BTreeMap<WalletId, T> {
        &self.wallet_infos
    }

    /// Get wallet count
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Import a wallet from an extended private key and add it to the manager
    ///
    /// # Arguments
    /// * `xprv` - The extended private key string (base58check encoded)
    /// * `network` - Network for the wallet
    /// * `account_creation_options` - Specifies which accounts to create during initialization
    ///
    /// # Returns
    /// * `Ok(WalletId)` - The computed wallet ID
    /// * `Err(WalletError)` - If the wallet already exists or creation fails
    pub fn import_wallet_from_extended_priv_key(
        &mut self,
        xprv: &str,
        network: Network,
        account_creation_options: key_wallet::wallet::initialization::WalletAccountCreationOptions,
    ) -> Result<WalletId, WalletError> {
        // Parse the extended private key
        let extended_priv_key = ExtendedPrivKey::from_str(xprv)
            .map_err(|e| WalletError::InvalidParameter(format!("Invalid xprv: {}", e)))?;

        // Create wallet from extended private key
        let wallet =
            Wallet::from_extended_key(extended_priv_key, &[network], account_creation_options)
                .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        // Compute wallet ID from the wallet's root public key
        let wallet_id = wallet.compute_wallet_id();

        // Check if wallet already exists
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // Create managed wallet info
        let mut managed_info = T::from_wallet(&wallet);
        managed_info
            .set_birth_height(Some(self.get_or_create_network_state(network).current_height));
        managed_info.set_first_loaded_at(current_timestamp());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        Ok(wallet_id)
    }

    /// Import a wallet from an extended public key and add it to the manager
    ///
    /// This creates a watch-only wallet that can monitor addresses and transactions
    /// but cannot sign them.
    ///
    /// # Arguments
    /// * `xpub` - The extended public key string (base58check encoded)
    /// * `network` - Network for the wallet
    /// * `can_sign_externally` - If true, creates an externally signable wallet (e.g., for hardware wallets).
    ///   If false, creates a pure watch-only wallet.
    ///
    /// # Returns
    /// * `Ok(WalletId)` - The computed wallet ID
    /// * `Err(WalletError)` - If the wallet already exists or creation fails
    pub fn import_wallet_from_xpub(
        &mut self,
        xpub: &str,
        network: Network,
        can_sign_externally: bool,
    ) -> Result<WalletId, WalletError> {
        // Parse the extended public key
        let extended_pub_key = ExtendedPubKey::from_str(xpub)
            .map_err(|e| WalletError::InvalidParameter(format!("Invalid xpub: {}", e)))?;

        // Create an empty account collection for the watch-only wallet
        let accounts = alloc::collections::BTreeMap::from([(network, Default::default())]);

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
        let mut managed_info = T::from_wallet(&wallet);
        managed_info
            .set_birth_height(Some(self.get_or_create_network_state(network).current_height));
        managed_info.set_first_loaded_at(current_timestamp());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
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

        // Create managed wallet info from the imported wallet
        let mut managed_info = T::from_wallet(&wallet);

        // Use the current network's height as the birth height since we don't know when it was originally created
        if let Some(network) = wallet.accounts.keys().next() {
            let network_state = self.get_or_create_network_state(*network);
            managed_info.set_birth_height(Some(network_state.current_height));
        }
        managed_info.set_first_loaded_at(current_timestamp());

        self.wallets.insert(wallet_id, wallet);
        self.wallet_infos.insert(wallet_id, managed_info);
        Ok(wallet_id)
    }

    /// Check a transaction against all wallets and update their states if relevant
    pub async fn check_transaction_in_all_wallets(
        &mut self,
        tx: &Transaction,
        network: Network,
        context: TransactionContext,
        update_state_if_found: bool,
    ) -> Vec<WalletId> {
        let mut relevant_wallets = Vec::new();

        // We need to iterate carefully since we're mutating
        let wallet_ids: Vec<WalletId> = self.wallets.keys().cloned().collect();

        for wallet_id in wallet_ids {
            // Get mutable references to both wallet and wallet_info
            // We need to use split borrowing to get around Rust's borrow checker
            let wallet_opt = self.wallets.get_mut(&wallet_id);
            let wallet_info_opt = self.wallet_infos.get_mut(&wallet_id);

            if let (Some(wallet), Some(wallet_info)) = (wallet_opt, wallet_info_opt) {
                let result = wallet_info
                    .check_transaction(tx, network, context, wallet, update_state_if_found)
                    .await;

                // If the transaction is relevant
                if result.is_relevant {
                    relevant_wallets.push(wallet_id);
                    // Note: balance update is already handled in check_transaction
                }
            }
        }

        // If any wallet found the transaction relevant, and we're updating state,
        // add it to the network's transaction history
        if !relevant_wallets.is_empty() && update_state_if_found {
            let txid = tx.txid();

            // Determine the height and confirmation status based on context
            let (height, _is_chain_locked) = match context {
                TransactionContext::Mempool => (None, false),
                TransactionContext::InBlock {
                    height,
                    ..
                } => (Some(height), false),
                TransactionContext::InChainLockedBlock {
                    height,
                    ..
                } => (Some(height), true),
            };

            let record = TransactionRecord {
                transaction: tx.clone(),
                txid,
                height,
                block_hash: None, // Could be added as a parameter if needed
                timestamp: current_timestamp(),
                net_amount: 0, // This would need to be calculated per wallet
                fee: None,
                label: None,
                is_ours: true,
            };

            let network_state = self.get_or_create_network_state(network);
            network_state.transactions.insert(txid, record);
        }

        relevant_wallets
    }

    /// Create an account in a specific wallet
    /// Note: The index parameter is kept for convenience, even though AccountType contains it
    pub fn create_account(
        &mut self,
        wallet_id: &WalletId,
        account_type: AccountType,
        network: Network,
        account_xpub: Option<ExtendedPubKey>,
    ) -> Result<(), WalletError> {
        let wallet =
            self.wallets.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        wallet
            .add_account(account_type, network, account_xpub)
            .map_err(|e| WalletError::AccountCreation(e.to_string()))
    }

    /// Get all accounts in a specific wallet
    pub fn get_accounts(&self, wallet_id: &WalletId) -> Result<Vec<&Account>, WalletError> {
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        Ok(wallet.all_accounts())
    }

    /// Get account by index in a specific wallet
    pub fn get_account(
        &self,
        wallet_id: &WalletId,
        index: u32,
    ) -> Result<Option<&Account>, WalletError> {
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Try to find the account in any network
        for network in wallet.accounts.keys() {
            if let Some(account) = wallet.get_bip44_account(*network, index) {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    /// Get receive address from a specific wallet and account
    pub fn get_receive_address(
        &mut self,
        wallet_id: &WalletId,
        network: Network,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Result<AddressGenerationResult, WalletError> {
        // Get the wallet account to access the xpub
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Get the account collection for the network
        let collection = managed_info.accounts_mut(network).ok_or(WalletError::InvalidNetwork)?;

        // Try to get address based on preference
        let (address_opt, account_type_used) = match account_type_pref {
            AccountTypePreference::BIP44 => {
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip44_accounts.get_mut(&account_index),
                    wallet.get_bip44_account(network, account_index),
                ) {
                    match managed_account
                        .next_receive_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            AccountTypePreference::BIP32 => {
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip32_accounts.get_mut(&account_index),
                    wallet.get_bip32_account(network, account_index),
                ) {
                    match managed_account
                        .next_receive_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            AccountTypePreference::PreferBIP44 => {
                // Try BIP44 first
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip44_accounts.get_mut(&account_index),
                    wallet.get_bip44_account(network, account_index),
                ) {
                    match managed_account
                        .next_receive_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => {
                            // Fallback to BIP32
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip32_accounts.get_mut(&account_index),
                                wallet.get_bip32_account(network, account_index),
                            ) {
                                match managed_account
                                    .next_receive_address(Some(&wallet_account.account_xpub), true)
                                {
                                    Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                                    Err(_) => (None, None),
                                }
                            } else {
                                (None, None)
                            }
                        }
                    }
                } else if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip32_accounts.get_mut(&account_index),
                    wallet.get_bip32_account(network, account_index),
                ) {
                    match managed_account
                        .next_receive_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            AccountTypePreference::PreferBIP32 => {
                // Try BIP32 first
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip32_accounts.get_mut(&account_index),
                    wallet.get_bip32_account(network, account_index),
                ) {
                    match managed_account
                        .next_receive_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => {
                            // Fallback to BIP44
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip44_accounts.get_mut(&account_index),
                                wallet.get_bip44_account(network, account_index),
                            ) {
                                match managed_account
                                    .next_receive_address(Some(&wallet_account.account_xpub), true)
                                {
                                    Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                                    Err(_) => (None, None),
                                }
                            } else {
                                (None, None)
                            }
                        }
                    }
                } else if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip44_accounts.get_mut(&account_index),
                    wallet.get_bip44_account(network, account_index),
                ) {
                    match managed_account
                        .next_receive_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
        };

        // Mark the address as used if requested
        if let Some(ref address) = address_opt {
            if mark_as_used {
                // Get the account collection again for marking
                if let Some(collection) = managed_info.accounts_mut(network) {
                    // Mark address as used in the appropriate account type
                    match account_type_used {
                        Some(AccountTypeUsed::BIP44) => {
                            if let Some(account) =
                                collection.standard_bip44_accounts.get_mut(&account_index)
                            {
                                account.mark_address_used(address);
                            }
                        }
                        Some(AccountTypeUsed::BIP32) => {
                            if let Some(account) =
                                collection.standard_bip32_accounts.get_mut(&account_index)
                            {
                                account.mark_address_used(address);
                            }
                        }
                        None => {}
                    }
                }
            }
        }

        Ok(AddressGenerationResult {
            address: address_opt,
            account_type_used,
        })
    }

    /// Get change address from a specific wallet and account
    pub fn get_change_address(
        &mut self,
        wallet_id: &WalletId,
        network: Network,
        account_index: u32,
        account_type_pref: AccountTypePreference,
        mark_as_used: bool,
    ) -> Result<AddressGenerationResult, WalletError> {
        // Get the wallet account to access the xpub
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Get the account collection for the network
        let collection = managed_info.accounts_mut(network).ok_or(WalletError::InvalidNetwork)?;

        // Try to get address based on preference
        let (address_opt, account_type_used) = match account_type_pref {
            AccountTypePreference::BIP44 => {
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip44_accounts.get_mut(&account_index),
                    wallet.get_bip44_account(network, account_index),
                ) {
                    match managed_account
                        .next_change_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            AccountTypePreference::BIP32 => {
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip32_accounts.get_mut(&account_index),
                    wallet.get_bip32_account(network, account_index),
                ) {
                    match managed_account
                        .next_change_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            AccountTypePreference::PreferBIP44 => {
                // Try BIP44 first
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip44_accounts.get_mut(&account_index),
                    wallet.get_bip44_account(network, account_index),
                ) {
                    match managed_account
                        .next_change_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => {
                            // Fallback to BIP32
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip32_accounts.get_mut(&account_index),
                                wallet.get_bip32_account(network, account_index),
                            ) {
                                match managed_account
                                    .next_change_address(Some(&wallet_account.account_xpub), true)
                                {
                                    Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                                    Err(_) => (None, None),
                                }
                            } else {
                                (None, None)
                            }
                        }
                    }
                } else if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip32_accounts.get_mut(&account_index),
                    wallet.get_bip32_account(network, account_index),
                ) {
                    match managed_account
                        .next_change_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
            AccountTypePreference::PreferBIP32 => {
                // Try BIP32 first
                if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip32_accounts.get_mut(&account_index),
                    wallet.get_bip32_account(network, account_index),
                ) {
                    match managed_account
                        .next_change_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => {
                            // Fallback to BIP44
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip44_accounts.get_mut(&account_index),
                                wallet.get_bip44_account(network, account_index),
                            ) {
                                match managed_account
                                    .next_change_address(Some(&wallet_account.account_xpub), true)
                                {
                                    Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                                    Err(_) => (None, None),
                                }
                            } else {
                                (None, None)
                            }
                        }
                    }
                } else if let (Some(managed_account), Some(wallet_account)) = (
                    collection.standard_bip44_accounts.get_mut(&account_index),
                    wallet.get_bip44_account(network, account_index),
                ) {
                    match managed_account
                        .next_change_address(Some(&wallet_account.account_xpub), true)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            }
        };

        // Mark the address as used if requested
        if let Some(ref address) = address_opt {
            if mark_as_used {
                // Get the account collection again for marking
                if let Some(collection) = managed_info.accounts_mut(network) {
                    // Mark address as used in the appropriate account type
                    match account_type_used {
                        Some(AccountTypeUsed::BIP44) => {
                            if let Some(account) =
                                collection.standard_bip44_accounts.get_mut(&account_index)
                            {
                                account.mark_address_used(address);
                            }
                        }
                        Some(AccountTypeUsed::BIP32) => {
                            if let Some(account) =
                                collection.standard_bip32_accounts.get_mut(&account_index)
                            {
                                account.mark_address_used(address);
                            }
                        }
                        None => {}
                    }
                }
            }
        }

        Ok(AddressGenerationResult {
            address: address_opt,
            account_type_used,
        })
    }

    /// Get transaction history for all wallets across all networks
    pub fn transaction_history(&self) -> Vec<&TransactionRecord> {
        let mut all_txs = Vec::new();
        for network_state in self.network_states.values() {
            all_txs.extend(network_state.transactions.values());
        }
        all_txs
    }

    /// Get transaction history for a specific wallet
    pub fn wallet_transaction_history(
        &self,
        wallet_id: &WalletId,
    ) -> Result<Vec<&TransactionRecord>, WalletError> {
        let managed_info =
            self.wallet_infos.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        Ok(managed_info.transaction_history())
    }

    /// Get UTXOs for all wallets across all networks
    pub fn get_all_utxos(&self) -> Vec<&Utxo> {
        let mut all_utxos = Vec::new();
        for network_state in self.network_states.values() {
            all_utxos.extend(network_state.utxo_set.all());
        }
        all_utxos
    }

    /// Get UTXOs for a specific wallet
    pub fn wallet_utxos(&self, wallet_id: &WalletId) -> Result<BTreeSet<&Utxo>, WalletError> {
        // Get the wallet info
        let wallet_info =
            self.wallet_infos.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Get UTXOs from the wallet info and clone them
        let utxos = wallet_info.utxos();

        Ok(utxos)
    }

    /// Get total balance across all wallets and networks
    pub fn get_total_balance(&self) -> u64 {
        self.network_states.values().map(|state| state.utxo_set.total_balance()).sum()
    }

    /// Get balance for a specific wallet
    pub fn get_wallet_balance(&self, wallet_id: &WalletId) -> Result<WalletBalance, WalletError> {
        // Get the wallet info
        let wallet_info =
            self.wallet_infos.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Get balance from the wallet info
        Ok(wallet_info.balance())
    }

    /// Update the cached balance for a specific wallet
    pub fn update_wallet_balance(&mut self, wallet_id: &WalletId) -> Result<(), WalletError> {
        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        managed_info.update_balance();
        Ok(())
    }

    /// Update wallet metadata
    pub fn update_wallet_metadata(
        &mut self,
        wallet_id: &WalletId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<(), WalletError> {
        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        if let Some(new_name) = name {
            managed_info.set_name(new_name);
        }

        if let Some(desc) = description {
            managed_info.set_description(Some(desc));
        }

        managed_info.update_last_synced(current_timestamp());

        Ok(())
    }

    /// Get current block height for a specific network
    pub fn current_height(&self, network: Network) -> u32 {
        self.network_states.get(&network).map(|state| state.current_height).unwrap_or(0)
    }

    /// Update current block height for a specific network
    pub fn update_height(&mut self, network: Network, height: u32) {
        let state = self.get_or_create_network_state(network);
        state.current_height = height;
    }

    /// Get or create network state for a specific network
    pub(crate) fn get_or_create_network_state(&mut self, network: Network) -> &mut NetworkState {
        self.network_states.entry(network).or_default()
    }

    /// Get network state for a specific network (public for SPVWalletManager)
    pub fn get_network_state(&self, network: Network) -> Option<&NetworkState> {
        self.network_states.get(&network)
    }

    /// Get mutable network state for a specific network (public for SPVWalletManager)
    pub fn get_network_state_mut(&mut self, network: Network) -> Option<&mut NetworkState> {
        self.network_states.get_mut(&network)
    }

    /// Get monitored addresses for all wallets for a specific network
    pub fn monitored_addresses(&self, network: Network) -> Vec<Address> {
        let mut addresses = Vec::new();
        for info in self.wallet_infos.values() {
            addresses.extend(info.monitored_addresses(network));
        }
        addresses
    }
}

/// Wallet manager errors
#[derive(Debug)]
pub enum WalletError {
    /// Wallet creation failed
    WalletCreation(String),
    /// Wallet not found
    WalletNotFound(WalletId),
    /// Wallet already exists
    WalletExists(WalletId),
    /// Invalid mnemonic
    InvalidMnemonic(String),
    /// Account creation failed
    AccountCreation(String),
    /// Account not found
    AccountNotFound(u32),
    /// Address generation failed
    AddressGeneration(String),
    /// Invalid network
    InvalidNetwork,
    /// Invalid parameter
    InvalidParameter(String),
    /// Transaction building failed
    TransactionBuild(String),
    /// Insufficient funds
    InsufficientFunds,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::WalletCreation(msg) => write!(f, "Wallet creation failed: {}", msg),
            WalletError::WalletNotFound(id) => {
                write!(f, "Wallet not found: ")?;
                for byte in id.iter() {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
            WalletError::WalletExists(id) => {
                write!(f, "Wallet already exists: ")?;
                for byte in id.iter() {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
            WalletError::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {}", msg),
            WalletError::AccountCreation(msg) => write!(f, "Account creation failed: {}", msg),
            WalletError::AccountNotFound(idx) => write!(f, "Account not found: {}", idx),
            WalletError::AddressGeneration(msg) => write!(f, "Address generation failed: {}", msg),
            WalletError::InvalidNetwork => write!(f, "Invalid network"),
            WalletError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            WalletError::TransactionBuild(err) => write!(f, "Transaction build failed: {}", err),
            WalletError::InsufficientFunds => write!(f, "Insufficient funds"),
        }
    }
}

/// Helper function for getting current timestamp
fn current_timestamp() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    #[cfg(not(feature = "std"))]
    {
        0 // In no_std environment, timestamp would need to be provided externally
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WalletError {}

/// Conversion from key_wallet::Error to WalletError
impl From<key_wallet::Error> for WalletError {
    fn from(err: key_wallet::Error) -> Self {
        use key_wallet::Error;

        match err {
            Error::InvalidMnemonic(msg) => WalletError::InvalidMnemonic(msg),
            Error::InvalidDerivationPath(msg) => {
                WalletError::InvalidParameter(format!("Invalid derivation path: {}", msg))
            }
            Error::InvalidAddress(msg) => {
                WalletError::AddressGeneration(format!("Invalid address: {}", msg))
            }
            Error::InvalidNetwork => WalletError::InvalidNetwork,
            Error::InvalidParameter(msg) => WalletError::InvalidParameter(msg),
            Error::WatchOnly => WalletError::InvalidParameter(
                "Operation not supported on watch-only wallet".to_string(),
            ),
            Error::CoinJoinNotEnabled => {
                WalletError::InvalidParameter("CoinJoin not enabled".to_string())
            }
            Error::KeyError(msg) => WalletError::AccountCreation(format!("Key error: {}", msg)),
            Error::Serialization(msg) => {
                WalletError::InvalidParameter(format!("Serialization error: {}", msg))
            }
            Error::Bip32(e) => WalletError::AccountCreation(format!("BIP32 error: {}", e)),
            Error::Secp256k1(e) => WalletError::AccountCreation(format!("Secp256k1 error: {}", e)),
            Error::Base58 => WalletError::InvalidParameter("Base58 decoding error".to_string()),
            Error::NoKeySource => {
                WalletError::InvalidParameter("No key source available".to_string())
            }
            #[allow(unreachable_patterns)]
            _ => WalletError::InvalidParameter(format!("Key wallet error: {}", err)),
        }
    }
}
