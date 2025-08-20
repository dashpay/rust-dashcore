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
use dashcore::Txid;
use key_wallet::wallet::managed_wallet_info::{ManagedWalletInfo, TransactionRecord};
use key_wallet::WalletBalance;
use key_wallet::{Account, AccountType, Address, Mnemonic, Network, Wallet, WalletConfig};
use std::collections::BTreeSet;

use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::{Utxo, UtxoSet};

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
        }
    }

    /// Create a new wallet from mnemonic and add it to the manager
    pub fn create_wallet_from_mnemonic(
        &mut self,
        wallet_id: WalletId,
        name: String,
        mnemonic: &str,
        passphrase: &str,
        network: Option<Network>,
        birth_height: Option<u32>,
    ) -> Result<&T, WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        let network = network
            .ok_or(WalletError::InvalidParameter("Network must be specified".to_string()))?;

        let mnemonic_obj = Mnemonic::from_phrase(mnemonic, key_wallet::mnemonic::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        // Use appropriate wallet creation method based on whether a passphrase is provided
        let wallet = if passphrase.is_empty() {
            Wallet::from_mnemonic(
                mnemonic_obj,
                WalletConfig::default(),
                network,
                key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
            )
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        } else {
            // For wallets with passphrase, use None since they can't derive accounts without the passphrase
            Wallet::from_mnemonic_with_passphrase(
                mnemonic_obj,
                passphrase.to_string(),
                WalletConfig::default(),
                network,
                key_wallet::wallet::initialization::WalletAccountCreationOptions::None,
            )
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?
        };

        // Create managed wallet info from the wallet to properly initialize accounts
        // This ensures the ManagedAccountCollection is synchronized with the Wallet's accounts
        let mut managed_info = T::from_wallet_with_name(&wallet, name);
        managed_info.set_birth_height(birth_height);
        managed_info.set_first_loaded_at(current_timestamp());

        // Create default account in the wallet
        // Skip account creation for wallets with passphrases as they need the passphrase to derive accounts
        let mut wallet_mut = wallet.clone();
        if !passphrase.is_empty() {
            // For wallets with passphrase, accounts can't be created without the passphrase
            // The wallet is already set up correctly with WalletAccountCreationOptions::None
        } else {
            if wallet_mut.get_bip44_account(network, 0).is_none() {
                use key_wallet::account::StandardAccountType;
                let account_type = AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                };
                wallet_mut
                    .add_account(account_type, network, None)
                    .map_err(|e| WalletError::AccountCreation(e.to_string()))?;
            }

            let _account = wallet_mut.get_bip44_account(network, 0).ok_or_else(|| {
                WalletError::AccountCreation("Failed to get default account".to_string())
            })?;
        }

        // Add the account to managed info and generate initial addresses
        // Note: Address generation would need to be done through proper derivation from the account's xpub
        // For now, we'll just store the wallet with the account ready

        self.wallets.insert(wallet_id, wallet_mut);
        self.wallet_infos.insert(wallet_id, managed_info);
        Ok(self.wallet_infos.get(&wallet_id).unwrap())
    }

    /// Create a new empty wallet and add it to the manager
    pub fn create_wallet(
        &mut self,
        wallet_id: WalletId,
        name: String,
        network: Network,
    ) -> Result<&T, WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        // For now, create a wallet with a fixed test mnemonic
        // In production, you'd generate a random mnemonic or use new_random with proper features
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic =
            Mnemonic::from_phrase(test_mnemonic, key_wallet::mnemonic::Language::English)
                .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        let wallet = Wallet::from_mnemonic(
            mnemonic,
            WalletConfig::default(),
            network,
            key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        // Create managed wallet info
        let mut managed_info = T::with_name(wallet.wallet_id, name);
        let network_state = self.get_or_create_network_state(network);
        managed_info.set_birth_height(Some(network_state.current_height));
        managed_info.set_first_loaded_at(current_timestamp());

        // Check if account 0 already exists (from_mnemonic might create it)
        let mut wallet_mut = wallet.clone();
        if wallet_mut.get_bip44_account(network, 0).is_none() {
            use key_wallet::account::StandardAccountType;
            let account_type = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            wallet_mut
                .add_account(account_type, network, None)
                .map_err(|e| WalletError::AccountCreation(e.to_string()))?;
        }

        // Note: Address generation would need to be done through proper derivation from the account's xpub
        // The ManagedAccount in managed_info will track the addresses

        self.wallets.insert(wallet_id, wallet_mut);
        self.wallet_infos.insert(wallet_id, managed_info);
        Ok(self.wallet_infos.get(&wallet_id).unwrap())
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

    /// Check a transaction against all wallets and update their states if relevant
    pub fn check_transaction_in_all_wallets(
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
            // Check the transaction for this wallet
            if let Some(wallet_info) = self.wallet_infos.get_mut(&wallet_id) {
                let result =
                    wallet_info.check_transaction(tx, network, context, update_state_if_found);

                // If the transaction is relevant
                if result.is_relevant {
                    relevant_wallets.push(wallet_id);
                    // Note: balance update is already handled in check_transaction when update_state_if_found is true
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
        index: u32,
        account_type: AccountType,
    ) -> Result<(), WalletError> {
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;
        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Clone wallet to mutate it
        let mut wallet_mut = wallet.clone();
        // Get the network from the wallet's accounts or require it to be passed
        let network = wallet.accounts.keys().next().copied().ok_or(
            WalletError::InvalidParameter("No network available for account creation".to_string()),
        )?;

        wallet_mut
            .add_account(account_type, network, None)
            .map_err(|e| WalletError::AccountCreation(e.to_string()))?;

        // Get the created account to verify it was created
        let _account = wallet_mut.get_bip44_account(network, index).ok_or_else(|| {
            WalletError::AccountCreation("Failed to get created account".to_string())
        })?;

        // Update wallet
        self.wallets.insert(*wallet_id, wallet_mut);

        // Update metadata
        managed_info.update_last_synced(current_timestamp());

        Ok(())
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
                        .get_next_receive_address(&wallet_account.account_xpub, network)
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
                        .get_next_receive_address(&wallet_account.account_xpub, network)
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
                        .get_next_receive_address(&wallet_account.account_xpub, network)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => {
                            // Fallback to BIP32
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip32_accounts.get_mut(&account_index),
                                wallet.get_bip32_account(network, account_index),
                            ) {
                                match managed_account
                                    .get_next_receive_address(&wallet_account.account_xpub, network)
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
                        .get_next_receive_address(&wallet_account.account_xpub, network)
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
                        .get_next_receive_address(&wallet_account.account_xpub, network)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => {
                            // Fallback to BIP44
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip44_accounts.get_mut(&account_index),
                                wallet.get_bip44_account(network, account_index),
                            ) {
                                match managed_account
                                    .get_next_receive_address(&wallet_account.account_xpub, network)
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
                        .get_next_receive_address(&wallet_account.account_xpub, network)
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
                        .get_next_change_address(&wallet_account.account_xpub, network)
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
                        .get_next_change_address(&wallet_account.account_xpub, network)
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
                        .get_next_change_address(&wallet_account.account_xpub, network)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP44)),
                        Err(_) => {
                            // Fallback to BIP32
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip32_accounts.get_mut(&account_index),
                                wallet.get_bip32_account(network, account_index),
                            ) {
                                match managed_account
                                    .get_next_change_address(&wallet_account.account_xpub, network)
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
                        .get_next_change_address(&wallet_account.account_xpub, network)
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
                        .get_next_change_address(&wallet_account.account_xpub, network)
                    {
                        Ok(addr) => (Some(addr), Some(AccountTypeUsed::BIP32)),
                        Err(_) => {
                            // Fallback to BIP44
                            if let (Some(managed_account), Some(wallet_account)) = (
                                collection.standard_bip44_accounts.get_mut(&account_index),
                                wallet.get_bip44_account(network, account_index),
                            ) {
                                match managed_account
                                    .get_next_change_address(&wallet_account.account_xpub, network)
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
                        .get_next_change_address(&wallet_account.account_xpub, network)
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
