//! High-level wallet management
//!
//! This module provides a high-level interface for managing multiple wallets,
//! each of which can have multiple accounts. This follows the architecture
//! pattern where a manager oversees multiple distinct wallets.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::PublicKey;
use dashcore::Txid;
use key_wallet::wallet::managed_wallet_info::{ManagedWalletInfo, TransactionRecord};
use key_wallet::WalletBalance;
use key_wallet::{
    Account, AccountType, Address, DerivationPath, ExtendedPubKey, Mnemonic, Network, Wallet,
    WalletConfig,
};
use secp256k1::Secp256k1;

use crate::fee::FeeLevel;
use key_wallet::{Utxo, UtxoSet};

/// Unique identifier for a wallet
pub type WalletId = String;

/// Unique identifier for an account within a wallet
pub type AccountId = u32;

/// High-level wallet manager that manages multiple wallets
///
/// Each wallet can contain multiple accounts following BIP44 standard.
/// This is the main entry point for wallet operations.
pub struct WalletManager {
    /// Immutable wallets indexed by wallet ID
    pub(crate) wallets: BTreeMap<WalletId, Wallet>,
    /// Mutable wallet info indexed by wallet ID
    pub(crate) wallet_infos: BTreeMap<WalletId, ManagedWalletInfo>,
    /// Global UTXO set across all wallets
    utxo_set: UtxoSet,
    /// Global transaction history
    transactions: BTreeMap<Txid, TransactionRecord>,
    /// Current block height
    current_height: u32,
    /// Default network for new wallets
    default_network: Network,
    /// Temporary wallet UTXOs storage (workaround for ManagedWalletInfo limitation)
    wallet_utxos: BTreeMap<WalletId, Vec<Utxo>>,
    /// Monitored addresses per wallet (temporary storage)
    pub(crate) monitored_addresses: BTreeMap<WalletId, BTreeSet<Address>>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub fn new(default_network: Network) -> Self {
        Self {
            wallets: BTreeMap::new(),
            wallet_infos: BTreeMap::new(),
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
            current_height: 0,
            default_network,
            wallet_utxos: BTreeMap::new(),
            monitored_addresses: BTreeMap::new(),
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
    ) -> Result<&ManagedWalletInfo, WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        let network = network.unwrap_or(self.default_network);

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

        // Create managed wallet info
        let mut managed_info = ManagedWalletInfo::with_name(wallet.wallet_id, name);
        managed_info.metadata.birth_height = birth_height;
        managed_info.metadata.first_loaded_at = current_timestamp();

        // Create default account in the wallet
        let mut wallet_mut = wallet.clone();
        if wallet_mut.get_account(network, 0).is_none() {
            use key_wallet::account::StandardAccountType;
            let account_type = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            wallet_mut
                .add_account(account_type, network, None)
                .map_err(|e| WalletError::AccountCreation(e.to_string()))?;
        }

        let account = wallet_mut.get_account(network, 0).ok_or_else(|| {
            WalletError::AccountCreation("Failed to get default account".to_string())
        })?;

        // Add the account to managed info and generate initial addresses
        // Note: Address generation would need to be done through proper derivation from the account's xpub
        // For now, we'll just store the wallet with the account ready

        self.wallets.insert(wallet_id.clone(), wallet_mut);
        self.wallet_infos.insert(wallet_id.clone(), managed_info);
        Ok(self.wallet_infos.get(&wallet_id).unwrap())
    }

    /// Create a new empty wallet and add it to the manager
    pub fn create_wallet(
        &mut self,
        wallet_id: WalletId,
        name: String,
        network: Option<Network>,
    ) -> Result<&ManagedWalletInfo, WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        let network = network.unwrap_or(self.default_network);

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
        let mut managed_info = ManagedWalletInfo::with_name(wallet.wallet_id, name);
        managed_info.metadata.birth_height = Some(self.current_height);
        managed_info.metadata.first_loaded_at = current_timestamp();

        // Check if account 0 already exists (from_mnemonic might create it)
        let mut wallet_mut = wallet.clone();
        if wallet_mut.get_account(network, 0).is_none() {
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

        self.wallets.insert(wallet_id.clone(), wallet_mut);
        self.wallet_infos.insert(wallet_id.clone(), managed_info);
        Ok(self.wallet_infos.get(&wallet_id).unwrap())
    }

    /// Get a wallet by ID
    pub fn get_wallet(&self, wallet_id: &WalletId) -> Option<&Wallet> {
        self.wallets.get(wallet_id)
    }

    /// Get wallet info by ID
    pub fn get_wallet_info(&self, wallet_id: &WalletId) -> Option<&ManagedWalletInfo> {
        self.wallet_infos.get(wallet_id)
    }

    /// Get mutable wallet info by ID
    pub fn get_wallet_info_mut(&mut self, wallet_id: &WalletId) -> Option<&mut ManagedWalletInfo> {
        self.wallet_infos.get_mut(wallet_id)
    }

    /// Get both wallet and info by ID
    pub fn get_wallet_and_info(
        &self,
        wallet_id: &WalletId,
    ) -> Option<(&Wallet, &ManagedWalletInfo)> {
        match (self.wallets.get(wallet_id), self.wallet_infos.get(wallet_id)) {
            (Some(wallet), Some(info)) => Some((wallet, info)),
            _ => None,
        }
    }

    /// Remove a wallet
    pub fn remove_wallet(
        &mut self,
        wallet_id: &WalletId,
    ) -> Result<(Wallet, ManagedWalletInfo), WalletError> {
        let wallet = self
            .wallets
            .remove(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;
        let info = self
            .wallet_infos
            .remove(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;
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
    pub fn get_all_wallet_infos(&self) -> &BTreeMap<WalletId, ManagedWalletInfo> {
        &self.wallet_infos
    }

    /// Get wallet count
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Create an account in a specific wallet
    /// Note: The index parameter is kept for convenience, even though AccountType contains it
    pub fn create_account(
        &mut self,
        wallet_id: &WalletId,
        index: u32,
        account_type: AccountType,
    ) -> Result<(), WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;
        let managed_info = self
            .wallet_infos
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Clone wallet to mutate it
        let mut wallet_mut = wallet.clone();
        let network = self.default_network;

        wallet_mut
            .add_account(account_type, network, None)
            .map_err(|e| WalletError::AccountCreation(e.to_string()))?;

        // Get the created account to verify it was created
        let _account = wallet_mut.get_account(network, index).ok_or_else(|| {
            WalletError::AccountCreation("Failed to get created account".to_string())
        })?;

        // Update wallet
        self.wallets.insert(wallet_id.clone(), wallet_mut);

        // Update metadata
        managed_info.update_last_synced(current_timestamp());

        Ok(())
    }

    /// Get all accounts in a specific wallet
    pub fn get_accounts(&self, wallet_id: &WalletId) -> Result<Vec<&Account>, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        Ok(wallet.all_accounts())
    }

    /// Get account by index in a specific wallet
    pub fn get_account(
        &self,
        wallet_id: &WalletId,
        index: u32,
    ) -> Result<Option<&Account>, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        Ok(wallet.get_account(self.default_network, index))
    }

    /// Get receive address from a specific wallet and account
    pub fn get_receive_address(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
    ) -> Result<Address, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;
        let managed_info = self
            .wallet_infos
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Get the account from the wallet
        let account = wallet
            .get_account(self.default_network, account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;

        // For now, we'll just derive the next address index
        // In a real implementation, we'd use the managed accounts properly

        // Find the next unused index for receive addresses
        let next_index = 0;

        // Derive the address from the account's xpub
        let address = derive_address_from_account(
            &account.account_xpub,
            false, // not change
            next_index,
            self.default_network,
        )?;

        // Track the address in the managed account's address pool
        // Note: AddressPool doesn't have a simple add method, so we need to track it differently
        // For now, just track in monitored addresses
        let path = DerivationPath::bip_44_payment_path(
            self.default_network,
            account_index,
            false,
            next_index,
        );
        managed_info.add_monitored_address(address.clone());
        self.add_monitored_address(&wallet_id, address.clone());

        Ok(address)
    }

    /// Get change address from a specific wallet and account
    pub fn get_change_address(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
    ) -> Result<Address, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;
        let managed_info = self
            .wallet_infos
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Get the account from the wallet
        let account = wallet
            .get_account(self.default_network, account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;

        // For now, we'll just derive the next address index
        // In a real implementation, we'd use the managed accounts properly

        // Find the next unused index for change addresses
        let next_index = 0;

        // Derive the address from the account's xpub
        let address = derive_address_from_account(
            &account.account_xpub,
            true, // is change
            next_index,
            self.default_network,
        )?;

        // Track the address in the managed account's address pool
        let path = DerivationPath::bip_44_payment_path(
            self.default_network,
            account_index,
            true,
            next_index,
        );
        managed_info.add_monitored_address(address.clone());
        self.add_monitored_address(&wallet_id, address.clone());

        Ok(address)
    }

    /// Send transaction from a specific wallet and account
    pub fn send_transaction(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
        recipients: Vec<(Address, u64)>,
        _fee_level: FeeLevel,
    ) -> Result<Transaction, WalletError> {
        // Get change address first
        let change_address = self.get_change_address(wallet_id, account_index)?;

        let managed_info = self
            .wallet_infos
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Get spendable UTXOs
        let utxos = managed_info.get_spendable_utxos();
        if utxos.is_empty() {
            return Err(WalletError::InsufficientFunds);
        }

        // Simple coin selection - just use first UTXOs that cover amount
        let total_needed: u64 = recipients.iter().map(|(_, amt)| amt).sum();
        let fee_estimate = 10000u64; // Fixed fee for now
        let mut selected_utxos = Vec::new();
        let mut total_input = 0u64;

        for utxo in utxos {
            if total_input >= total_needed + fee_estimate {
                break;
            }
            selected_utxos.push(utxo.clone());
            total_input += utxo.txout.value;
        }

        if total_input < total_needed + fee_estimate {
            return Err(WalletError::InsufficientFunds);
        }

        // Build transaction (simplified - would need proper implementation)
        // For now, return an error as we need proper transaction building
        return Err(WalletError::TransactionBuild(
            "Transaction building implementation needed".to_string(),
        ));

        #[allow(unreachable_code)]
        {
            let tx: Transaction = unimplemented!("Transaction building needs implementation");

            // Record transaction
            let txid = tx.txid();
            let record = TransactionRecord {
                transaction: tx.clone(),
                txid,
                height: None,
                block_hash: None,
                timestamp: current_timestamp(),
                net_amount: -(recipients.iter().map(|(_, amount)| *amount as i64).sum::<i64>()),
                fee: Some(fee_estimate),
                label: None,
                is_ours: true,
            };

            managed_info.add_transaction(record.clone());
            self.transactions.insert(txid, record);

            // Update last used timestamp
            managed_info.update_last_synced(current_timestamp());

            Ok(tx)
        }
    }

    /// Get transaction history for all wallets
    pub fn transaction_history(&self) -> Vec<&TransactionRecord> {
        self.transactions.values().collect()
    }

    /// Get transaction history for a specific wallet
    pub fn wallet_transaction_history(
        &self,
        wallet_id: &WalletId,
    ) -> Result<Vec<&TransactionRecord>, WalletError> {
        let managed_info = self
            .wallet_infos
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        Ok(managed_info.get_transaction_history())
    }

    /// Add UTXO to a specific wallet
    pub fn add_utxo(&mut self, wallet_id: &WalletId, utxo: Utxo) -> Result<(), WalletError> {
        // Verify wallet exists
        if !self.wallet_infos.contains_key(wallet_id) {
            return Err(WalletError::WalletNotFound(wallet_id.clone()));
        }

        // Store the UTXO directly
        let wallet_utxo = utxo.clone();

        // Store in our temporary storage
        self.wallet_utxos.entry(wallet_id.clone()).or_insert_with(Vec::new).push(wallet_utxo);

        self.utxo_set.add(utxo); // Also add to global set

        Ok(())
    }

    /// Get UTXOs for all wallets
    pub fn get_all_utxos(&self) -> Vec<&Utxo> {
        self.utxo_set.all()
    }

    /// Get UTXOs for a specific wallet
    pub fn get_wallet_utxos(&self, wallet_id: &WalletId) -> Result<Vec<Utxo>, WalletError> {
        // Verify wallet exists
        if !self.wallet_infos.contains_key(wallet_id) {
            return Err(WalletError::WalletNotFound(wallet_id.clone()));
        }

        // Get from our temporary storage
        let wallet_utxos = self.wallet_utxos.get(wallet_id);

        let utxos = if let Some(wallet_utxos) = wallet_utxos {
            wallet_utxos.iter().map(|wu| wu.clone()).collect()
        } else {
            Vec::new()
        };

        Ok(utxos)
    }

    /// Get total balance across all wallets
    pub fn get_total_balance(&self) -> u64 {
        self.utxo_set.total_balance()
    }

    /// Get balance for a specific wallet
    pub fn get_wallet_balance(&self, wallet_id: &WalletId) -> Result<WalletBalance, WalletError> {
        // Verify wallet exists
        if !self.wallet_infos.contains_key(wallet_id) {
            return Err(WalletError::WalletNotFound(wallet_id.clone()));
        }

        // Calculate balance from our temporary storage
        let wallet_utxos = self.wallet_utxos.get(wallet_id);

        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        let mut locked = 0u64;

        if let Some(utxos) = wallet_utxos {
            for utxo in utxos {
                let value = utxo.txout.value;
                if utxo.is_locked {
                    locked += value;
                } else if utxo.is_confirmed {
                    confirmed += value;
                } else {
                    unconfirmed += value;
                }
            }
        }

        WalletBalance::new(confirmed, unconfirmed, locked)
            .map_err(|_| WalletError::InvalidParameter("Balance overflow".to_string()))
    }

    /// Update the cached balance for a specific wallet
    pub fn update_wallet_balance(&mut self, wallet_id: &WalletId) -> Result<(), WalletError> {
        let managed_info = self
            .wallet_infos
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

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
        let managed_info = self
            .wallet_infos
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        if let Some(new_name) = name {
            managed_info.set_name(new_name);
        }

        if let Some(desc) = description {
            managed_info.set_description(desc);
        }

        managed_info.update_last_synced(current_timestamp());

        Ok(())
    }

    /// Get current block height
    pub fn current_height(&self) -> u32 {
        self.current_height
    }

    /// Update current block height
    pub fn update_height(&mut self, height: u32) {
        self.current_height = height;
    }

    /// Get default network
    pub fn default_network(&self) -> Network {
        self.default_network
    }

    /// Set default network
    pub fn set_default_network(&mut self, network: Network) {
        self.default_network = network;
    }

    /// Add a monitored address for a wallet
    pub fn add_monitored_address(&mut self, wallet_id: &WalletId, address: Address) {
        self.monitored_addresses
            .entry(wallet_id.clone())
            .or_insert_with(BTreeSet::new)
            .insert(address);
    }

    /// Get monitored addresses for a wallet
    pub fn get_monitored_addresses(&self, wallet_id: &WalletId) -> Vec<Address> {
        self.monitored_addresses
            .get(wallet_id)
            .map(|addrs| addrs.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get wallet UTXOs (temporary accessor)
    pub fn get_wallet_utxos_temp(&self, wallet_id: &WalletId) -> Vec<Utxo> {
        self.wallet_utxos.get(wallet_id).map(|utxos| utxos.clone()).unwrap_or_default()
    }

    /// Remove a spent UTXO from wallet storage
    pub fn remove_spent_utxo(&mut self, wallet_id: &WalletId, outpoint: &OutPoint) {
        if let Some(wallet_utxos) = self.wallet_utxos.get_mut(wallet_id) {
            wallet_utxos.retain(|u| u.outpoint != *outpoint);
        }
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
            WalletError::WalletNotFound(id) => write!(f, "Wallet not found: {}", id),
            WalletError::WalletExists(id) => write!(f, "Wallet already exists: {}", id),
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

/// Derive an address from an account's extended public key
fn derive_address_from_account(
    account_xpub: &ExtendedPubKey,
    is_change: bool,
    index: u32,
    network: Network,
) -> Result<Address, WalletError> {
    let secp = Secp256k1::new();

    // Derive change/receive branch (account xpub is already at m/44'/5'/account')
    let change_num = if is_change {
        1
    } else {
        0
    };
    let branch_xpub = account_xpub
        .derive_pub(&secp, &[key_wallet::ChildNumber::from_normal_idx(change_num).unwrap()])
        .map_err(|e| WalletError::AddressGeneration(format!("Failed to derive branch: {}", e)))?;

    // Derive the specific address index
    let address_xpub = branch_xpub
        .derive_pub(&secp, &[key_wallet::ChildNumber::from_normal_idx(index).unwrap()])
        .map_err(|e| WalletError::AddressGeneration(format!("Failed to derive address: {}", e)))?;

    // Convert to public key and create address
    let pubkey = PublicKey::from_slice(&address_xpub.public_key.serialize())
        .map_err(|e| WalletError::AddressGeneration(format!("Failed to create pubkey: {}", e)))?;

    Ok(Address::p2pkh(&pubkey, network))
}

#[cfg(feature = "std")]
impl std::error::Error for WalletError {}
