//! High-level wallet management
//!
//! This module provides a high-level interface for managing multiple wallets,
//! each of which can have multiple accounts. This follows the architecture
//! pattern where a manager oversees multiple distinct wallets.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use dashcore::blockdata::transaction::Transaction;
use dashcore_hashes::Hash;
use key_wallet::{Account, AccountType, Address, Mnemonic, Network, Wallet, WalletConfig};

use crate::fee::FeeLevel;
use crate::utxo::{Utxo, UtxoSet};

/// Unique identifier for a wallet
pub type WalletId = String;

/// Unique identifier for an account within a wallet
pub type AccountId = u32;

/// High-level wallet manager that manages multiple wallets
///
/// Each wallet can contain multiple accounts following BIP44 standard.
/// This is the main entry point for wallet operations.
pub struct WalletManager {
    /// All managed wallets indexed by wallet ID
    wallets: BTreeMap<WalletId, ManagedWallet>,
    /// Global UTXO set across all wallets
    utxo_set: UtxoSet,
    /// Global transaction history
    transactions: BTreeMap<[u8; 32], TransactionRecord>,
    /// Current block height
    current_height: u32,
    /// Default network for new wallets
    default_network: Network,
}

/// A managed wallet with its metadata and state
#[derive(Debug, Clone)]
pub struct ManagedWallet {
    /// The underlying wallet instance
    pub wallet: Wallet,
    /// Wallet metadata
    pub metadata: WalletMetadata,
    /// Per-wallet UTXO set
    pub utxo_set: UtxoSet,
    /// Per-wallet transaction history
    pub transactions: BTreeMap<[u8; 32], TransactionRecord>,
}

/// Metadata for a managed wallet
#[derive(Debug, Clone)]
pub struct WalletMetadata {
    /// Wallet identifier
    pub id: WalletId,
    /// Human-readable name
    pub name: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used: u64,
    /// Network this wallet operates on
    pub network: Network,
    /// Whether this wallet is watch-only
    pub is_watch_only: bool,
    /// Optional description
    pub description: Option<String>,
}

/// Transaction record
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    /// The transaction
    pub transaction: Transaction,
    /// Block height (if confirmed)
    pub height: Option<u32>,
    /// Timestamp
    pub timestamp: u64,
    /// Net amount for wallet
    pub net_amount: i64,
    /// Fee paid (if known)
    pub fee: Option<u64>,
    /// Transaction label
    pub label: Option<String>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub fn new(default_network: Network) -> Self {
        Self {
            wallets: BTreeMap::new(),
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
            current_height: 0,
            default_network,
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
    ) -> Result<&ManagedWallet, WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        let network = network.unwrap_or(self.default_network);

        let mnemonic_obj = Mnemonic::from_phrase(mnemonic, key_wallet::mnemonic::Language::English)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

        let wallet = Wallet::from_mnemonic_with_passphrase(
            mnemonic_obj,
            passphrase.to_string(),
            WalletConfig::default(),
            network,
        )
        .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        let metadata = WalletMetadata {
            id: wallet_id.clone(),
            name,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_used: 0,
            network,
            is_watch_only: false,
            description: None,
        };

        let managed_wallet = ManagedWallet {
            wallet,
            metadata,
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
        };

        self.wallets.insert(wallet_id.clone(), managed_wallet);
        Ok(self.wallets.get(&wallet_id).unwrap())
    }

    /// Create a new empty wallet and add it to the manager
    pub fn create_wallet(
        &mut self,
        wallet_id: WalletId,
        name: String,
        network: Option<Network>,
    ) -> Result<&ManagedWallet, WalletError> {
        if self.wallets.contains_key(&wallet_id) {
            return Err(WalletError::WalletExists(wallet_id));
        }

        let network = network.unwrap_or(self.default_network);

        let wallet = Wallet::new_random(WalletConfig::default(), network)
            .map_err(|e| WalletError::WalletCreation(e.to_string()))?;

        let metadata = WalletMetadata {
            id: wallet_id.clone(),
            name,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_used: 0,
            network,
            is_watch_only: false,
            description: None,
        };

        let managed_wallet = ManagedWallet {
            wallet,
            metadata,
            utxo_set: UtxoSet::new(),
            transactions: BTreeMap::new(),
        };

        self.wallets.insert(wallet_id.clone(), managed_wallet);
        Ok(self.wallets.get(&wallet_id).unwrap())
    }

    /// Get a wallet by ID
    pub fn get_wallet(&self, wallet_id: &WalletId) -> Option<&ManagedWallet> {
        self.wallets.get(wallet_id)
    }

    /// Get a mutable wallet by ID
    pub fn get_wallet_mut(&mut self, wallet_id: &WalletId) -> Option<&mut ManagedWallet> {
        self.wallets.get_mut(wallet_id)
    }

    /// Remove a wallet
    pub fn remove_wallet(&mut self, wallet_id: &WalletId) -> Result<ManagedWallet, WalletError> {
        self.wallets.remove(wallet_id).ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))
    }

    /// List all wallet IDs
    pub fn list_wallets(&self) -> Vec<&WalletId> {
        self.wallets.keys().collect()
    }

    /// Get all wallets
    pub fn get_all_wallets(&self) -> &BTreeMap<WalletId, ManagedWallet> {
        &self.wallets
    }

    /// Get wallet count
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Create an account in a specific wallet
    pub fn create_account(
        &mut self,
        wallet_id: &WalletId,
        index: u32,
        account_type: AccountType,
    ) -> Result<(), WalletError> {
        let wallet = self
            .wallets
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        wallet
            .wallet
            .add_account(index, account_type, wallet.metadata.network)
            .map_err(|e| WalletError::AccountCreation(e.to_string()))?;

        // Update last used timestamp
        wallet.metadata.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }

    /// Get all accounts in a specific wallet
    pub fn get_accounts(&self, wallet_id: &WalletId) -> Result<Vec<&Account>, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        let _network = wallet.metadata.network;
        Ok(wallet.wallet.all_accounts())
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

        let network = wallet.metadata.network;
        Ok(wallet.wallet.get_account(network, index))
    }

    /// Get receive address from a specific wallet and account
    /// NOTE: This method is temporarily disabled due to the Account/ManagedAccount refactoring.
    /// Address generation now requires ManagedAccount which holds mutable state.
    pub fn get_receive_address(
        &mut self,
        _wallet_id: &WalletId,
        _account_index: u32,
    ) -> Result<Address, WalletError> {
        // TODO: Implement ManagedAccount integration for address generation
        Err(WalletError::AddressGeneration(
            "Address generation requires ManagedAccount integration".to_string(),
        ))
    }

    /// Get change address from a specific wallet and account
    /// NOTE: This method is temporarily disabled due to the Account/ManagedAccount refactoring.
    /// Address generation now requires ManagedAccount which holds mutable state.
    pub fn get_change_address(
        &mut self,
        _wallet_id: &WalletId,
        _account_index: u32,
    ) -> Result<Address, WalletError> {
        // TODO: Implement ManagedAccount integration for address generation
        Err(WalletError::AddressGeneration(
            "Address generation requires ManagedAccount integration".to_string(),
        ))
    }

    /// Send transaction from a specific wallet and account
    pub fn send_transaction(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
    ) -> Result<Transaction, WalletError> {
        // Get change address first
        let change_address = self.get_change_address(wallet_id, account_index)?;

        let wallet = self
            .wallets
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Get the account
        let network = wallet.metadata.network;
        let _account = wallet
            .wallet
            .get_account(network, account_index)
            .ok_or(WalletError::AccountNotFound(account_index))?;
        // TODO: Get addresses from ManagedAccount once integrated
        let account_addresses: Vec<Address> = Vec::new();

        // Filter UTXOs for this account
        let account_utxos: Vec<&Utxo> = wallet.utxo_set.for_address(&change_address);

        // TODO: Fix transaction building once ManagedAccount is integrated
        return Err(WalletError::TransactionBuild(
            "Transaction building needs ManagedAccount integration".to_string(),
        ));
        #[allow(unreachable_code)]
        let tx: Transaction =
            unimplemented!("Transaction building needs ManagedAccount integration");

        // Record transaction
        let txid = tx.txid();
        let record = TransactionRecord {
            transaction: tx.clone(),
            height: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            net_amount: -(recipients.iter().map(|(_, amount)| *amount as i64).sum::<i64>()),
            fee: None, // TODO: Calculate actual fee
            label: None,
        };

        wallet.transactions.insert(txid.to_byte_array(), record.clone());
        self.transactions.insert(txid.to_byte_array(), record);

        // Update last used timestamp
        wallet.metadata.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(tx)
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
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        Ok(wallet.transactions.values().collect())
    }

    /// Add UTXO to a specific wallet
    pub fn add_utxo(&mut self, wallet_id: &WalletId, utxo: Utxo) -> Result<(), WalletError> {
        let wallet = self
            .wallets
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        wallet.utxo_set.add(utxo.clone());
        self.utxo_set.add(utxo); // Also add to global set

        Ok(())
    }

    /// Get UTXOs for all wallets
    pub fn get_all_utxos(&self) -> Vec<&Utxo> {
        self.utxo_set.all()
    }

    /// Get UTXOs for a specific wallet
    pub fn get_wallet_utxos(&self, wallet_id: &WalletId) -> Result<Vec<&Utxo>, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        Ok(wallet.utxo_set.all())
    }

    /// Get total balance across all wallets
    pub fn get_total_balance(&self) -> u64 {
        self.utxo_set.total_balance()
    }

    /// Get balance for a specific wallet
    pub fn get_wallet_balance(&self, wallet_id: &WalletId) -> Result<u64, WalletError> {
        let wallet = self
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        Ok(wallet.utxo_set.total_balance())
    }

    /// Update wallet metadata
    pub fn update_wallet_metadata(
        &mut self,
        wallet_id: &WalletId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<(), WalletError> {
        let wallet = self
            .wallets
            .get_mut(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        if let Some(new_name) = name {
            wallet.metadata.name = new_name;
        }

        wallet.metadata.description = description;
        wallet.metadata.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WalletError {}
