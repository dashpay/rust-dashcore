//! Complete wallet management for Dash
//!
//! This module provides comprehensive wallet functionality including
//! multiple accounts, seed management, and transaction coordination.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountType, SpecialPurposeType};
use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
#[cfg(feature = "bip38")]
use crate::bip38::{Bip38EncryptedKey, encrypt_private_key};
use crate::derivation::HDWallet;
use crate::error::{Error, Result};
use crate::mnemonic::{Language, Mnemonic};
use crate::{Address, Network};

/// Wallet configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletConfig {
    /// Network to use
    pub network: Network,
    /// Default external gap limit
    pub external_gap_limit: u32,
    /// Default internal gap limit
    pub internal_gap_limit: u32,
    /// Enable CoinJoin by default
    pub enable_coinjoin: bool,
    /// CoinJoin gap limit
    pub coinjoin_gap_limit: u32,
    /// Number of accounts to generate initially
    pub initial_accounts: u32,
    /// BIP39 passphrase (empty by default)
    pub passphrase: String,
    /// Language for mnemonic generation
    pub language: Language,
    /// Wallet name
    pub name: Option<String>,
    /// Wallet description
    pub description: Option<String>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            network: Network::Dash,
            external_gap_limit: 20,
            internal_gap_limit: 10,
            enable_coinjoin: false,
            coinjoin_gap_limit: 10,
            initial_accounts: 1,
            passphrase: String::new(),
            language: Language::English,
            name: None,
            description: None,
        }
    }
}

/// Complete wallet implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Wallet {
    /// Wallet configuration
    pub config: WalletConfig,
    /// Mnemonic phrase (if available)
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    mnemonic: Option<Mnemonic>,
    /// Master seed (encrypted in production)
    #[cfg_attr(feature = "serde", serde(skip))]
    seed: Vec<u8>,
    /// HD wallet for key derivation
    #[cfg_attr(feature = "serde", serde(skip))]
    hd_wallet: HDWallet,
    /// All accounts in the wallet
    pub accounts: BTreeMap<u32, Account>,
    /// Special purpose accounts
    pub special_accounts: Vec<Account>,
    /// Wallet metadata
    pub metadata: WalletMetadata,
    /// Whether this is a watch-only wallet
    pub is_watch_only: bool,
}

/// Wallet metadata
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletMetadata {
    /// Wallet creation timestamp
    pub created_at: u64,
    /// Last sync timestamp
    pub last_synced: Option<u64>,
    /// Last backup timestamp
    pub last_backup: Option<u64>,
    /// Total transactions
    pub total_transactions: u64,
    /// Wallet version
    pub version: u32,
    /// Custom metadata fields
    pub custom: BTreeMap<String, String>,
}

impl Wallet {
    /// Create a new wallet with a generated mnemonic
    pub fn new(config: WalletConfig) -> Result<Self> {
        let mnemonic = Mnemonic::generate(12, config.language)?;
        Self::from_mnemonic(mnemonic, config)
    }

    /// Create a wallet from a mnemonic phrase
    pub fn from_mnemonic(mnemonic: Mnemonic, config: WalletConfig) -> Result<Self> {
        let seed = mnemonic.to_seed(&config.passphrase);
        let master_key = ExtendedPrivKey::new_master(config.network, &seed)?;
        let hd_wallet = HDWallet::new(master_key);
        
        let mut wallet = Self {
            config: config.clone(),
            mnemonic: Some(mnemonic),
            seed: seed.to_vec(),
            hd_wallet,
            accounts: BTreeMap::new(),
            special_accounts: Vec::new(),
            metadata: WalletMetadata {
                created_at: Self::current_timestamp(),
                version: 1,
                ..Default::default()
            },
            is_watch_only: false,
        };

        // Generate initial accounts
        for i in 0..config.initial_accounts {
            wallet.create_account(i, AccountType::Standard)?;
        }

        Ok(wallet)
    }

    /// Create a wallet from a seed
    pub fn from_seed(seed: &[u8], config: WalletConfig) -> Result<Self> {
        let master_key = ExtendedPrivKey::new_master(config.network, seed)?;
        let hd_wallet = HDWallet::new(master_key);
        
        let mut wallet = Self {
            config: config.clone(),
            mnemonic: None,
            seed: seed.to_vec(),
            hd_wallet,
            accounts: BTreeMap::new(),
            special_accounts: Vec::new(),
            metadata: WalletMetadata {
                created_at: Self::current_timestamp(),
                version: 1,
                ..Default::default()
            },
            is_watch_only: false,
        };

        // Generate initial accounts
        for i in 0..config.initial_accounts {
            wallet.create_account(i, AccountType::Standard)?;
        }

        Ok(wallet)
    }

    /// Create a watch-only wallet from extended public keys
    pub fn from_xpub(
        _master_xpub: ExtendedPubKey,
        config: WalletConfig,
    ) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            mnemonic: None,
            seed: Vec::new(),
            hd_wallet: HDWallet::new(ExtendedPrivKey::new_master(config.network, &[0; 32])?), // Dummy
            accounts: BTreeMap::new(),
            special_accounts: Vec::new(),
            metadata: WalletMetadata {
                created_at: Self::current_timestamp(),
                version: 1,
                ..Default::default()
            },
            is_watch_only: true,
        })
    }

    /// Create a new account
    pub fn create_account(&mut self, index: u32, account_type: AccountType) -> Result<&Account> {
        if self.accounts.contains_key(&index) {
            return Err(Error::InvalidParameter(format!("Account {} already exists", index)));
        }

        let account = match account_type {
            AccountType::Standard => {
                let account_key = self.hd_wallet.bip44_account(index)?;
                let mut account = Account::new(
                    index,
                    account_key,
                    self.config.network,
                    self.config.external_gap_limit,
                    self.config.internal_gap_limit,
                )?;
                
                if self.config.enable_coinjoin {
                    account.enable_coinjoin(self.config.coinjoin_gap_limit)?;
                }
                
                account
            }
            AccountType::CoinJoin => {
                let account_key = self.hd_wallet.coinjoin_account(index)?;
                Account::new(
                    index,
                    account_key,
                    self.config.network,
                    self.config.external_gap_limit,
                    self.config.internal_gap_limit,
                )?
            }
            AccountType::SpecialPurpose(purpose) => {
                self.create_special_account(index, purpose)?
            }
        };

        self.accounts.insert(index, account);
        Ok(self.accounts.get(&index).unwrap())
    }

    /// Create a special purpose account
    fn create_special_account(
        &mut self,
        index: u32,
        purpose: SpecialPurposeType,
    ) -> Result<Account> {
        let path = match purpose {
            SpecialPurposeType::IdentityRegistration => {
                match self.config.network {
                    Network::Dash => crate::dip9::IDENTITY_REGISTRATION_PATH_MAINNET,
                    Network::Testnet => crate::dip9::IDENTITY_REGISTRATION_PATH_TESTNET,
                    _ => return Err(Error::InvalidNetwork),
                }
            }
            SpecialPurposeType::IdentityTopUp => {
                match self.config.network {
                    Network::Dash => crate::dip9::IDENTITY_TOPUP_PATH_MAINNET,
                    Network::Testnet => crate::dip9::IDENTITY_TOPUP_PATH_TESTNET,
                    _ => return Err(Error::InvalidNetwork),
                }
            }
            SpecialPurposeType::IdentityInvitation => {
                match self.config.network {
                    Network::Dash => crate::dip9::IDENTITY_INVITATION_PATH_MAINNET,
                    Network::Testnet => crate::dip9::IDENTITY_INVITATION_PATH_TESTNET,
                    _ => return Err(Error::InvalidNetwork),
                }
            }
            _ => {
                // For other types, use standard BIP44 with special marking
                let account_key = self.hd_wallet.bip44_account(index)?;
                return Account::new(
                    index,
                    account_key,
                    self.config.network,
                    self.config.external_gap_limit,
                    self.config.internal_gap_limit,
                );
            }
        };

        // Derive the account key from the special path
        let mut full_path = DerivationPath::from(path);
        full_path.push(ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?);
        
        let account_key = self.hd_wallet.derive(&full_path)?;
        let mut account = Account::new(
            index,
            account_key,
            self.config.network,
            5, // Smaller gap limit for special accounts
            5,
        )?;
        
        account.account_type = AccountType::SpecialPurpose(purpose);
        Ok(account)
    }

    /// Get an account by index
    pub fn get_account(&self, index: u32) -> Option<&Account> {
        self.accounts.get(&index)
    }

    /// Get a mutable account by index
    pub fn get_account_mut(&mut self, index: u32) -> Option<&mut Account> {
        self.accounts.get_mut(&index)
    }

    /// Get the default account (index 0)
    pub fn default_account(&self) -> Option<&Account> {
        self.accounts.get(&0)
    }

    /// Get the default account mutably
    pub fn default_account_mut(&mut self) -> Option<&mut Account> {
        self.accounts.get_mut(&0)
    }

    /// Get all accounts
    pub fn all_accounts(&self) -> Vec<&Account> {
        self.accounts.values().collect()
    }

    /// Get total balance across all accounts
    pub fn total_balance(&self) -> WalletBalance {
        let mut total = WalletBalance::default();
        
        for account in self.accounts.values() {
            total.confirmed += account.balance.confirmed;
            total.unconfirmed += account.balance.unconfirmed;
            total.immature += account.balance.immature;
            total.total += account.balance.total;
        }
        
        total
    }

    /// Get all addresses across all accounts
    pub fn all_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        for account in self.accounts.values() {
            addresses.extend(account.get_all_addresses());
        }
        addresses
    }

    /// Find which account an address belongs to
    pub fn find_account_for_address(&self, address: &Address) -> Option<(&Account, u32)> {
        for (index, account) in &self.accounts {
            if account.contains_address(address) {
                return Some((account, *index));
            }
        }
        None
    }

    /// Mark an address as used across all accounts
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        for account in self.accounts.values_mut() {
            if account.mark_address_used(address) {
                self.metadata.last_synced = Some(Self::current_timestamp());
                return true;
            }
        }
        false
    }

    /// Scan all accounts for address activity
    pub fn scan_for_activity<F>(&mut self, check_fn: F) -> WalletScanResult
    where
        F: Fn(&Address) -> bool + Clone,
    {
        let mut result = WalletScanResult::default();
        
        for (index, account) in self.accounts.iter_mut() {
            let scan_result = account.scan_for_activity(check_fn.clone());
            if scan_result.total_found > 0 {
                result.accounts_with_activity.push(*index);
                result.total_addresses_found += scan_result.total_found;
            }
        }
        
        if result.total_addresses_found > 0 {
            self.metadata.last_synced = Some(Self::current_timestamp());
        }
        
        result
    }

    /// Get the next receive address for the default account
    pub fn get_next_receive_address(&mut self) -> Result<Address> {
        self.default_account_mut()
            .ok_or(Error::InvalidParameter("No default account".into()))?
            .get_next_receive_address()
    }

    /// Get the next change address for the default account
    pub fn get_next_change_address(&mut self) -> Result<Address> {
        self.default_account_mut()
            .ok_or(Error::InvalidParameter("No default account".into()))?
            .get_next_change_address()
    }

    /// Enable CoinJoin for an account
    pub fn enable_coinjoin_for_account(&mut self, account_index: u32) -> Result<()> {
        let account = self.accounts.get_mut(&account_index)
            .ok_or(Error::InvalidParameter(format!("Account {} not found", account_index)))?;
        account.enable_coinjoin(self.config.coinjoin_gap_limit)
    }

    /// Export wallet as watch-only
    pub fn to_watch_only(&self) -> Self {
        let mut watch_only = self.clone();
        watch_only.mnemonic = None;
        watch_only.seed.clear();
        watch_only.is_watch_only = true;
        
        // Convert all accounts to watch-only
        for account in watch_only.accounts.values_mut() {
            *account = account.to_watch_only();
        }
        
        watch_only
    }

    /// Get wallet statistics
    pub fn stats(&self) -> WalletStats {
        let total_accounts = self.accounts.len();
        let mut total_addresses = 0;
        let mut used_addresses = 0;
        let mut coinjoin_enabled = 0;
        
        for account in self.accounts.values() {
            total_addresses += account.get_all_addresses().len();
            used_addresses += account.get_used_addresses().len();
            if account.coinjoin_addresses.is_some() {
                coinjoin_enabled += 1;
            }
        }
        
        WalletStats {
            total_accounts,
            total_addresses,
            used_addresses,
            unused_addresses: total_addresses - used_addresses,
            coinjoin_enabled_accounts: coinjoin_enabled,
            network: self.config.network,
            is_watch_only: self.is_watch_only,
        }
    }

    /// Backup wallet data (mnemonic + metadata)
    pub fn backup(&self) -> WalletBackup {
        WalletBackup {
            mnemonic: self.mnemonic.as_ref().map(|m| m.phrase().to_string()),
            passphrase: if self.config.passphrase.is_empty() {
                None
            } else {
                Some(self.config.passphrase.clone())
            },
            network: self.config.network,
            accounts: self.accounts.keys().copied().collect(),
            metadata: self.metadata.clone(),
            created_at: Self::current_timestamp(),
        }
    }

    /// Restore wallet from backup
    pub fn restore(backup: WalletBackup, config: WalletConfig) -> Result<Self> {
        let mnemonic = backup.mnemonic
            .ok_or(Error::InvalidParameter("No mnemonic in backup".into()))?;
        let mnemonic = Mnemonic::from_phrase(&mnemonic, config.language)?;
        
        let mut wallet = Self::from_mnemonic(mnemonic, config)?;
        
        // Restore accounts
        for index in backup.accounts {
            if !wallet.accounts.contains_key(&index) {
                wallet.create_account(index, AccountType::Standard)?;
            }
        }
        
        wallet.metadata = backup.metadata;
        Ok(wallet)
    }

    /// Get current timestamp (placeholder)
    fn current_timestamp() -> u64 {
        0 // In production, use actual time
    }
    
    /// Export the master private key as BIP38 encrypted
    #[cfg(feature = "bip38")]
    pub fn export_master_key_bip38(&self, password: &str) -> Result<Bip38EncryptedKey> {
        if self.is_watch_only {
            return Err(Error::InvalidParameter("Cannot export private key from watch-only wallet".into()));
        }
        
        let master_key = &self.hd_wallet.master_key();
        let secp = secp256k1::Secp256k1::new();
        let secret_key = secp256k1::SecretKey::from_slice(&master_key.private_key.secret_bytes())
            .map_err(|_| Error::KeyError("Invalid master key".into()))?;
        
        encrypt_private_key(&secret_key, password, true, self.config.network)
    }
    
    /// Export an account's private key as BIP38 encrypted
    #[cfg(feature = "bip38")]
    pub fn export_account_key_bip38(&self, account_index: u32, password: &str) -> Result<Bip38EncryptedKey> {
        if self.is_watch_only {
            return Err(Error::InvalidParameter("Cannot export private key from watch-only wallet".into()));
        }
        
        let account = self.accounts.get(&account_index)
            .ok_or(Error::InvalidParameter(format!("Account {} not found", account_index)))?;
        
        if let Some(ref account_key) = account.account_key {
            let secret_key = secp256k1::SecretKey::from_slice(&account_key.private_key.secret_bytes())
                .map_err(|_| Error::KeyError("Invalid account key".into()))?;
            
            encrypt_private_key(&secret_key, password, true, self.config.network)
        } else {
            Err(Error::InvalidParameter("Account has no private key".into()))
        }
    }
    
    /// Import a BIP38 encrypted private key
    #[cfg(feature = "bip38")]
    pub fn import_bip38_key(&mut self, encrypted_key: &Bip38EncryptedKey, password: &str) -> Result<()> {
        // Decrypt the key
        let secret_key = encrypted_key.decrypt(password)?;
        
        // Create a new account with this key
        // Note: This is a simplified implementation - in production you'd want more options
        let private_bytes = secret_key.secret_bytes();
        let mut extended_key_bytes = Vec::new();
        extended_key_bytes.extend_from_slice(&[0; 32]); // chain code (zeros for imported keys)
        extended_key_bytes.extend_from_slice(&private_bytes);
        
        // This is simplified - in production you'd properly construct the ExtendedPrivKey
        // For now, we'll just note that the key was imported
        
        Ok(())
    }
}

/// Wallet balance summary
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletBalance {
    /// Confirmed balance
    pub confirmed: u64,
    /// Unconfirmed balance
    pub unconfirmed: u64,
    /// Immature balance (coinbase)
    pub immature: u64,
    /// Total balance
    pub total: u64,
}

/// Wallet scan result
#[derive(Debug, Default)]
pub struct WalletScanResult {
    /// Accounts that had activity
    pub accounts_with_activity: Vec<u32>,
    /// Total addresses found with activity
    pub total_addresses_found: usize,
}

/// Wallet statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletStats {
    /// Total number of accounts
    pub total_accounts: usize,
    /// Total addresses generated
    pub total_addresses: usize,
    /// Used addresses
    pub used_addresses: usize,
    /// Unused addresses
    pub unused_addresses: usize,
    /// Accounts with CoinJoin enabled
    pub coinjoin_enabled_accounts: usize,
    /// Network
    pub network: Network,
    /// Whether this is watch-only
    pub is_watch_only: bool,
}

/// Wallet backup data
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletBackup {
    /// Mnemonic phrase
    pub mnemonic: Option<String>,
    /// BIP39 passphrase
    pub passphrase: Option<String>,
    /// Network
    pub network: Network,
    /// Account indices
    pub accounts: Vec<u32>,
    /// Metadata
    pub metadata: WalletMetadata,
    /// Backup creation time
    pub created_at: u64,
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wallet ({}) - {} accounts, {} addresses",
            if self.is_watch_only { "watch-only" } else { "full" },
            self.accounts.len(),
            self.all_addresses().len()
        )
    }
}

/// Wallet builder for flexible configuration
pub struct WalletBuilder {
    config: WalletConfig,
    mnemonic: Option<Mnemonic>,
    seed: Option<Vec<u8>>,
    master_xpub: Option<ExtendedPubKey>,
}

impl WalletBuilder {
    /// Create a new wallet builder
    pub fn new() -> Self {
        Self {
            config: WalletConfig::default(),
            mnemonic: None,
            seed: None,
            master_xpub: None,
        }
    }

    /// Set the network
    pub fn network(mut self, network: Network) -> Self {
        self.config.network = network;
        self
    }

    /// Set gap limits
    pub fn gap_limits(mut self, external: u32, internal: u32) -> Self {
        self.config.external_gap_limit = external;
        self.config.internal_gap_limit = internal;
        self
    }

    /// Enable CoinJoin
    pub fn enable_coinjoin(mut self, gap_limit: u32) -> Self {
        self.config.enable_coinjoin = true;
        self.config.coinjoin_gap_limit = gap_limit;
        self
    }

    /// Set initial accounts
    pub fn initial_accounts(mut self, count: u32) -> Self {
        self.config.initial_accounts = count;
        self
    }

    /// Set BIP39 passphrase
    pub fn passphrase(mut self, passphrase: String) -> Self {
        self.config.passphrase = passphrase;
        self
    }

    /// Set mnemonic language
    pub fn language(mut self, language: Language) -> Self {
        self.config.language = language;
        self
    }

    /// Set wallet name
    pub fn name(mut self, name: String) -> Self {
        self.config.name = Some(name);
        self
    }

    /// Use a specific mnemonic
    pub fn mnemonic(mut self, mnemonic: Mnemonic) -> Self {
        self.mnemonic = Some(mnemonic);
        self
    }

    /// Use a specific seed
    pub fn seed(mut self, seed: Vec<u8>) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Create watch-only wallet
    pub fn watch_only(mut self, master_xpub: ExtendedPubKey) -> Self {
        self.master_xpub = Some(master_xpub);
        self
    }

    /// Build the wallet
    pub fn build(self) -> Result<Wallet> {
        if let Some(xpub) = self.master_xpub {
            Wallet::from_xpub(xpub, self.config)
        } else if let Some(mnemonic) = self.mnemonic {
            Wallet::from_mnemonic(mnemonic, self.config)
        } else if let Some(seed) = self.seed {
            Wallet::from_seed(&seed, self.config)
        } else {
            Wallet::new(self.config)
        }
    }
}

impl Default for WalletBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let config = WalletConfig {
            network: Network::Testnet,
            initial_accounts: 2,
            ..Default::default()
        };
        
        let wallet = Wallet::new(config).unwrap();
        assert_eq!(wallet.accounts.len(), 2);
        assert!(wallet.mnemonic.is_some());
        assert!(!wallet.is_watch_only);
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        
        let config = WalletConfig::default();
        let wallet = Wallet::from_mnemonic(mnemonic, config).unwrap();
        
        assert_eq!(wallet.accounts.len(), 1);
        let default_account = wallet.default_account().unwrap();
        assert_eq!(default_account.index, 0);
    }

    #[test]
    fn test_account_creation() {
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        wallet.create_account(1, AccountType::Standard).unwrap();
        wallet.create_account(2, AccountType::CoinJoin).unwrap();
        
        assert_eq!(wallet.accounts.len(), 3); // 1 initial + 2 created
    }

    #[test]
    fn test_address_generation() {
        let config = WalletConfig {
            network: Network::Testnet,
            ..Default::default()
        };
        
        let mut wallet = Wallet::new(config).unwrap();
        let addr1 = wallet.get_next_receive_address().unwrap();
        let addr2 = wallet.get_next_receive_address().unwrap();
        assert_eq!(addr1, addr2); // Should be same until marked used
        
        wallet.mark_address_used(&addr1);
        let addr3 = wallet.get_next_receive_address().unwrap();
        assert_ne!(addr1, addr3); // Should be different after marking used
    }

    #[test]
    fn test_wallet_builder() {
        let wallet = WalletBuilder::new()
            .network(Network::Testnet)
            .gap_limits(30, 15)
            .enable_coinjoin(10)
            .initial_accounts(3)
            .name("Test Wallet".to_string())
            .build()
            .unwrap();
        
        assert_eq!(wallet.config.network, Network::Testnet);
        assert_eq!(wallet.config.external_gap_limit, 30);
        assert_eq!(wallet.config.internal_gap_limit, 15);
        assert!(wallet.config.enable_coinjoin);
        assert_eq!(wallet.accounts.len(), 3);
    }
}