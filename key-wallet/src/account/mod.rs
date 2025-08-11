//! Account management for HD wallets
//!
//! This module provides comprehensive account management following BIP44,
//! including gap limit tracking, address pool management, and support for
//! multiple account types (standard, CoinJoin, watch-only).

pub mod address_pool;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use secp256k1::Secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::dip9::DerivationPathReference;
use crate::error::{Error, Result};
use crate::gap_limit::{GapLimit, GapLimitManager};
use crate::Network;
use address_pool::{AddressPool, KeySource};
use dashcore::Address;

/// Account types supported by the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum AccountType {
    /// Standard BIP44 account for regular transactions
    Standard,
    /// CoinJoin account for private transactions
    CoinJoin,
    /// Special purpose account (e.g., for identity funding)
    SpecialPurpose(SpecialPurposeType),
}

/// Special purpose account types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum SpecialPurposeType {
    /// Identity registration funding
    IdentityRegistration,
    /// Identity top-up funding
    IdentityTopUp,
    /// Identity invitation funding
    IdentityInvitation,
    /// Masternode collateral
    MasternodeCollateral,
    /// Provider funds
    ProviderFunds,
}

/// Account metadata for organization and tracking
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AccountMetadata {
    /// Human-readable account name
    pub name: Option<String>,
    /// Account description
    pub description: Option<String>,
    /// Account color for UI (hex format)
    pub color: Option<String>,
    /// Custom tags for categorization
    pub tags: Vec<String>,
    /// Account creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_used: Option<u64>,
    /// Total received amount
    pub total_received: u64,
    /// Total sent amount
    pub total_sent: u64,
    /// Transaction count
    pub tx_count: u32,
}

/// Complete account structure with all derivation paths and address pools
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Account {
    /// Account index (BIP44 account level)
    pub index: u32,
    /// Account type
    pub account_type: AccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Account-level extended public key
    pub account_xpub: ExtendedPubKey,
    /// External (receive) address pool
    pub external_addresses: AddressPool,
    /// Internal (change) address pool
    pub internal_addresses: AddressPool,
    /// CoinJoin address pools (if enabled)
    pub coinjoin_addresses: Option<CoinJoinPools>,
    /// Gap limit manager
    pub gap_limits: GapLimitManager,
    /// All derivation paths used by this account
    pub derivation_paths: BTreeMap<DerivationPathReference, DerivationPath>,
    /// Account metadata
    pub metadata: AccountMetadata,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
    /// Account balance information
    pub balance: AccountBalance,
}

/// CoinJoin-specific address pools
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct CoinJoinPools {
    /// CoinJoin receive addresses
    pub external: AddressPool,
    /// CoinJoin change addresses
    pub internal: AddressPool,
    /// CoinJoin rounds completed
    pub rounds_completed: u32,
    /// CoinJoin balance
    pub coinjoin_balance: u64,
}

/// Account balance tracking
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AccountBalance {
    /// Confirmed balance
    pub confirmed: u64,
    /// Unconfirmed balance
    pub unconfirmed: u64,
    /// Immature balance (coinbase)
    pub immature: u64,
    /// Total balance (confirmed + unconfirmed)
    pub total: u64,
}

impl Account {
    /// Create a new standard account from an extended private key
    pub fn new(
        index: u32,
        account_key: ExtendedPrivKey,
        network: Network,
        external_gap_limit: u32,
        internal_gap_limit: u32,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let account_xpub = ExtendedPubKey::from_priv(&secp, &account_key);

        // Create base derivation paths for external and internal chains
        let external_path =
            DerivationPath::from(vec![ChildNumber::from_normal_idx(0).map_err(Error::Bip32)?]);
        let internal_path =
            DerivationPath::from(vec![ChildNumber::from_normal_idx(1).map_err(Error::Bip32)?]);

        let mut account = Self {
            index,
            account_type: AccountType::Standard,
            network,
            account_xpub,
            external_addresses: AddressPool::new(
                external_path.clone(),
                false,
                external_gap_limit,
                network,
            ),
            internal_addresses: AddressPool::new(
                internal_path.clone(),
                true,
                internal_gap_limit,
                network,
            ),
            coinjoin_addresses: None,
            gap_limits: GapLimitManager::new(external_gap_limit, internal_gap_limit, None),
            derivation_paths: BTreeMap::new(),
            metadata: AccountMetadata {
                created_at: Self::current_timestamp(),
                ..Default::default()
            },
            is_watch_only: false,
            balance: AccountBalance::default(),
        };

        // Add standard derivation paths
        account.add_derivation_path(DerivationPathReference::BIP44, external_path)?;
        account.add_derivation_path(DerivationPathReference::BIP44, internal_path)?;

        // Generate initial addresses up to gap limit
        let key_source = KeySource::Private(account_key);
        account.external_addresses.generate_addresses(external_gap_limit, &key_source)?;
        account.internal_addresses.generate_addresses(internal_gap_limit, &key_source)?;

        Ok(account)
    }

    /// Create a watch-only account from an extended public key
    pub fn from_xpub(
        index: u32,
        account_xpub: ExtendedPubKey,
        network: Network,
        external_gap_limit: u32,
        internal_gap_limit: u32,
    ) -> Result<Self> {
        let external_path =
            DerivationPath::from(vec![ChildNumber::from_normal_idx(0).map_err(Error::Bip32)?]);
        let internal_path =
            DerivationPath::from(vec![ChildNumber::from_normal_idx(1).map_err(Error::Bip32)?]);

        let mut account = Self {
            index,
            account_type: AccountType::Standard,
            network,
            account_xpub,
            external_addresses: AddressPool::new(
                external_path.clone(),
                false,
                external_gap_limit,
                network,
            ),
            internal_addresses: AddressPool::new(
                internal_path.clone(),
                true,
                internal_gap_limit,
                network,
            ),
            coinjoin_addresses: None,
            gap_limits: GapLimitManager::new(external_gap_limit, internal_gap_limit, None),
            derivation_paths: BTreeMap::new(),
            metadata: AccountMetadata {
                created_at: Self::current_timestamp(),
                ..Default::default()
            },
            is_watch_only: true,
            balance: AccountBalance::default(),
        };

        // Generate initial addresses up to gap limit
        let key_source = KeySource::Public(account_xpub);
        account.external_addresses.generate_addresses(external_gap_limit, &key_source)?;
        account.internal_addresses.generate_addresses(internal_gap_limit, &key_source)?;

        Ok(account)
    }

    /// Enable CoinJoin for this account
    pub fn enable_coinjoin(&mut self, gap_limit: u32) -> Result<()> {
        if self.coinjoin_addresses.is_some() {
            return Ok(()); // Already enabled
        }

        let coinjoin_external_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(2).map_err(Error::Bip32)?,
            ChildNumber::from_normal_idx(0).map_err(Error::Bip32)?,
        ]);
        let coinjoin_internal_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(2).map_err(Error::Bip32)?,
            ChildNumber::from_normal_idx(1).map_err(Error::Bip32)?,
        ]);

        let mut coinjoin_external =
            AddressPool::new(coinjoin_external_path.clone(), false, gap_limit, self.network);
        let mut coinjoin_internal =
            AddressPool::new(coinjoin_internal_path.clone(), true, gap_limit, self.network);

        // Generate initial CoinJoin addresses
        let key_source = self.get_key_source()?;
        coinjoin_external.generate_addresses(gap_limit, &key_source)?;
        coinjoin_internal.generate_addresses(gap_limit, &key_source)?;

        self.coinjoin_addresses = Some(CoinJoinPools {
            external: coinjoin_external,
            internal: coinjoin_internal,
            rounds_completed: 0,
            coinjoin_balance: 0,
        });

        self.gap_limits.coinjoin = Some(GapLimit::new(gap_limit));

        Ok(())
    }

    /// Get the next unused receive address
    pub fn get_next_receive_address(&mut self) -> Result<Address> {
        let key_source = self.get_key_source()?;
        self.external_addresses.get_next_unused(&key_source)
    }

    /// Get the next unused change address
    pub fn get_next_change_address(&mut self) -> Result<Address> {
        let key_source = self.get_key_source()?;
        self.internal_addresses.get_next_unused(&key_source)
    }

    /// Get the next unused CoinJoin receive address
    pub fn get_next_coinjoin_receive_address(&mut self) -> Result<Address> {
        let key_source = self.get_key_source()?;
        let pools = self.coinjoin_addresses.as_mut().ok_or(Error::CoinJoinNotEnabled)?;
        pools.external.get_next_unused(&key_source)
    }

    /// Get the next unused CoinJoin change address
    pub fn get_next_coinjoin_change_address(&mut self) -> Result<Address> {
        let key_source = self.get_key_source()?;
        let pools = self.coinjoin_addresses.as_mut().ok_or(Error::CoinJoinNotEnabled)?;
        pools.internal.get_next_unused(&key_source)
    }

    /// Mark an address as used
    pub fn mark_address_used(&mut self, address: &Address) -> bool {
        // Check external addresses
        if self.external_addresses.mark_used(address) {
            self.gap_limits
                .external
                .mark_used(self.external_addresses.get_address_index(address).unwrap_or(0));
            self.metadata.last_used = Some(Self::current_timestamp());
            return true;
        }

        // Check internal addresses
        if self.internal_addresses.mark_used(address) {
            self.gap_limits
                .internal
                .mark_used(self.internal_addresses.get_address_index(address).unwrap_or(0));
            self.metadata.last_used = Some(Self::current_timestamp());
            return true;
        }

        // Check CoinJoin addresses if enabled
        if let Some(ref mut coinjoin) = self.coinjoin_addresses {
            if coinjoin.external.mark_used(address) {
                if let Some(ref mut gap) = self.gap_limits.coinjoin {
                    gap.mark_used(coinjoin.external.get_address_index(address).unwrap_or(0));
                }
                self.metadata.last_used = Some(Self::current_timestamp());
                return true;
            }
            if coinjoin.internal.mark_used(address) {
                if let Some(ref mut gap) = self.gap_limits.coinjoin {
                    gap.mark_used(coinjoin.internal.get_address_index(address).unwrap_or(0));
                }
                self.metadata.last_used = Some(Self::current_timestamp());
                return true;
            }
        }

        false
    }

    /// Scan for address activity and mark used addresses
    pub fn scan_for_activity<F>(&mut self, check_fn: F) -> ScanResult
    where
        F: Fn(&Address) -> bool + Clone,
    {
        let mut result = ScanResult::default();

        // Scan external addresses
        let external_found = self.external_addresses.scan_for_usage(check_fn.clone());
        result.external_found = external_found.len();
        for addr in &external_found {
            if let Some(index) = self.external_addresses.get_address_index(addr) {
                self.gap_limits.external.mark_used(index);
            }
        }

        // Scan internal addresses
        let internal_found = self.internal_addresses.scan_for_usage(check_fn.clone());
        result.internal_found = internal_found.len();
        for addr in &internal_found {
            if let Some(index) = self.internal_addresses.get_address_index(addr) {
                self.gap_limits.internal.mark_used(index);
            }
        }

        // Scan CoinJoin addresses if enabled
        if let Some(ref mut coinjoin) = self.coinjoin_addresses {
            let coinjoin_external = coinjoin.external.scan_for_usage(check_fn.clone());
            let coinjoin_internal = coinjoin.internal.scan_for_usage(check_fn);
            result.coinjoin_found = coinjoin_external.len() + coinjoin_internal.len();

            if let Some(ref mut gap) = self.gap_limits.coinjoin {
                for addr in &coinjoin_external {
                    if let Some(index) = coinjoin.external.get_address_index(addr) {
                        gap.mark_used(index);
                    }
                }
                for addr in &coinjoin_internal {
                    if let Some(index) = coinjoin.internal.get_address_index(addr) {
                        gap.mark_used(index);
                    }
                }
            }
        }

        result.total_found = result.external_found + result.internal_found + result.coinjoin_found;

        if result.total_found > 0 {
            self.metadata.last_used = Some(Self::current_timestamp());
        }

        result
    }

    /// Get all addresses (both used and unused)
    pub fn get_all_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        addresses.extend(self.external_addresses.get_all_addresses());
        addresses.extend(self.internal_addresses.get_all_addresses());

        if let Some(ref coinjoin) = self.coinjoin_addresses {
            addresses.extend(coinjoin.external.get_all_addresses());
            addresses.extend(coinjoin.internal.get_all_addresses());
        }

        addresses
    }

    /// Get only used addresses
    pub fn get_used_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        addresses.extend(self.external_addresses.get_used_addresses());
        addresses.extend(self.internal_addresses.get_used_addresses());

        if let Some(ref coinjoin) = self.coinjoin_addresses {
            addresses.extend(coinjoin.external.get_used_addresses());
            addresses.extend(coinjoin.internal.get_used_addresses());
        }

        addresses
    }

    /// Get unused addresses
    pub fn get_unused_addresses(&self) -> Vec<Address> {
        let mut addresses = Vec::new();
        addresses.extend(self.external_addresses.get_unused_addresses());
        addresses.extend(self.internal_addresses.get_unused_addresses());

        if let Some(ref coinjoin) = self.coinjoin_addresses {
            addresses.extend(coinjoin.external.get_unused_addresses());
            addresses.extend(coinjoin.internal.get_unused_addresses());
        }

        addresses
    }

    /// Check if an address belongs to this account
    pub fn contains_address(&self, address: &Address) -> bool {
        self.external_addresses.contains_address(address)
            || self.internal_addresses.contains_address(address)
            || self
                .coinjoin_addresses
                .as_ref()
                .map(|cj| {
                    cj.external.contains_address(address) || cj.internal.contains_address(address)
                })
                .unwrap_or(false)
    }

    /// Update account balance
    pub fn update_balance(&mut self, confirmed: u64, unconfirmed: u64, immature: u64) {
        self.balance.confirmed = confirmed;
        self.balance.unconfirmed = unconfirmed;
        self.balance.immature = immature;
        self.balance.total = confirmed + unconfirmed;
    }

    /// Add a derivation path to this account
    pub fn add_derivation_path(
        &mut self,
        reference: DerivationPathReference,
        path: DerivationPath,
    ) -> Result<()> {
        self.derivation_paths.insert(reference, path);
        Ok(())
    }

    /// Get the key source for address derivation
    fn get_key_source(&self) -> Result<KeySource> {
        // Since we no longer store the private key, always use the public key
        Ok(KeySource::Public(self.account_xpub))
    }

    /// Get current timestamp (placeholder - should use actual time source)
    fn current_timestamp() -> u64 {
        // In production, this would use std::time::SystemTime or similar
        0
    }

    /// Export account as watch-only
    pub fn to_watch_only(&self) -> Self {
        let mut watch_only = self.clone();
        watch_only.is_watch_only = true;
        watch_only
    }

    /// Serialize account to bytes
    #[cfg(feature = "bincode")]
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Deserialize account from bytes
    #[cfg(feature = "bincode")]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Get external address pool
    pub fn external_pool(&self) -> &AddressPool {
        &self.external_addresses
    }

    /// Get external address pool mutably
    pub fn external_pool_mut(&mut self) -> &mut AddressPool {
        &mut self.external_addresses
    }

    /// Get internal address pool
    pub fn internal_pool(&self) -> &AddressPool {
        &self.internal_addresses
    }

    /// Get internal address pool mutably
    pub fn internal_pool_mut(&mut self) -> &mut AddressPool {
        &mut self.internal_addresses
    }

    /// Get the extended public key for this account
    pub fn extended_public_key(&self) -> ExtendedPubKey {
        self.account_xpub
    }

    /// Get external address at specific index
    pub fn get_external_address(&self, index: u32) -> Result<Address> {
        self.external_addresses.get_address_at_index(index).ok_or_else(|| {
            Error::InvalidParameter(format!("External address at index {} not found", index))
        })
    }

    /// Get internal address at specific index
    pub fn get_internal_address(&self, index: u32) -> Result<Address> {
        self.internal_addresses.get_address_at_index(index).ok_or_else(|| {
            Error::InvalidParameter(format!("Internal address at index {} not found", index))
        })
    }
}

/// Result of address scanning
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Number of external addresses found with activity
    pub external_found: usize,
    /// Number of internal addresses found with activity
    pub internal_found: usize,
    /// Number of CoinJoin addresses found with activity
    pub coinjoin_found: usize,
    /// Total addresses found with activity
    pub total_found: usize,
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Account #{} ({:?}) - {} addresses ({} used)",
            self.index,
            self.account_type,
            self.get_all_addresses().len(),
            self.get_used_addresses().len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::{Language, Mnemonic};

    fn test_account() -> Account {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

        // Derive account key (m/44'/1'/0')
        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_key = master.derive_priv(&secp, &path).unwrap();

        Account::new(0, account_key, Network::Testnet, 20, 10).unwrap()
    }

    #[test]
    fn test_account_creation() {
        let account = test_account();
        assert_eq!(account.index, 0);
        assert_eq!(account.account_type, AccountType::Standard);
        assert!(!account.is_watch_only);
        assert!(account.external_addresses.get_all_addresses().len() >= 20);
        assert!(account.internal_addresses.get_all_addresses().len() >= 10);
    }

    #[test]
    fn test_watch_only_account() {
        let account = test_account();
        let watch_only =
            Account::from_xpub(0, account.account_xpub, Network::Testnet, 20, 10).unwrap();

        assert!(watch_only.is_watch_only);
        assert_eq!(watch_only.external_addresses.get_all_addresses().len(), 20);
    }

    #[test]
    fn test_address_usage() {
        let mut account = test_account();
        let address = account.get_next_receive_address().unwrap();

        assert!(account.mark_address_used(&address));
        assert_eq!(account.get_used_addresses().len(), 1);

        // Should get a different address now
        let next_address = account.get_next_receive_address().unwrap();
        assert_ne!(address, next_address);
    }

    #[test]
    fn test_coinjoin_enabling() {
        let mut account = test_account();
        assert!(account.coinjoin_addresses.is_none());

        account.enable_coinjoin(10).unwrap();
        assert!(account.coinjoin_addresses.is_some());

        let coinjoin_addr = account.get_next_coinjoin_receive_address().unwrap();
        assert!(account.contains_address(&coinjoin_addr));
    }

    #[test]
    #[cfg(feature = "bincode")]
    fn test_serialization() {
        let account = test_account();
        let serialized = account.serialize().unwrap();
        let deserialized = Account::deserialize(&serialized).unwrap();

        assert_eq!(account.index, deserialized.index);
        assert_eq!(account.account_type, deserialized.account_type);
        assert_eq!(account.get_all_addresses().len(), deserialized.get_all_addresses().len());
    }
}
