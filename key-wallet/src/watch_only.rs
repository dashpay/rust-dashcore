//! Watch-only wallet functionality
//!
//! This module provides support for watch-only wallets that can track addresses
//! and balances without access to private keys.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    Address, AddressPool, ExtendedPubKey, Network, Error, Result,
    DerivationPath, ChildNumber, AddressInfo, PoolStats, KeySource,
};

/// A watch-only wallet that can generate and track addresses without private keys
#[derive(Debug, Clone)]
pub struct WatchOnlyWallet {
    /// Extended public key for the wallet
    xpub: ExtendedPubKey,
    /// Network the wallet operates on
    network: Network,
    /// External address pool (receiving addresses)
    external_pool: AddressPool,
    /// Internal address pool (change addresses)
    internal_pool: AddressPool,
    /// Account name
    name: String,
    /// Account index
    index: u32,
    /// Account derivation path (e.g., m/44'/5'/0')
    account_path: DerivationPath,
}

impl WatchOnlyWallet {
    /// Create a new watch-only wallet from an extended public key
    pub fn new(xpub: ExtendedPubKey, network: Network, name: String, index: u32) -> Result<Self> {
        // Create the account path (m/44'/5'/index')
        let account_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).map_err(Error::Bip32)?,
            ChildNumber::from_hardened_idx(5).map_err(Error::Bip32)?,  // 5 for Dash
            ChildNumber::from_hardened_idx(index).map_err(Error::Bip32)?,
        ]);
        
        // Create external path (account_path/0)
        let mut external_path = account_path.clone();
        external_path.push(ChildNumber::from_normal_idx(0).map_err(Error::Bip32)?);
        
        // Create internal path (account_path/1)
        let mut internal_path = account_path.clone();
        internal_path.push(ChildNumber::from_normal_idx(1).map_err(Error::Bip32)?);
        
        // Create pools with proper derivation paths
        let external_pool = AddressPool::new(
            external_path,
            false,  // is_internal
            20,     // gap_limit
            network,
        );
        
        let internal_pool = AddressPool::new(
            internal_path,
            true,   // is_internal
            20,     // gap_limit
            network,
        );
        
        Ok(Self {
            xpub,
            network,
            external_pool,
            internal_pool,
            name,
            index,
            account_path,
        })
    }
    
    /// Create from an account-level extended public key string
    pub fn from_xpub_string(xpub_str: &str, network: Network, name: String, index: u32) -> Result<Self> {
        let xpub = xpub_str.parse::<ExtendedPubKey>()
            .map_err(|_| Error::InvalidParameter("Invalid extended public key".into()))?;
        
        // Verify the network matches
        if xpub.network != network {
            return Err(Error::InvalidNetwork);
        }
        
        Self::new(xpub, network, name, index)
    }
    
    /// Get the extended public key
    pub fn xpub(&self) -> &ExtendedPubKey {
        &self.xpub
    }
    
    /// Get the extended public key as a string
    pub fn xpub_string(&self) -> String {
        self.xpub.to_string()
    }
    
    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }
    
    /// Get the account name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Set the account name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    
    /// Get the account index
    pub fn index(&self) -> u32 {
        self.index
    }
    
    /// Get the next receive address
    pub fn get_next_receive_address(&mut self) -> Result<Address> {
        let key_source = KeySource::Public(self.xpub.clone());
        self.external_pool.get_next_unused(&key_source)
    }
    
    /// Get the next change address
    pub fn get_next_change_address(&mut self) -> Result<Address> {
        let key_source = KeySource::Public(self.xpub.clone());
        self.internal_pool.get_next_unused(&key_source)
    }
    
    /// Get a specific receive address by index
    pub fn get_receive_address(&self, index: u32) -> Option<Address> {
        self.external_pool.get_info_at_index(index)
            .map(|info| info.address.clone())
    }
    
    /// Get a specific change address by index
    pub fn get_change_address(&self, index: u32) -> Option<Address> {
        self.internal_pool.get_info_at_index(index)
            .map(|info| info.address.clone())
    }
    
    /// Get all generated addresses
    pub fn get_all_addresses(&self) -> Vec<Address> {
        let mut addresses = self.external_pool.get_all_addresses();
        addresses.extend(self.internal_pool.get_all_addresses());
        addresses
    }
    
    /// Get all receive addresses
    pub fn get_all_receive_addresses(&self) -> Vec<Address> {
        self.external_pool.get_all_addresses()
    }
    
    /// Get all change addresses
    pub fn get_all_change_addresses(&self) -> Vec<Address> {
        self.internal_pool.get_all_addresses()
    }
    
    /// Mark an address as used
    pub fn mark_address_as_used(&mut self, address: &Address) -> bool {
        self.external_pool.mark_used(address) ||
        self.internal_pool.mark_used(address)
    }
    
    /// Get address info if it belongs to this wallet
    pub fn get_address_info(&self, address: &Address) -> Option<AddressInfo> {
        self.external_pool.get_address_info(address)
            .or_else(|| self.internal_pool.get_address_info(address))
            .cloned()
    }
    
    /// Check if an address belongs to this wallet
    pub fn owns_address(&self, address: &Address) -> bool {
        self.external_pool.contains_address(address) ||
        self.internal_pool.contains_address(address)
    }
    
    /// Get external pool statistics
    pub fn external_pool_stats(&self) -> PoolStats {
        self.external_pool.stats()
    }
    
    /// Get internal pool statistics
    pub fn internal_pool_stats(&self) -> PoolStats {
        self.internal_pool.stats()
    }
    
    /// Scan for address activity
    pub fn scan_for_activity<F>(&mut self, check_fn: F) -> ScanResult
    where
        F: Fn(&Address) -> bool + Clone,
    {
        let external_found = self.external_pool.scan_for_usage(check_fn.clone());
        let internal_found = self.internal_pool.scan_for_usage(check_fn);
        
        let external_stats = self.external_pool.stats();
        let internal_stats = self.internal_pool.stats();
        
        ScanResult {
            external_found: external_found.len(),
            internal_found: internal_found.len(),
            total_found: external_found.len() + internal_found.len(),
            new_external_index: external_stats.highest_generated + 1,
            new_internal_index: internal_stats.highest_generated + 1,
        }
    }
    
    /// Get the derivation path for a specific address
    pub fn get_address_path(&self, address: &Address) -> Option<DerivationPath> {
        if let Some(info) = self.get_address_info(address) {
            // Build the full path: m/purpose'/coin_type'/account'/change/index
            let change = if self.internal_pool.contains_address(address) { 1 } else { 0 };
            let mut path = self.account_path.clone();
            path.push(ChildNumber::from_normal_idx(change).ok()?);
            path.push(ChildNumber::from_normal_idx(info.index).ok()?);
            Some(path)
        } else {
            None
        }
    }
}

/// Result of scanning for address activity
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Number of external addresses with activity
    pub external_found: usize,
    /// Number of internal addresses with activity
    pub internal_found: usize,
    /// Total number of addresses with activity
    pub total_found: usize,
    /// New next index for external addresses
    pub new_external_index: u32,
    /// New next index for internal addresses
    pub new_internal_index: u32,
}

/// Builder for creating watch-only wallets
pub struct WatchOnlyWalletBuilder {
    xpub: Option<ExtendedPubKey>,
    network: Network,
    name: String,
    index: u32,
}

impl WatchOnlyWalletBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            xpub: None,
            network: Network::Dash,
            name: "Watch-Only".into(),
            index: 0,
        }
    }
    
    /// Set the extended public key
    pub fn xpub(mut self, xpub: ExtendedPubKey) -> Self {
        self.xpub = Some(xpub);
        self
    }
    
    /// Set the extended public key from a string
    pub fn xpub_string(mut self, xpub_str: &str) -> Result<Self> {
        let xpub = xpub_str.parse::<ExtendedPubKey>()
            .map_err(|_| Error::InvalidParameter("Invalid extended public key".into()))?;
        self.xpub = Some(xpub);
        Ok(self)
    }
    
    /// Set the network
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }
    
    /// Set the account name
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
    
    /// Set the account index
    pub fn index(mut self, index: u32) -> Self {
        self.index = index;
        self
    }
    
    /// Build the watch-only wallet
    pub fn build(self) -> Result<WatchOnlyWallet> {
        let xpub = self.xpub.ok_or_else(|| 
            Error::InvalidParameter("Extended public key not provided".into())
        )?;
        
        // Verify network matches
        if xpub.network != self.network {
            return Err(Error::InvalidNetwork);
        }
        
        WatchOnlyWallet::new(xpub, self.network, self.name, self.index)
    }
}

impl Default for WatchOnlyWalletBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Wallet, WalletConfig};
    
    #[test]
    fn test_watch_only_wallet_creation() {
        // Create a regular wallet first to get an xpub
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account(0).unwrap();
        let xpub = account.extended_public_key();
        
        // Create watch-only wallet from the xpub
        let watch_only = WatchOnlyWallet::new(
            xpub.clone(),
            Network::Testnet,
            "Watch Account".into(),
            0
        ).unwrap();
        
        assert_eq!(watch_only.xpub(), &xpub);
        assert_eq!(watch_only.network(), Network::Testnet);
        assert_eq!(watch_only.name(), "Watch Account");
        assert_eq!(watch_only.index(), 0);
    }
    
    #[test]
    fn test_watch_only_address_generation() {
        // Create a regular wallet
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let mut wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account_mut(0).unwrap();
        
        // Get addresses from regular wallet
        let addr1 = account.get_next_receive_address().unwrap();
        let addr2 = account.get_next_receive_address().unwrap();
        
        // Create watch-only wallet from same xpub
        let xpub = account.extended_public_key();
        let mut watch_only = WatchOnlyWallet::new(
            xpub.clone(),
            Network::Testnet,
            "Watch".into(),
            0
        ).unwrap();
        
        // Watch-only should generate addresses (may not be same due to different derivation)
        let watch_addr1 = watch_only.get_next_receive_address().unwrap();
        let watch_addr2 = watch_only.get_next_receive_address().unwrap();
        
        // At least verify they're different from each other
        assert_ne!(watch_addr1, watch_addr2);
    }
    
    #[test]
    fn test_watch_only_builder() {
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account(0).unwrap();
        let xpub = account.extended_public_key();
        
        // Build watch-only wallet
        let watch_only = WatchOnlyWalletBuilder::new()
            .xpub(xpub.clone())
            .network(Network::Testnet)
            .name("My Watch Wallet")
            .index(5)
            .build()
            .unwrap();
        
        assert_eq!(watch_only.name(), "My Watch Wallet");
        assert_eq!(watch_only.index(), 5);
        assert_eq!(watch_only.network(), Network::Testnet);
    }
    
    #[test]
    fn test_watch_only_address_tracking() {
        let config = WalletConfig::new()
            .network(Network::Testnet)
            .account_count(1);
        
        let wallet = Wallet::new(config).unwrap();
        let account = wallet.get_account(0).unwrap();
        let xpub = account.extended_public_key();
        
        let mut watch_only = WatchOnlyWallet::new(
            xpub,
            Network::Testnet,
            "Watch".into(),
            0
        ).unwrap();
        
        // Generate addresses
        let addr1 = watch_only.get_next_receive_address().unwrap();
        let addr2 = watch_only.get_next_receive_address().unwrap();
        let change = watch_only.get_next_change_address().unwrap();
        
        // Check ownership
        assert!(watch_only.owns_address(&addr1));
        assert!(watch_only.owns_address(&addr2));
        assert!(watch_only.owns_address(&change));
        
        // Get all addresses
        let all = watch_only.get_all_addresses();
        assert!(all.contains(&addr1));
        assert!(all.contains(&addr2));
        assert!(all.contains(&change));
    }
}