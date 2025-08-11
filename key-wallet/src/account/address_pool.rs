//! Address pool management for HD wallets
//!
//! This module provides comprehensive address pool management including
//! generation, usage tracking, and discovery.

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use core::fmt;
use secp256k1::Secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::error::{Error, Result};
use crate::Network;
use dashcore::{Address, AddressType};

/// Key source for address derivation
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum KeySource {
    /// Private key for full wallet
    Private(ExtendedPrivKey),
    /// Public key for watch-only wallet
    Public(ExtendedPubKey),
}

impl KeySource {
    /// Derive a child key at the given path
    pub fn derive_at_path(&self, path: &DerivationPath) -> Result<ExtendedPubKey> {
        let secp = Secp256k1::new();
        match self {
            KeySource::Private(xprv) => {
                let child = xprv.derive_priv(&secp, path).map_err(Error::Bip32)?;
                Ok(ExtendedPubKey::from_priv(&secp, &child))
            }
            KeySource::Public(xpub) => xpub.derive_pub(&secp, path).map_err(Error::Bip32),
        }
    }

    /// Check if this is a watch-only key source
    pub fn is_watch_only(&self) -> bool {
        matches!(self, KeySource::Public(_))
    }
}

/// Information about a single address in the pool
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AddressInfo {
    /// The address
    pub address: Address,
    /// Derivation index
    pub index: u32,
    /// Full derivation path
    pub path: DerivationPath,
    /// Whether this address has been used
    pub used: bool,
    /// When the address was first generated (timestamp)
    pub generated_at: u64,
    /// When the address was first used (timestamp)
    pub used_at: Option<u64>,
    /// Transaction count for this address
    pub tx_count: u32,
    /// Total received amount
    pub total_received: u64,
    /// Total sent amount
    pub total_sent: u64,
    /// Current balance
    pub balance: u64,
    /// Custom label
    pub label: Option<String>,
    /// Custom metadata
    pub metadata: BTreeMap<String, String>,
}

impl AddressInfo {
    /// Create new address info
    fn new(address: Address, index: u32, path: DerivationPath) -> Self {
        Self {
            address,
            index,
            path,
            used: false,
            generated_at: 0, // Should use actual timestamp
            used_at: None,
            tx_count: 0,
            total_received: 0,
            total_sent: 0,
            balance: 0,
            label: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Mark this address as used
    fn mark_used(&mut self) {
        if !self.used {
            self.used = true;
            self.used_at = Some(0); // Should use actual timestamp
        }
    }

    /// Update transaction statistics
    pub fn update_stats(&mut self, received: u64, sent: u64) {
        self.total_received += received;
        self.total_sent += sent;
        self.tx_count += 1;
    }
}

/// Address pool for managing HD wallet addresses
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AddressPool {
    /// Base derivation path for this pool
    pub base_path: DerivationPath,
    /// Whether this is a change/internal address pool
    pub is_internal: bool,
    /// Gap limit for this pool
    pub gap_limit: u32,
    /// Network for address generation
    pub network: Network,
    /// All addresses in the pool
    addresses: BTreeMap<u32, AddressInfo>,
    /// Reverse lookup: address -> index
    address_index: HashMap<Address, u32>,
    /// Set of used address indices
    used_indices: HashSet<u32>,
    /// Highest generated index (None if no addresses generated yet)
    highest_generated: Option<u32>,
    /// Highest used index
    highest_used: Option<u32>,
    /// Lookahead window for performance
    lookahead_size: u32,
    /// Address type preference
    address_type: AddressType,
}

impl AddressPool {
    /// Create a new address pool
    pub fn new(
        base_path: DerivationPath,
        is_internal: bool,
        gap_limit: u32,
        network: Network,
    ) -> Self {
        Self {
            base_path,
            is_internal,
            gap_limit,
            network,
            addresses: BTreeMap::new(),
            address_index: HashMap::new(),
            used_indices: HashSet::new(),
            highest_generated: None,
            highest_used: None,
            lookahead_size: gap_limit * 2,
            address_type: AddressType::P2pkh,
        }
    }

    /// Set the address type for new addresses
    pub fn set_address_type(&mut self, address_type: AddressType) {
        self.address_type = address_type;
    }

    /// Generate addresses up to the specified count
    pub fn generate_addresses(
        &mut self,
        count: u32,
        key_source: &KeySource,
    ) -> Result<Vec<Address>> {
        let mut new_addresses = Vec::new();
        let start_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
        let end_index = start_index + count;

        for index in start_index..end_index {
            let address = self.generate_address_at_index(index, key_source)?;
            new_addresses.push(address);
        }

        Ok(new_addresses)
    }

    /// Generate a specific address at an index
    fn generate_address_at_index(&mut self, index: u32, key_source: &KeySource) -> Result<Address> {
        // Check if already generated
        if let Some(info) = self.addresses.get(&index) {
            return Ok(info.address.clone());
        }

        // Build the full path
        let mut full_path = self.base_path.clone();
        full_path.push(ChildNumber::from_normal_idx(index).map_err(Error::Bip32)?);

        // Derive the key
        let pubkey = key_source.derive_at_path(&full_path)?;

        // Generate the address
        let dash_pubkey = dashcore::PublicKey::new(pubkey.public_key);
        let network = dashcore::Network::from(self.network);
        let address = match self.address_type {
            AddressType::P2pkh => Address::p2pkh(&dash_pubkey, network),
            AddressType::P2sh => {
                // For P2SH, we'd need script information
                // For now, default to P2PKH
                Address::p2pkh(&dash_pubkey, network)
            }
        };

        // Store the address info
        let info = AddressInfo::new(address.clone(), index, full_path);
        self.addresses.insert(index, info);
        self.address_index.insert(address.clone(), index);

        // Update highest generated
        if self.highest_generated.map(|h| index > h).unwrap_or(true) {
            self.highest_generated = Some(index);
        }

        Ok(address)
    }

    /// Get the next unused address
    pub fn get_next_unused(&mut self, key_source: &KeySource) -> Result<Address> {
        // First, try to find an already generated unused address
        for i in 0..=self.highest_generated.unwrap_or(0) {
            if let Some(info) = self.addresses.get(&i) {
                if !info.used {
                    return Ok(info.address.clone());
                }
            }
        }

        // Generate a new address
        let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
        self.generate_address_at_index(next_index, key_source)
    }

    /// Get multiple unused addresses
    pub fn get_unused_addresses_count(
        &mut self,
        count: u32,
        key_source: &KeySource,
    ) -> Result<Vec<Address>> {
        let mut unused = Vec::new();
        let mut current_index = 0;

        // Collect existing unused addresses
        while unused.len() < count as usize
            && self.highest_generated.map(|h| current_index <= h).unwrap_or(false)
        {
            if let Some(info) = self.addresses.get(&current_index) {
                if !info.used {
                    unused.push(info.address.clone());
                }
            }
            current_index += 1;
        }

        // Generate more if needed
        while unused.len() < count as usize {
            let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
            let address = self.generate_address_at_index(next_index, key_source)?;
            unused.push(address);
        }

        Ok(unused)
    }

    /// Mark an address as used
    pub fn mark_used(&mut self, address: &Address) -> bool {
        if let Some(&index) = self.address_index.get(address) {
            if let Some(info) = self.addresses.get_mut(&index) {
                if !info.used {
                    info.mark_used();
                    self.used_indices.insert(index);

                    // Update highest used
                    self.highest_used = match self.highest_used {
                        None => Some(index),
                        Some(current) => Some(current.max(index)),
                    };

                    return true;
                }
            }
        }
        false
    }

    /// Mark an address at a specific index as used
    pub fn mark_index_used(&mut self, index: u32) -> bool {
        if let Some(info) = self.addresses.get_mut(&index) {
            if !info.used {
                info.mark_used();
                self.used_indices.insert(index);

                // Update highest used
                self.highest_used = match self.highest_used {
                    None => Some(index),
                    Some(current) => Some(current.max(index)),
                };

                return true;
            }
        }
        false
    }

    /// Scan addresses for usage using a check function
    pub fn scan_for_usage<F>(&mut self, check_fn: F) -> Vec<Address>
    where
        F: Fn(&Address) -> bool,
    {
        let mut found = Vec::new();

        for (_, info) in self.addresses.iter_mut() {
            if !info.used && check_fn(&info.address) {
                info.mark_used();
                self.used_indices.insert(info.index);
                found.push(info.address.clone());

                // Update highest used
                self.highest_used = match self.highest_used {
                    None => Some(info.index),
                    Some(current) => Some(current.max(info.index)),
                };
            }
        }

        found
    }

    /// Get all addresses in the pool
    pub fn get_all_addresses(&self) -> Vec<Address> {
        self.addresses.values().map(|info| info.address.clone()).collect()
    }

    /// Get only used addresses
    pub fn get_used_addresses(&self) -> Vec<Address> {
        self.addresses.values().filter(|info| info.used).map(|info| info.address.clone()).collect()
    }

    /// Get only unused addresses
    pub fn get_unused_addresses(&self) -> Vec<Address> {
        self.addresses.values().filter(|info| !info.used).map(|info| info.address.clone()).collect()
    }

    /// Get address at specific index
    pub fn get_address_at_index(&self, index: u32) -> Option<Address> {
        self.addresses.get(&index).map(|info| info.address.clone())
    }

    /// Get address info by address
    pub fn get_address_info(&self, address: &Address) -> Option<&AddressInfo> {
        self.address_index.get(address).and_then(|&index| self.addresses.get(&index))
    }

    /// Get mutable address info by address
    pub fn get_address_info_mut(&mut self, address: &Address) -> Option<&mut AddressInfo> {
        if let Some(&index) = self.address_index.get(address) {
            self.addresses.get_mut(&index)
        } else {
            None
        }
    }

    /// Get address info by index
    pub fn get_info_at_index(&self, index: u32) -> Option<&AddressInfo> {
        self.addresses.get(&index)
    }

    /// Get the index of an address
    pub fn get_address_index(&self, address: &Address) -> Option<u32> {
        self.address_index.get(address).copied()
    }

    /// Check if an address belongs to this pool
    pub fn contains_address(&self, address: &Address) -> bool {
        self.address_index.contains_key(address)
    }

    /// Check if we need to generate more addresses
    pub fn needs_more_addresses(&self) -> bool {
        let unused_count = self.addresses.values().filter(|info| !info.used).count() as u32;

        unused_count < self.gap_limit
    }

    /// Generate addresses to maintain the gap limit
    pub fn maintain_gap_limit(&mut self, key_source: &KeySource) -> Result<Vec<Address>> {
        let target = match self.highest_used {
            None => self.gap_limit,
            Some(highest) => highest + self.gap_limit + 1,
        };

        let mut new_addresses = Vec::new();
        while self.highest_generated.unwrap_or(0) < target {
            let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
            let address = self.generate_address_at_index(next_index, key_source)?;
            new_addresses.push(address);
        }

        Ok(new_addresses)
    }

    /// Generate lookahead addresses for performance
    pub fn generate_lookahead(&mut self, key_source: &KeySource) -> Result<Vec<Address>> {
        let target = match self.highest_used {
            None => self.lookahead_size,
            Some(highest) => highest + self.lookahead_size + 1,
        };

        let mut new_addresses = Vec::new();
        while self.highest_generated.unwrap_or(0) < target {
            let next_index = self.highest_generated.map(|h| h + 1).unwrap_or(0);
            let address = self.generate_address_at_index(next_index, key_source)?;
            new_addresses.push(address);
        }

        Ok(new_addresses)
    }

    /// Set a custom label for an address
    pub fn set_address_label(&mut self, address: &Address, label: String) -> bool {
        if let Some(info) = self.get_address_info_mut(address) {
            info.label = Some(label);
            true
        } else {
            false
        }
    }

    /// Add custom metadata to an address
    pub fn add_address_metadata(&mut self, address: &Address, key: String, value: String) -> bool {
        if let Some(info) = self.get_address_info_mut(address) {
            info.metadata.insert(key, value);
            true
        } else {
            false
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let used_count = self.used_indices.len() as u32;
        let unused_count = self.addresses.len() as u32 - used_count;

        PoolStats {
            total_generated: self.addresses.len() as u32,
            used_count,
            unused_count,
            highest_used: self.highest_used,
            highest_generated: self.highest_generated,
            gap_limit: self.gap_limit,
            is_internal: self.is_internal,
        }
    }

    /// Reset the pool (for rescan)
    pub fn reset_usage(&mut self) {
        for info in self.addresses.values_mut() {
            info.used = false;
            info.used_at = None;
            info.tx_count = 0;
            info.total_received = 0;
            info.total_sent = 0;
            info.balance = 0;
        }
        self.used_indices.clear();
        self.highest_used = None;
    }

    /// Prune unused addresses beyond the gap limit
    pub fn prune_unused(&mut self) -> u32 {
        let keep_until = match self.highest_used {
            None => self.gap_limit - 1, // Keep indices 0 to gap_limit-1
            Some(highest) => highest + self.gap_limit, // Keep up to highest + gap_limit
        };

        let mut pruned = 0;
        let indices_to_remove: Vec<u32> = self
            .addresses
            .keys()
            .filter(|&&idx| idx > keep_until && !self.used_indices.contains(&idx))
            .copied()
            .collect();

        for idx in indices_to_remove {
            if let Some(info) = self.addresses.remove(&idx) {
                self.address_index.remove(&info.address);
                pruned += 1;
            }
        }

        if let Some(&new_highest) = self.addresses.keys().max() {
            self.highest_generated = Some(new_highest);
        }

        pruned
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoolStats {
    /// Total addresses generated
    pub total_generated: u32,
    /// Number of used addresses
    pub used_count: u32,
    /// Number of unused addresses
    pub unused_count: u32,
    /// Highest used index
    pub highest_used: Option<u32>,
    /// Highest generated index (None if no addresses generated)
    pub highest_generated: Option<u32>,
    /// Gap limit
    pub gap_limit: u32,
    /// Whether this is an internal pool
    pub is_internal: bool,
}

impl fmt::Display for PoolStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} pool: {} addresses ({} used, {} unused), gap limit: {}",
            if self.is_internal {
                "Internal"
            } else {
                "External"
            },
            self.total_generated,
            self.used_count,
            self.unused_count,
            self.gap_limit
        )
    }
}

/// Builder for AddressPool
pub struct AddressPoolBuilder {
    base_path: Option<DerivationPath>,
    is_internal: bool,
    gap_limit: u32,
    network: Network,
    lookahead_size: u32,
    address_type: AddressType,
}

impl AddressPoolBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_path: None,
            is_internal: false,
            gap_limit: 20,
            network: Network::Dash,
            lookahead_size: 40,
            address_type: AddressType::P2pkh,
        }
    }

    /// Set the base derivation path
    pub fn base_path(mut self, path: DerivationPath) -> Self {
        self.base_path = Some(path);
        self
    }

    /// Set whether this is an internal (change) pool
    pub fn internal(mut self, is_internal: bool) -> Self {
        self.is_internal = is_internal;
        self
    }

    /// Set the gap limit
    pub fn gap_limit(mut self, limit: u32) -> Self {
        self.gap_limit = limit;
        self
    }

    /// Set the network
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set the lookahead size
    pub fn lookahead(mut self, size: u32) -> Self {
        self.lookahead_size = size;
        self
    }

    /// Set the address type
    pub fn address_type(mut self, addr_type: AddressType) -> Self {
        self.address_type = addr_type;
        self
    }

    /// Build the address pool
    pub fn build(self) -> Result<AddressPool> {
        let base_path =
            self.base_path.ok_or(Error::InvalidParameter("base_path required".into()))?;

        let mut pool = AddressPool::new(base_path, self.is_internal, self.gap_limit, self.network);
        pool.lookahead_size = self.lookahead_size;
        pool.address_type = self.address_type;

        Ok(pool)
    }
}

impl Default for AddressPoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::{Language, Mnemonic};

    fn test_key_source() -> KeySource {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_key = master.derive_priv(&secp, &path).unwrap();

        KeySource::Private(account_key)
    }

    #[test]
    fn test_address_pool_generation() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 20, Network::Testnet);
        let key_source = test_key_source();

        let addresses = pool.generate_addresses(10, &key_source).unwrap();
        assert_eq!(addresses.len(), 10);
        assert_eq!(pool.highest_generated, Some(9));
        assert_eq!(pool.addresses.len(), 10);
    }

    #[test]
    fn test_address_usage() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 5, Network::Testnet);
        let key_source = test_key_source();

        let addresses = pool.generate_addresses(5, &key_source).unwrap();
        let first_addr = &addresses[0];

        assert!(pool.mark_used(first_addr));
        assert_eq!(pool.used_indices.len(), 1);
        assert_eq!(pool.highest_used, Some(0));

        let used = pool.get_used_addresses();
        assert_eq!(used.len(), 1);
        assert_eq!(&used[0], first_addr);
    }

    #[test]
    fn test_next_unused() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 5, Network::Testnet);
        let key_source = test_key_source();

        let addr1 = pool.get_next_unused(&key_source).unwrap();
        let addr2 = pool.get_next_unused(&key_source).unwrap();
        assert_eq!(addr1, addr2); // Should return same unused address

        pool.mark_used(&addr1);
        let addr3 = pool.get_next_unused(&key_source).unwrap();
        assert_ne!(addr1, addr3); // Should return different address after marking used
    }

    #[test]
    fn test_gap_limit_maintenance() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 5, Network::Testnet);
        let key_source = test_key_source();

        // Generate initial addresses
        pool.generate_addresses(3, &key_source).unwrap();
        pool.mark_index_used(1);

        // Maintain gap limit
        let _new_addrs = pool.maintain_gap_limit(&key_source).unwrap();
        assert!(pool.highest_generated.unwrap_or(0) >= 6); // Should have at least index 1 + gap limit 5
    }

    #[test]
    fn test_address_pool_builder() {
        let pool = AddressPoolBuilder::new()
            .base_path(DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]))
            .internal(true)
            .gap_limit(10)
            .network(Network::Testnet)
            .lookahead(20)
            .address_type(AddressType::P2PKH)
            .build()
            .unwrap();

        assert!(pool.is_internal);
        assert_eq!(pool.gap_limit, 10);
        assert_eq!(pool.network, Network::Testnet);
        assert_eq!(pool.lookahead_size, 20);
    }

    #[test]
    fn test_scan_for_usage() {
        let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let mut pool = AddressPool::new(base_path, false, 5, Network::Testnet);
        let key_source = test_key_source();

        let addresses = pool.generate_addresses(10, &key_source).unwrap();

        // Simulate checking for usage - mark addresses at indices 2, 5, 7 as used
        let check_fn = |addr: &Address| {
            addresses[2] == *addr || addresses[5] == *addr || addresses[7] == *addr
        };

        let found = pool.scan_for_usage(check_fn);
        assert_eq!(found.len(), 3);
        assert_eq!(pool.used_indices.len(), 3);
        assert_eq!(pool.highest_used, Some(7));
    }
}
