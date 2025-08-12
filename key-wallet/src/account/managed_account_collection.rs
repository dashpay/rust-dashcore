//! Collection of managed accounts organized by network
//!
//! This module provides a structure for managing multiple accounts
//! across different networks in a hierarchical manner.

use super::managed_account::ManagedAccount;
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Collection of managed accounts organized by network
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedAccountCollection {
    /// Accounts organized by network and then by index
    accounts: BTreeMap<Network, BTreeMap<u32, ManagedAccount>>,
}

impl ManagedAccountCollection {
    /// Create a new empty account collection
    pub fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
        }
    }

    /// Insert an account into the collection
    pub fn insert(&mut self, network: Network, index: u32, account: ManagedAccount) {
        self.accounts.entry(network).or_insert_with(BTreeMap::new).insert(index, account);
    }

    /// Get an account by network and index
    pub fn get(&self, network: Network, index: u32) -> Option<&ManagedAccount> {
        self.accounts.get(&network).and_then(|accounts| accounts.get(&index))
    }

    /// Get a mutable account by network and index
    pub fn get_mut(&mut self, network: Network, index: u32) -> Option<&mut ManagedAccount> {
        self.accounts.get_mut(&network).and_then(|accounts| accounts.get_mut(&index))
    }

    /// Remove an account from the collection
    pub fn remove(&mut self, network: Network, index: u32) -> Option<ManagedAccount> {
        self.accounts.get_mut(&network).and_then(|accounts| accounts.remove(&index))
    }

    /// Check if an account exists
    pub fn contains_key(&self, network: Network, index: u32) -> bool {
        self.accounts.get(&network).map(|accounts| accounts.contains_key(&index)).unwrap_or(false)
    }

    /// Get all accounts for a network
    pub fn network_accounts(&self, network: Network) -> Vec<&ManagedAccount> {
        self.accounts.get(&network).map(|accounts| accounts.values().collect()).unwrap_or_default()
    }

    /// Get all accounts for a network mutably
    pub fn network_accounts_mut(&mut self, network: Network) -> Vec<&mut ManagedAccount> {
        self.accounts
            .get_mut(&network)
            .map(|accounts| accounts.values_mut().collect())
            .unwrap_or_default()
    }

    /// Get the count of accounts for a network
    pub fn network_count(&self, network: Network) -> usize {
        self.accounts.get(&network).map(|accounts| accounts.len()).unwrap_or(0)
    }

    /// Get all account indices for a network
    pub fn network_indices(&self, network: Network) -> Vec<u32> {
        self.accounts
            .get(&network)
            .map(|accounts| accounts.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Get all accounts across all networks
    pub fn all_accounts(&self) -> Vec<&ManagedAccount> {
        self.accounts.values().flat_map(|accounts| accounts.values()).collect()
    }

    /// Get all accounts across all networks mutably
    pub fn all_accounts_mut(&mut self) -> Vec<&mut ManagedAccount> {
        self.accounts.values_mut().flat_map(|accounts| accounts.values_mut()).collect()
    }

    /// Get total count of all accounts
    pub fn total_count(&self) -> usize {
        self.accounts.values().map(|accounts| accounts.len()).sum()
    }

    /// Get all indices across all networks
    pub fn all_indices(&self) -> Vec<(Network, u32)> {
        let mut indices = Vec::new();
        for (network, accounts) in &self.accounts {
            for index in accounts.keys() {
                indices.push((*network, *index));
            }
        }
        indices
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() || self.accounts.values().all(|accounts| accounts.is_empty())
    }

    /// Clear all accounts
    pub fn clear(&mut self) {
        self.accounts.clear();
    }

    /// Get the networks present in the collection
    pub fn networks(&self) -> Vec<Network> {
        self.accounts.keys().copied().collect()
    }
}
