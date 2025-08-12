//! Account collection management for wallets
//!
//! This module provides a structured way to manage accounts across different networks.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::Network;

/// Collection of accounts organized by network
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountCollection {
    /// Accounts organized by network, then by index
    accounts: BTreeMap<Network, BTreeMap<u32, Account>>,
}

impl AccountCollection {
    /// Create a new empty account collection
    pub fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
        }
    }

    /// Insert an account for a specific network and index
    pub fn insert(&mut self, network: Network, index: u32, account: Account) {
        self.accounts.entry(network).or_default().insert(index, account);
    }

    /// Get an account by network and index
    pub fn get(&self, network: Network, index: u32) -> Option<&Account> {
        self.accounts.get(&network)?.get(&index)
    }

    /// Get a mutable account by network and index
    pub fn get_mut(&mut self, network: Network, index: u32) -> Option<&mut Account> {
        self.accounts.get_mut(&network)?.get_mut(&index)
    }

    /// Check if an account exists for a specific network and index
    pub fn contains_key(&self, network: Network, index: u32) -> bool {
        self.accounts
            .get(&network)
            .is_some_and(|network_accounts| network_accounts.contains_key(&index))
    }

    /// Get all accounts for a specific network
    pub fn get_network_accounts(&self, network: Network) -> Option<&BTreeMap<u32, Account>> {
        self.accounts.get(&network)
    }

    /// Get all accounts for a specific network (mutable)
    pub fn get_network_accounts_mut(
        &mut self,
        network: Network,
    ) -> Option<&mut BTreeMap<u32, Account>> {
        self.accounts.get_mut(&network)
    }

    /// Get all accounts across all networks
    pub fn all_accounts(&self) -> Vec<&Account> {
        let mut accounts = Vec::new();
        for network_accounts in self.accounts.values() {
            accounts.extend(network_accounts.values());
        }
        accounts
    }

    /// Get all accounts across all networks (mutable)
    pub fn all_accounts_mut(&mut self) -> Vec<&mut Account> {
        let mut accounts = Vec::new();
        for network_accounts in self.accounts.values_mut() {
            accounts.extend(network_accounts.values_mut());
        }
        accounts
    }

    /// Get total count of accounts across all networks
    pub fn total_count(&self) -> usize {
        self.accounts.values().map(|network_accounts| network_accounts.len()).sum()
    }

    /// Get count of accounts for a specific network
    pub fn network_count(&self, network: Network) -> usize {
        self.accounts.get(&network).map_or(0, |network_accounts| network_accounts.len())
    }

    /// Get all account indices for a specific network
    pub fn network_indices(&self, network: Network) -> Vec<u32> {
        self.accounts
            .get(&network)
            .map_or(Vec::new(), |network_accounts| network_accounts.keys().copied().collect())
    }

    /// Get all account indices across all networks
    pub fn all_indices(&self) -> Vec<(Network, u32)> {
        let mut indices = Vec::new();
        for (network, network_accounts) in &self.accounts {
            for index in network_accounts.keys() {
                indices.push((*network, *index));
            }
        }
        indices
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
            || self.accounts.values().all(|network_accounts| network_accounts.is_empty())
    }

    /// Get all networks that have accounts
    pub fn networks(&self) -> Vec<Network> {
        self.accounts.keys().copied().collect()
    }
}
