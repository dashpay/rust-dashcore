//! Collection of managed accounts organized by network
//!
//! This module provides a structure for managing multiple accounts
//! across different networks in a hierarchical manner.

use super::account_collection::AccountCollection;
use super::address_pool::AddressPool;
use super::managed_account::ManagedAccount;
use super::types::{AccountType, ManagedAccountType};
use crate::gap_limit::GapLimitManager;
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Collection of managed accounts organized by type
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedAccountCollection {
    /// Standard BIP44 accounts by index
    pub standard_bip44_accounts: BTreeMap<u32, ManagedAccount>,
    /// Standard BIP32 accounts by index
    pub standard_bip32_accounts: BTreeMap<u32, ManagedAccount>,
    /// CoinJoin accounts by index
    pub coinjoin_accounts: BTreeMap<u32, ManagedAccount>,
    /// Identity registration account (optional)
    pub identity_registration: Option<ManagedAccount>,
    /// Identity top-up accounts by registration index
    pub identity_topup: BTreeMap<u32, ManagedAccount>,
    /// Identity top-up not bound to identity (optional)
    pub identity_topup_not_bound: Option<ManagedAccount>,
    /// Identity invitation account (optional)
    pub identity_invitation: Option<ManagedAccount>,
    /// Provider voting keys (optional)
    pub provider_voting_keys: Option<ManagedAccount>,
    /// Provider owner keys (optional)
    pub provider_owner_keys: Option<ManagedAccount>,
    /// Provider operator keys (optional)
    pub provider_operator_keys: Option<ManagedAccount>,
    /// Provider platform keys (optional)
    pub provider_platform_keys: Option<ManagedAccount>,
}

impl ManagedAccountCollection {
    /// Create a new empty account collection
    pub fn new() -> Self {
        Self {
            standard_bip44_accounts: BTreeMap::new(),
            standard_bip32_accounts: BTreeMap::new(),
            coinjoin_accounts: BTreeMap::new(),
            identity_registration: None,
            identity_topup: BTreeMap::new(),
            identity_topup_not_bound: None,
            identity_invitation: None,
            provider_voting_keys: None,
            provider_owner_keys: None,
            provider_operator_keys: None,
            provider_platform_keys: None,
        }
    }

    /// Create a ManagedAccountCollection from an AccountCollection
    /// This properly initializes ManagedAccounts for each Account in the collection
    pub fn from_account_collection(account_collection: &AccountCollection) -> Self {
        let mut managed_collection = Self::new();

        // Convert standard BIP44 accounts
        for (index, account) in &account_collection.standard_bip44_accounts {
            let managed_account = Self::create_managed_account_from_account(account);
            managed_collection.standard_bip44_accounts.insert(*index, managed_account);
        }

        // Convert standard BIP32 accounts
        for (index, account) in &account_collection.standard_bip32_accounts {
            let managed_account = Self::create_managed_account_from_account(account);
            managed_collection.standard_bip32_accounts.insert(*index, managed_account);
        }

        // Convert CoinJoin accounts
        for (index, account) in &account_collection.coinjoin_accounts {
            let managed_account = Self::create_managed_account_from_account(account);
            managed_collection.coinjoin_accounts.insert(*index, managed_account);
        }

        // Convert special purpose accounts
        if let Some(account) = &account_collection.identity_registration {
            managed_collection.identity_registration =
                Some(Self::create_managed_account_from_account(account));
        }

        for (index, account) in &account_collection.identity_topup {
            let managed_account = Self::create_managed_account_from_account(account);
            managed_collection.identity_topup.insert(*index, managed_account);
        }

        if let Some(account) = &account_collection.identity_topup_not_bound {
            managed_collection.identity_topup_not_bound =
                Some(Self::create_managed_account_from_account(account));
        }

        if let Some(account) = &account_collection.identity_invitation {
            managed_collection.identity_invitation =
                Some(Self::create_managed_account_from_account(account));
        }

        if let Some(account) = &account_collection.provider_voting_keys {
            managed_collection.provider_voting_keys =
                Some(Self::create_managed_account_from_account(account));
        }

        if let Some(account) = &account_collection.provider_owner_keys {
            managed_collection.provider_owner_keys =
                Some(Self::create_managed_account_from_account(account));
        }

        if let Some(account) = &account_collection.provider_operator_keys {
            managed_collection.provider_operator_keys =
                Some(Self::create_managed_account_from_account(account));
        }

        if let Some(account) = &account_collection.provider_platform_keys {
            managed_collection.provider_platform_keys =
                Some(Self::create_managed_account_from_account(account));
        }

        managed_collection
    }

    /// Create a ManagedAccount from an Account
    fn create_managed_account_from_account(account: &super::Account) -> ManagedAccount {
        Self::create_managed_account_from_account_type(
            account.account_type,
            account.network,
            account.is_watch_only,
        )
    }

    /// Create a ManagedAccount from an Account type with network and watch-only status
    fn create_managed_account_from_account_type(
        account_type: AccountType,
        network: Network,
        is_watch_only: bool,
    ) -> ManagedAccount {
        // Get the derivation path for this account type
        let base_path = account_type
            .derivation_path(network)
            .unwrap_or_else(|_| crate::bip32::DerivationPath::master());

        // Create the appropriate ManagedAccountType with address pools
        let managed_type = match account_type {
            AccountType::Standard {
                index,
                standard_account_type,
            } => {
                // For standard accounts, add the receive/change branch to the path
                let mut external_path = base_path.clone();
                external_path.push(crate::bip32::ChildNumber::from_normal_idx(0).unwrap()); // 0 for external
                let external_pool = AddressPool::new(external_path, false, 20, network);

                let mut internal_path = base_path;
                internal_path.push(crate::bip32::ChildNumber::from_normal_idx(1).unwrap()); // 1 for internal
                let internal_pool = AddressPool::new(internal_path, true, 20, network);

                let managed_standard_type = standard_account_type;

                ManagedAccountType::Standard {
                    index,
                    standard_account_type: managed_standard_type,
                    external_addresses: external_pool,
                    internal_addresses: internal_pool,
                }
            }
            AccountType::CoinJoin {
                index,
            } => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::CoinJoin {
                    index,
                    addresses,
                }
            }
            AccountType::IdentityRegistration => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::IdentityRegistration {
                    addresses,
                }
            }
            AccountType::IdentityTopUp {
                registration_index,
            } => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::IdentityTopUp {
                    registration_index,
                    addresses,
                }
            }
            AccountType::IdentityTopUpNotBoundToIdentity => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                    addresses,
                }
            }
            AccountType::IdentityInvitation => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::IdentityInvitation {
                    addresses,
                }
            }
            AccountType::ProviderVotingKeys => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::ProviderVotingKeys {
                    addresses,
                }
            }
            AccountType::ProviderOwnerKeys => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::ProviderOwnerKeys {
                    addresses,
                }
            }
            AccountType::ProviderOperatorKeys => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::ProviderOperatorKeys {
                    addresses,
                }
            }
            AccountType::ProviderPlatformKeys => {
                let addresses = AddressPool::new(base_path, false, 20, network);
                ManagedAccountType::ProviderPlatformKeys {
                    addresses,
                }
            }
        };

        ManagedAccount::new(managed_type, network, GapLimitManager::default(), is_watch_only)
    }

    /// Insert an account into the collection
    pub fn insert(&mut self, account: ManagedAccount) {
        use super::types::{ManagedAccountType, StandardAccountType};

        match &account.account_type {
            ManagedAccountType::Standard {
                index,
                standard_account_type,
                ..
            } => match standard_account_type {
                StandardAccountType::BIP44Account => {
                    self.standard_bip44_accounts.insert(*index, account);
                }
                StandardAccountType::BIP32Account => {
                    self.standard_bip32_accounts.insert(*index, account);
                }
            },
            ManagedAccountType::CoinJoin {
                index,
                ..
            } => {
                self.coinjoin_accounts.insert(*index, account);
            }
            ManagedAccountType::IdentityRegistration {
                ..
            } => {
                self.identity_registration = Some(account);
            }
            ManagedAccountType::IdentityTopUp {
                registration_index,
                ..
            } => {
                self.identity_topup.insert(*registration_index, account);
            }
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                ..
            } => {
                self.identity_topup_not_bound = Some(account);
            }
            ManagedAccountType::IdentityInvitation {
                ..
            } => {
                self.identity_invitation = Some(account);
            }
            ManagedAccountType::ProviderVotingKeys {
                ..
            } => {
                self.provider_voting_keys = Some(account);
            }
            ManagedAccountType::ProviderOwnerKeys {
                ..
            } => {
                self.provider_owner_keys = Some(account);
            }
            ManagedAccountType::ProviderOperatorKeys {
                ..
            } => {
                self.provider_operator_keys = Some(account);
            }
            ManagedAccountType::ProviderPlatformKeys {
                ..
            } => {
                self.provider_platform_keys = Some(account);
            }
        }
    }

    /// Get an account by index
    pub fn get(&self, index: u32) -> Option<&ManagedAccount> {
        // Try standard BIP44 first
        if let Some(account) = self.standard_bip44_accounts.get(&index) {
            return Some(account);
        }

        // Try standard BIP32
        if let Some(account) = self.standard_bip32_accounts.get(&index) {
            return Some(account);
        }

        // Try CoinJoin
        if let Some(account) = self.coinjoin_accounts.get(&index) {
            return Some(account);
        }

        // For identity top-up with registration index
        if let Some(account) = self.identity_topup.get(&index) {
            return Some(account);
        }

        None
    }

    /// Get a mutable account by index
    pub fn get_mut(&mut self, index: u32) -> Option<&mut ManagedAccount> {
        // Try standard BIP44 first
        if let Some(account) = self.standard_bip44_accounts.get_mut(&index) {
            return Some(account);
        }

        // Try standard BIP32
        if let Some(account) = self.standard_bip32_accounts.get_mut(&index) {
            return Some(account);
        }

        // Try CoinJoin
        if let Some(account) = self.coinjoin_accounts.get_mut(&index) {
            return Some(account);
        }

        // For identity top-up with registration index
        if let Some(account) = self.identity_topup.get_mut(&index) {
            return Some(account);
        }

        None
    }

    /// Remove an account from the collection
    pub fn remove(&mut self, index: u32) -> Option<ManagedAccount> {
        // Try standard BIP44 first
        if let Some(account) = self.standard_bip44_accounts.remove(&index) {
            return Some(account);
        }

        // Try standard BIP32
        if let Some(account) = self.standard_bip32_accounts.remove(&index) {
            return Some(account);
        }

        // Try CoinJoin
        if let Some(account) = self.coinjoin_accounts.remove(&index) {
            return Some(account);
        }

        // For identity top-up with registration index
        if let Some(account) = self.identity_topup.remove(&index) {
            return Some(account);
        }

        None
    }

    /// Check if an account exists
    pub fn contains_key(&self, index: u32) -> bool {
        // Check standard BIP44
        if self.standard_bip44_accounts.contains_key(&index) {
            return true;
        }

        // Check standard BIP32
        if self.standard_bip32_accounts.contains_key(&index) {
            return true;
        }

        // Check CoinJoin
        if self.coinjoin_accounts.contains_key(&index) {
            return true;
        }

        // Check identity top-up with registration index
        if self.identity_topup.contains_key(&index) {
            return true;
        }

        false
    }

    /// Get all accounts
    pub fn all_accounts(&self) -> Vec<&ManagedAccount> {
        let mut accounts = Vec::new();

        // Add standard BIP44 accounts
        accounts.extend(self.standard_bip44_accounts.values());

        // Add standard BIP32 accounts
        accounts.extend(self.standard_bip32_accounts.values());

        // Add CoinJoin accounts
        accounts.extend(self.coinjoin_accounts.values());

        // Add special purpose accounts
        if let Some(account) = &self.identity_registration {
            accounts.push(account);
        }

        accounts.extend(self.identity_topup.values());

        if let Some(account) = &self.identity_topup_not_bound {
            accounts.push(account);
        }

        if let Some(account) = &self.identity_invitation {
            accounts.push(account);
        }

        if let Some(account) = &self.provider_voting_keys {
            accounts.push(account);
        }

        if let Some(account) = &self.provider_owner_keys {
            accounts.push(account);
        }

        if let Some(account) = &self.provider_operator_keys {
            accounts.push(account);
        }

        if let Some(account) = &self.provider_platform_keys {
            accounts.push(account);
        }

        accounts
    }

    /// Get all accounts mutably
    pub fn all_accounts_mut(&mut self) -> Vec<&mut ManagedAccount> {
        let mut accounts = Vec::new();

        // Add standard BIP44 accounts
        accounts.extend(self.standard_bip44_accounts.values_mut());

        // Add standard BIP32 accounts
        accounts.extend(self.standard_bip32_accounts.values_mut());

        // Add CoinJoin accounts
        accounts.extend(self.coinjoin_accounts.values_mut());

        // Add special purpose accounts
        if let Some(account) = &mut self.identity_registration {
            accounts.push(account);
        }

        accounts.extend(self.identity_topup.values_mut());

        if let Some(account) = &mut self.identity_topup_not_bound {
            accounts.push(account);
        }

        if let Some(account) = &mut self.identity_invitation {
            accounts.push(account);
        }

        if let Some(account) = &mut self.provider_voting_keys {
            accounts.push(account);
        }

        if let Some(account) = &mut self.provider_owner_keys {
            accounts.push(account);
        }

        if let Some(account) = &mut self.provider_operator_keys {
            accounts.push(account);
        }

        if let Some(account) = &mut self.provider_platform_keys {
            accounts.push(account);
        }

        accounts
    }

    /// Get the count of accounts
    pub fn count(&self) -> usize {
        self.all_accounts().len()
    }

    /// Get all account indices
    pub fn all_indices(&self) -> Vec<u32> {
        let mut indices = Vec::new();

        // Add standard BIP44 indices
        indices.extend(self.standard_bip44_accounts.keys().copied());

        // Add standard BIP32 indices
        indices.extend(self.standard_bip32_accounts.keys().copied());

        // Add CoinJoin indices
        indices.extend(self.coinjoin_accounts.keys().copied());

        // Add identity top-up registration indices
        indices.extend(self.identity_topup.keys().copied());

        indices
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.standard_bip44_accounts.is_empty()
            && self.standard_bip32_accounts.is_empty()
            && self.coinjoin_accounts.is_empty()
            && self.identity_registration.is_none()
            && self.identity_topup.is_empty()
            && self.identity_topup_not_bound.is_none()
            && self.identity_invitation.is_none()
            && self.provider_voting_keys.is_none()
            && self.provider_owner_keys.is_none()
            && self.provider_operator_keys.is_none()
            && self.provider_platform_keys.is_none()
    }

    /// Clear all accounts
    pub fn clear(&mut self) {
        self.standard_bip44_accounts.clear();
        self.standard_bip32_accounts.clear();
        self.coinjoin_accounts.clear();
        self.identity_registration = None;
        self.identity_topup.clear();
        self.identity_topup_not_bound = None;
        self.identity_invitation = None;
        self.provider_voting_keys = None;
        self.provider_owner_keys = None;
        self.provider_operator_keys = None;
        self.provider_platform_keys = None;
    }

    /// Check if a transaction belongs to any accounts in this collection
    pub fn check_transaction(
        &self,
        tx: &dashcore::blockdata::transaction::Transaction,
        account_types: &[crate::transaction_checking::transaction_router::AccountTypeToCheck],
    ) -> crate::transaction_checking::account_checker::TransactionCheckResult {
        use crate::transaction_checking::account_checker::AccountTransactionChecker;
        AccountTransactionChecker::check_transaction(self, tx, account_types)
    }
}
