//! Account collection management for wallets
//!
//! This module provides a structured way to manage accounts by type.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::account::Account;

/// Collection of accounts organized by type
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountCollection {
    /// Standard BIP44 accounts by index
    pub standard_bip44_accounts: BTreeMap<u32, Account>,
    /// Standard BIP32 accounts by index
    pub standard_bip32_accounts: BTreeMap<u32, Account>,
    /// CoinJoin accounts by index
    pub coinjoin_accounts: BTreeMap<u32, Account>,
    /// Identity registration account (optional)
    pub identity_registration: Option<Account>,
    /// Identity top-up accounts by registration index
    pub identity_topup: BTreeMap<u32, Account>,
    /// Identity top-up not bound to identity (optional)
    pub identity_topup_not_bound: Option<Account>,
    /// Identity invitation account (optional)
    pub identity_invitation: Option<Account>,
    /// Provider voting keys (optional)
    pub provider_voting_keys: Option<Account>,
    /// Provider owner keys (optional)
    pub provider_owner_keys: Option<Account>,
    /// Provider operator keys (optional)
    pub provider_operator_keys: Option<Account>,
    /// Provider platform keys (optional)
    pub provider_platform_keys: Option<Account>,
}

impl AccountCollection {
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

    /// Insert an account into the collection
    pub fn insert(&mut self, account: Account) {
        use crate::account::{AccountType, StandardAccountType};

        match &account.account_type {
            AccountType::Standard {
                index,
                standard_account_type,
            } => match standard_account_type {
                StandardAccountType::BIP44Account => {
                    self.standard_bip44_accounts.insert(*index, account);
                }
                StandardAccountType::BIP32Account => {
                    self.standard_bip32_accounts.insert(*index, account);
                }
            },
            AccountType::CoinJoin {
                index,
            } => {
                self.coinjoin_accounts.insert(*index, account);
            }
            AccountType::IdentityRegistration => {
                self.identity_registration = Some(account);
            }
            AccountType::IdentityTopUp {
                registration_index,
            } => {
                self.identity_topup.insert(*registration_index, account);
            }
            AccountType::IdentityTopUpNotBoundToIdentity => {
                self.identity_topup_not_bound = Some(account);
            }
            AccountType::IdentityInvitation => {
                self.identity_invitation = Some(account);
            }
            AccountType::ProviderVotingKeys => {
                self.provider_voting_keys = Some(account);
            }
            AccountType::ProviderOwnerKeys => {
                self.provider_owner_keys = Some(account);
            }
            AccountType::ProviderOperatorKeys => {
                self.provider_operator_keys = Some(account);
            }
            AccountType::ProviderPlatformKeys => {
                self.provider_platform_keys = Some(account);
            }
        }
    }

    /// Get an account by index (tries standard BIP44, BIP32, then CoinJoin)
    pub fn get(&self, index: u32) -> Option<&Account> {
        self.standard_bip44_accounts
            .get(&index)
            .or_else(|| self.standard_bip32_accounts.get(&index))
            .or_else(|| self.coinjoin_accounts.get(&index))
            .or_else(|| self.identity_topup.get(&index))
    }

    /// Get a mutable account by index
    pub fn get_mut(&mut self, index: u32) -> Option<&mut Account> {
        if let Some(account) = self.standard_bip44_accounts.get_mut(&index) {
            return Some(account);
        }
        if let Some(account) = self.standard_bip32_accounts.get_mut(&index) {
            return Some(account);
        }
        if let Some(account) = self.coinjoin_accounts.get_mut(&index) {
            return Some(account);
        }
        if let Some(account) = self.identity_topup.get_mut(&index) {
            return Some(account);
        }
        None
    }

    /// Remove an account from the collection
    pub fn remove(&mut self, index: u32) -> Option<Account> {
        self.standard_bip44_accounts
            .remove(&index)
            .or_else(|| self.standard_bip32_accounts.remove(&index))
            .or_else(|| self.coinjoin_accounts.remove(&index))
            .or_else(|| self.identity_topup.remove(&index))
    }

    /// Check if an account exists
    pub fn contains_key(&self, index: u32) -> bool {
        self.standard_bip44_accounts.contains_key(&index)
            || self.standard_bip32_accounts.contains_key(&index)
            || self.coinjoin_accounts.contains_key(&index)
            || self.identity_topup.contains_key(&index)
    }

    /// Get all accounts
    pub fn all_accounts(&self) -> Vec<&Account> {
        let mut accounts = Vec::new();

        accounts.extend(self.standard_bip44_accounts.values());
        accounts.extend(self.standard_bip32_accounts.values());
        accounts.extend(self.coinjoin_accounts.values());

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
    pub fn all_accounts_mut(&mut self) -> Vec<&mut Account> {
        let mut accounts = Vec::new();

        accounts.extend(self.standard_bip44_accounts.values_mut());
        accounts.extend(self.standard_bip32_accounts.values_mut());
        accounts.extend(self.coinjoin_accounts.values_mut());

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

        indices.extend(self.standard_bip44_accounts.keys().copied());
        indices.extend(self.standard_bip32_accounts.keys().copied());
        indices.extend(self.coinjoin_accounts.keys().copied());
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
}
