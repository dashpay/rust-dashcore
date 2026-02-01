//! Collection of managed accounts organized by network
//!
//! This module provides a structure for managing multiple accounts
//! across different networks in a hierarchical manner.

use crate::account::account_collection::{DashpayAccountKey, PlatformPaymentAccountKey};
use crate::account::account_type::AccountType;
use crate::gap_limit::{
    DEFAULT_COINJOIN_GAP_LIMIT, DEFAULT_EXTERNAL_GAP_LIMIT, DEFAULT_INTERNAL_GAP_LIMIT,
    DEFAULT_SPECIAL_GAP_LIMIT, DIP17_GAP_LIMIT,
};
use crate::managed_account::address_pool::{AddressPool, AddressPoolType};
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::managed_account::managed_platform_account::ManagedPlatformAccount;
use crate::managed_account::ManagedCoreAccount;
use crate::transaction_checking::account_checker::CoreAccountTypeMatch;
use crate::{Account, AccountCollection};
use crate::{KeySource, Network};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Collection of managed accounts organized by type
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManagedAccountCollection {
    /// Standard BIP44 accounts by index
    pub standard_bip44_accounts: BTreeMap<u32, ManagedCoreAccount>,
    /// Standard BIP32 accounts by index
    pub standard_bip32_accounts: BTreeMap<u32, ManagedCoreAccount>,
    /// CoinJoin accounts by index
    pub coinjoin_accounts: BTreeMap<u32, ManagedCoreAccount>,
    /// Identity registration account (optional)
    pub identity_registration: Option<ManagedCoreAccount>,
    /// Identity top-up accounts by registration index
    pub identity_topup: BTreeMap<u32, ManagedCoreAccount>,
    /// Identity top-up not bound to identity (optional)
    pub identity_topup_not_bound: Option<ManagedCoreAccount>,
    /// Identity invitation account (optional)
    pub identity_invitation: Option<ManagedCoreAccount>,
    /// Provider voting keys (optional)
    pub provider_voting_keys: Option<ManagedCoreAccount>,
    /// Provider owner keys (optional)
    pub provider_owner_keys: Option<ManagedCoreAccount>,
    /// Provider operator keys (optional)
    pub provider_operator_keys: Option<ManagedCoreAccount>,
    /// Provider platform keys (optional)
    pub provider_platform_keys: Option<ManagedCoreAccount>,
    /// DashPay receiving funds accounts keyed by (index, user_id, friend_id)
    pub dashpay_receival_accounts: BTreeMap<DashpayAccountKey, ManagedCoreAccount>,
    /// DashPay external accounts keyed by (index, user_id, friend_id)
    pub dashpay_external_accounts: BTreeMap<DashpayAccountKey, ManagedCoreAccount>,
    /// Platform Payment accounts (DIP-17)
    /// Uses ManagedPlatformAccount for simplified balance tracking without transactions/UTXOs
    pub platform_payment_accounts: BTreeMap<PlatformPaymentAccountKey, ManagedPlatformAccount>,
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
            dashpay_receival_accounts: BTreeMap::new(),
            dashpay_external_accounts: BTreeMap::new(),
            platform_payment_accounts: BTreeMap::new(),
        }
    }

    /// Check if a managed account type exists in the collection
    pub fn contains_managed_account_type(&self, managed_type: &ManagedAccountType) -> bool {
        use crate::account::StandardAccountType;

        match managed_type {
            ManagedAccountType::Standard {
                index,
                standard_account_type,
                ..
            } => match standard_account_type {
                StandardAccountType::BIP44Account => {
                    self.standard_bip44_accounts.contains_key(index)
                }
                StandardAccountType::BIP32Account => {
                    self.standard_bip32_accounts.contains_key(index)
                }
            },
            ManagedAccountType::CoinJoin {
                index,
                ..
            } => self.coinjoin_accounts.contains_key(index),
            ManagedAccountType::IdentityRegistration {
                ..
            } => self.identity_registration.is_some(),
            ManagedAccountType::IdentityTopUp {
                registration_index,
                ..
            } => self.identity_topup.contains_key(registration_index),
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                ..
            } => self.identity_topup_not_bound.is_some(),
            ManagedAccountType::IdentityInvitation {
                ..
            } => self.identity_invitation.is_some(),
            ManagedAccountType::ProviderVotingKeys {
                ..
            } => self.provider_voting_keys.is_some(),
            ManagedAccountType::ProviderOwnerKeys {
                ..
            } => self.provider_owner_keys.is_some(),
            ManagedAccountType::ProviderOperatorKeys {
                ..
            } => self.provider_operator_keys.is_some(),
            ManagedAccountType::ProviderPlatformKeys {
                ..
            } => self.provider_platform_keys.is_some(),
            ManagedAccountType::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
                ..
            } => {
                let key = DashpayAccountKey {
                    index: *index,
                    user_identity_id: *user_identity_id,
                    friend_identity_id: *friend_identity_id,
                };
                self.dashpay_receival_accounts.contains_key(&key)
            }
            ManagedAccountType::DashpayExternalAccount {
                index,
                user_identity_id,
                friend_identity_id,
                ..
            } => {
                let key = DashpayAccountKey {
                    index: *index,
                    user_identity_id: *user_identity_id,
                    friend_identity_id: *friend_identity_id,
                };
                self.dashpay_external_accounts.contains_key(&key)
            }
            ManagedAccountType::PlatformPayment {
                account,
                key_class,
                ..
            } => {
                let key = PlatformPaymentAccountKey {
                    account: *account,
                    key_class: *key_class,
                };
                self.platform_payment_accounts.contains_key(&key)
            }
        }
    }

    /// Insert a managed account into the collection
    pub fn insert(&mut self, account: ManagedCoreAccount) {
        use crate::account::StandardAccountType;

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
            ManagedAccountType::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
                ..
            } => {
                let key = DashpayAccountKey {
                    index: *index,
                    user_identity_id: *user_identity_id,
                    friend_identity_id: *friend_identity_id,
                };
                self.dashpay_receival_accounts.insert(key, account);
            }
            ManagedAccountType::DashpayExternalAccount {
                index,
                user_identity_id,
                friend_identity_id,
                ..
            } => {
                let key = DashpayAccountKey {
                    index: *index,
                    user_identity_id: *user_identity_id,
                    friend_identity_id: *friend_identity_id,
                };
                self.dashpay_external_accounts.insert(key, account);
            }
            ManagedAccountType::PlatformPayment {
                ..
            } => {
                // Platform Payment accounts should use insert_platform_account() instead
                // as they use ManagedPlatformAccount, not ManagedCoreAccount
                panic!("Use insert_platform_account() for Platform Payment accounts")
            }
        }
    }

    /// Insert a managed platform account into the collection
    pub fn insert_platform_account(&mut self, account: ManagedPlatformAccount) {
        let key = PlatformPaymentAccountKey {
            account: account.account,
            key_class: account.key_class,
        };
        self.platform_payment_accounts.insert(key, account);
    }

    /// Create a ManagedAccountCollection from an AccountCollection
    /// This properly initializes ManagedAccounts for each Account in the collection
    pub fn from_account_collection(account_collection: &AccountCollection) -> Self {
        let mut managed_collection = Self::new();

        // Convert standard BIP44 accounts
        for (index, account) in &account_collection.standard_bip44_accounts {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.standard_bip44_accounts.insert(*index, managed_account);
            }
        }

        // Convert standard BIP32 accounts
        for (index, account) in &account_collection.standard_bip32_accounts {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.standard_bip32_accounts.insert(*index, managed_account);
            }
        }

        // Convert CoinJoin accounts
        for (index, account) in &account_collection.coinjoin_accounts {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.coinjoin_accounts.insert(*index, managed_account);
            }
        }

        // Convert special purpose accounts
        if let Some(account) = &account_collection.identity_registration {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.identity_registration = Some(managed_account);
            }
        }

        for (index, account) in &account_collection.identity_topup {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.identity_topup.insert(*index, managed_account);
            }
        }

        if let Some(account) = &account_collection.identity_topup_not_bound {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.identity_topup_not_bound = Some(managed_account);
            }
        }

        if let Some(account) = &account_collection.identity_invitation {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.identity_invitation = Some(managed_account);
            }
        }

        if let Some(account) = &account_collection.provider_voting_keys {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.provider_voting_keys = Some(managed_account);
            }
        }

        if let Some(account) = &account_collection.provider_owner_keys {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.provider_owner_keys = Some(managed_account);
            }
        }

        #[cfg(feature = "bls")]
        if let Some(account) = &account_collection.provider_operator_keys {
            if let Ok(managed_account) = Self::create_managed_account_from_bls_account(account) {
                managed_collection.provider_operator_keys = Some(managed_account);
            }
        }

        #[cfg(feature = "eddsa")]
        if let Some(account) = &account_collection.provider_platform_keys {
            if let Ok(managed_account) =
                Self::create_managed_account_from_eddsa_account(account, None)
            {
                managed_collection.provider_platform_keys = Some(managed_account);
            }
        }

        // Convert DashPay receiving accounts
        for (key, account) in &account_collection.dashpay_receival_accounts {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.dashpay_receival_accounts.insert(*key, managed_account);
            }
        }

        // Convert DashPay external accounts
        for (key, account) in &account_collection.dashpay_external_accounts {
            if let Ok(managed_account) = Self::create_managed_account_from_account(account) {
                managed_collection.dashpay_external_accounts.insert(*key, managed_account);
            }
        }

        // Convert Platform Payment accounts
        for (key, account) in &account_collection.platform_payment_accounts {
            if let Ok(managed_account) =
                Self::create_managed_platform_account_from_account(account, key)
            {
                managed_collection.platform_payment_accounts.insert(*key, managed_account);
            }
        }

        managed_collection
    }

    /// Create a ManagedAccount from an Account
    fn create_managed_account_from_account(
        account: &Account,
    ) -> Result<ManagedCoreAccount, crate::error::Error> {
        // Use the account's existing public key
        let key_source = KeySource::Public(account.account_xpub);
        Self::create_managed_account_from_account_type(
            account.account_type,
            account.network,
            account.is_watch_only,
            &key_source,
        )
    }

    /// Create a ManagedAccount from a BLS Account
    #[cfg(feature = "bls")]
    fn create_managed_account_from_bls_account(
        account: &super::BLSAccount,
    ) -> Result<ManagedCoreAccount, crate::error::Error> {
        let key_source = KeySource::BLSPublic(account.bls_public_key.clone());
        Self::create_managed_account_from_account_type(
            account.account_type,
            account.network,
            account.is_watch_only,
            &key_source,
        )
    }

    /// Create a ManagedAccount from an EdDSA Account
    #[cfg(feature = "eddsa")]
    fn create_managed_account_from_eddsa_account(
        account: &super::EdDSAAccount,
        xpriv: Option<crate::derivation_slip10::ExtendedEd25519PrivKey>,
    ) -> Result<ManagedCoreAccount, crate::error::Error> {
        // EdDSA requires hardened derivation, so we need the private key to generate addresses
        let key_source = match xpriv {
            Some(priv_key) => KeySource::EdDSAPrivate(priv_key),
            None => KeySource::NoKeySource,
        };
        Self::create_managed_account_from_account_type(
            account.account_type,
            account.network,
            account.is_watch_only,
            &key_source,
        )
    }

    /// Create a ManagedAccount from an Account type with network and watch-only status
    fn create_managed_account_from_account_type(
        account_type: AccountType,
        network: Network,
        is_watch_only: bool,
        key_source: &KeySource,
    ) -> Result<ManagedCoreAccount, crate::error::Error> {
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
                external_path.push(crate::bip32::ChildNumber::from_normal_idx(0)?); // 0 for external
                let external_pool = AddressPool::new(
                    external_path,
                    AddressPoolType::External,
                    DEFAULT_EXTERNAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                let mut internal_path = base_path;
                internal_path.push(crate::bip32::ChildNumber::from_normal_idx(1)?); // 1 for internal
                let internal_pool = AddressPool::new(
                    internal_path,
                    AddressPoolType::Internal,
                    DEFAULT_INTERNAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

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
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_COINJOIN_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::CoinJoin {
                    index,
                    addresses,
                }
            }
            AccountType::IdentityRegistration => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::IdentityRegistration {
                    addresses,
                }
            }
            AccountType::IdentityTopUp {
                registration_index,
            } => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::IdentityTopUp {
                    registration_index,
                    addresses,
                }
            }
            AccountType::IdentityTopUpNotBoundToIdentity => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                    addresses,
                }
            }
            AccountType::IdentityInvitation => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::IdentityInvitation {
                    addresses,
                }
            }
            AccountType::ProviderVotingKeys => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::ProviderVotingKeys {
                    addresses,
                }
            }
            AccountType::ProviderOwnerKeys => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::ProviderOwnerKeys {
                    addresses,
                }
            }
            AccountType::ProviderOperatorKeys => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::ProviderOperatorKeys {
                    addresses,
                }
            }
            AccountType::ProviderPlatformKeys => {
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::AbsentHardened,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::ProviderPlatformKeys {
                    addresses,
                }
            }
            AccountType::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
            } => {
                let addresses =
                    AddressPool::new(base_path, AddressPoolType::Absent, 20, network, key_source)?;
                ManagedAccountType::DashpayReceivingFunds {
                    index,
                    user_identity_id,
                    friend_identity_id,
                    addresses,
                }
            }
            AccountType::DashpayExternalAccount {
                index,
                user_identity_id,
                friend_identity_id,
            } => {
                let addresses =
                    AddressPool::new(base_path, AddressPoolType::Absent, 20, network, key_source)?;
                ManagedAccountType::DashpayExternalAccount {
                    index,
                    user_identity_id,
                    friend_identity_id,
                    addresses,
                }
            }
            AccountType::PlatformPayment {
                account,
                key_class,
            } => {
                // DIP-17/DIP-18: Platform Payment addresses
                let addresses = AddressPool::new(
                    base_path,
                    AddressPoolType::Absent,
                    DIP17_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                ManagedAccountType::PlatformPayment {
                    account,
                    key_class,
                    addresses,
                }
            }
        };

        Ok(ManagedCoreAccount::new(managed_type, network, is_watch_only))
    }

    /// Create a ManagedPlatformAccount from an Account for Platform Payment accounts
    fn create_managed_platform_account_from_account(
        account: &Account,
        key: &PlatformPaymentAccountKey,
    ) -> Result<ManagedPlatformAccount, crate::error::Error> {
        // Use the account's existing public key
        let key_source = KeySource::Public(account.account_xpub);

        // Get the derivation path for this account type
        let base_path = account
            .account_type
            .derivation_path(account.network)
            .unwrap_or_else(|_| crate::bip32::DerivationPath::master());

        // Create address pool for DIP-17 Platform Payment addresses
        let addresses = AddressPool::new(
            base_path,
            AddressPoolType::Absent,
            DIP17_GAP_LIMIT,
            account.network,
            &key_source,
        )?;

        Ok(ManagedPlatformAccount::new(
            key.account,
            key.key_class,
            addresses,
            account.is_watch_only,
        ))
    }

    pub fn get(&self, index: u32) -> Option<&ManagedCoreAccount> {
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
    pub fn get_mut(&mut self, index: u32) -> Option<&mut ManagedCoreAccount> {
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

    /// Get an account reference by CoreAccountTypeMatch
    pub fn get_by_account_type_match(
        &self,
        account_type_match: &CoreAccountTypeMatch,
    ) -> Option<&ManagedCoreAccount> {
        match account_type_match {
            CoreAccountTypeMatch::StandardBIP44 {
                account_index,
                ..
            } => self.standard_bip44_accounts.get(account_index),
            CoreAccountTypeMatch::StandardBIP32 {
                account_index,
                ..
            } => self.standard_bip32_accounts.get(account_index),
            CoreAccountTypeMatch::CoinJoin {
                account_index,
                ..
            } => self.coinjoin_accounts.get(account_index),
            CoreAccountTypeMatch::IdentityRegistration {
                ..
            } => self.identity_registration.as_ref(),
            CoreAccountTypeMatch::IdentityTopUp {
                account_index,
                ..
            } => self.identity_topup.get(account_index),
            CoreAccountTypeMatch::IdentityTopUpNotBound {
                ..
            } => self.identity_topup_not_bound.as_ref(),
            CoreAccountTypeMatch::IdentityInvitation {
                ..
            } => self.identity_invitation.as_ref(),
            CoreAccountTypeMatch::ProviderVotingKeys {
                ..
            } => self.provider_voting_keys.as_ref(),
            CoreAccountTypeMatch::ProviderOwnerKeys {
                ..
            } => self.provider_owner_keys.as_ref(),
            CoreAccountTypeMatch::ProviderOperatorKeys {
                ..
            } => self.provider_operator_keys.as_ref(),
            CoreAccountTypeMatch::ProviderPlatformKeys {
                ..
            } => self.provider_platform_keys.as_ref(),
            CoreAccountTypeMatch::DashpayReceivingFunds {
                account_index,
                involved_addresses,
            } => {
                // Match by index and addresses since multiple accounts can share the same index
                self.dashpay_receival_accounts.values().find(|account| {
                    match &account.account_type {
                        ManagedAccountType::DashpayReceivingFunds {
                            index,
                            addresses,
                            ..
                        } => {
                            *index == *account_index
                                && involved_addresses
                                    .iter()
                                    .any(|addr| addresses.contains_address(&addr.address))
                        }
                        _ => false,
                    }
                })
            }
            CoreAccountTypeMatch::DashpayExternalAccount {
                account_index,
                involved_addresses,
            } => {
                // Match by index and addresses since multiple accounts can share the same index
                self.dashpay_external_accounts.values().find(|account| {
                    match &account.account_type {
                        ManagedAccountType::DashpayExternalAccount {
                            index,
                            addresses,
                            ..
                        } => {
                            *index == *account_index
                                && involved_addresses
                                    .iter()
                                    .any(|addr| addresses.contains_address(&addr.address))
                        }
                        _ => false,
                    }
                })
            }
        }
    }

    /// Remove an account from the collection
    pub fn remove(&mut self, index: u32) -> Option<ManagedCoreAccount> {
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
    pub fn all_accounts(&self) -> Vec<&ManagedCoreAccount> {
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

        // Add DashPay accounts
        accounts.extend(self.dashpay_receival_accounts.values());
        accounts.extend(self.dashpay_external_accounts.values());

        accounts
    }

    /// Get all accounts mutably
    pub fn all_accounts_mut(&mut self) -> Vec<&mut ManagedCoreAccount> {
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

        // Add DashPay accounts
        accounts.extend(self.dashpay_receival_accounts.values_mut());
        accounts.extend(self.dashpay_external_accounts.values_mut());

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
            && self.dashpay_receival_accounts.is_empty()
            && self.dashpay_external_accounts.is_empty()
            && self.platform_payment_accounts.is_empty()
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
        self.dashpay_receival_accounts.clear();
        self.dashpay_external_accounts.clear();
        self.platform_payment_accounts.clear();
    }

    /// Get all platform payment accounts
    pub fn all_platform_accounts(&self) -> Vec<&ManagedPlatformAccount> {
        self.platform_payment_accounts.values().collect()
    }

    /// Get all platform payment accounts mutably
    pub fn all_platform_accounts_mut(&mut self) -> Vec<&mut ManagedPlatformAccount> {
        self.platform_payment_accounts.values_mut().collect()
    }

    /// Get a platform payment account by key
    pub fn get_platform_account(
        &self,
        key: &PlatformPaymentAccountKey,
    ) -> Option<&ManagedPlatformAccount> {
        self.platform_payment_accounts.get(key)
    }

    /// Get a mutable platform payment account by key
    pub fn get_platform_account_mut(
        &mut self,
        key: &PlatformPaymentAccountKey,
    ) -> Option<&mut ManagedPlatformAccount> {
        self.platform_payment_accounts.get_mut(key)
    }
}
