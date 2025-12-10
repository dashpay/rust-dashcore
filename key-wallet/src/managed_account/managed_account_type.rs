use crate::account::account_collection::{DashpayContactIdentityId, DashpayOurUserIdentityId};
use crate::account::StandardAccountType;
use crate::gap_limit::{
    DEFAULT_COINJOIN_GAP_LIMIT, DEFAULT_EXTERNAL_GAP_LIMIT, DEFAULT_INTERNAL_GAP_LIMIT,
    DEFAULT_SPECIAL_GAP_LIMIT, DIP17_GAP_LIMIT,
};

use crate::{AccountType, AddressPool, DerivationPath};
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use dashcore::ScriptBuf;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Managed account type with embedded address pools
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[allow(clippy::large_enum_variant)]
pub enum ManagedAccountType {
    /// Standard BIP44 account for regular transactions
    Standard {
        /// Account index
        index: u32,
        /// Standard account type (BIP44 or BIP32)
        standard_account_type: StandardAccountType,
        /// External (receive) address pool
        external_addresses: AddressPool,
        /// Internal (change) address pool
        internal_addresses: AddressPool,
    },
    /// CoinJoin account for private transactions
    CoinJoin {
        /// Account index
        index: u32,
        /// CoinJoin address pool
        addresses: AddressPool,
    },
    /// Identity registration funding
    IdentityRegistration {
        /// Identity registration address pool
        addresses: AddressPool,
    },
    /// Identity top-up funding
    IdentityTopUp {
        /// Registration index (which identity this is topping up)
        registration_index: u32,
        /// Identity top-up address pool
        addresses: AddressPool,
    },
    /// Identity top-up funding not bound to a specific identity
    IdentityTopUpNotBoundToIdentity {
        /// Identity top-up address pool
        addresses: AddressPool,
    },
    /// Identity invitation funding
    IdentityInvitation {
        /// Identity invitation address pool
        addresses: AddressPool,
    },
    /// Provider voting keys (DIP-3)
    /// Path: m/9'/5'/3'/1'/[key_index]
    ProviderVotingKeys {
        /// Provider voting keys address pool
        addresses: AddressPool,
    },
    /// Provider owner keys (DIP-3)
    /// Path: m/9'/5'/3'/2'/[key_index]
    ProviderOwnerKeys {
        /// Provider owner keys address pool
        addresses: AddressPool,
    },
    /// Provider operator keys (DIP-3)
    /// Path: m/9'/5'/3'/3'/[key_index]
    ProviderOperatorKeys {
        /// Provider operator keys address pool
        addresses: AddressPool,
    },
    /// Provider platform P2P keys (DIP-3, ED25519)
    /// Path: m/9'/5'/3'/4'/[key_index]
    ProviderPlatformKeys {
        /// Provider platform keys address pool
        addresses: AddressPool,
    },
    /// DashPay receiving funds account (single-pool)
    DashpayReceivingFunds {
        /// Account index
        index: u32,
        /// Our identity id
        user_identity_id: DashpayOurUserIdentityId,
        /// Contact identity id
        friend_identity_id: DashpayContactIdentityId,
        /// Address pool
        addresses: AddressPool,
    },
    /// DashPay external (watch-only) account (single-pool)
    DashpayExternalAccount {
        /// Account index
        index: u32,
        /// Our identity id
        user_identity_id: DashpayOurUserIdentityId,
        /// Contact identity id
        friend_identity_id: DashpayContactIdentityId,
        /// Address pool
        addresses: AddressPool,
    },
    /// Platform Payment account (DIP-17)
    /// Path: m/9'/coin_type'/17'/account'/key_class'/index
    /// These addresses are encoded with DIP-18 format ("D"/"d" prefix for P2PKH).
    /// **Warning**: Platform addresses MUST NOT be used in Core chain transactions.
    PlatformPayment {
        /// Account index (hardened)
        account: u32,
        /// Key class (hardened)
        key_class: u32,
        /// Platform payment address pool (single pool, non-hardened leaf index)
        addresses: AddressPool,
    },
}

impl ManagedAccountType {
    /// Get the primary index for this account type
    /// Returns None for provider key types and identity types that don't have account indices
    pub fn index(&self) -> Option<u32> {
        match self {
            Self::Standard {
                index,
                ..
            }
            | Self::CoinJoin {
                index,
                ..
            } => Some(*index),
            // Identity and provider types don't have account indices
            Self::IdentityRegistration {
                ..
            }
            | Self::IdentityTopUp {
                ..
            }
            | Self::IdentityTopUpNotBoundToIdentity {
                ..
            }
            | Self::IdentityInvitation {
                ..
            }
            | Self::ProviderVotingKeys {
                ..
            }
            | Self::ProviderOwnerKeys {
                ..
            }
            | Self::ProviderOperatorKeys {
                ..
            }
            | Self::ProviderPlatformKeys {
                ..
            } => None,
            Self::DashpayReceivingFunds {
                index,
                ..
            }
            | Self::DashpayExternalAccount {
                index,
                ..
            } => Some(*index),
            Self::PlatformPayment {
                account,
                ..
            } => Some(*account),
        }
    }

    /// Get the primary index for this account type, returning 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.index().unwrap_or(0)
    }

    /// Get the registration index for identity top-up accounts
    pub fn registration_index(&self) -> Option<u32> {
        match self {
            Self::IdentityTopUp {
                registration_index,
                ..
            } => Some(*registration_index),
            _ => None,
        }
    }

    /// Get all address pools for this account type
    pub fn address_pools(&self) -> Vec<&AddressPool> {
        match self {
            Self::Standard {
                external_addresses,
                internal_addresses,
                ..
            } => {
                vec![external_addresses, internal_addresses]
            }
            Self::CoinJoin {
                addresses,
                ..
            }
            | Self::IdentityRegistration {
                addresses,
                ..
            }
            | Self::IdentityTopUp {
                addresses,
                ..
            }
            | Self::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | Self::IdentityInvitation {
                addresses,
                ..
            }
            | Self::ProviderVotingKeys {
                addresses,
                ..
            }
            | Self::ProviderOwnerKeys {
                addresses,
                ..
            }
            | Self::ProviderOperatorKeys {
                addresses,
                ..
            }
            | Self::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                vec![addresses]
            }
            Self::DashpayReceivingFunds {
                addresses,
                ..
            }
            | Self::DashpayExternalAccount {
                addresses,
                ..
            }
            | Self::PlatformPayment {
                addresses,
                ..
            } => vec![addresses],
        }
    }

    /// Get mutable references to all address pools for this account type
    pub fn address_pools_mut(&mut self) -> Vec<&mut AddressPool> {
        match self {
            Self::Standard {
                external_addresses,
                internal_addresses,
                ..
            } => {
                vec![external_addresses, internal_addresses]
            }
            Self::CoinJoin {
                addresses,
                ..
            }
            | Self::IdentityRegistration {
                addresses,
                ..
            }
            | Self::IdentityTopUp {
                addresses,
                ..
            }
            | Self::IdentityTopUpNotBoundToIdentity {
                addresses,
                ..
            }
            | Self::IdentityInvitation {
                addresses,
                ..
            }
            | Self::ProviderVotingKeys {
                addresses,
                ..
            }
            | Self::ProviderOwnerKeys {
                addresses,
                ..
            }
            | Self::ProviderOperatorKeys {
                addresses,
                ..
            }
            | Self::ProviderPlatformKeys {
                addresses,
                ..
            } => {
                vec![addresses]
            }
            Self::DashpayReceivingFunds {
                addresses,
                ..
            }
            | Self::DashpayExternalAccount {
                addresses,
                ..
            }
            | Self::PlatformPayment {
                addresses,
                ..
            } => vec![addresses],
        }
    }

    /// Check if an address belongs to this account type
    pub fn contains_address(&self, address: &crate::Address) -> bool {
        self.address_pools().iter().any(|pool| pool.contains_address(address))
    }

    /// Check if a script pubkey belongs to this account type
    pub fn contains_script_pub_key(&self, script_pubkey: &ScriptBuf) -> bool {
        self.address_pools().iter().any(|pool| pool.contains_script_pubkey(script_pubkey))
    }

    /// Get the derivation path for an address if it belongs to this account type
    pub fn get_address_derivation_path(&self, address: &crate::Address) -> Option<DerivationPath> {
        for pool in self.address_pools() {
            if let Some(info) = pool.address_info(address) {
                return Some(info.path.clone());
            }
        }
        None
    }

    /// Get address info for a given address
    pub fn get_address_info(
        &self,
        address: &crate::Address,
    ) -> Option<crate::managed_account::address_pool::AddressInfo> {
        for pool in self.address_pools() {
            if let Some(info) = pool.address_info(address) {
                return Some(info.clone());
            }
        }
        None
    }

    /// Mark an address as used
    pub fn mark_address_used(&mut self, address: &crate::Address) -> bool {
        for pool in self.address_pools_mut() {
            if pool.mark_used(address) {
                return true;
            }
        }
        false
    }

    /// Get all addresses from all pools
    pub fn all_addresses(&self) -> Vec<crate::Address> {
        self.address_pools().iter().flat_map(|pool| pool.all_addresses()).collect()
    }

    /// Get the account type as the original enum
    pub fn to_account_type(&self) -> AccountType {
        match self {
            Self::Standard {
                index,
                standard_account_type,
                ..
            } => AccountType::Standard {
                index: *index,
                standard_account_type: *standard_account_type,
            },
            Self::CoinJoin {
                index,
                ..
            } => AccountType::CoinJoin {
                index: *index,
            },
            Self::IdentityRegistration {
                ..
            } => AccountType::IdentityRegistration,
            Self::IdentityTopUp {
                registration_index,
                ..
            } => AccountType::IdentityTopUp {
                registration_index: *registration_index,
            },
            Self::IdentityTopUpNotBoundToIdentity {
                ..
            } => AccountType::IdentityTopUpNotBoundToIdentity,
            Self::IdentityInvitation {
                ..
            } => AccountType::IdentityInvitation,
            Self::ProviderVotingKeys {
                ..
            } => AccountType::ProviderVotingKeys,
            Self::ProviderOwnerKeys {
                ..
            } => AccountType::ProviderOwnerKeys,
            Self::ProviderOperatorKeys {
                ..
            } => AccountType::ProviderOperatorKeys,
            Self::ProviderPlatformKeys {
                ..
            } => AccountType::ProviderPlatformKeys,
            Self::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
                ..
            } => AccountType::DashpayReceivingFunds {
                index: *index,
                user_identity_id: *user_identity_id,
                friend_identity_id: *friend_identity_id,
            },
            Self::DashpayExternalAccount {
                index,
                user_identity_id,
                friend_identity_id,
                ..
            } => AccountType::DashpayExternalAccount {
                index: *index,
                user_identity_id: *user_identity_id,
                friend_identity_id: *friend_identity_id,
            },
            Self::PlatformPayment {
                account,
                key_class,
                ..
            } => AccountType::PlatformPayment {
                account: *account,
                key_class: *key_class,
            },
        }
    }

    /// Create a ManagedAccountType from an AccountType with address pools
    pub fn from_account_type(
        account_type: AccountType,
        network: crate::Network,
        key_source: &crate::KeySource,
    ) -> Result<Self, crate::error::Error> {
        use crate::bip32::DerivationPath;
        use crate::managed_account::address_pool::{AddressPool, AddressPoolType};

        match account_type {
            AccountType::Standard {
                index,
                standard_account_type,
            } => {
                // Create external and internal address pools for standard accounts
                let base_path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());

                let mut external_path = base_path.clone();
                external_path.push(crate::bip32::ChildNumber::from_normal_idx(0).unwrap());
                let external_pool = AddressPool::new(
                    external_path,
                    AddressPoolType::External,
                    DEFAULT_EXTERNAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                let mut internal_path = base_path;
                internal_path.push(crate::bip32::ChildNumber::from_normal_idx(1).unwrap());
                let internal_pool = AddressPool::new(
                    internal_path,
                    AddressPoolType::Internal,
                    DEFAULT_INTERNAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::Standard {
                    index,
                    standard_account_type,
                    external_addresses: external_pool,
                    internal_addresses: internal_pool,
                })
            }
            AccountType::CoinJoin {
                index,
            } => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_COINJOIN_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::CoinJoin {
                    index,
                    addresses: pool,
                })
            }
            AccountType::IdentityRegistration => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::IdentityRegistration {
                    addresses: pool,
                })
            }
            AccountType::IdentityTopUp {
                registration_index,
            } => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::IdentityTopUp {
                    registration_index,
                    addresses: pool,
                })
            }
            AccountType::IdentityTopUpNotBoundToIdentity => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::IdentityTopUpNotBoundToIdentity {
                    addresses: pool,
                })
            }
            AccountType::IdentityInvitation => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::IdentityInvitation {
                    addresses: pool,
                })
            }
            AccountType::ProviderVotingKeys => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::ProviderVotingKeys {
                    addresses: pool,
                })
            }
            AccountType::ProviderOwnerKeys => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::ProviderOwnerKeys {
                    addresses: pool,
                })
            }
            AccountType::ProviderOperatorKeys => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::Absent,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::ProviderOperatorKeys {
                    addresses: pool,
                })
            }
            AccountType::ProviderPlatformKeys => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    AddressPoolType::AbsentHardened,
                    DEFAULT_SPECIAL_GAP_LIMIT,
                    network,
                    key_source,
                )?;

                Ok(Self::ProviderPlatformKeys {
                    addresses: pool,
                })
            }
            AccountType::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
            } => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    crate::managed_account::address_pool::AddressPoolType::Absent,
                    20,
                    network,
                    key_source,
                )?;
                Ok(Self::DashpayReceivingFunds {
                    index,
                    user_identity_id,
                    friend_identity_id,
                    addresses: pool,
                })
            }
            AccountType::DashpayExternalAccount {
                index,
                user_identity_id,
                friend_identity_id,
            } => {
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    crate::managed_account::address_pool::AddressPoolType::Absent,
                    20,
                    network,
                    key_source,
                )?;
                Ok(Self::DashpayExternalAccount {
                    index,
                    user_identity_id,
                    friend_identity_id,
                    addresses: pool,
                })
            }
            AccountType::PlatformPayment {
                account,
                key_class,
            } => {
                // DIP-17: m/9'/coin_type'/17'/account'/key_class'/index
                // The leaf index is non-hardened
                let path = account_type
                    .derivation_path(network)
                    .unwrap_or_else(|_| DerivationPath::master());
                let pool = AddressPool::new(
                    path,
                    crate::managed_account::address_pool::AddressPoolType::Absent,
                    DIP17_GAP_LIMIT,
                    network,
                    key_source,
                )?;
                Ok(Self::PlatformPayment {
                    account,
                    key_class,
                    addresses: pool,
                })
            }
        }
    }
}
