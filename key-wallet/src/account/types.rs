//! Account type definitions
//!
//! This module contains the various account type enumerations.

use super::address_pool::AddressPool;
use crate::bip32::{ChildNumber, DerivationPath};
use crate::dip9::DerivationPathReference;
use crate::Network;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Account types supported by the wallet
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum StandardAccountType {
    /// Standard BIP44 account for regular transactions m/44'/coin_type'/account'/x/x
    #[default]
    BIP44Account,
    /// BIP32 account for regular transactions m/account'/x/x
    BIP32Account,
}

/// Account types supported by the wallet
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum AccountType {
    /// Standard BIP44 account for regular transactions
    Standard { 
        /// Account index
        index: u32,
        /// StandardAccountType
        standard_account_type: StandardAccountType,
    },
    /// CoinJoin account for private transactions
    CoinJoin { 
        /// Account index
        index: u32 
    },
    /// Identity registration funding
    IdentityRegistration,
    /// Identity top-up funding  
    IdentityTopUp { 
        /// Registration index (which identity this is topping up)
        registration_index: u32,
    },
    /// Identity top-up funding not bound to a specific identity
    IdentityTopUpNotBoundToIdentity,
    /// Identity invitation funding
    IdentityInvitation,
    /// Provider voting keys (DIP-3)
    /// Path: m/9'/5'/3'/1'/[key_index]
    ProviderVotingKeys,
    /// Provider owner keys (DIP-3)
    /// Path: m/9'/5'/3'/2'/[key_index]
    ProviderOwnerKeys,
    /// Provider operator keys (DIP-3)
    /// Path: m/9'/5'/3'/3'/[key_index]
    ProviderOperatorKeys,
    /// Provider platform P2P keys (DIP-3, ED25519)
    /// Path: m/9'/5'/3'/4'/[key_index]
    ProviderPlatformKeys,
}

impl AccountType {
    /// Get the primary index for this account type
    /// Returns None for provider key types and identity types that don't have account indices
    pub fn index(&self) -> Option<u32> {
        match self {
            Self::Standard { index, .. } |
            Self::CoinJoin { index } => Some(*index),
            // Identity and provider types don't have account indices
            Self::IdentityRegistration |
            Self::IdentityTopUp { .. } |
            Self::IdentityTopUpNotBoundToIdentity |
            Self::IdentityInvitation |
            Self::ProviderVotingKeys |
            Self::ProviderOwnerKeys |
            Self::ProviderOperatorKeys |
            Self::ProviderPlatformKeys => None,
        }
    }
    
    /// Get the primary index for this account type, returning 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.index().unwrap_or(0)
    }

    /// Get the registration index for identity top-up accounts
    pub fn registration_index(&self) -> Option<u32> {
        match self {
            Self::IdentityTopUp { registration_index, .. } => Some(*registration_index),
            _ => None,
        }
    }

    /// Get the derivation path reference for this account type
    pub fn derivation_path_reference(&self) -> DerivationPathReference {
        match self {
            Self::Standard { standard_account_type, .. } => {
                match standard_account_type {
                    StandardAccountType::BIP44Account => DerivationPathReference::BIP44,
                    StandardAccountType::BIP32Account => DerivationPathReference::BIP32,
                }
            }
            Self::CoinJoin { .. } => DerivationPathReference::CoinJoin,
            Self::IdentityRegistration { .. } => DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
            Self::IdentityTopUp { .. } => DerivationPathReference::BlockchainIdentityCreditTopupFunding,
            Self::IdentityTopUpNotBoundToIdentity => DerivationPathReference::BlockchainIdentityCreditTopupFunding,
            Self::IdentityInvitation { .. } => DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
            Self::ProviderVotingKeys { .. } => DerivationPathReference::ProviderVotingKeys,
            Self::ProviderOwnerKeys { .. } => DerivationPathReference::ProviderOwnerKeys,
            Self::ProviderOperatorKeys { .. } => DerivationPathReference::ProviderOperatorKeys,
            Self::ProviderPlatformKeys { .. } => DerivationPathReference::ProviderPlatformNodeKeys,
        }
    }

    /// Get the derivation path for this account type
    pub fn derivation_path(&self, network: Network) -> Result<DerivationPath, crate::error::Error> {
        let coin_type = if network == Network::Dash { 5 } else { 1 };
        
        match self {
            Self::Standard { index, standard_account_type } => {
                match standard_account_type {
                    StandardAccountType::BIP44Account => {
                        // m/44'/coin_type'/account'
                        Ok(DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(44).map_err(crate::error::Error::Bip32)?,
                            ChildNumber::from_hardened_idx(coin_type).map_err(crate::error::Error::Bip32)?,
                            ChildNumber::from_hardened_idx(*index).map_err(crate::error::Error::Bip32)?,
                        ]))
                    }
                    StandardAccountType::BIP32Account => {
                        // m/account'
                        Ok(DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(*index).map_err(crate::error::Error::Bip32)?,
                        ]))
                    }
                }
            }
            Self::CoinJoin { index } => {
                // m/9'/coin_type'/account'
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(*index).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::IdentityRegistration => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Dash => Ok(DerivationPath::from(crate::dip9::IDENTITY_REGISTRATION_PATH_MAINNET)),
                    Network::Testnet => Ok(DerivationPath::from(crate::dip9::IDENTITY_REGISTRATION_PATH_TESTNET)),
                    _ => Err(crate::error::Error::InvalidNetwork),
                }
            }
            Self::IdentityTopUp { registration_index } => {
                // Base path with registration index - actual key index added when deriving
                let base_path = match network {
                    Network::Dash => crate::dip9::IDENTITY_TOPUP_PATH_MAINNET,
                    Network::Testnet => crate::dip9::IDENTITY_TOPUP_PATH_TESTNET,
                    _ => return Err(crate::error::Error::InvalidNetwork),
                };
                let mut path = DerivationPath::from(base_path);
                path.push(ChildNumber::from_hardened_idx(*registration_index).map_err(crate::error::Error::Bip32)?);
                Ok(path)
            }
            Self::IdentityTopUpNotBoundToIdentity => {
                // Base path without registration index - actual key index added when deriving
                match network {
                    Network::Dash => Ok(DerivationPath::from(crate::dip9::IDENTITY_TOPUP_PATH_MAINNET)),
                    Network::Testnet => Ok(DerivationPath::from(crate::dip9::IDENTITY_TOPUP_PATH_TESTNET)),
                    _ => Err(crate::error::Error::InvalidNetwork),
                }
            }
            Self::IdentityInvitation => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Dash => Ok(DerivationPath::from(crate::dip9::IDENTITY_INVITATION_PATH_MAINNET)),
                    Network::Testnet => Ok(DerivationPath::from(crate::dip9::IDENTITY_INVITATION_PATH_TESTNET)),
                    _ => Err(crate::error::Error::InvalidNetwork),
                }
            }
            Self::ProviderVotingKeys => {
                // DIP-3: m/9'/5'/3'/1' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(1).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::ProviderOwnerKeys => {
                // DIP-3: m/9'/5'/3'/2' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(2).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::ProviderOperatorKeys => {
                // DIP-3: m/9'/5'/3'/3' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::ProviderPlatformKeys => {
                // DIP-3: m/9'/5'/3'/4' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(4).map_err(crate::error::Error::Bip32)?,
                ]))
            }
        }
    }
}

/// Managed account type with embedded address pools
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
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
}

impl ManagedAccountType {
    /// Get the primary index for this account type
    /// Returns None for provider key types and identity types that don't have account indices
    pub fn index(&self) -> Option<u32> {
        match self {
            Self::Standard { index, .. } |
            Self::CoinJoin { index, .. } => Some(*index),
            // Identity and provider types don't have account indices
            Self::IdentityRegistration { .. } |
            Self::IdentityTopUp { .. } |
            Self::IdentityTopUpNotBoundToIdentity { .. } |
            Self::IdentityInvitation { .. } |
            Self::ProviderVotingKeys { .. } |
            Self::ProviderOwnerKeys { .. } |
            Self::ProviderOperatorKeys { .. } |
            Self::ProviderPlatformKeys { .. } => None,
        }
    }
    
    /// Get the primary index for this account type, returning 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.index().unwrap_or(0)
    }

    /// Get the registration index for identity top-up accounts
    pub fn registration_index(&self) -> Option<u32> {
        match self {
            Self::IdentityTopUp { registration_index, .. } => Some(*registration_index),
            _ => None,
        }
    }

    /// Get all address pools for this account type
    pub fn get_address_pools(&self) -> Vec<&AddressPool> {
        match self {
            Self::Standard { external_addresses, internal_addresses, .. } => {
                vec![external_addresses, internal_addresses]
            }
            Self::CoinJoin { addresses, .. } |
            Self::IdentityRegistration { addresses, .. } |
            Self::IdentityTopUp { addresses, .. } |
            Self::IdentityTopUpNotBoundToIdentity { addresses, .. } |
            Self::IdentityInvitation { addresses, .. } |
            Self::ProviderVotingKeys { addresses, .. } |
            Self::ProviderOwnerKeys { addresses, .. } |
            Self::ProviderOperatorKeys { addresses, .. } |
            Self::ProviderPlatformKeys { addresses, .. } => {
                vec![addresses]
            }
        }
    }

    /// Get mutable references to all address pools for this account type
    pub fn get_address_pools_mut(&mut self) -> Vec<&mut AddressPool> {
        match self {
            Self::Standard { external_addresses, internal_addresses, .. } => {
                vec![external_addresses, internal_addresses]
            }
            Self::CoinJoin { addresses, .. } |
            Self::IdentityRegistration { addresses, .. } |
            Self::IdentityTopUp { addresses, .. } |
            Self::IdentityTopUpNotBoundToIdentity { addresses, .. } |
            Self::IdentityInvitation { addresses, .. } |
            Self::ProviderVotingKeys { addresses, .. } |
            Self::ProviderOwnerKeys { addresses, .. } |
            Self::ProviderOperatorKeys { addresses, .. } |
            Self::ProviderPlatformKeys { addresses, .. } => {
                vec![addresses]
            }
        }
    }

    /// Check if an address belongs to this account type
    pub fn contains_address(&self, address: &crate::Address) -> bool {
        self.get_address_pools()
            .iter()
            .any(|pool| pool.contains_address(address))
    }

    /// Get the derivation path for an address if it belongs to this account type
    pub fn get_address_derivation_path(&self, address: &crate::Address) -> Option<crate::DerivationPath> {
        for pool in self.get_address_pools() {
            if let Some(info) = pool.get_address_info(address) {
                return Some(info.path.clone());
            }
        }
        None
    }

    /// Mark an address as used
    pub fn mark_address_used(&mut self, address: &crate::Address) -> bool {
        for pool in self.get_address_pools_mut() {
            if pool.mark_used(address) {
                return true;
            }
        }
        false
    }

    /// Get all addresses from all pools
    pub fn get_all_addresses(&self) -> Vec<crate::Address> {
        self.get_address_pools()
            .iter()
            .flat_map(|pool| pool.get_all_addresses())
            .collect()
    }

    /// Get the account type as the original enum
    pub fn to_account_type(&self) -> AccountType {
        match self {
            Self::Standard { index, standard_account_type, .. } => AccountType::Standard { 
                index: *index,
                standard_account_type: standard_account_type.clone(),
            },
            Self::CoinJoin { index, .. } => AccountType::CoinJoin { index: *index },
            Self::IdentityRegistration { .. } => AccountType::IdentityRegistration,
            Self::IdentityTopUp { registration_index, .. } => AccountType::IdentityTopUp { 
                registration_index: *registration_index,
            },
            Self::IdentityTopUpNotBoundToIdentity { .. } => AccountType::IdentityTopUpNotBoundToIdentity,
            Self::IdentityInvitation { .. } => AccountType::IdentityInvitation,
            Self::ProviderVotingKeys { .. } => AccountType::ProviderVotingKeys,
            Self::ProviderOwnerKeys { .. } => AccountType::ProviderOwnerKeys,
            Self::ProviderOperatorKeys { .. } => AccountType::ProviderOperatorKeys,
            Self::ProviderPlatformKeys { .. } => AccountType::ProviderPlatformKeys,
        }
    }
}
