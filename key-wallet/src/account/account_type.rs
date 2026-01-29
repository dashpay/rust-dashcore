//! Account type definitions
//!
//! This module contains the various account type enumerations.

use crate::bip32::{ChildNumber, DerivationPath};
use crate::dip9::DerivationPathReference;
use crate::transaction_checking::transaction_router::AccountTypeToCheck;
use crate::Network;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Account types supported by the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        index: u32,
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
    /// Path: `m/9'/5'/3'/1'/[key_index]`
    ProviderVotingKeys,
    /// Provider owner keys (DIP-3)
    /// Path: `m/9'/5'/3'/2'/[key_index]`
    ProviderOwnerKeys,
    /// Provider operator keys (DIP-3)
    /// Path: `m/9'/5'/3'/3'/[key_index]`
    ProviderOperatorKeys,
    /// Provider platform P2P keys (DIP-3, ED25519)
    /// Path: `m/9'/5'/3'/4'/[key_index]`
    ProviderPlatformKeys,
    /// Incoming DashPay funds account using 256-bit derivation
    /// The derivation path used is user_identity_id/friend_identity_id
    DashpayReceivingFunds {
        /// Account index (account-level selection)
        index: u32,
        /// Our identity id (32 bytes)
        user_identity_id: [u8; 32],
        /// Our contact's identity id (32 bytes)
        friend_identity_id: [u8; 32],
    },
    /// DashPay external (watch-only) account using 256-bit derivation
    /// The derivation path used is friend_identity_id/user_identity_id
    DashpayExternalAccount {
        /// Account index (account-level selection)
        index: u32,
        /// Our identity id (32 bytes)
        user_identity_id: [u8; 32],
        /// Our contact's identity id (32 bytes)
        friend_identity_id: [u8; 32],
    },
    /// Platform Payment account (DIP-17)
    /// Path: m/9'/coin_type'/17'/account'/key_class'/index
    /// Address encoding (DIP-18 bech32m) is handled by the Platform repo.
    PlatformPayment {
        /// Account index (hardened) - default 0'
        account: u32,
        /// Key class (hardened) - default 0', 1' reserved for change-like segregation
        key_class: u32,
    },
}

impl From<AccountType> for AccountTypeToCheck {
    fn from(value: AccountType) -> Self {
        match value {
            AccountType::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                StandardAccountType::BIP44Account => AccountTypeToCheck::StandardBIP44,
                StandardAccountType::BIP32Account => AccountTypeToCheck::StandardBIP32,
            },
            AccountType::CoinJoin {
                ..
            } => AccountTypeToCheck::CoinJoin,
            AccountType::IdentityRegistration => AccountTypeToCheck::IdentityRegistration,
            AccountType::IdentityTopUp {
                ..
            } => AccountTypeToCheck::IdentityTopUp,
            AccountType::IdentityTopUpNotBoundToIdentity => {
                AccountTypeToCheck::IdentityTopUpNotBound
            }
            AccountType::IdentityInvitation => AccountTypeToCheck::IdentityInvitation,
            AccountType::ProviderVotingKeys => AccountTypeToCheck::ProviderVotingKeys,
            AccountType::ProviderOwnerKeys => AccountTypeToCheck::ProviderOwnerKeys,
            AccountType::ProviderOperatorKeys => AccountTypeToCheck::ProviderOperatorKeys,
            AccountType::ProviderPlatformKeys => AccountTypeToCheck::ProviderPlatformKeys,
            AccountType::DashpayReceivingFunds {
                ..
            } => AccountTypeToCheck::DashpayReceivingFunds,
            AccountType::DashpayExternalAccount {
                ..
            } => AccountTypeToCheck::DashpayExternalAccount,
            AccountType::PlatformPayment {
                ..
            } => AccountTypeToCheck::PlatformPayment,
        }
    }
}

impl AccountType {
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
            }
            | Self::DashpayReceivingFunds {
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
            // Identity and provider types don't have account indices
            Self::IdentityRegistration
            | Self::IdentityTopUp {
                ..
            }
            | Self::IdentityTopUpNotBoundToIdentity
            | Self::IdentityInvitation
            | Self::ProviderVotingKeys
            | Self::ProviderOwnerKeys
            | Self::ProviderOperatorKeys
            | Self::ProviderPlatformKeys => None,
        }
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

    /// Get the derivation path reference for this account type
    pub fn derivation_path_reference(&self) -> DerivationPathReference {
        match self {
            Self::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                StandardAccountType::BIP44Account => DerivationPathReference::BIP44,
                StandardAccountType::BIP32Account => DerivationPathReference::BIP32,
            },
            Self::CoinJoin {
                ..
            } => DerivationPathReference::CoinJoin,
            Self::IdentityRegistration {
                ..
            } => DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
            Self::IdentityTopUp {
                ..
            } => DerivationPathReference::BlockchainIdentityCreditTopupFunding,
            Self::IdentityTopUpNotBoundToIdentity => {
                DerivationPathReference::BlockchainIdentityCreditTopupFunding
            }
            Self::IdentityInvitation {
                ..
            } => DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
            Self::ProviderVotingKeys {
                ..
            } => DerivationPathReference::ProviderVotingKeys,
            Self::ProviderOwnerKeys {
                ..
            } => DerivationPathReference::ProviderOwnerKeys,
            Self::ProviderOperatorKeys {
                ..
            } => DerivationPathReference::ProviderOperatorKeys,
            Self::ProviderPlatformKeys {
                ..
            } => DerivationPathReference::ProviderPlatformNodeKeys,
            Self::DashpayReceivingFunds {
                ..
            } => DerivationPathReference::ContactBasedFunds,
            Self::DashpayExternalAccount {
                ..
            } => DerivationPathReference::ContactBasedFundsExternal,
            Self::PlatformPayment {
                ..
            } => DerivationPathReference::PlatformPayment,
        }
    }

    /// Get the derivation path for this account type
    pub fn derivation_path(&self, network: Network) -> Result<DerivationPath, crate::error::Error> {
        let coin_type = if network == Network::Dash {
            5
        } else {
            1
        };

        match self {
            Self::Standard {
                index,
                standard_account_type,
            } => {
                match standard_account_type {
                    StandardAccountType::BIP44Account => {
                        // m/44'/coin_type'/account'
                        Ok(DerivationPath::from(vec![
                            ChildNumber::from_hardened_idx(44)
                                .map_err(crate::error::Error::Bip32)?,
                            ChildNumber::from_hardened_idx(coin_type)
                                .map_err(crate::error::Error::Bip32)?,
                            ChildNumber::from_hardened_idx(*index)
                                .map_err(crate::error::Error::Bip32)?,
                        ]))
                    }
                    StandardAccountType::BIP32Account => {
                        // m/account'
                        Ok(DerivationPath::from(vec![ChildNumber::from_hardened_idx(*index)
                            .map_err(crate::error::Error::Bip32)?]))
                    }
                }
            }
            Self::CoinJoin {
                index,
            } => {
                // m/9'/coin_type'/account'
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type)
                        .map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(*index).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::IdentityRegistration => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Dash => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_REGISTRATION_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_REGISTRATION_PATH_TESTNET))
                    }
                    _ => Err(crate::error::Error::InvalidNetwork),
                }
            }
            Self::IdentityTopUp {
                registration_index,
            } => {
                // Base path with registration index - actual key index added when deriving
                let base_path = match network {
                    Network::Dash => crate::dip9::IDENTITY_TOPUP_PATH_MAINNET,
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        crate::dip9::IDENTITY_TOPUP_PATH_TESTNET
                    }
                    _ => return Err(crate::error::Error::InvalidNetwork),
                };
                let mut path = DerivationPath::from(base_path);
                path.push(
                    ChildNumber::from_hardened_idx(*registration_index)
                        .map_err(crate::error::Error::Bip32)?,
                );
                Ok(path)
            }
            Self::IdentityTopUpNotBoundToIdentity => {
                // Base path without registration index - actual key index added when deriving
                match network {
                    Network::Dash => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_TOPUP_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_TOPUP_PATH_TESTNET))
                    }
                    _ => Err(crate::error::Error::InvalidNetwork),
                }
            }
            Self::IdentityInvitation => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Dash => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_INVITATION_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_INVITATION_PATH_TESTNET))
                    }
                    _ => Err(crate::error::Error::InvalidNetwork),
                }
            }
            Self::ProviderVotingKeys => {
                // DIP-3: m/9'/5'/3'/1' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type)
                        .map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(1).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::ProviderOwnerKeys => {
                // DIP-3: m/9'/5'/3'/2' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type)
                        .map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(2).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::ProviderOperatorKeys => {
                // DIP-3: m/9'/5'/3'/3' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type)
                        .map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::ProviderPlatformKeys => {
                // DIP-3: m/9'/5'/3'/4' (base path, actual key index added when deriving)
                Ok(DerivationPath::from(vec![
                    ChildNumber::from_hardened_idx(9).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(coin_type)
                        .map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(3).map_err(crate::error::Error::Bip32)?,
                    ChildNumber::from_hardened_idx(4).map_err(crate::error::Error::Bip32)?,
                ]))
            }
            Self::DashpayReceivingFunds {
                user_identity_id,
                friend_identity_id,
                ..
            } => {
                // Base DashPay root + account 0' + user_id/friend_id (non-hardened per DIP-14/DIP-15)
                let mut path = match network {
                    Network::Dash => DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_MAINNET),
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_TESTNET)
                    }
                    _ => return Err(crate::error::Error::InvalidNetwork),
                };
                path.push(ChildNumber::from_hardened_idx(0).map_err(crate::error::Error::Bip32)?);
                path.push(ChildNumber::Normal256 {
                    index: *user_identity_id,
                });
                path.push(ChildNumber::Normal256 {
                    index: *friend_identity_id,
                });
                Ok(path)
            }
            Self::DashpayExternalAccount {
                user_identity_id,
                friend_identity_id,
                ..
            } => {
                // Base DashPay root + account 0' + friend_id/user_id (non-hardened per DIP-14/DIP-15)
                let mut path = match network {
                    Network::Dash => DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_MAINNET),
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_TESTNET)
                    }
                    _ => return Err(crate::error::Error::InvalidNetwork),
                };
                path.push(ChildNumber::from_hardened_idx(0).map_err(crate::error::Error::Bip32)?);
                path.push(ChildNumber::Normal256 {
                    index: *friend_identity_id,
                });
                path.push(ChildNumber::Normal256 {
                    index: *user_identity_id,
                });
                Ok(path)
            }
            Self::PlatformPayment {
                account,
                key_class,
            } => {
                // DIP-17: m/9'/coin_type'/17'/account'/key_class'
                // The leaf index is non-hardened and appended during address generation
                let mut path = match network {
                    Network::Dash => {
                        DerivationPath::from(crate::dip9::PLATFORM_PAYMENT_ROOT_PATH_MAINNET)
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        DerivationPath::from(crate::dip9::PLATFORM_PAYMENT_ROOT_PATH_TESTNET)
                    }
                    _ => return Err(crate::error::Error::InvalidNetwork),
                };
                path.push(
                    ChildNumber::from_hardened_idx(*account).map_err(crate::error::Error::Bip32)?,
                );
                path.push(
                    ChildNumber::from_hardened_idx(*key_class)
                        .map_err(crate::error::Error::Bip32)?,
                );
                Ok(path)
            }
        }
    }
}
