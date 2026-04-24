//! Account type definitions
//!
//! This module contains the various account type enumerations.

use crate::bip32::{ChildNumber, DerivationPath};
use crate::dip9::DerivationPathReference;
use crate::transaction_checking::transaction_router::{
    AccountTypeToCheck, PlatformAccountConversionError,
};
use crate::Network;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Account types supported by the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum StandardAccountType {
    /// Standard BIP44 account for regular transactions m/44'/coin_type'/account'/x/x
    #[default]
    BIP44Account,
    /// BIP32 account for regular transactions m/account'/x/x
    BIP32Account,
}

/// Account types supported by the wallet.
///
/// # Ordering and storage format stability
///
/// `AccountType` derives `PartialOrd`/`Ord`/`Hash` because it's used as
/// the key in `WalletChangeSet::per_account` (a `BTreeMap<AccountType, _>`)
/// and must serialize deterministically under bincode. **The derived order
/// follows variant declaration order, then field declaration order.**
/// Reordering variants or fields here is a persistent storage-format
/// break: it silently changes `BTreeMap` iteration order (affecting any
/// serialization that depends on it) and flips bincode variant
/// discriminants, corrupting on-disk data. Add new variants at the end
/// only; never reorder, never insert in the middle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// Per-identity authentication keys using ECDSA (DIP-13, sub-feature 0', key type 0').
    ///
    /// Account-level path: `m/9'/coin_type'/5'/0'/0'/identity_index'`. Individual
    /// keys live at `.../identity_index'/key_index'` and are managed sequentially
    /// by the `AddressPool` below this account. These accounts carry no L1
    /// balance — they are pure signing-key chains the user employs to sign Dash
    /// Platform state transitions.
    IdentityAuthenticationEcdsa {
        /// Which identity in this wallet these keys belong to (hardened).
        identity_index: u32,
    },
    /// Per-identity authentication keys using BLS (DIP-13, sub-feature 0', key type 1').
    ///
    /// Account-level path: `m/9'/coin_type'/5'/0'/1'/identity_index'`. When the
    /// `bls` feature is enabled this is backed by
    /// [`BLSAccount`](crate::account::BLSAccount); like
    /// [`AccountType::IdentityAuthenticationEcdsa`] these carry no L1 balance.
    ///
    /// The variant itself is always present so that downstream pattern matches
    /// remain exhaustive regardless of features; the BLS-typed storage it maps
    /// into (see [`crate::account::AccountCollection::identity_authentication_bls`])
    /// is what is gated on the `bls` feature.
    IdentityAuthenticationBls {
        /// Which identity in this wallet these keys belong to (hardened).
        identity_index: u32,
    },
    /// Asset lock address top-up funding (subfeature 4)
    /// Path: m/9'/coinType'/5'/4'/index'
    AssetLockAddressTopUp,
    /// Asset lock shielded address top-up funding (subfeature 5)
    /// Path: m/9'/coinType'/5'/5'/index'
    AssetLockShieldedAddressTopUp,
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

impl TryFrom<AccountType> for AccountTypeToCheck {
    type Error = PlatformAccountConversionError;

    fn try_from(value: AccountType) -> Result<Self, Self::Error> {
        match value {
            AccountType::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                StandardAccountType::BIP44Account => Ok(AccountTypeToCheck::StandardBIP44),
                StandardAccountType::BIP32Account => Ok(AccountTypeToCheck::StandardBIP32),
            },
            AccountType::CoinJoin {
                ..
            } => Ok(AccountTypeToCheck::CoinJoin),
            AccountType::IdentityRegistration => Ok(AccountTypeToCheck::IdentityRegistration),
            AccountType::IdentityTopUp {
                ..
            } => Ok(AccountTypeToCheck::IdentityTopUp),
            AccountType::IdentityTopUpNotBoundToIdentity => {
                Ok(AccountTypeToCheck::IdentityTopUpNotBound)
            }
            AccountType::IdentityInvitation => Ok(AccountTypeToCheck::IdentityInvitation),
            AccountType::IdentityAuthenticationEcdsa {
                ..
            }
            | AccountType::IdentityAuthenticationBls {
                ..
            } => {
                // DIP-13 per-identity authentication accounts are Platform-only,
                // operating on Dash Platform rather than the Core chain.
                Err(PlatformAccountConversionError)
            }
            AccountType::AssetLockAddressTopUp => Ok(AccountTypeToCheck::AssetLockAddressTopUp),
            AccountType::AssetLockShieldedAddressTopUp => {
                Ok(AccountTypeToCheck::AssetLockShieldedAddressTopUp)
            }
            AccountType::ProviderVotingKeys => Ok(AccountTypeToCheck::ProviderVotingKeys),
            AccountType::ProviderOwnerKeys => Ok(AccountTypeToCheck::ProviderOwnerKeys),
            AccountType::ProviderOperatorKeys => Ok(AccountTypeToCheck::ProviderOperatorKeys),
            AccountType::ProviderPlatformKeys => Ok(AccountTypeToCheck::ProviderPlatformKeys),
            AccountType::DashpayReceivingFunds {
                ..
            } => Ok(AccountTypeToCheck::DashpayReceivingFunds),
            AccountType::DashpayExternalAccount {
                ..
            } => Ok(AccountTypeToCheck::DashpayExternalAccount),
            AccountType::PlatformPayment {
                ..
            } => {
                // Platform Payment accounts (DIP-17) operate on Dash Platform, not Core chain.
                Err(PlatformAccountConversionError)
            }
        }
    }
}

#[cfg(feature = "bincode")]
impl AccountType {
    /// Encode as a stable byte key for persistent storage (e.g. as a
    /// BLOB primary key in a database table).
    ///
    /// Uses bincode 2.x standard config. The stability contract lives
    /// on the type declaration: variants are append-only, field order
    /// is frozen. Encoding is infallible for this type (no `Vec` or
    /// heap types that can fail to encode).
    ///
    /// Paired with [`AccountType::from_db_key`] for round-trip.
    pub fn to_db_key(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .expect("AccountType bincode encoding is infallible")
    }

    /// Decode an `AccountType` from the byte form produced by
    /// [`AccountType::to_db_key`]. Returns a bincode error for
    /// corrupted bytes or an unrecognized variant discriminant
    /// (which can happen if the DB was written by a newer version
    /// of the crate).
    pub fn from_db_key(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::decode_from_slice(bytes, bincode::config::standard()).map(|(v, _)| v)
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
            | Self::IdentityAuthenticationEcdsa {
                ..
            }
            | Self::IdentityAuthenticationBls {
                ..
            }
            | Self::AssetLockAddressTopUp
            | Self::AssetLockShieldedAddressTopUp
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
            Self::IdentityAuthenticationEcdsa {
                ..
            } => DerivationPathReference::BlockchainIdentityAuthenticationEcdsa,
            Self::IdentityAuthenticationBls {
                ..
            } => DerivationPathReference::BlockchainIdentityAuthenticationBls,
            Self::AssetLockAddressTopUp {
                ..
            } => DerivationPathReference::BlockchainAssetLockAddressTopupFunding,
            Self::AssetLockShieldedAddressTopUp {
                ..
            } => DerivationPathReference::BlockchainAssetLockShieldedAddressTopupFunding,
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
        let coin_type = if network == Network::Mainnet {
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
                    Network::Mainnet => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_REGISTRATION_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_REGISTRATION_PATH_TESTNET))
                    }
                }
            }
            Self::IdentityTopUp {
                registration_index,
            } => {
                // Base path with registration index - actual key index added when deriving
                let base_path = match network {
                    Network::Mainnet => crate::dip9::IDENTITY_TOPUP_PATH_MAINNET,
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        crate::dip9::IDENTITY_TOPUP_PATH_TESTNET
                    }
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
                    Network::Mainnet => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_TOPUP_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_TOPUP_PATH_TESTNET))
                    }
                }
            }
            Self::IdentityInvitation => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Mainnet => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_INVITATION_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::IDENTITY_INVITATION_PATH_TESTNET))
                    }
                }
            }
            Self::IdentityAuthenticationEcdsa {
                identity_index,
            } => {
                // DIP-13: m/9'/coin_type'/5'/0'/0'/identity_index'
                // The base const supplies the first 5 hardened levels; we append identity_index'.
                let base_path = match network {
                    Network::Mainnet => crate::dip9::IDENTITY_AUTHENTICATION_ECDSA_PATH_MAINNET,
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        crate::dip9::IDENTITY_AUTHENTICATION_ECDSA_PATH_TESTNET
                    }
                };
                let mut path = DerivationPath::from(base_path);
                path.push(
                    ChildNumber::from_hardened_idx(*identity_index)
                        .map_err(crate::error::Error::Bip32)?,
                );
                Ok(path)
            }
            Self::IdentityAuthenticationBls {
                identity_index,
            } => {
                // DIP-13: m/9'/coin_type'/5'/0'/1'/identity_index'
                // The base const supplies the first 5 hardened levels; we append identity_index'.
                let base_path = match network {
                    Network::Mainnet => crate::dip9::IDENTITY_AUTHENTICATION_BLS_PATH_MAINNET,
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        crate::dip9::IDENTITY_AUTHENTICATION_BLS_PATH_TESTNET
                    }
                };
                let mut path = DerivationPath::from(base_path);
                path.push(
                    ChildNumber::from_hardened_idx(*identity_index)
                        .map_err(crate::error::Error::Bip32)?,
                );
                Ok(path)
            }
            Self::AssetLockAddressTopUp => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Mainnet => {
                        Ok(DerivationPath::from(crate::dip9::ASSET_LOCK_ADDRESS_TOPUP_PATH_MAINNET))
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(crate::dip9::ASSET_LOCK_ADDRESS_TOPUP_PATH_TESTNET))
                    }
                }
            }
            Self::AssetLockShieldedAddressTopUp => {
                // Base path without index - actual key index added when deriving
                match network {
                    Network::Mainnet => Ok(DerivationPath::from(
                        crate::dip9::ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_MAINNET,
                    )),
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        Ok(DerivationPath::from(
                            crate::dip9::ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_TESTNET,
                        ))
                    }
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
                    Network::Mainnet => {
                        DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_MAINNET)
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_TESTNET)
                    }
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
                    Network::Mainnet => {
                        DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_MAINNET)
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        DerivationPath::from(crate::dip9::DASHPAY_ROOT_PATH_TESTNET)
                    }
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
                    Network::Mainnet => {
                        DerivationPath::from(crate::dip9::PLATFORM_PAYMENT_ROOT_PATH_MAINNET)
                    }
                    Network::Testnet | Network::Devnet | Network::Regtest => {
                        DerivationPath::from(crate::dip9::PLATFORM_PAYMENT_ROOT_PATH_TESTNET)
                    }
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

#[cfg(test)]
mod identity_authentication_tests {
    use super::*;

    /// Helper: build a `DerivationPath` of hardened children from the given
    /// indices. Keeps tests readable.
    fn hardened_path(indices: &[u32]) -> DerivationPath {
        DerivationPath::from(
            indices.iter().map(|i| ChildNumber::from_hardened_idx(*i).unwrap()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn test_identity_authentication_ecdsa_mainnet_path() {
        let account_type = AccountType::IdentityAuthenticationEcdsa {
            identity_index: 0,
        };
        let path = account_type.derivation_path(Network::Mainnet).unwrap();
        // m/9'/5'/5'/0'/0'/0'
        assert_eq!(path, hardened_path(&[9, 5, 5, 0, 0, 0]));
    }

    #[test]
    fn test_identity_authentication_ecdsa_testnet_path() {
        let account_type = AccountType::IdentityAuthenticationEcdsa {
            identity_index: 7,
        };
        let path = account_type.derivation_path(Network::Testnet).unwrap();
        // m/9'/1'/5'/0'/0'/7'
        assert_eq!(path, hardened_path(&[9, 1, 5, 0, 0, 7]));
    }

    #[test]
    fn test_identity_authentication_ecdsa_index_is_none() {
        // `index()` is for BIP44-style account indices, not identity indices.
        let account_type = AccountType::IdentityAuthenticationEcdsa {
            identity_index: 42,
        };
        assert!(account_type.index().is_none());
    }

    #[test]
    fn test_identity_authentication_ecdsa_derivation_path_reference() {
        let account_type = AccountType::IdentityAuthenticationEcdsa {
            identity_index: 0,
        };
        assert_eq!(
            account_type.derivation_path_reference(),
            crate::dip9::DerivationPathReference::BlockchainIdentityAuthenticationEcdsa,
        );
    }

    #[test]
    fn test_identity_authentication_ecdsa_to_account_type_to_check_errs() {
        // DIP-13 identity-authentication accounts are Platform-only and must
        // never be mapped onto a Core-chain [`AccountTypeToCheck`] variant.
        let account_type = AccountType::IdentityAuthenticationEcdsa {
            identity_index: 3,
        };
        let result: Result<AccountTypeToCheck, _> = account_type.try_into();
        assert_eq!(result, Err(PlatformAccountConversionError));
    }

    #[test]
    fn test_identity_authentication_bls_mainnet_path() {
        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 0,
        };
        let path = account_type.derivation_path(Network::Mainnet).unwrap();
        // m/9'/5'/5'/0'/1'/0'
        assert_eq!(path, hardened_path(&[9, 5, 5, 0, 1, 0]));
    }

    #[test]
    fn test_identity_authentication_bls_testnet_path() {
        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 2,
        };
        let path = account_type.derivation_path(Network::Testnet).unwrap();
        // m/9'/1'/5'/0'/1'/2'
        assert_eq!(path, hardened_path(&[9, 1, 5, 0, 1, 2]));
    }

    #[test]
    fn test_identity_authentication_bls_regtest_uses_testnet_coin_type() {
        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 5,
        };
        let path = account_type.derivation_path(Network::Regtest).unwrap();
        // Regtest/Devnet use the same coin_type (1') as Testnet.
        assert_eq!(path, hardened_path(&[9, 1, 5, 0, 1, 5]));
    }

    #[test]
    fn test_identity_authentication_bls_index_is_none() {
        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 99,
        };
        assert!(account_type.index().is_none());
    }

    #[test]
    fn test_identity_authentication_bls_derivation_path_reference() {
        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 0,
        };
        assert_eq!(
            account_type.derivation_path_reference(),
            crate::dip9::DerivationPathReference::BlockchainIdentityAuthenticationBls,
        );
    }

    #[test]
    fn test_identity_authentication_bls_to_account_type_to_check_errs() {
        // DIP-13 identity-authentication accounts are Platform-only and must
        // never be mapped onto a Core-chain [`AccountTypeToCheck`] variant.
        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 3,
        };
        let result: Result<AccountTypeToCheck, _> = account_type.try_into();
        assert_eq!(result, Err(PlatformAccountConversionError));
    }

    /// End-to-end: insert an ECDSA identity-authentication account into an
    /// `AccountCollection` and round-trip through `contains_account_type` /
    /// `account_of_type`.
    #[test]
    fn test_account_collection_round_trip_ecdsa() {
        use crate::account::{Account, AccountCollection};
        use crate::bip32::{ExtendedPrivKey, ExtendedPubKey};
        use crate::mnemonic::{Language, Mnemonic};
        use secp256k1::Secp256k1;

        let mut collection = AccountCollection::new();

        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
            Language::English,
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let secp = Secp256k1::new();
        let xpub = ExtendedPubKey::from_priv(&secp, &master);

        let account_type = AccountType::IdentityAuthenticationEcdsa {
            identity_index: 4,
        };
        let account = Account::new(None, account_type, xpub, Network::Testnet).unwrap();

        assert!(!collection.contains_account_type(&account_type));
        assert!(collection.insert(account).is_ok());
        assert!(collection.contains_account_type(&account_type));
        assert!(collection.account_of_type(account_type).is_some());

        // Sanity: the ECDSA variant is *not* routed to the BLS map, so the BLS
        // lookup on an ECDSA variant returns None regardless of features.
        #[cfg(feature = "bls")]
        {
            let bls_probe = AccountType::IdentityAuthenticationBls {
                identity_index: 4,
            };
            assert!(collection.bls_account_of_type(bls_probe).is_none());
        }
    }

    /// End-to-end: insert a BLS identity-authentication account into an
    /// `AccountCollection` via `insert_bls_account`, and round-trip through
    /// `contains_account_type` / `bls_account_of_type`.
    #[cfg(feature = "bls")]
    #[test]
    fn test_account_collection_round_trip_bls() {
        use crate::account::{AccountCollection, BLSAccount};

        let mut collection = AccountCollection::new();

        let account_type = AccountType::IdentityAuthenticationBls {
            identity_index: 11,
        };
        let bls_account =
            BLSAccount::from_seed(None, account_type, [7u8; 32], Network::Testnet).unwrap();

        assert!(!collection.contains_account_type(&account_type));
        assert!(collection.insert_bls_account(bls_account).is_ok());
        assert!(collection.contains_account_type(&account_type));
        assert!(collection.bls_account_of_type(account_type).is_some());

        // ECDSA `account_of_type` should refuse BLS lookups via the plain
        // accessor.
        assert!(collection.account_of_type(account_type).is_none());
    }

    /// Inserting a BLS account via the plain `insert` path must fail with a
    /// pointer to `insert_bls_account`.
    #[cfg(feature = "bls")]
    #[test]
    fn test_account_collection_rejects_bls_via_plain_insert() {
        use crate::account::{Account, AccountCollection};
        use crate::bip32::{ExtendedPrivKey, ExtendedPubKey};
        use crate::mnemonic::{Language, Mnemonic};
        use secp256k1::Secp256k1;

        let mut collection = AccountCollection::new();

        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
            Language::English,
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let secp = Secp256k1::new();
        let xpub = ExtendedPubKey::from_priv(&secp, &master);

        // Using an Account (ECDSA) constructor but with a BLS auth type is a
        // programming error — insert() routes it to the BLS error arm.
        let account = Account::new(
            None,
            AccountType::IdentityAuthenticationBls {
                identity_index: 0,
            },
            xpub,
            Network::Testnet,
        )
        .unwrap();

        let err = collection.insert(account).unwrap_err();
        assert!(err.contains("insert_bls_account"));
    }
}
