//! Account management for HD wallets
//!
//! This module provides comprehensive account management following BIP44,
//! including gap limit tracking, address pool management, and support for
//! multiple account types (standard, CoinJoin, watch-only).

pub mod account_collection;
pub mod address_pool;
pub mod coinjoin;
pub mod managed_account;
pub mod managed_account_collection;
pub mod metadata;
pub mod scan;
pub mod transaction_record;
pub mod types;

use core::fmt;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use secp256k1::Secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::dip9::DerivationPathReference;
use crate::error::Result;
use crate::Network;

pub use coinjoin::CoinJoinPools;
pub use managed_account::{ManagedAccount, Utxo};
pub use managed_account_collection::ManagedAccountCollection;
pub use metadata::AccountMetadata;
pub use scan::ScanResult;
pub use transaction_record::TransactionRecord;
pub use types::{AccountType, ManagedAccountType, StandardAccountType};

/// Complete account structure with all derivation paths
///
/// This is an immutable account structure that contains only the core
/// identity information that doesn't change during normal operation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Account {
    /// Wallet id
    pub parent_wallet_id: Option<[u8; 32]>,
    /// Account type (includes index information and derivation path)
    pub account_type: AccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Account-level extended public key
    pub account_xpub: ExtendedPubKey,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
}

impl Account {
    /// Create a new account from an extended public key
    pub fn new(
        parent_wallet_id: Option<[u8; 32]>,
        account_type: AccountType,
        account_xpub: ExtendedPubKey,
        network: Network,
    ) -> Result<Self> {
        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            account_xpub,
            is_watch_only: false,
        })
    }

    /// Create an account from an extended private key (derives the public key)
    pub fn from_xpriv(
        parent_wallet_id: Option<[u8; 32]>,
        account_type: AccountType,
        account_xpriv: ExtendedPrivKey,
        network: Network,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let account_xpub = ExtendedPubKey::from_priv(&secp, &account_xpriv);

        Self::new(parent_wallet_id, account_type, account_xpub, network)
    }

    /// Create a watch-only account from an extended public key
    pub fn from_xpub(
        parent_wallet_id: Option<[u8; 32]>,
        account_type: AccountType,
        account_xpub: ExtendedPubKey,
        network: Network,
    ) -> Result<Self> {
        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            account_xpub,
            is_watch_only: true,
        })
    }

    /// Get the account index
    pub fn index(&self) -> Option<u32> {
        self.account_type.index()
    }

    /// Get the account index or 0 if none exists
    pub fn index_or_default(&self) -> u32 {
        self.account_type.index_or_default()
    }

    /// Get the derivation path reference for this account
    pub fn derivation_path_reference(&self) -> DerivationPathReference {
        self.account_type.derivation_path_reference()
    }

    /// Get the derivation path for this account
    pub fn derivation_path(&self) -> Result<DerivationPath> {
        self.account_type.derivation_path(self.network)
    }

    /// Export account as watch-only
    pub fn to_watch_only(&self) -> Self {
        let mut watch_only = self.clone();
        watch_only.is_watch_only = true;
        watch_only
    }

    /// Serialize account to bytes
    #[cfg(feature = "bincode")]
    pub fn serialize(&self) -> Result<alloc::vec::Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Deserialize account from bytes
    #[cfg(feature = "bincode")]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Get the extended public key for this account
    pub fn extended_public_key(&self) -> ExtendedPubKey {
        self.account_xpub
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(index) = self.index() {
            write!(f, "Account #{} ({:?}) - Network: {:?}", index, self.account_type, self.network)
        } else {
            write!(f, "Account ({:?}) - Network: {:?}", self.account_type, self.network)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::ChildNumber;
    use crate::mnemonic::{Language, Mnemonic};

    fn test_account() -> Account {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

        // Derive account key (m/44'/1'/0')
        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(44).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let account_xpriv = master.derive_priv(&secp, &path).unwrap();

        Account::from_xpriv(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            account_xpriv,
            Network::Testnet,
        )
        .unwrap()
    }

    #[test]
    fn test_account_creation() {
        let account = test_account();
        assert_eq!(account.index(), Some(0));
        assert_eq!(
            account.account_type,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account
            }
        );
        assert!(!account.is_watch_only);
    }

    #[test]
    fn test_watch_only_account() {
        let account = test_account();
        let watch_only = Account::from_xpub(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            account.account_xpub,
            Network::Testnet,
        )
        .unwrap();

        assert!(watch_only.is_watch_only);
    }

    #[test]
    #[cfg(feature = "bincode")]
    fn test_serialization() {
        let account = test_account();
        let serialized = account.serialize().unwrap();
        let deserialized = Account::deserialize(&serialized).unwrap();

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
    }
}
