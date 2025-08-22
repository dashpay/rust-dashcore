//! Account management for HD wallets
//!
//! This module provides comprehensive account management following BIP44,
//! including gap limit tracking, address pool management, and support for
//! multiple account types (standard, CoinJoin, watch-only).

pub mod account_collection;
pub mod account_trait;
pub mod address_pool;
pub mod bls_account;
pub mod coinjoin;
pub mod eddsa_account;
pub mod managed_account;
pub mod managed_account_collection;
pub mod managed_account_trait;
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

pub use account_collection::AccountCollection;
pub use account_trait::{AccountTrait, ECDSAAccountTrait};
pub use bls_account::BLSAccount;
pub use coinjoin::CoinJoinPools;
pub use eddsa_account::EdDSAAccount;
pub use managed_account::ManagedAccount;
pub use managed_account_collection::ManagedAccountCollection;
pub use managed_account_trait::ManagedAccountTrait;
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

    /// Derive an extended private key from a wallet's master private key
    ///
    /// This requires the wallet to have the master private key available.
    /// Returns None for watch-only wallets.
    pub fn derive_xpriv_from_master_xpriv(
        &self,
        master_xpriv: &ExtendedPrivKey,
    ) -> Result<ExtendedPrivKey> {
        if self.is_watch_only {
            return Err(crate::error::Error::WatchOnly);
        }

        let secp = Secp256k1::new();
        let path = self.derivation_path()?;
        master_xpriv.derive_priv(&secp, &path).map_err(crate::error::Error::Bip32)
    }

    /// Derive a child private key at a specific path from the account
    ///
    /// This requires providing the account's extended private key.
    /// The path should be relative to the account (e.g., "0/5" for external address 5)
    pub fn derive_child_xpriv_from_account_xpriv(
        &self,
        account_xpriv: &ExtendedPrivKey,
        child_path: &DerivationPath,
    ) -> Result<ExtendedPrivKey> {
        if self.is_watch_only {
            return Err(crate::error::Error::WatchOnly);
        }

        let secp = Secp256k1::new();
        account_xpriv.derive_priv(&secp, child_path).map_err(crate::error::Error::Bip32)
    }

    /// Derive a child public key at a specific path from the account
    ///
    /// The path should be relative to the account (e.g., "0/5" for external address 5)
    pub fn derive_child_xpub(&self, child_path: &DerivationPath) -> Result<ExtendedPubKey> {
        let secp = Secp256k1::new();
        self.account_xpub.derive_pub(&secp, child_path).map_err(crate::error::Error::Bip32)
    }

    /// Derive an address at a specific chain and index
    ///
    /// # Arguments
    /// * `is_internal` - If true, derives from internal chain (1), otherwise external chain (0)
    /// * `index` - The address index
    ///
    /// # Example
    /// ```ignore
    /// let external_addr = account.derive_address_at(false, 5)?;  // Same as derive_receive_address(5)
    /// let internal_addr = account.derive_address_at(true, 3)?;   // Same as derive_change_address(3)
    /// ```
    pub fn derive_address_at(&self, is_internal: bool, index: u32) -> Result<dashcore::Address> {
        if is_internal {
            self.derive_change_address_impl(index)
        } else {
            self.derive_receive_address_impl(index)
        }
    }

    // Internal implementation methods to avoid name conflicts with trait defaults
    fn derive_receive_address_impl(&self, index: u32) -> Result<dashcore::Address> {
        use crate::bip32::ChildNumber;

        // Build path: 0/index (external chain)
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0)?, // External chain
            ChildNumber::from_normal_idx(index)?,
        ]);

        let xpub = self.derive_child_xpub(&path)?;
        // Convert secp256k1::PublicKey to dashcore::PublicKey
        let pubkey =
            dashcore::PublicKey::from_slice(&xpub.public_key.serialize()).map_err(|e| {
                crate::error::Error::InvalidParameter(format!("Invalid public key: {}", e))
            })?;
        Ok(dashcore::Address::p2pkh(&pubkey, self.network))
    }

    fn derive_change_address_impl(&self, index: u32) -> Result<dashcore::Address> {
        use crate::bip32::ChildNumber;

        // Build path: 1/index (internal/change chain)
        let path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1)?, // Internal chain
            ChildNumber::from_normal_idx(index)?,
        ]);

        let xpub = self.derive_child_xpub(&path)?;
        // Convert secp256k1::PublicKey to dashcore::PublicKey
        let pubkey =
            dashcore::PublicKey::from_slice(&xpub.public_key.serialize()).map_err(|e| {
                crate::error::Error::InvalidParameter(format!("Invalid public key: {}", e))
            })?;
        Ok(dashcore::Address::p2pkh(&pubkey, self.network))
    }

    /// Get the extended public key for a specific chain
    ///
    /// # Arguments
    /// * `is_internal` - If true, returns the internal chain xpub, otherwise external chain xpub
    ///
    /// # Example
    /// ```ignore
    /// let external_chain_xpub = account.get_chain_xpub(false)?;
    /// let internal_chain_xpub = account.get_chain_xpub(true)?;
    /// ```
    pub fn get_chain_xpub(&self, is_internal: bool) -> Result<ExtendedPubKey> {
        use crate::bip32::ChildNumber;

        let chain = if is_internal {
            1
        } else {
            0
        };
        let path = DerivationPath::from(vec![ChildNumber::from_normal_idx(chain)?]);

        self.derive_child_xpub(&path)
    }
}

impl AccountTrait for Account {
    fn parent_wallet_id(&self) -> Option<[u8; 32]> {
        self.parent_wallet_id
    }

    fn account_type(&self) -> &AccountType {
        &self.account_type
    }

    fn network(&self) -> Network {
        self.network
    }

    fn is_watch_only(&self) -> bool {
        self.is_watch_only
    }

    fn derive_address_at(&self, is_internal: bool, index: u32) -> Result<dashcore::Address> {
        self.derive_address_at(is_internal, index)
    }

    fn get_public_key_bytes(&self) -> alloc::vec::Vec<u8> {
        self.account_xpub.public_key.serialize().to_vec()
    }
}

impl ECDSAAccountTrait for Account {
    fn account_xpub(&self) -> ExtendedPubKey {
        self.account_xpub
    }

    fn derive_child_xpub(&self, child_path: &DerivationPath) -> Result<ExtendedPubKey> {
        self.derive_child_xpub(child_path)
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

    #[test]
    fn test_derive_receive_address() {
        let account = test_account();

        // Derive receive address at index 0
        let addr0 = account.derive_receive_address(0).unwrap();
        assert!(!addr0.to_string().is_empty());

        // Derive receive address at index 5
        let addr5 = account.derive_receive_address(5).unwrap();
        assert!(!addr5.to_string().is_empty());

        // Addresses at different indices should be different
        assert_ne!(addr0, addr5);
    }

    #[test]
    fn test_derive_change_address() {
        let account = test_account();

        // Derive change address at index 0
        let addr0 = account.derive_change_address(0).unwrap();
        assert!(!addr0.to_string().is_empty());

        // Derive change address at index 3
        let addr3 = account.derive_change_address(3).unwrap();
        assert!(!addr3.to_string().is_empty());

        // Addresses at different indices should be different
        assert_ne!(addr0, addr3);

        // Change address should be different from receive address at same index
        let receive0 = account.derive_receive_address(0).unwrap();
        assert_ne!(addr0, receive0);
    }

    #[test]
    fn test_derive_multiple_addresses() {
        let account = test_account();

        // Derive 5 receive addresses starting from index 0
        let receive_addrs = account.derive_receive_addresses(0, 5).unwrap();
        assert_eq!(receive_addrs.len(), 5);

        // All addresses should be unique
        let unique: std::collections::HashSet<_> = receive_addrs.iter().collect();
        assert_eq!(unique.len(), 5);

        // Derive 3 change addresses starting from index 2
        let change_addrs = account.derive_change_addresses(2, 3).unwrap();
        assert_eq!(change_addrs.len(), 3);

        // Verify the addresses match individual derivation
        assert_eq!(change_addrs[0], account.derive_change_address(2).unwrap());
        assert_eq!(change_addrs[1], account.derive_change_address(3).unwrap());
        assert_eq!(change_addrs[2], account.derive_change_address(4).unwrap());
    }

    #[test]
    fn test_derive_address_at() {
        let account = test_account();

        // External address at index 5
        let external5 = account.derive_address_at(false, 5).unwrap();
        let receive5 = account.derive_receive_address(5).unwrap();
        assert_eq!(external5, receive5);

        // Internal address at index 3
        let internal3 = account.derive_address_at(true, 3).unwrap();
        let change3 = account.derive_change_address(3).unwrap();
        assert_eq!(internal3, change3);
    }

    #[test]
    fn test_get_chain_xpub() {
        let account = test_account();

        // Get external chain xpub
        let external_xpub = account.get_chain_xpub(false).unwrap();

        // Get internal chain xpub
        let internal_xpub = account.get_chain_xpub(true).unwrap();

        // They should be different
        assert_ne!(external_xpub, internal_xpub);

        // Derive an address manually from the external chain xpub
        let secp = Secp256k1::new();
        let path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
        let addr_xpub = external_xpub.derive_pub(&secp, &path).unwrap();
        let pubkey = dashcore::PublicKey::from_slice(&addr_xpub.public_key.serialize()).unwrap();
        let manual_addr = dashcore::Address::p2pkh(&pubkey, Network::Testnet);

        // Should match the address derived using derive_receive_address
        let derived_addr = account.derive_receive_address(0).unwrap();
        assert_eq!(manual_addr, derived_addr);
    }

    #[test]
    fn test_address_derivation_consistency() {
        // Test that addresses are derived consistently
        let account = test_account();

        // Derive the same address multiple times
        let addr1 = account.derive_receive_address(42).unwrap();
        let addr2 = account.derive_receive_address(42).unwrap();
        assert_eq!(addr1, addr2, "Same index should always produce same address");

        // Test with change addresses too
        let change1 = account.derive_change_address(17).unwrap();
        let change2 = account.derive_change_address(17).unwrap();
        assert_eq!(change1, change2, "Same change index should always produce same address");
    }
}
