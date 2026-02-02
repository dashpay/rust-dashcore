//! Account management for HD wallets
//!
//! This module provides comprehensive account management following BIP44,
//! including gap limit tracking, address pool management, and support for
//! multiple account types (standard, CoinJoin, watch-only).

pub mod account_collection;
pub mod account_trait;
#[cfg(feature = "bls")]
pub mod bls_account;
pub mod coinjoin;
#[cfg(feature = "eddsa")]
pub mod eddsa_account;
// pub mod scan;
pub mod account_type;
pub mod derivation;
mod serialization;

use core::fmt;

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use secp256k1::Secp256k1;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::dip9::DerivationPathReference;
use crate::error::Result;
use crate::{ChildNumber, Error, Network};

use crate::account::derivation::AccountDerivation;
use crate::managed_account::address_pool::AddressPoolType;
pub use crate::managed_account::managed_account_collection::ManagedAccountCollection;
pub use crate::managed_account::managed_account_trait::ManagedAccountTrait;
pub use crate::managed_account::managed_account_type::ManagedAccountType;
pub use crate::managed_account::metadata::AccountMetadata;
pub use crate::managed_account::transaction_record::TransactionRecord;
pub use crate::managed_account::ManagedCoreAccount;
pub use account_collection::AccountCollection;
pub use account_trait::AccountTrait;
pub use account_type::{AccountType, StandardAccountType};
#[cfg(feature = "bls")]
pub use bls_account::BLSAccount;
pub use coinjoin::CoinJoinPools;
use dashcore::{Address, PublicKey};
#[cfg(feature = "eddsa")]
pub use eddsa_account::EdDSAAccount;

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
        Self::from_xpub(parent_wallet_id, account_type, account_xpub, network)
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

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            account_xpub,
            is_watch_only: false, // Not watch-only when created from private key
        })
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

    /// Get the extended public key for this account
    pub fn extended_public_key(&self) -> ExtendedPubKey {
        self.account_xpub
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

    fn get_public_key_bytes(&self) -> Vec<u8> {
        self.account_xpub.public_key.serialize().to_vec()
    }
}

impl AccountDerivation<ExtendedPrivKey, ExtendedPubKey, PublicKey, dashcore::PrivateKey>
    for Account
{
    fn defaults_to_hardened_derivation(&self) -> bool {
        false
    }

    fn has_intermediate_derivation(&self) -> Option<ChildNumber> {
        match self.account_type {
            AccountType::IdentityTopUp {
                registration_index,
            } => Some(ChildNumber::Hardened {
                index: registration_index,
            }),
            _ => None,
        }
    }

    fn has_internal_and_external(&self) -> bool {
        matches!(self.account_type, AccountType::Standard { .. })
    }
    /// Derive an extended private key from a wallet's master private key
    ///
    /// This requires the wallet to have the master private key available.
    /// Returns None for watch-only wallets.
    fn derive_xpriv_from_master_xpriv(
        &self,
        master_xpriv: &ExtendedPrivKey,
    ) -> std::result::Result<ExtendedPrivKey, Error> {
        if self.is_watch_only {
            return Err(Error::WatchOnly);
        }

        let secp = Secp256k1::new();
        let path = self.derivation_path()?;
        master_xpriv.derive_priv(&secp, &path).map_err(Error::Bip32)
    }

    /// Derive a child private key at a specific path from the account
    ///
    /// This requires providing the account's extended private key.
    /// The path should be relative to the account (e.g., "0/5" for external address 5)
    fn derive_child_xpriv_from_account_xpriv(
        &self,
        account_xpriv: &ExtendedPrivKey,
        child_path: &DerivationPath,
    ) -> std::result::Result<ExtendedPrivKey, Error> {
        if self.is_watch_only {
            return Err(Error::WatchOnly);
        }

        let secp = Secp256k1::new();
        account_xpriv.derive_priv(&secp, child_path).map_err(Error::Bip32)
    }

    /// Derive a child public key at a specific path from the account
    ///
    /// The path should be relative to the account (e.g., "0/5" for external address 5)
    fn derive_child_xpub(
        &self,
        child_path: &DerivationPath,
    ) -> std::result::Result<ExtendedPubKey, Error> {
        let secp = Secp256k1::new();
        self.account_xpub.derive_pub(&secp, child_path).map_err(Error::Bip32)
    }

    /// Derive an address at a specific **chain** (external/internal) and **index**.
    ///
    /// This derives the child (xpub or xpriv → xpub) at:
    /// - External chain:   `.../0/{index}`
    /// - Internal (change) `.../1/{index}`
    /// - Absent:           `.../{index}`
    ///
    /// If `use_hardened_with_priv_key` is **Some(xpriv)**, hardened derivation is
    /// performed for the returned path components (and we derive via private key,
    /// then compute the corresponding extended public key). If it is **None**, we
    /// perform **non-hardened** derivation from the account xpub.
    ///
    /// **BIP44 note:** the “change” level is `0` for external receive addresses and
    /// `1` for internal/change addresses.
    ///
    /// # Parameters
    /// - `address_pool_type`: which chain to use (`External` = 0, `Internal` = 1, or `Absent`)
    /// - `index`: address index on that chain
    /// - `use_hardened_with_priv_key`: when `Some(xpriv)`, use the provided extended
    ///   private key to derive hardened children; when `None`, derive public children
    ///   from the account xpub (non-hardened)
    ///
    /// # Returns
    /// A `dashcore::Address` derived at the requested chain and index.
    ///
    /// # Examples
    /// ```ignore
    /// // Derive external (receive) and internal (change) addresses at specific indices,
    /// // using public (non-hardened) derivation:
    /// let recv = account.derive_address_at(AddressPoolType::External, 5, None)?;   // .../0/5
    /// let change = account.derive_address_at(AddressPoolType::Internal, 3, None)?; // .../1/3
    ///
    /// // Derive the same positions using hardened derivation from an xpriv:
    /// let recv_h = account.derive_address_at(AddressPoolType::External, 5, Some(account_xpriv.clone()))?;
    /// let chg_h  = account.derive_address_at(AddressPoolType::Internal, 3, Some(account_xpriv))?;
    /// ```
    fn derive_address_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedPrivKey>,
    ) -> std::result::Result<Address, Error> {
        let public_key = self.derive_extended_public_key_at(
            address_pool_type,
            index,
            use_hardened_with_priv_key,
        )?;
        Ok(Address::p2pkh(&public_key.to_pub(), self.network))
    }

    fn derive_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedPrivKey>,
    ) -> std::result::Result<PublicKey, Error> {
        Ok(self
            .derive_extended_public_key_at(address_pool_type, index, use_hardened_with_priv_key)?
            .to_pub())
    }

    fn derive_extended_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedPrivKey>,
    ) -> std::result::Result<ExtendedPubKey, Error> {
        let derivation_path = Self::derivation_path_for_index(
            address_pool_type,
            index,
            use_hardened_with_priv_key.is_some(),
        )?;
        if let Some(priv_key) = use_hardened_with_priv_key {
            let xpriv = if priv_key.depth == 0 {
                self.derive_xpriv_from_master_xpriv(&priv_key)?
            } else {
                self.derive_child_xpriv_from_account_xpriv(&priv_key, &derivation_path)?
            };
            let secp = Secp256k1::new();
            Ok(ExtendedPubKey::from_priv(&secp, &xpriv))
        } else {
            self.derive_child_xpub(&derivation_path)
        }
    }

    fn derive_from_master_xpriv_private_key_at(
        &self,
        master_xpriv: &ExtendedPrivKey,
        index: u32,
    ) -> std::result::Result<dashcore::PrivateKey, Error> {
        let xpriv = self.derive_from_master_xpriv_extended_xpriv_at(master_xpriv, index)?;
        // Wrap into dashcore::PrivateKey with compressed=true
        Ok(dashcore::PrivateKey {
            compressed: true,
            network: self.network,
            inner: xpriv.private_key,
        })
    }

    fn derive_from_seed_extended_xpriv_at(
        &self,
        seed: &[u8],
        index: u32,
    ) -> std::result::Result<ExtendedPrivKey, Error> {
        let master = ExtendedPrivKey::new_master(self.network, seed).map_err(Error::Bip32)?;
        self.derive_from_master_xpriv_extended_xpriv_at(&master, index)
    }

    fn derive_from_seed_private_key_at(
        &self,
        seed: &[u8],
        index: u32,
    ) -> std::result::Result<dashcore::PrivateKey, Error> {
        let xpriv = self.derive_from_seed_extended_xpriv_at(seed, index)?;
        Ok(dashcore::PrivateKey {
            compressed: true,
            network: self.network,
            inner: xpriv.private_key,
        })
    }
}

pub trait ECDSAAddressDerivation:
    AccountDerivation<ExtendedPrivKey, ExtendedPubKey, PublicKey, dashcore::PrivateKey>
{
    /// Derive a receive (external) address at a specific index
    fn derive_receive_address(&self, index: u32) -> Result<Address> {
        self.derive_address_at(AddressPoolType::External, index, None)
    }

    /// Derive a change (internal) address at a specific index
    fn derive_change_address(&self, index: u32) -> Result<Address> {
        self.derive_address_at(AddressPoolType::Internal, index, None)
    }

    /// Derive multiple receive addresses starting from a specific index
    fn derive_receive_addresses(&self, start_index: u32, count: u32) -> Result<Vec<Address>> {
        let mut addresses = Vec::with_capacity(count as usize);
        for i in 0..count {
            addresses.push(self.derive_receive_address(start_index + i)?);
        }
        Ok(addresses)
    }

    /// Derive multiple change addresses starting from a specific index
    fn derive_change_addresses(&self, start_index: u32, count: u32) -> Result<Vec<Address>> {
        let mut addresses = Vec::with_capacity(count as usize);
        for i in 0..count {
            addresses.push(self.derive_change_address(start_index + i)?);
        }
        Ok(addresses)
    }
}

impl ECDSAAddressDerivation for Account {}

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

    pub(crate) fn test_account() -> Account {
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
        let external5 = account.derive_address_at(AddressPoolType::External, 5, None).unwrap();
        let receive5 = account.derive_receive_address(5).unwrap();
        assert_eq!(external5, receive5);

        // Internal address at index 3
        let internal3 = account.derive_address_at(AddressPoolType::Internal, 3, None).unwrap();
        let change3 = account.derive_change_address(3).unwrap();
        assert_eq!(internal3, change3);
    }
}
