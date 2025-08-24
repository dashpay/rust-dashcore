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
pub mod scan;
pub mod account_type;
mod helpers;
mod derivation;
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
use crate::Network;

pub use account_collection::AccountCollection;
pub use account_trait::{AccountTrait, ECDSAAccountTrait};
#[cfg(feature = "bls")]
pub use bls_account::BLSAccount;
pub use coinjoin::CoinJoinPools;
#[cfg(feature = "eddsa")]
pub use eddsa_account::EdDSAAccount;
pub use crate::managed_account::ManagedAccount;
pub use crate::managed_account::managed_account_collection::ManagedAccountCollection;
pub use crate::managed_account::managed_account_trait::ManagedAccountTrait;
pub use crate::managed_account::metadata::AccountMetadata;
pub use scan::ScanResult;
pub use crate::managed_account::transaction_record::TransactionRecord;
pub use account_type::{AccountType, StandardAccountType};
use crate::managed_account::address_pool::AddressPoolType;
pub use crate::managed_account::managed_account_type::ManagedAccountType;

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
