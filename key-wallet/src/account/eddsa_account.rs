//! EdDSA (Ed25519) account implementation
//!
//! This module provides account functionality using Ed25519 keys
//! for Platform identity operations.

use super::account_trait::AccountTrait;
use crate::account::AccountType;
use crate::derivation_slip10::{ExtendedEd25519PrivKey, ExtendedEd25519PubKey, VerifyingKey};
use crate::error::{Error, Result};
use crate::{ChildNumber, DerivationPath, Network};
use alloc::vec::Vec;
use core::fmt;
use dashcore::Address;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::account::derivation::AccountDerivation;
use crate::bip32::{ChainCode, Fingerprint};
use crate::managed_account::address_pool::AddressPoolType;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};

/// EdDSA (Ed25519) account structure for Platform identity operations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct EdDSAAccount {
    /// Wallet id (stored as Vec for serialization)
    pub parent_wallet_id: Option<Vec<u8>>,
    /// Account type (includes index information and derivation path)
    pub account_type: AccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Extended Ed25519 public key for HD derivation
    pub ed25519_public_key: ExtendedEd25519PubKey,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
}

impl EdDSAAccount {
    /// Create a new EdDSA account from an extended public key
    pub fn new(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        ed25519_public_key: ExtendedEd25519PubKey,
        network: Network,
    ) -> Result<Self> {
        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            ed25519_public_key,
            is_watch_only: true,
        })
    }

    /// Create a new EdDSA account from raw public key bytes
    pub fn from_public_key_bytes(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        ed25519_public_key: [u8; 32],
        network: Network,
    ) -> Result<Self> {
        // Create an extended public key with default metadata
        use dashcore::ed25519_dalek::VerifyingKey;
        let verifying_key = VerifyingKey::from_bytes(&ed25519_public_key)
            .map_err(|e| Error::InvalidParameter(format!("Invalid Ed25519 public key: {}", e)))?;

        let extended_key = ExtendedEd25519PubKey {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            public_key: verifying_key,
            chain_code: ChainCode::from([0u8; 32]),
        };

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            ed25519_public_key: extended_key,
            is_watch_only: true,
        })
    }

    /// Create an EdDSA account from a private key (seed)
    pub fn from_seed(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        ed25519_seed: [u8; 32],
        network: Network,
    ) -> Result<Self> {
        let ed25519_private_key = ExtendedEd25519PrivKey::new_master(network, &ed25519_seed)?;
        let ed25519_public_key = ExtendedEd25519PubKey::from_priv(&ed25519_private_key)?;

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            ed25519_public_key,
            is_watch_only: false,
        })
    }

    /// Create an EdDSA account from an extended private key
    pub fn from_private_key(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        ed25519_private_key: ExtendedEd25519PrivKey,
        network: Network,
    ) -> Result<Self> {
        let ed25519_public_key = ExtendedEd25519PubKey::from_priv(&ed25519_private_key)?;

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            ed25519_public_key,
            is_watch_only: false,
        })
    }

    /// Derive an Ed25519 key at a specific path
    /// Note: Ed25519 with SLIP-0010 only supports hardened derivation
    pub fn derive_ed25519_key_at_path(&self, path: &[u32]) -> Result<ExtendedEd25519PubKey> {
        if !self.is_watch_only {
            // For non-watch-only accounts, we can't derive without the private key
            // The private key should be managed separately by the wallet
            return Err(Error::InvalidParameter(
                "Cannot derive keys from EdDSA account without private key access".to_string(),
            ));
        }

        // Ed25519 only supports hardened derivation, so watch-only can't derive
        for &index in path {
            if index >= 0x80000000 {
                return Err(Error::WatchOnly);
            }
        }

        // Since Ed25519 only supports hardened derivation, we can't derive from public key
        Err(Error::WatchOnly)
    }

    /// Derive an Ed25519 key at a specific index
    pub fn derive_ed25519_key_at_index(&self, index: u32) -> Result<ExtendedEd25519PubKey> {
        self.derive_ed25519_key_at_path(&[index])
    }

    /// Create a watch-only version of this account
    pub fn to_watch_only(&self) -> Self {
        let mut watch_only = self.clone();
        watch_only.is_watch_only = true;
        watch_only
    }

    /// Serialize account to bytes
    #[cfg(feature = "bincode")]
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Deserialize account from bytes
    #[cfg(feature = "bincode")]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Derive a Platform identity key at index
    pub fn derive_identity_key(&self, index: u32) -> Result<ExtendedEd25519PubKey> {
        self.derive_ed25519_key_at_index(index)
    }

    /// Get the master identity public key
    pub fn get_master_identity_key(&self) -> [u8; 32] {
        self.ed25519_public_key.public_key.to_bytes()
    }
}

impl AccountTrait for EdDSAAccount {
    fn parent_wallet_id(&self) -> Option<[u8; 32]> {
        self.parent_wallet_id.as_ref().and_then(|v| {
            if v.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(v);
                Some(arr)
            } else {
                None
            }
        })
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
        self.ed25519_public_key.public_key.to_bytes().to_vec()
    }
}

impl fmt::Display for EdDSAAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(index) = self.index() {
            write!(
                f,
                "EdDSA Account #{} ({:?}) - Network: {:?}",
                index, self.account_type, self.network
            )
        } else {
            write!(f, "EdDSA Account ({:?}) - Network: {:?}", self.account_type, self.network)
        }
    }
}

impl AccountDerivation<ExtendedEd25519PrivKey, ExtendedEd25519PubKey, VerifyingKey>
    for EdDSAAccount
{
    /// Derive an extended private key from the wallet's master Ed25519 private key
    /// using the EdDSA account's derivation path.
    ///
    /// Returns an error for watch-only accounts.
    fn derive_xpriv_from_master_xpriv(
        &self,
        master_xpriv: &ExtendedEd25519PrivKey,
    ) -> Result<ExtendedEd25519PrivKey> {
        if self.is_watch_only {
            return Err(Error::WatchOnly);
        }

        // Get the derivation path for this account type
        let path = self.account_type.derivation_path(self.network)?;

        // Derive the account private key from master
        master_xpriv
            .derive_priv(&path)
            .map_err(|e| Error::InvalidParameter(format!("Ed25519 derivation error: {}", e)))
    }

    /// Derive a child Ed25519 private key at a path relative to the account.
    ///
    /// Returns an error for watch-only accounts.
    fn derive_child_xpriv_from_account_xpriv(
        &self,
        account_xpriv: &ExtendedEd25519PrivKey,
        child_path: &DerivationPath,
    ) -> Result<ExtendedEd25519PrivKey> {
        if self.is_watch_only {
            return Err(Error::WatchOnly);
        }

        // Derive the child private key from account private key
        account_xpriv
            .derive_priv(child_path)
            .map_err(|e| Error::InvalidParameter(format!("Ed25519 child derivation error: {}", e)))
    }

    /// Derive a child Ed25519 public key at a path relative to the account.
    ///
    /// Ed25519 only supports hardened derivation, so this always returns an error.
    fn derive_child_xpub(&self, _child_path: &DerivationPath) -> Result<ExtendedEd25519PubKey> {
        // Ed25519 with SLIP-0010 only supports hardened derivation
        // Cannot derive from public key alone
        Err(Error::InvalidParameter(
            "Ed25519 does not support public key derivation (only hardened paths allowed)"
                .to_string(),
        ))
    }

    /// Derive an Ed25519-based address at a specific chain and index.
    ///
    /// Creates a P2PKH-style address from the hash160 of the Ed25519 public key.
    fn derive_address_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedEd25519PrivKey>,
    ) -> Result<Address> {
        // Get the Ed25519 public key at the specified index
        let ed25519_pubkey =
            self.derive_public_key_at(address_pool_type, index, use_hardened_with_priv_key)?;

        // Get the Ed25519 public key bytes (32 bytes for Ed25519)
        let pubkey_bytes = ed25519_pubkey.to_bytes();

        // Create a P2PKH address from the hash160 of the Ed25519 public key
        // This uses the same hash160 (SHA256 + RIPEMD160) as ECDSA addresses
        use dashcore::hashes::{hash160, Hash};
        let pubkey_hash = hash160::Hash::hash(&pubkey_bytes);

        // Create the address from the public key hash
        use dashcore::address::Payload;
        let payload = Payload::PubkeyHash(pubkey_hash.into());
        Ok(Address::new(self.network, payload))
    }

    /// Derive an Ed25519 public key at a specific chain and index.
    ///
    /// Requires private key for derivation since Ed25519 only supports hardened paths.
    fn derive_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedEd25519PrivKey>,
    ) -> Result<VerifyingKey> {
        let extended_pubkey = self.derive_extended_public_key_at(
            address_pool_type,
            index,
            use_hardened_with_priv_key,
        )?;
        Ok(extended_pubkey.public_key)
    }

    /// Derive an extended Ed25519 public key at a specific chain and index.
    ///
    /// Ed25519 only supports hardened derivation, so requires private key.
    fn derive_extended_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedEd25519PrivKey>,
    ) -> Result<ExtendedEd25519PubKey> {
        // Ed25519 only supports hardened derivation
        let priv_key = use_hardened_with_priv_key.ok_or_else(|| {
            Error::InvalidParameter(
                "Ed25519 requires private key for derivation (only hardened paths supported)"
                    .to_string(),
            )
        })?;

        // Always use hardened derivation for Ed25519
        let derivation_path = Self::derivation_path_for_index(
            address_pool_type,
            index,
            true, // always hardened for Ed25519
        )?;

        // Derive using private key
        let derived_priv = if priv_key.depth == 0 {
            // This is the master key, derive the account first
            self.derive_xpriv_from_master_xpriv(&priv_key)?
        } else {
            // This is already the account key, derive the child
            self.derive_child_xpriv_from_account_xpriv(&priv_key, &derivation_path)?
        };

        ExtendedEd25519PubKey::from_priv(&derived_priv).map_err(|e| {
            Error::InvalidParameter(format!("Failed to get Ed25519 public key: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::account_type::StandardAccountType;
    use crate::managed_account::address_pool::AddressPoolType;

    #[test]
    fn test_eddsa_account_creation() {
        // First create a valid Ed25519 key pair to get a real public key
        let seed = [42u8; 32];
        let ed25519_private = ExtendedEd25519PrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create Ed25519 private key from seed");
        let ed25519_public = ExtendedEd25519PubKey::from_priv(&ed25519_private)
            .expect("Failed to derive Ed25519 public key from private key");
        let public_key_bytes = ed25519_public.public_key.to_bytes();

        // Now create account from the valid public key bytes
        let account = EdDSAAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from public key bytes");

        assert_eq!(account.get_public_key_bytes(), public_key_bytes.to_vec());
        assert!(account.is_watch_only);
        assert_eq!(account.index(), Some(0));
    }

    #[test]
    fn test_eddsa_account_from_seed() {
        let seed = [2u8; 32];
        let account = EdDSAAccount::from_seed(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            seed,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from seed");

        assert!(!account.is_watch_only);
    }

    #[test]
    fn test_eddsa_to_watch_only() {
        let seed = [3u8; 32];
        let account = EdDSAAccount::from_seed(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            seed,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from seed");

        let watch_only = account.to_watch_only();
        assert!(watch_only.is_watch_only);
        assert_eq!(watch_only.get_public_key_bytes(), account.get_public_key_bytes());
    }

    #[test]
    fn test_eddsa_address_derivation_fails() {
        // First create a valid Ed25519 key pair to get a real public key
        let seed = [4u8; 32];
        let ed25519_private = ExtendedEd25519PrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create Ed25519 private key from seed");
        let ed25519_public = ExtendedEd25519PubKey::from_priv(&ed25519_private)
            .expect("Failed to derive Ed25519 public key from private key");
        let public_key_bytes = ed25519_public.public_key.to_bytes();

        let account = EdDSAAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from public key bytes");

        // EdDSA accounts require private key for address derivation (hardened only)
        let result = account.derive_address_at(AddressPoolType::External, 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_identity_key() {
        let seed = [5u8; 32];
        let account = EdDSAAccount::from_seed(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            seed,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from seed");

        // EdDSA accounts can't derive without private key access
        let result = account.derive_identity_key(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_master_identity_key() {
        // First create a valid Ed25519 key pair to get a real public key
        let seed = [6u8; 32];
        let ed25519_private = ExtendedEd25519PrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create Ed25519 private key from seed");
        let ed25519_public = ExtendedEd25519PubKey::from_priv(&ed25519_private)
            .expect("Failed to derive Ed25519 public key from private key");
        let public_key_bytes = ed25519_public.public_key.to_bytes();

        let account = EdDSAAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from public key bytes");

        assert_eq!(account.get_master_identity_key(), public_key_bytes);
    }
}
