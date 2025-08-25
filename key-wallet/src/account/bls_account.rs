//! BLS-based account implementation
//!
//! This module provides account functionality using BLS12-381 keys
//! for Platform and masternode operations.

use super::account_trait::AccountTrait;
use crate::account::AccountType;
use crate::derivation_bls_bip32::{ExtendedBLSPrivKey, ExtendedBLSPubKey};
use crate::error::{Error, Result};
use crate::managed_account::address_pool::AddressPoolType;
use crate::{ChildNumber, DerivationPath, Network};
use alloc::vec::Vec;
use core::fmt;
use dashcore::Address;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::bip32::{ChainCode, Fingerprint};
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use dashcore::blsful::{Bls12381G2Impl, SerializationFormat};

use crate::account::derivation::AccountDerivation;
pub use dashcore::blsful::PublicKey as BLSPublicKey;
pub use dashcore::blsful::SecretKey;

/// BLS account structure for Platform and masternode operations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct BLSAccount {
    /// Wallet id (stored as Vec for serialization)
    pub parent_wallet_id: Option<Vec<u8>>,
    /// Account type (includes index information and derivation path)
    pub account_type: AccountType,
    /// Network this account belongs to
    pub network: Network,
    /// Extended BLS public key for HD derivation
    pub bls_public_key: ExtendedBLSPubKey,
    /// Whether this is a watch-only account
    pub is_watch_only: bool,
}

impl BLSAccount {
    /// Create a new BLS account from an extended public key
    pub fn new(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        bls_public_key: ExtendedBLSPubKey,
        network: Network,
    ) -> Result<Self> {
        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            bls_public_key,
            is_watch_only: true,
        })
    }

    /// Create a new BLS account from raw public key bytes
    pub fn from_public_key_bytes(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        bls_public_key: [u8; 48],
        network: Network,
    ) -> Result<Self> {
        // Create a BlsPublicKey from bytes
        let public_key = BLSPublicKey::<Bls12381G2Impl>::from_bytes_with_mode(
            &bls_public_key,
            SerializationFormat::Modern,
        )
        .map_err(|e| Error::InvalidParameter(format!("Invalid BLS public key: {}", e)))?;

        // Create an extended public key with default metadata
        let extended_key = ExtendedBLSPubKey {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key,
            chain_code: ChainCode::from([0u8; 32]),
        };

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            bls_public_key: extended_key,
            is_watch_only: true,
        })
    }

    /// Create a BLS account from an extended private key
    pub fn from_private_key(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        bls_private_key: ExtendedBLSPrivKey,
        network: Network,
    ) -> Result<Self> {
        let bls_public_key = ExtendedBLSPubKey::from_private_key(&bls_private_key);

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            bls_public_key,
            is_watch_only: false,
        })
    }

    /// Create a BLS account from raw private key bytes (seed)
    pub fn from_seed(
        parent_wallet_id: Option<Vec<u8>>,
        account_type: AccountType,
        seed: [u8; 32],
        network: Network,
    ) -> Result<Self> {
        let bls_private_key = ExtendedBLSPrivKey::new_master(network, &seed)?;
        let bls_public_key = ExtendedBLSPubKey::from_private_key(&bls_private_key);

        Ok(Self {
            parent_wallet_id,
            account_type,
            network,
            bls_public_key,
            is_watch_only: false,
        })
    }

    /// Derive a BLS key at a specific path (watch-only, non-hardened paths only)
    pub fn derive_bls_key_at_path(&self, path: &[u32]) -> Result<ExtendedBLSPubKey> {
        if self.is_watch_only {
            // For watch-only accounts, can only derive non-hardened paths from public key
            let mut current_key = self.bls_public_key.clone();

            for &index in path {
                if index >= 0x80000000 {
                    return Err(Error::WatchOnly);
                }
                let child_num = ChildNumber::from_normal_idx(index)?;
                current_key = current_key.ckd_pub(child_num)?;
            }

            Ok(current_key)
        } else {
            // For non-watch-only accounts, we can't derive without the private key
            // The private key should be managed separately by the wallet
            Err(Error::InvalidParameter(
                "Cannot derive keys from BLS account without private key access".to_string(),
            ))
        }
    }

    /// Derive a BLS key at a specific index
    pub fn derive_bls_key_at_index(&self, index: u32) -> Result<ExtendedBLSPubKey> {
        self.derive_bls_key_at_path(&[index])
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
}

impl AccountTrait for BLSAccount {
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
        self.bls_public_key.to_bytes().to_vec()
    }
}

impl fmt::Display for BLSAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(index) = self.index() {
            write!(
                f,
                "BLS Account #{} ({:?}) - Network: {:?}",
                index, self.account_type, self.network
            )
        } else {
            write!(f, "BLS Account ({:?}) - Network: {:?}", self.account_type, self.network)
        }
    }
}

impl AccountDerivation<ExtendedBLSPrivKey, ExtendedBLSPubKey, BLSPublicKey<Bls12381G2Impl>>
    for BLSAccount
{
    /// Derive an extended private key from the wallet's master BLS private key
    /// using the BLS account's derivation path.
    ///
    /// Returns an error for watch-only accounts.
    fn derive_xpriv_from_master_xpriv(
        &self,
        master_xpriv: &ExtendedBLSPrivKey,
    ) -> Result<ExtendedBLSPrivKey> {
        if self.is_watch_only {
            return Err(Error::WatchOnly);
        }

        // Get the derivation path for this account type
        let path = self.account_type.derivation_path(self.network)?;

        // Derive the account private key from master
        master_xpriv
            .derive_path(&path)
            .map_err(|e| Error::InvalidParameter(format!("BLS derivation error: {}", e)))
    }

    /// Derive a child BLS private key at a path relative to the account.
    ///
    /// Returns an error for watch-only accounts.
    fn derive_child_xpriv_from_account_xpriv(
        &self,
        account_xpriv: &ExtendedBLSPrivKey,
        child_path: &DerivationPath,
    ) -> Result<ExtendedBLSPrivKey> {
        if self.is_watch_only {
            return Err(Error::WatchOnly);
        }

        // Derive the child private key from account private key
        account_xpriv
            .derive_path(child_path)
            .map_err(|e| Error::InvalidParameter(format!("BLS child derivation error: {}", e)))
    }

    /// Derive a child BLS public key at a path relative to the account.
    ///
    /// Only non-hardened paths are supported for public key derivation.
    fn derive_child_xpub(&self, child_path: &DerivationPath) -> Result<ExtendedBLSPubKey> {
        // Check if any child in the path is hardened
        for child in child_path.as_ref() {
            if child.is_hardened() {
                return Err(Error::InvalidParameter(
                    "Cannot derive hardened child from BLS public key".to_string(),
                ));
            }
        }

        // Derive the child public key from account public key
        self.bls_public_key
            .derive_path(child_path)
            .map_err(|e| Error::InvalidParameter(format!("BLS public key derivation error: {}", e)))
    }

    /// Derive a BLS-based address at a specific chain and index.
    ///
    /// Creates a P2PKH-style address from the hash160 of the BLS public key.
    fn derive_address_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedBLSPrivKey>,
    ) -> Result<Address> {
        // Get the BLS public key at the specified index
        let bls_pubkey =
            self.derive_public_key_at(address_pool_type, index, use_hardened_with_priv_key)?;

        // Get the BLS public key bytes (48 bytes for BLS12-381 G2)
        let pubkey_bytes = bls_pubkey.to_bytes();

        // Create a P2PKH address from the hash160 of the BLS public key
        // This uses the same hash160 (SHA256 + RIPEMD160) as ECDSA addresses
        use dashcore::hashes::{hash160, Hash};
        let pubkey_hash = hash160::Hash::hash(&pubkey_bytes);

        // Create the address from the public key hash
        use dashcore::address::Payload;
        let payload = Payload::PubkeyHash(pubkey_hash.into());
        Ok(Address::new(self.network, payload))
    }

    /// Derive a BLS public key at a specific chain and index.
    ///
    /// If `use_hardened_with_priv_key` is provided, hardened derivation is used.
    /// Otherwise, only non-hardened derivation from the public key is possible.
    fn derive_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedBLSPrivKey>,
    ) -> Result<BLSPublicKey<Bls12381G2Impl>> {
        let extended_pubkey = self.derive_extended_public_key_at(
            address_pool_type,
            index,
            use_hardened_with_priv_key,
        )?;
        Ok(extended_pubkey.public_key)
    }

    /// Derive an extended BLS public key at a specific chain and index.
    ///
    /// Note: This method signature must match the trait, which uses ExtendedPrivKey.
    /// Since BLS accounts use ExtendedBLSPrivKey internally, we ignore the parameter
    /// and use None for public derivation.
    fn derive_extended_public_key_at(
        &self,
        address_pool_type: AddressPoolType,
        index: u32,
        use_hardened_with_priv_key: Option<ExtendedBLSPrivKey>,
    ) -> Result<ExtendedBLSPubKey> {
        let derivation_path = Self::derivation_path_for_index(
            address_pool_type,
            index,
            use_hardened_with_priv_key.is_some(),
        )?;

        if let Some(priv_key) = use_hardened_with_priv_key {
            // Derive using private key (supports hardened derivation)
            let derived_priv = if priv_key.depth == 0 {
                // This is the master key, derive the account first
                self.derive_xpriv_from_master_xpriv(&priv_key)?
            } else {
                // This is already the account key, derive the child
                self.derive_child_xpriv_from_account_xpriv(&priv_key, &derivation_path)?
            };
            Ok(ExtendedBLSPubKey::from_private_key(&derived_priv))
        } else {
            // Derive using public key (only non-hardened)
            self.derive_child_xpub(&derivation_path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::account_type::StandardAccountType;

    #[test]
    fn test_bls_account_creation() {
        // First create a valid BLS key pair to get a real public key
        let seed = [42u8; 32];
        let bls_private = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create BLS private key from seed");
        let bls_public = ExtendedBLSPubKey::from_private_key(&bls_private);
        let public_key_bytes = bls_public.to_bytes();

        // Now create account from the valid public key bytes
        let account = BLSAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes,
            Network::Testnet,
        )
        .expect("Failed to create BLS account from public key bytes");

        assert_eq!(account.get_public_key_bytes().len(), 48);
        assert!(account.is_watch_only);
        assert_eq!(account.index(), Some(0));
    }

    #[test]
    fn test_bls_account_from_seed() {
        let seed = [2u8; 32];
        let account = BLSAccount::from_seed(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            seed,
            Network::Testnet,
        )
        .expect("Failed to create BLS account from seed");

        assert!(!account.is_watch_only);
    }

    #[test]
    fn test_bls_to_watch_only() {
        let seed = [3u8; 32];
        let account = BLSAccount::from_seed(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            seed,
            Network::Testnet,
        )
        .expect("Failed to create BLS account from seed");

        let watch_only = account.to_watch_only();
        assert!(watch_only.is_watch_only);
        assert_eq!(watch_only.get_public_key_bytes(), account.get_public_key_bytes());
    }

    #[test]
    fn test_bls_address_derivation() {
        let seed = [4u8; 32];
        let account = BLSAccount::from_seed(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            seed,
            Network::Testnet,
        )
        .expect("Failed to create BLS account from seed");

        // BLS accounts now support P2PKH-style address derivation using hash160
        // But require private key for hardened derivation
        let bls_priv = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create BLS master private key");
        let result = account.derive_address_at(AddressPoolType::External, 0, Some(bls_priv));
        assert!(result.is_ok());

        let address = result.expect("Failed to derive BLS address");
        // Verify it's a valid testnet address
        assert_eq!(address.network(), &Network::Testnet);
    }
}
