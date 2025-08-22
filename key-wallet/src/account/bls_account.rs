//! BLS-based account implementation
//!
//! This module provides account functionality using BLS12-381 keys
//! for Platform and masternode operations.

use super::account_trait::AccountTrait;
use crate::account::AccountType;
use crate::derivation_bls_bip32::{ExtendedBLSPrivKey, ExtendedBLSPubKey};
use crate::error::{Error, Result};
use crate::{ChildNumber, Network};
use alloc::vec::Vec;
use core::fmt;
use dashcore::Address;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::bip32::{ChainCode, Fingerprint};
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use dashcore::blsful::{Bls12381G2Impl, SerializationFormat};

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
        format: SerializationFormat,
        network: Network,
    ) -> Result<Self> {
        // Create a BlsPublicKey from bytes
        let public_key =
            BLSPublicKey::<Bls12381G2Impl>::from_bytes_with_mode(&bls_public_key, format)
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

    fn derive_address_at(&self, _is_internal: bool, _index: u32) -> Result<Address> {
        // BLS keys don't directly map to standard addresses
        // They're used for Platform operations and voting
        // For now, we'll return an error indicating this isn't supported
        Err(Error::InvalidParameter(
            "BLS accounts don't support standard address derivation".to_string(),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::types::StandardAccountType;

    #[test]
    fn test_bls_account_creation() {
        let public_key = [1u8; 48];
        let account = BLSAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key,
            Network::Testnet,
        )
        .unwrap();

        assert_eq!(account.get_public_key_bytes(), public_key.to_vec());
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
        .unwrap();

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
        .unwrap();

        let watch_only = account.to_watch_only();
        assert!(watch_only.is_watch_only);
        assert_eq!(watch_only.get_public_key_bytes(), account.get_public_key_bytes());
    }

    #[test]
    fn test_bls_address_derivation_fails() {
        let public_key = [4u8; 48];
        let account = BLSAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key,
            Network::Testnet,
        )
        .unwrap();

        // BLS accounts don't support standard address derivation
        let result = account.derive_address_at(false, 0);
        assert!(result.is_err());
    }
}
