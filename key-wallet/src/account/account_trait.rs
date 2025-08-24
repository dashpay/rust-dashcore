//! Trait for common account functionality
//!
//! This module defines the AccountTrait which provides common functionality
//! for all account types (ECDSA, BLS, EdDSA).

use crate::bip32::{DerivationPath, ExtendedPubKey};
use crate::dip9::DerivationPathReference;
use crate::error::Result;
use crate::Network;
use alloc::vec::Vec;
use dashcore::Address;

/// Common trait for all account types
pub trait AccountTrait {
    /// Get the parent wallet ID
    fn parent_wallet_id(&self) -> Option<[u8; 32]>;

    /// Get the account type
    fn account_type(&self) -> &crate::account::AccountType;

    /// Get the network this account belongs to
    fn network(&self) -> Network;

    /// Check if this is a watch-only account
    fn is_watch_only(&self) -> bool;

    /// Get the account index
    fn index(&self) -> Option<u32> {
        self.account_type().index()
    }

    /// Get the derivation path reference for this account
    fn derivation_path_reference(&self) -> DerivationPathReference {
        self.account_type().derivation_path_reference()
    }

    /// Get the derivation path for this account
    fn derivation_path(&self) -> Result<DerivationPath> {
        self.account_type().derivation_path(self.network())
    }

    /// Derive an address at a specific chain and index
    fn derive_address_at(&self, is_internal: bool, index: u32) -> Result<Address>;

    /// Derive a receive (external) address at a specific index
    fn derive_receive_address(&self, index: u32) -> Result<Address> {
        self.derive_address_at(false, index)
    }

    /// Derive a change (internal) address at a specific index
    fn derive_change_address(&self, index: u32) -> Result<Address> {
        self.derive_address_at(true, index)
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

    /// Get the public key bytes for verification (key type specific)
    fn get_public_key_bytes(&self) -> Vec<u8>;

    /// Export account as watch-only
    fn to_watch_only(&self) -> Self
    where
        Self: Sized + Clone,
    {
        self.clone()
    }
}

/// Extended trait for ECDSA-based accounts
pub trait ECDSAAccountTrait: AccountTrait {
    /// Get the account-level extended public key
    fn account_xpub(&self) -> ExtendedPubKey;

    /// Derive a child public key at a specific path from the account
    fn derive_child_xpub(&self, child_path: &DerivationPath) -> Result<ExtendedPubKey>;

    /// Get the extended public key for a specific chain
    fn get_chain_xpub(&self, is_internal: bool) -> Result<ExtendedPubKey> {
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
