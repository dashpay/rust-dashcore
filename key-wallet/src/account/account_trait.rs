//! Trait for common account functionality
//!
//! This module defines the AccountTrait which provides common functionality
//! for all account types (ECDSA, BLS, EdDSA).

use crate::bip32::DerivationPath;
use crate::dip9::DerivationPathReference;
use crate::error::Result;
use crate::Network;
use alloc::vec::Vec;

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
