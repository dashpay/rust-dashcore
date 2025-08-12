//! Wallet metadata types and functionality
//!
//! This module contains the metadata structures for wallets.

use alloc::collections::BTreeMap;
use alloc::string::String;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet metadata
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletMetadata {
    /// Wallet creation timestamp
    pub created_at: u64,
    /// Last sync timestamp
    pub last_synced: Option<u64>,
    /// Total transactions
    pub total_transactions: u64,
    /// Wallet version
    pub version: u32,
    /// Custom metadata fields
    pub custom: BTreeMap<String, String>,
}
