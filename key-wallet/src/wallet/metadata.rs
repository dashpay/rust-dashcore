//! Wallet metadata types and functionality
//!
//! This module contains the metadata structures for wallets.

use alloc::collections::BTreeMap;
use alloc::string::String;
use dashcore::prelude::CoreBlockHeight;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet metadata
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletMetadata {
    /// Wallet creation timestamp
    pub first_loaded_at: u64,
    /// Birth height (when wallet was created/restored) - 0 (genesis) if unknown
    pub birth_height: CoreBlockHeight,
    /// Last sync timestamp
    pub last_synced: Option<u64>,
    /// Total transactions
    pub total_transactions: u64,
    /// Wallet version
    pub version: u32,
    /// Custom metadata fields
    pub custom: BTreeMap<String, String>,
}
