//! Wallet balance types and functionality
//!
//! This module contains balance-related structures for wallets.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet balance summary
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletBalance {
    /// Confirmed balance
    pub confirmed: u64,
    /// Unconfirmed balance
    pub unconfirmed: u64,
    /// Immature balance (coinbase)
    pub immature: u64,
    /// Total balance
    pub total: u64,
}
