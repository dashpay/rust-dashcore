//! Account balance tracking
//!
//! This module contains balance tracking structures for accounts.

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Account balance tracking
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AccountBalance {
    /// Confirmed balance
    pub confirmed: u64,
    /// Unconfirmed balance
    pub unconfirmed: u64,
    /// Immature balance (coinbase)
    pub immature: u64,
    /// Total balance (confirmed + unconfirmed)
    pub total: u64,
}
