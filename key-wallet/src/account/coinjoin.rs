//! CoinJoin-specific address pools
//!
//! This module contains structures for managing CoinJoin address pools.

use super::address_pool::AddressPool;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// CoinJoin-specific address pools
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct CoinJoinPools {
    /// CoinJoin receive addresses
    pub external: AddressPool,
    /// CoinJoin change addresses
    pub internal: AddressPool,
    /// CoinJoin rounds completed
    pub rounds_completed: u32,
    /// CoinJoin balance
    pub coinjoin_balance: u64,
}
