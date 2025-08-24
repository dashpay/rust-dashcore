//! Account metadata for organization and tracking
//!
//! This module contains metadata structures for accounts.

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Account metadata for organization and tracking
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct AccountMetadata {
    /// Human-readable account name
    pub name: Option<String>,
    /// Account description
    pub description: Option<String>,
    /// Account color for UI (hex format)
    pub color: Option<String>,
    /// Custom tags for categorization
    pub tags: Vec<String>,
    /// Account creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_used: Option<u64>,
    /// Total received amount
    pub total_received: u64,
    /// Total sent amount
    pub total_sent: u64,
    /// Transaction count
    pub tx_count: u32,
}
