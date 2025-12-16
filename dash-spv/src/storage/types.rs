//! Storage-related types and structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Masternode state for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeState {
    /// Last processed height.
    pub last_height: u32,

    /// Serialized masternode list engine state.
    pub engine_state: Vec<u8>,

    /// Last update timestamp.
    pub last_update: u64,
}

/// Storage statistics.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Number of headers stored.
    pub header_count: u64,

    /// Number of filter headers stored.
    pub filter_header_count: u64,

    /// Number of filters stored.
    pub filter_count: u64,

    /// Total storage size in bytes.
    pub total_size: u64,

    /// Individual component sizes.
    pub component_sizes: HashMap<String, u64>,
}
