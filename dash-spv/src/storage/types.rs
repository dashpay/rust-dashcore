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

/// Storage configuration.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Maximum number of headers to cache in memory.
    pub max_header_cache: usize,

    /// Maximum number of filter headers to cache in memory.
    pub max_filter_header_cache: usize,

    /// Maximum number of filters to cache in memory.
    pub max_filter_cache: usize,

    /// Whether to compress data on disk.
    pub enable_compression: bool,

    /// Sync to disk frequency.
    pub sync_frequency: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_header_cache: 10000,
            max_filter_header_cache: 10000,
            max_filter_cache: 1000,
            enable_compression: true,
            sync_frequency: 100,
        }
    }
}
