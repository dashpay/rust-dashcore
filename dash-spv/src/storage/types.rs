//! Storage-related types and structures.

use serde::{Deserialize, Serialize};

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
