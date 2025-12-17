//! Persistent sync state management for resuming sync after restarts.

use dashcore::{BlockHash, Network};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::types::SyncProgress;

/// Complete persistent sync state that can be saved and restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentSyncState {
    /// Network this state is for.
    pub network: Network,

    /// Current chain tip information.
    pub chain_tip: ChainTip,

    /// Sync progress at the time of saving.
    pub sync_progress: SyncProgress,

    /// Checkpoint data for optimized sync resumption.
    pub checkpoints: Vec<SyncCheckpoint>,

    /// Masternode sync state.
    pub masternode_sync: MasternodeSyncState,

    /// Filter sync state.
    pub filter_sync: FilterSyncState,

    /// Timestamp when this state was saved.
    pub saved_at: SystemTime,

    /// Chain work up to the tip (for validation).
    pub chain_work: String,
}

/// Chain tip information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTip {
    /// Height of the chain tip.
    pub height: u32,

    /// Hash of the tip block.
    pub hash: BlockHash,

    /// Previous block hash (for validation).
    pub prev_hash: BlockHash,

    /// Time of the tip block.
    pub time: u32,
}

/// Sync checkpoint for resuming from a known good state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    /// Height of the checkpoint.
    pub height: u32,

    /// Block hash at this height.
    pub block_hash: BlockHash,

    /// Filter header hash at this height (if available).
    pub filter_header: Option<dashcore::hash_types::FilterHeader>,

    /// Whether this checkpoint has been validated.
    pub validated: bool,

    /// Timestamp when this checkpoint was created.
    pub created_at: SystemTime,
}

/// Masternode sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeSyncState {
    /// Last height where masternode list was synced.
    pub last_synced_height: Option<u32>,

    /// Whether masternode sync is complete.
    pub is_synced: bool,

    /// Number of masternodes in the list.
    pub masternode_count: usize,

    /// Last masternode diff applied.
    pub last_diff_height: Option<u32>,
}

/// Filter sync state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterSyncState {
    /// Last filter header height synced.
    pub filter_header_height: u32,

    /// Last filter height downloaded.
    pub filter_height: u32,

    /// Number of filters downloaded.
    pub filters_downloaded: u64,

    /// Heights where filters matched (for recovery).
    pub matched_heights: Vec<u32>,

    /// Whether filter sync is available from peers.
    pub filter_sync_available: bool,
}

/// Sync state validation result.
#[derive(Debug)]
pub struct SyncStateValidation {
    /// Whether the state is valid.
    pub is_valid: bool,

    /// Validation errors if any.
    pub errors: Vec<String>,

    /// Warnings that don't prevent loading.
    pub warnings: Vec<String>,

    /// Suggested recovery action.
    pub recovery_suggestion: Option<RecoverySuggestion>,
}

/// Recovery suggestions for invalid or corrupted state.
#[derive(Debug, Clone)]
pub enum RecoverySuggestion {
    /// Start fresh sync from genesis.
    StartFresh,

    /// Rollback to a specific height.
    RollbackToHeight(u32),

    /// Use a checkpoint for recovery.
    UseCheckpoint(u32),

    /// Partial recovery - keep headers, resync filters.
    PartialRecovery,
}
