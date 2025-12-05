//! Persistent sync state management for resuming sync after restarts.

use crate::error::StorageResult;
use crate::types::{ChainState, SyncProgress};
use crate::StorageError;
use dashcore::{BlockHash, Network};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Version for sync state serialization format.
/// Increment this when making breaking changes to the format.
const SYNC_STATE_VERSION: u32 = 2;

/// Complete persistent sync state that can be saved and restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentSyncState {
    /// Version of the sync state format.
    pub version: u32,

    /// Network this state is for.
    pub network: Network,

    /// Current chain tip information.
    pub chain_tip: ChainTip,

    /// Sync progress at the time of saving.
    pub sync_progress: SyncProgress,

    /// Masternode sync state.
    pub masternode_sync: MasternodeSyncState,

    /// Filter sync state.
    pub filter_sync: FilterSyncState,

    /// Chain work up to the tip (for validation).
    pub chain_work: String,

    /// Base height when syncing from a checkpoint (0 if syncing from genesis).
    pub sync_base_height: u32,
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

/// Recovery suggestions for invalid or corrupted state.
#[derive(Debug, Clone)]
pub enum RecoverySuggestion {
    /// Start fresh sync from genesis.
    StartFresh,

    /// Rollback to a specific height.
    RollbackToHeight(u32),

    /// Partial recovery - keep headers, resync filters.
    PartialRecovery,
}

impl PersistentSyncState {
    /// Create a new persistent sync state from current chain state.
    pub fn from_chain_state(
        chain_state: &ChainState,
        sync_progress: &SyncProgress,
        network: Network,
    ) -> Option<Self> {
        let tip_height = chain_state.tip_height();
        let tip_hash = chain_state.tip_hash()?;
        let tip_header = chain_state.get_tip_header()?;

        Some(Self {
            version: SYNC_STATE_VERSION,
            network,
            chain_tip: ChainTip {
                height: tip_height,
                hash: tip_hash,
                prev_hash: tip_header.prev_blockhash,
                time: tip_header.time,
            },
            sync_progress: sync_progress.clone(),
            masternode_sync: MasternodeSyncState {
                last_synced_height: None,
                is_synced: false,
                masternode_count: chain_state
                    .masternode_engine
                    .as_ref()
                    .and_then(|engine| engine.latest_masternode_list())
                    .map(|list| list.masternodes.len())
                    .unwrap_or(0),
                last_diff_height: chain_state.last_masternode_diff_height,
            },
            filter_sync: FilterSyncState {
                filter_header_height: sync_progress.filter_header_height,
                filter_height: sync_progress.last_synced_filter_height.unwrap_or(0),
                filters_downloaded: sync_progress.filters_downloaded,
                matched_heights: chain_state.get_filter_matched_heights().unwrap_or_default(),
                filter_sync_available: sync_progress.filter_sync_available,
            },
            chain_work: chain_state
                .calculate_chain_work()
                .map(|work| format!("{:?}", work))
                .unwrap_or_else(|| String::from("0")),
            sync_base_height: chain_state.sync_base_height,
        })
    }

    /// Validate the sync state for consistency and corruption.
    pub fn validate(&self, network: Network) -> StorageResult<()> {
        // Check version compatibility
        if self.version > SYNC_STATE_VERSION {
            return Err(StorageError::InconsistentState(
                format!(
                    "Sync state version {} is newer than supported version {}",
                    self.version, SYNC_STATE_VERSION
                ),
                RecoverySuggestion::StartFresh,
            ));
        }

        // Check network match
        if self.network != network {
            return Err(StorageError::InconsistentState(
                format!(
                    "Sync state is for network {:?} but client is configured for {:?}",
                    self.network, network
                ),
                RecoverySuggestion::StartFresh,
            ));
        }

        // Check height consistency
        if self.sync_progress.header_height > self.chain_tip.height {
            return Err(StorageError::InconsistentState(
                format!(
                    "Sync progress height {} exceeds chain tip height {}",
                    self.sync_progress.header_height, self.chain_tip.height
                ),
                RecoverySuggestion::RollbackToHeight(self.chain_tip.height),
            ));
        }

        // Check filter height consistency
        if self.filter_sync.filter_header_height > self.chain_tip.height {
            return Err(StorageError::InconsistentState(
                format!(
                    "Filter header height {} exceeds chain tip height {}",
                    self.filter_sync.filter_header_height, self.chain_tip.height
                ),
                RecoverySuggestion::PartialRecovery,
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore_hashes::Hash;

    #[test]
    fn test_sync_state_validation() {
        let mut state = PersistentSyncState {
            version: SYNC_STATE_VERSION,
            network: Network::Testnet,
            chain_tip: ChainTip {
                height: 1000,
                hash: BlockHash::from_byte_array([0; 32]),
                prev_hash: BlockHash::from_byte_array([0; 32]),
                time: 0,
            },
            sync_progress: SyncProgress::default(),
            masternode_sync: MasternodeSyncState {
                last_synced_height: None,
                is_synced: false,
                masternode_count: 0,
                last_diff_height: None,
            },
            filter_sync: FilterSyncState {
                filter_header_height: 0,
                filter_height: 0,
                filters_downloaded: 0,
                matched_heights: vec![],
                filter_sync_available: false,
            },
            chain_work: String::new(),
            sync_base_height: 0,
        };

        // Valid state
        assert!(state.validate(Network::Testnet).is_ok());

        // Wrong network
        assert!(state.validate(Network::Dash).is_err());

        // Invalid height
        state.sync_progress.header_height = 2000;
        assert!(state.validate(Network::Testnet).is_err());
    }
}
