//! Persistent sync state management for resuming sync after restarts.

use dashcore::{BlockHash, Network};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::types::{ChainState, SyncProgress};

/// Version for sync state serialization format.
/// Increment this when making breaking changes to the format.
const SYNC_STATE_VERSION: u32 = 1;

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
            checkpoints: Self::create_checkpoints(chain_state),
            masternode_sync: MasternodeSyncState {
                last_synced_height: if sync_progress.masternodes_synced {
                    Some(sync_progress.masternode_height)
                } else {
                    None
                },
                is_synced: sync_progress.masternodes_synced,
                masternode_count: chain_state.masternode_engine
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
            saved_at: SystemTime::now(),
            chain_work: chain_state.calculate_chain_work()
                .map(|work| format!("{:?}", work))
                .unwrap_or_else(|| String::from("0")),
        })
    }
    
    /// Create checkpoints from chain state for faster recovery.
    fn create_checkpoints(chain_state: &ChainState) -> Vec<SyncCheckpoint> {
        let mut checkpoints = Vec::new();
        let tip_height = chain_state.tip_height();
        
        // Create checkpoints at strategic intervals
        let checkpoint_intervals = [1000, 10000, 50000, 100000];
        
        for &interval in &checkpoint_intervals {
            let mut height = interval;
            while height <= tip_height {
                if let Some(header) = chain_state.header_at_height(height) {
                    let filter_header = chain_state.filter_header_at_height(height).copied();
                    checkpoints.push(SyncCheckpoint {
                        height,
                        block_hash: header.block_hash(),
                        filter_header,
                        validated: true,
                        created_at: SystemTime::now(),
                    });
                }
                height += interval;
            }
        }
        
        // Always add the tip as a checkpoint
        if tip_height > 0 {
            if let Some(header) = chain_state.get_tip_header() {
                let filter_header = chain_state.filter_header_at_height(tip_height).copied();
                checkpoints.push(SyncCheckpoint {
                    height: tip_height,
                    block_hash: header.block_hash(),
                    filter_header,
                    validated: true,
                    created_at: SystemTime::now(),
                });
            }
        }
        
        checkpoints
    }
    
    /// Validate the sync state for consistency and corruption.
    pub fn validate(&self, network: Network) -> SyncStateValidation {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut recovery_suggestion = None;
        
        // Check version compatibility
        if self.version > SYNC_STATE_VERSION {
            errors.push(format!(
                "Sync state version {} is newer than supported version {}",
                self.version, SYNC_STATE_VERSION
            ));
            recovery_suggestion = Some(RecoverySuggestion::StartFresh);
        }
        
        // Check network match
        if self.network != network {
            errors.push(format!(
                "Sync state is for network {:?} but client is configured for {:?}",
                self.network, network
            ));
            recovery_suggestion = Some(RecoverySuggestion::StartFresh);
        }
        
        // Check time consistency
        if self.saved_at > SystemTime::now() {
            warnings.push("Sync state has future timestamp".to_string());
        }
        
        // Check height consistency
        if self.sync_progress.header_height > self.chain_tip.height {
            errors.push(format!(
                "Sync progress height {} exceeds chain tip height {}",
                self.sync_progress.header_height, self.chain_tip.height
            ));
            recovery_suggestion = Some(RecoverySuggestion::RollbackToHeight(self.chain_tip.height));
        }
        
        // Check filter height consistency
        if self.filter_sync.filter_header_height > self.chain_tip.height {
            errors.push(format!(
                "Filter header height {} exceeds chain tip height {}",
                self.filter_sync.filter_header_height, self.chain_tip.height
            ));
            recovery_suggestion = Some(RecoverySuggestion::PartialRecovery);
        }
        
        // Validate checkpoints
        let mut prev_height = 0;
        for checkpoint in &self.checkpoints {
            if checkpoint.height <= prev_height {
                errors.push(format!(
                    "Checkpoint heights not in ascending order: {} <= {}",
                    checkpoint.height, prev_height
                ));
            }
            if checkpoint.height > self.chain_tip.height {
                errors.push(format!(
                    "Checkpoint height {} exceeds chain tip height {}",
                    checkpoint.height, self.chain_tip.height
                ));
            }
            prev_height = checkpoint.height;
        }
        
        // If we have errors but valid checkpoints, suggest using the highest valid checkpoint
        if !errors.is_empty() && !self.checkpoints.is_empty() {
            if let Some(last_checkpoint) = self.checkpoints.last() {
                if last_checkpoint.validated && last_checkpoint.height <= self.chain_tip.height {
                    recovery_suggestion = Some(RecoverySuggestion::UseCheckpoint(last_checkpoint.height));
                }
            }
        }
        
        SyncStateValidation {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            recovery_suggestion,
        }
    }
    
    /// Get the best checkpoint to use for recovery.
    pub fn get_best_checkpoint(&self) -> Option<&SyncCheckpoint> {
        self.checkpoints
            .iter()
            .rev()
            .find(|cp| cp.validated)
    }
    
    /// Check if we should create a new checkpoint at the given height.
    pub fn should_checkpoint(&self, height: u32) -> bool {
        // Checkpoint every 1000 blocks initially, then less frequently
        let interval = if height < 10000 {
            1000
        } else if height < 100000 {
            10000
        } else {
            50000
        };
        
        height % interval == 0
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
            checkpoints: vec![],
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
            saved_at: SystemTime::now(),
            chain_work: String::new(),
        };
        
        // Valid state
        let validation = state.validate(Network::Testnet);
        assert!(validation.is_valid);
        assert!(validation.errors.is_empty());
        
        // Wrong network
        let validation = state.validate(Network::Dash);
        assert!(!validation.is_valid);
        assert!(!validation.errors.is_empty());
        
        // Invalid height
        state.sync_progress.header_height = 2000;
        let validation = state.validate(Network::Testnet);
        assert!(!validation.is_valid);
        assert!(!validation.errors.is_empty());
    }
}