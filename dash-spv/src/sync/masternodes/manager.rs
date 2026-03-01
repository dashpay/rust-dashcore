//! Masternode manager for parallel sync.
//!
//! Handles masternode list synchronization via QRInfo and MnListDiff messages.
//! Subscribes to BlockHeaderSyncComplete events to start sync after headers are caught up.
//! Emits MasternodeStateUpdated events.

use std::sync::Arc;
use std::time::Instant;

use dashcore::network::constants::NetworkExt;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use tokio::sync::RwLock;

use super::pipeline::MnListDiffPipeline;
use crate::error::{SyncError, SyncResult};
use crate::network::RequestSender;
use crate::storage::BlockHeaderStorage;
use crate::sync::{MasternodesProgress, SyncEvent, SyncManager, SyncState};
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use std::collections::{BTreeSet, HashSet};

/// What the MnListDiff pipeline is currently being used for.
#[derive(Debug, Clone, Default)]
pub(super) enum PipelineMode {
    /// Post-QRInfo quorum validation diffs. Run full `verify_and_complete()` on completion.
    #[default]
    QuorumValidation,
    /// Per-block incremental masternode list update. Skip quorum verification on completion.
    Incremental {
        target: BlockHash,
    },
}

/// Sync state for masternode list synchronization.
#[derive(Debug, Default)]
pub(super) struct MasternodeSyncState {
    /// Block hashes for which we have received MnListDiffs.
    pub(super) known_block_hashes: HashSet<BlockHash>,
    /// Heights where the engine has masternode lists (for chaining diffs).
    pub(super) known_mn_list_heights: BTreeSet<u32>,
    /// Last block hash we synced the masternode list to (base for both QRInfo and incremental diffs).
    pub(super) last_synced_block_hash: Option<BlockHash>,
    /// Pipeline for MnListDiff requests.
    pub(super) mnlistdiff_pipeline: MnListDiffPipeline,
    /// Whether we are waiting for a QRInfo response.
    pub(super) waiting_for_qrinfo: bool,
    /// When we started waiting for QRInfo response.
    pub(super) qrinfo_wait_start: Option<Instant>,
    /// Current retry count for QRInfo.
    pub(super) qrinfo_retry_count: u8,
    /// When to retry after a ChainLock unavailability error.
    /// The QRInfo response includes the current tip which may not have ChainLock yet.
    pub(super) chainlock_retry_after: Option<Instant>,
    /// Controls pipeline completion behavior (quorum validation vs incremental update).
    pipeline_mode: PipelineMode,
}

impl MasternodeSyncState {
    fn new() -> Self {
        Self::default()
    }

    pub(super) fn has_pending_requests(&self) -> bool {
        !self.mnlistdiff_pipeline.is_complete() || self.waiting_for_qrinfo
    }

    pub(super) fn clear_pending(&mut self) {
        self.mnlistdiff_pipeline.clear();
        self.waiting_for_qrinfo = false;
        self.qrinfo_wait_start = None;
        self.pipeline_mode = PipelineMode::QuorumValidation;
    }

    fn start_waiting_for_qrinfo(&mut self) {
        self.waiting_for_qrinfo = true;
        self.qrinfo_wait_start = Some(Instant::now());
    }

    pub(super) fn qrinfo_received(&mut self) {
        self.waiting_for_qrinfo = false;
        self.qrinfo_wait_start = None;
    }
}

/// Masternode manager for synchronizing masternode lists.
///
/// This manager:
/// - Waits for BlockHeaderSyncComplete event before starting sync
/// - Handles QRInfo and MnListDiff messages
/// - Verifies quorums
/// - Emits MasternodeStateUpdated events
///
/// Generic over `H: BlockHeaderStorage` to allow different storage implementations.
pub struct MasternodesManager<H: BlockHeaderStorage> {
    /// Current progress of the manager.
    pub(super) progress: MasternodesProgress,
    /// Block header storage (for height lookups).
    pub(super) header_storage: Arc<RwLock<H>>,
    /// Shared Masternode list engine.
    pub(super) engine: Arc<RwLock<MasternodeListEngine>>,
    /// Network type for genesis hash.
    network: dashcore::Network,
    /// Sync state tracking.
    pub(super) sync_state: MasternodeSyncState,
}

impl<H: BlockHeaderStorage> MasternodesManager<H> {
    /// Create a new masternode manager with the given header storage.
    pub async fn new(
        header_storage: Arc<RwLock<H>>,
        engine: Arc<RwLock<MasternodeListEngine>>,
        network: dashcore::Network,
    ) -> Self {
        // Load current height from engine's masternode lists
        let current_height =
            engine.read().await.masternode_lists.keys().last().copied().unwrap_or(0);

        // Load block header tip for progress display
        let header_tip =
            header_storage.read().await.get_tip().await.map(|t| t.height()).unwrap_or(0);

        let mut initial_progress = MasternodesProgress::default();
        initial_progress.update_current_height(current_height);
        initial_progress.update_target_height(header_tip);
        initial_progress.update_block_header_tip_height(header_tip);
        initial_progress.set_state(SyncState::WaitingForConnections);

        Self {
            progress: initial_progress,
            header_storage,
            engine,
            network,
            sync_state: MasternodeSyncState::new(),
        }
    }

    /// Check whether the tip crosses a rotating quorum cycle boundary relative to
    /// our last synced height. Returns true when a full QRInfo is needed (first sync
    /// or crossing an `isd_llmq_type` DKG interval boundary).
    pub(super) fn needs_qrinfo_update(&self, tip_height: u32) -> bool {
        let last = self.progress.current_height();
        if last == 0 {
            return true;
        }
        let interval = self.network.isd_llmq_type().params().dkg_params.interval;
        tip_height / interval > last / interval
    }

    /// Send an incremental GetMnListDiff for the current tip.
    pub(super) async fn send_mnlistdiff_for_tip(
        &mut self,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        let storage = self.header_storage.read().await;
        let tip = match storage.get_tip().await {
            Some(tip) => tip,
            None => return Ok(vec![]),
        };
        let tip_hash = *tip.hash();
        drop(storage);

        let base_hash = self
            .sync_state
            .last_synced_block_hash
            .or_else(|| self.network.known_genesis_block_hash())
            .unwrap_or_else(BlockHash::all_zeros);

        self.sync_state.pipeline_mode = PipelineMode::Incremental {
            target: tip_hash,
        };
        self.sync_state.mnlistdiff_pipeline.queue_requests(vec![(base_hash, tip_hash)]);
        self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

        tracing::debug!("Requesting incremental MnListDiff: {} -> {}", base_hash, tip_hash);
        Ok(vec![])
    }

    /// Send QRInfo request for the current tip.
    ///
    /// Called when BlockHeaderSyncComplete is received, ensuring we have all headers.
    pub(super) async fn send_qrinfo_for_tip(
        &mut self,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Get info from storage
        let (tip_height, tip_block_hash) = {
            let storage = self.header_storage.read().await;
            match storage.get_tip().await {
                Some(tip) => (tip.height(), *tip.hash()),
                None => {
                    tracing::warn!("MasternodesManager: No headers available for QRInfo request");
                    return Ok(vec![]);
                }
            }
        };

        if tip_height == 0 {
            tracing::info!("MasternodesManager: At genesis, nothing to sync");
            return Ok(vec![]);
        }

        // Only transition to Syncing if not already Synced (incremental updates stay Synced)
        if self.state() != SyncState::Synced {
            self.set_state(SyncState::Syncing);
        }

        // Build known hashes from tracked block hashes
        let mut known_hashes: Vec<_> = self.sync_state.known_block_hashes.iter().copied().collect();

        // Add base hash
        let base_hash = self
            .sync_state
            .last_synced_block_hash
            .or_else(|| self.network.known_genesis_block_hash());
        if let Some(hash) = base_hash {
            known_hashes.push(hash);
        }

        // Send QRInfo request for the tip
        // Note: The server's response includes `mn_list_diff_tip` which is always the current tip,
        // regardless of the requested block. If the tip was just mined and doesn't have a ChainLock
        // yet, we'll retry after a delay.
        tracing::info!("Requesting QRInfo for tip at height {}", tip_height);
        requests.request_qr_info(known_hashes, tip_block_hash, true)?;

        self.sync_state.start_waiting_for_qrinfo();

        Ok(vec![])
    }

    /// Handle pipeline completion by branching on the current pipeline mode.
    ///
    /// - `QuorumValidation`: run full quorum verification (post-QRInfo flow).
    /// - `Incremental`: update progress and emit event without quorum verification.
    pub(super) async fn complete_pipeline(&mut self) -> SyncResult<Vec<SyncEvent>> {
        match &self.sync_state.pipeline_mode {
            PipelineMode::QuorumValidation => {
                tracing::info!("All MnListDiff responses received");
                self.verify_and_complete().await
            }
            PipelineMode::Incremental {
                target,
            } => {
                let target = *target;
                self.sync_state.last_synced_block_hash = Some(target);
                let engine = self.engine.read().await;
                if let Some(&height) = engine.masternode_lists.keys().last() {
                    drop(engine);
                    self.progress.update_current_height(height);
                    tracing::debug!("Incremental MnListDiff complete at height {}", height);
                    return Ok(vec![SyncEvent::MasternodeStateUpdated {
                        height,
                    }]);
                }
                Ok(vec![])
            }
        }
    }

    /// Verify non-rotating quorums and finalize the post-QRInfo sync pipeline.
    ///
    /// Emits `MasternodeStateUpdated` on success. On initial sync, also transitions
    /// state to `Synced`.
    pub(super) async fn verify_and_complete(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();
        let is_initial_sync = self.state() == SyncState::Syncing;

        let mut engine = self.engine.write().await;

        // Get the latest height from the engine and verify at that height
        if let Some(&height) = engine.masternode_lists.keys().last() {
            if let Err(e) = engine.verify_non_rotating_masternode_list_quorums(height, &[]) {
                drop(engine);
                self.set_state(SyncState::Error);
                return Err(SyncError::MasternodeSyncFailed(format!(
                    "Quorum verification failed at height {}: {}",
                    height, e
                )));
            }

            tracing::info!("Non-rotating quorum verification completed at height {}", height);

            self.progress.update_current_height(height);

            events.push(SyncEvent::MasternodeStateUpdated {
                height,
            });
        } else if is_initial_sync {
            drop(engine);
            self.set_state(SyncState::Error);
            return Err(SyncError::MasternodeSyncFailed("No masternode lists available".into()));
        }

        drop(engine);

        if is_initial_sync {
            self.set_state(SyncState::Synced);
            tracing::info!("Masternode sync complete at height {}", self.progress.current_height());
        }

        Ok(events)
    }
}

impl<H: BlockHeaderStorage> std::fmt::Debug for MasternodesManager<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodesManager").field("progress", &self.progress).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MessageType;
    use crate::storage::{DiskStorageManager, PersistentBlockHeaderStorage, StorageManager};
    use crate::sync::sync_manager::SyncManager;
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};

    type TestMasternodesManager = MasternodesManager<PersistentBlockHeaderStorage>;

    async fn create_test_manager() -> TestMasternodesManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let engine = Arc::new(RwLock::new(MasternodeListEngine::default_for_network(
            dashcore::Network::Testnet,
        )));
        MasternodesManager::new(storage.block_headers(), engine, dashcore::Network::Testnet).await
    }

    #[tokio::test]
    async fn test_masternode_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Masternode);
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert_eq!(
            manager.wanted_message_types(),
            vec![MessageType::MnListDiff, MessageType::QRInfo]
        );
    }

    #[tokio::test]
    async fn test_masternode_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.progress.update_current_height(500);
        manager.progress.update_target_height(1000);
        manager.progress.add_diffs_processed(10);

        let progress = manager.progress();
        if let SyncManagerProgress::Masternodes(progress) = progress {
            assert_eq!(progress.current_height(), 500);
            assert_eq!(progress.target_height(), 1000);
            assert_eq!(progress.diffs_processed(), 10);
            assert!(progress.last_activity().elapsed().as_secs() < 1);
        } else {
            panic!("Expected SyncManagerProgress::Masternodes");
        }
    }

    #[tokio::test]
    async fn test_needs_qrinfo_when_never_synced() {
        let manager = create_test_manager().await;
        // current_height == 0 means we've never synced, always need QRInfo
        assert!(manager.needs_qrinfo_update(1));
        assert!(manager.needs_qrinfo_update(288));
        assert!(manager.needs_qrinfo_update(1000));
    }

    #[tokio::test]
    async fn test_needs_qrinfo_at_cycle_boundary() {
        let mut manager = create_test_manager().await;
        // isd_llmq_type for testnet is Llmqtype60_75 with interval 288
        manager.progress.update_current_height(287);

        // Tip at 288 crosses the cycle boundary (287/288 = 0, 288/288 = 1)
        assert!(manager.needs_qrinfo_update(288));

        // Multiple cycles ahead also triggers (100/288 = 0, 1000/288 = 3)
        manager.progress.update_current_height(100);
        assert!(manager.needs_qrinfo_update(1000));
    }

    #[tokio::test]
    async fn test_skips_qrinfo_within_cycle() {
        let mut manager = create_test_manager().await;
        manager.progress.update_current_height(290);

        // Tip within the same cycle (290/288 = 1, 300/288 = 1)
        assert!(!manager.needs_qrinfo_update(300));
        assert!(!manager.needs_qrinfo_update(575));
    }

    #[tokio::test]
    async fn test_clear_pending_resets_pipeline_mode() {
        let mut manager = create_test_manager().await;
        manager.sync_state.pipeline_mode = PipelineMode::Incremental {
            target: BlockHash::all_zeros(),
        };
        manager.sync_state.clear_pending();
        assert!(matches!(manager.sync_state.pipeline_mode, PipelineMode::QuorumValidation));
    }
}
