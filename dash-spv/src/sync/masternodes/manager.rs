//! Masternode manager for parallel sync.
//!
//! Handles masternode list synchronization via QRInfo and MnListDiff messages.
//! Subscribes to BlockHeaderSyncComplete events to start sync after headers are caught up.
//! Emits MasternodeStateUpdated events.

use std::sync::Arc;
use std::time::Instant;

use dashcore::network::constants::NetworkExt;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use tokio::sync::RwLock;

use super::pipeline::MnListDiffPipeline;
use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::storage::BlockHeaderStorage;
use crate::sync::{MasternodesProgress, SyncEvent, SyncManager, SyncState};
use dashcore::BlockHash;
use std::collections::{BTreeSet, HashSet};

/// Sync state for masternode list synchronization.
#[derive(Debug, Default)]
pub(super) struct MasternodeSyncState {
    /// Block hashes for which we have received MnListDiffs.
    pub(super) known_block_hashes: HashSet<BlockHash>,
    /// Heights where the engine has masternode lists (for chaining diffs).
    pub(super) known_mn_list_heights: BTreeSet<u32>,
    /// Last successfully processed QRInfo block hash (for progressive sync).
    pub(super) last_qrinfo_block_hash: Option<BlockHash>,
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
    pub fn new(
        header_storage: Arc<RwLock<H>>,
        engine: Arc<RwLock<MasternodeListEngine>>,
        network: dashcore::Network,
    ) -> Self {
        Self {
            progress: MasternodesProgress::default(),
            header_storage,
            engine,
            network,
            sync_state: MasternodeSyncState::new(),
        }
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
            .last_qrinfo_block_hash
            .or_else(|| self.network.known_genesis_block_hash());
        if let Some(hash) = base_hash {
            known_hashes.push(hash);
        }

        // Send QRInfo request for the tip
        // Note: The server's response includes `mn_list_diff_tip` which is always the current tip,
        // regardless of the requested block. If the tip was just mined and doesn't have a ChainLock
        // yet, we'll retry after a delay.
        tracing::info!("Requesting QRInfo for tip at height {}", tip_height);
        requests.request_qr_info(known_hashes, tip_block_hash)?;

        self.sync_state.start_waiting_for_qrinfo();

        Ok(vec![])
    }

    /// Verify quorums and mark complete.
    ///
    /// For initial sync (state == Syncing), emits MasternodeStateUpdated and logs completion.
    /// For incremental updates (state == Synced), updates quietly without events.
    pub(super) async fn verify_and_complete(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();
        let is_initial_sync = self.state() == SyncState::Syncing;

        let mut engine = self.engine.write().await;

        // Get the latest height from the engine and verify at that height
        if let Some(&height) = engine.masternode_lists.keys().last() {
            match engine.verify_non_rotating_masternode_list_quorums(height, &[]) {
                Ok(()) => {
                    tracing::info!(
                        "Non-rotating quorum verification completed at height {}",
                        height
                    );
                }
                Err(e) => {
                    tracing::warn!("Quorum verification failed at height {}: {}", height, e);
                }
            }

            self.progress.update_current_height(height);

            events.push(SyncEvent::MasternodeStateUpdated {
                height,
            });
        } else {
            tracing::warn!("No masternode lists available for verification");
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
    use crate::storage::{DiskStorageManager, PersistentBlockHeaderStorage};
    use crate::sync::sync_manager::SyncManager;
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};

    type TestMasternodesManager = MasternodesManager<PersistentBlockHeaderStorage>;

    async fn create_test_manager() -> TestMasternodesManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let engine = Arc::new(RwLock::new(MasternodeListEngine::default_for_network(
            dashcore::Network::Testnet,
        )));
        MasternodesManager::new(storage.header_storage(), engine, dashcore::Network::Testnet)
    }

    #[tokio::test]
    async fn test_masternode_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Masternode);
        assert_eq!(manager.state(), SyncState::Initializing);
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
}
