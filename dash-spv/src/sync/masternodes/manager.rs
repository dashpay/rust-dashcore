//! Masternode manager for parallel sync.
//!
//! Handles masternode list synchronization via QRInfo and MnListDiff messages.
//! Subscribes to BlockHeaderSyncComplete events to start sync after headers are caught up.
//! Emits MasternodeStateUpdated events.

use std::sync::Arc;
use std::time::Instant;

use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use tokio::sync::RwLock;

use super::pipeline::MnListDiffPipeline;
use crate::error::{SyncError, SyncResult};
use crate::network::RequestSender;
use crate::storage::BlockHeaderStorage;
use crate::sync::{MasternodesProgress, SyncEvent, SyncManager, SyncState};
use dashcore::BlockHash;
use std::collections::BTreeSet;

/// Anchor `baseBlockHashes` at or before `H - 4 * dkg_interval`. `send_qrinfo_for_tip`
/// requests QRInfo with `extra_share: true`, which covers `H` down to `H-4C`, so the
/// base must sit at or before `H-4C` for every historical diff's `(base, target]`
/// range to include its commit block. Drop to `3` if `extra_share` ever becomes
/// `false` at the call site.
const QRINFO_ANCHOR_CYCLES_BEHIND: u32 = 4;

/// Sync state for masternode list synchronization.
#[derive(Debug, Default)]
pub(super) struct MasternodeSyncState {
    /// Heights where the engine has masternode lists (for chaining diffs).
    pub(super) known_mn_list_heights: BTreeSet<u32>,
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

/// Pick the QRInfo base anchor for a request at `tip_height`: the highest stored
/// masternode list at height `<= tip_cycle_start - QRINFO_ANCHOR_CYCLES_BEHIND *
/// dkg_interval`.
///
/// The anchor has to be a block the engine already has a list for. The server's
/// historical cycle diffs need a base to apply against, and `apply_diff` with no
/// matching base list fails with `MissingStartMasternodeList`.
///
/// Returns `None` on fresh restart (engine empty, or no list old enough to satisfy
/// the cycles-behind rule). The caller then sends an empty `baseBlockHashes` and the
/// server falls back to genesis.
fn compute_qrinfo_anchor_hash(
    engine: &MasternodeListEngine,
    network: dashcore::Network,
    tip_height: u32,
) -> Option<BlockHash> {
    let dkg_interval = network.isd_llmq_type().params().dkg_params.interval;
    if dkg_interval == 0 {
        return None;
    }
    let tip_cycle_start = tip_height - (tip_height % dkg_interval);
    let max_anchor_height =
        tip_cycle_start.checked_sub(QRINFO_ANCHOR_CYCLES_BEHIND * dkg_interval)?;
    let (_, list) = engine.masternode_lists.range(..=max_anchor_height).next_back()?;
    Some(list.block_hash)
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

        let base_hashes = {
            let engine = self.engine.read().await;
            match compute_qrinfo_anchor_hash(&engine, self.network, tip_height) {
                Some(anchor) => vec![anchor],
                None => Vec::new(),
            }
        };

        tracing::info!(
            "Requesting QRInfo for tip at height {} with {} base hash(es)",
            tip_height,
            base_hashes.len()
        );
        requests.request_qr_info(base_hashes, tip_block_hash, true)?;

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
    use dashcore::hashes::Hash;
    use dashcore::sml::masternode_list::MasternodeList;

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

    fn anchor_hash(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    fn engine_with_lists(lists: &[(u32, u8)]) -> MasternodeListEngine {
        let mut engine = MasternodeListEngine::default_for_network(dashcore::Network::Regtest);
        for (height, tag) in lists {
            engine
                .masternode_lists
                .insert(*height, MasternodeList::empty(anchor_hash(*tag), *height));
        }
        engine
    }

    // Regtest `isd_llmq_type` is `LlmqtypeTestDIP0024` which uses `DKG_TEST` with
    // `interval=24`, so `max_anchor_height = tip_cycle_start - 4 * 24`.
    #[test]
    fn test_compute_qrinfo_anchor_hash() {
        struct Case {
            name: &'static str,
            lists: &'static [(u32, u8)],
            tip: u32,
            expect: Option<u8>,
        }
        let cases = [
            Case {
                name: "empty engine",
                lists: &[],
                tip: 200,
                expect: None,
            },
            Case {
                name: "tip too low, anchor underflows",
                lists: &[(0, 1)],
                tip: 50,
                expect: None,
            },
            Case {
                name: "no stored list old enough",
                lists: &[(100, 1), (150, 2)],
                tip: 200,
                expect: None,
            },
            Case {
                name: "single list exactly at max_anchor_height",
                lists: &[(96, 1)],
                tip: 200,
                expect: Some(1),
            },
            Case {
                name: "picks highest list at or below max_anchor_height",
                lists: &[(50, 1), (80, 2), (100, 3)],
                tip: 200,
                expect: Some(2),
            },
            Case {
                name: "mid-cycle tip rounds down to cycle start",
                lists: &[(96, 1)],
                tip: 215,
                expect: Some(1),
            },
        ];
        for case in &cases {
            let engine = engine_with_lists(case.lists);
            let got = compute_qrinfo_anchor_hash(&engine, dashcore::Network::Regtest, case.tip);
            assert_eq!(got, case.expect.map(anchor_hash), "case: {}", case.name);
        }
    }
}
