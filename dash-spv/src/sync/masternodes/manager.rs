//! Masternode manager for parallel sync.
//!
//! Handles masternode list synchronization via QRInfo and MnListDiff messages.
//! Subscribes to BlockHeaderSyncComplete events to start sync after headers are caught up.
//! Emits MasternodeStateUpdated events.

use std::sync::Arc;
use std::time::Instant;

use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::masternode_list_engine::{MasternodeListEngine, QRInfoFeedSummary};
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

/// Single enum that serves two roles in the masternode-sync flow:
///
/// - **Decision** — returned from [`MasternodesManager::next_pipeline_mode`] to pick
///   which request to fire when a new header lands while sync is `Synced`.
/// - **State** — stored on [`MasternodeSyncState::pipeline_mode`] to record what the
///   mnlistdiff pipeline is currently running, so [`MasternodesManager::complete_pipeline`]
///   can dispatch the right completion flow when the pipeline drains.
///
/// The two variants map 1:1 between the two roles:
///
/// | Variant             | Decision action                              | Completion flow                          |
/// |---------------------|----------------------------------------------|------------------------------------------|
/// | `QuorumValidation`  | Fire `getqrinfo` (which queues historical diffs for non-rotating quorum verification). | Full `verify_and_complete`: hard-fails into `Error` on verification failure, transitions initial sync to `Synced` on success. |
/// | `Incremental`       | Fire a targeted `GetMnListDiff` from the latest known masternode list tip to the new header tip. | Lightweight verification at the latest height; on failure log warn and stay in `Synced` - a single failed tip refresh should not kill the whole sync state. |
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PipelineMode {
    /// Full `getqrinfo` request / post-QRInfo historical cycle diffs. See enum docs.
    ///
    /// `qr_info_summary` is set by the QRInfo message handler when a response is
    /// successfully fed to the engine, and is consumed by `complete_pipeline` when
    /// the mnlistdiff pipeline drains. `None` while the pipeline is being set up
    /// or between cycles.
    QuorumValidation {
        qr_info_summary: Option<QRInfoFeedSummary>,
    },
    /// Targeted single-diff tip refresh. See enum docs.
    Incremental,
}

impl Default for PipelineMode {
    fn default() -> Self {
        Self::QuorumValidation {
            qr_info_summary: None,
        }
    }
}

/// Sync state for masternode list synchronization.
#[derive(Debug, Default)]
pub(super) struct MasternodeSyncState {
    /// Heights where the engine has masternode lists (for chaining diffs).
    pub(super) known_mn_list_heights: BTreeSet<u32>,
    /// Pipeline for MnListDiff requests.
    pub(super) mnlistdiff_pipeline: MnListDiffPipeline,
    /// What the pipeline is currently being used for. See [`PipelineMode`].
    pub(super) pipeline_mode: PipelineMode,
    /// Whether we are waiting for a QRInfo response.
    pub(super) waiting_for_qrinfo: bool,
    /// When we started waiting for QRInfo response.
    pub(super) qrinfo_wait_start: Option<Instant>,
    /// Current retry count for QRInfo.
    pub(super) qrinfo_retry_count: u8,
    /// When to retry after a ChainLock unavailability error.
    /// The QRInfo response includes the current tip which may not have ChainLock yet.
    pub(super) chainlock_retry_after: Option<Instant>,
    /// Block hash of the latest masternode list the engine holds. Initialized from
    /// engine state on startup (so it survives restarts) and refreshed after every
    /// successful pipeline completion.
    pub(super) last_synced_block_hash: Option<BlockHash>,
    /// Rotation cycle boundary heights we have successfully freshly-validated. Used
    /// to stop firing QRInfo for a cycle once its rotated quorums are verified;
    /// subsequent tip updates within the same cycle take the `MnListDiffOnly` path.
    pub(super) validated_cycle_heights: BTreeSet<u32>,
    /// Current cycle boundary height the in-cycle tracking is for. Resets on cycle
    /// change.
    pub(super) current_cycle_height: Option<u32>,
    /// Number of QRInfo attempts fired for `current_cycle_height`. Used for the
    /// one-shot degraded-cycle log message; there is no hard cap - QRInfo is fired
    /// on every new block inside the mining window until one succeeds.
    pub(super) current_cycle_attempts: u8,
    /// Whether the "mining window closed without a successful fresh validation"
    /// warning has already been logged for `current_cycle_height`. Prevents the
    /// warning from spamming once per block for the rest of the degraded cycle.
    pub(super) current_cycle_degraded_logged: bool,
    /// Highest tip height a QRInfo has already been fired for inside the current
    /// cycle's mining window. Gates `next_pipeline_mode` so that unrelated ticks
    /// (peer events, response receipt, timers) cannot re-fire QRInfo for the same
    /// tip when validation fails deterministically. Reset on cycle rollover.
    pub(super) last_window_qrinfo_tip: Option<u32>,
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
        self.pipeline_mode = PipelineMode::default();
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
        // Recover sync state from the engine's stored masternode lists so that a
        // restart can resume from where the previous run left off.
        let (current_height, last_synced_block_hash) = {
            let engine_guard = engine.read().await;
            match engine_guard.masternode_lists.iter().next_back() {
                Some((&height, list)) => (height, Some(list.block_hash)),
                None => (0, None),
            }
        };

        // Load block header tip for progress display
        let header_tip =
            header_storage.read().await.get_tip().await.map(|t| t.height()).unwrap_or(0);

        let mut initial_progress = MasternodesProgress::default();
        initial_progress.update_current_height(current_height);
        initial_progress.update_target_height(header_tip);
        initial_progress.update_block_header_tip_height(header_tip);
        initial_progress.set_state(SyncState::WaitingForConnections);

        let mut sync_state = MasternodeSyncState::new();
        sync_state.last_synced_block_hash = last_synced_block_hash;

        Self {
            progress: initial_progress,
            header_storage,
            engine,
            network,
            sync_state,
        }
    }

    /// Decide which [`PipelineMode`] to use when a new header lands at `tip_height`
    /// and masternode sync needs to catch up. The rule is:
    ///
    /// - Before `cycle_start + dkgMiningWindowStart`: the rotated commitment for this
    ///   cycle cannot possibly have been mined yet, so a QRInfo would fail `sigmtip`.
    ///   Return `Incremental` to fire a targeted `GetMnListDiff` that keeps the tip
    ///   list fresh.
    /// - Inside `[cycle_start + dkgMiningWindowStart, cycle_start + dkgMiningWindowEnd]`
    ///   and the cycle is not yet validated: return `QuorumValidation` so a full
    ///   QRInfo fires on every new header. Any block in this window can be the one
    ///   that contains the commit, and firing on every block gives the earliest
    ///   success path to fresh rotated quorum validation. The mining window is short
    ///   (e.g. 9 blocks for `llmq_60_75`), so the per-cycle request volume is
    ///   naturally bounded by the window length.
    /// - Once `feed_qr_info` returns a summary where every rotated quorum was freshly
    ///   validated, `mark_cycle_validated` records the cycle done and every
    ///   subsequent header in that cycle falls through to `Incremental`.
    /// - After `cycle_start + dkgMiningWindowEnd` without a successful validation:
    ///   the cycle is degraded (DKG likely failed or commits were never mined). Log
    ///   the condition once per cycle and fall through to `Incremental` for the
    ///   remainder of the cycle.
    ///
    /// This applies only to the incremental-update path while state is `Synced`.
    /// Initial sync and explicit retry paths (ChainLock delay, timeout) bypass it.
    pub(super) fn next_pipeline_mode(&mut self, tip_height: u32) -> PipelineMode {
        let params = self.network.isd_llmq_type().params();
        let dkg_interval = params.dkg_params.interval;
        if dkg_interval == 0 {
            return PipelineMode::QuorumValidation {
                qr_info_summary: None,
            };
        }
        let mining_start = params.dkg_params.mining_window_start;
        let mining_end = params.dkg_params.mining_window_end;
        let cycle_height = tip_height - (tip_height % dkg_interval);
        let window_start = cycle_height + mining_start;
        let window_end = cycle_height + mining_end;

        // Reset per-cycle tracking when the tip enters a new cycle.
        if self.sync_state.current_cycle_height != Some(cycle_height) {
            self.sync_state.current_cycle_height = Some(cycle_height);
            self.sync_state.current_cycle_attempts = 0;
            self.sync_state.current_cycle_degraded_logged = false;
            self.sync_state.last_window_qrinfo_tip = None;
        }

        // Already validated this cycle? Keep the tip list fresh but don't touch QRInfo.
        if self.sync_state.validated_cycle_heights.contains(&cycle_height) {
            tracing::debug!(
                tip_height,
                cycle_height,
                window_start,
                window_end,
                "next_pipeline_mode: cycle already validated, picking Incremental"
            );
            return PipelineMode::Incremental;
        }
        // Before mining window opens: QRInfo would fail `sigmtip`. Keep tip list fresh.
        if tip_height < window_start {
            tracing::debug!(
                tip_height,
                cycle_height,
                window_start,
                window_end,
                "next_pipeline_mode: before mining window, picking Incremental"
            );
            return PipelineMode::Incremental;
        }
        // Past mining window without success.
        if tip_height > window_end {
            // If we never attempted QRInfo for this cycle (all blocks arrived
            // in a batch that overshot the window), fire ONE QRInfo now so the
            // cycle's rotated quorums get stored. Without this, IS locks from
            // the new cycle can't be verified.
            if self.sync_state.current_cycle_attempts == 0 {
                self.sync_state.current_cycle_attempts += 1;
                tracing::info!(
                    cycle_height,
                    tip_height,
                    "Mining window missed (blocks batched); firing catch-up QRInfo"
                );
                return PipelineMode::QuorumValidation {
                    qr_info_summary: None,
                };
            }
            if !self.sync_state.current_cycle_degraded_logged {
                tracing::warn!(
                    cycle_height,
                    mining_window_start = cycle_height + mining_start,
                    mining_window_end = cycle_height + mining_end,
                    attempts = self.sync_state.current_cycle_attempts,
                    "Rotated quorum fresh validation failed for cycle: mining window \
                     closed without a successful QRInfo response. Falling back to \
                     mnlistdiff-only tip updates for the remainder of this cycle."
                );
                self.sync_state.current_cycle_degraded_logged = true;
            }
            return PipelineMode::Incremental;
        }

        // Inside the mining window and not yet validated: fire QRInfo once per new
        // tip. Unrelated ticks at the same tip fall through to `Incremental` so a
        // deterministic `feed_qr_info` failure doesn't re-fire on every event.
        if self.sync_state.last_window_qrinfo_tip == Some(tip_height) {
            tracing::trace!(
                tip_height,
                cycle_height,
                attempts = self.sync_state.current_cycle_attempts,
                "next_pipeline_mode: QRInfo already fired for this tip, picking Incremental"
            );
            return PipelineMode::Incremental;
        }
        self.sync_state.last_window_qrinfo_tip = Some(tip_height);
        self.sync_state.current_cycle_attempts += 1;
        tracing::debug!(
            tip_height,
            cycle_height,
            window_start,
            window_end,
            attempts = self.sync_state.current_cycle_attempts,
            "next_pipeline_mode: inside mining window, picking QuorumValidation"
        );
        PipelineMode::QuorumValidation {
            qr_info_summary: None,
        }
    }

    /// Mark a cycle boundary height as freshly validated, so `next_pipeline_mode`
    /// will return `Incremental` for any future tip update in this cycle. Called
    /// after a successful `feed_qr_info` where every rotated quorum was freshly
    /// validated.
    pub(super) fn mark_cycle_validated(&mut self, cycle_height: u32) {
        self.sync_state.validated_cycle_heights.insert(cycle_height);
    }

    /// Fire a targeted `GetMnListDiff` from the latest known masternode list tip to
    /// the current header tip, to keep the tip list fresh without running a full
    /// QRInfo. Sets `pipeline_mode = Incremental` so `complete_pipeline()` takes the
    /// lightweight completion path when the response drains the pipeline.
    pub(super) async fn send_tip_mnlistdiff_update(
        &mut self,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        let new_tip_hash = {
            let storage = self.header_storage.read().await;
            match storage.get_tip().await {
                Some(tip) => *tip.hash(),
                None => return Ok(vec![]),
            }
        };

        let Some(base_hash) = self.sync_state.last_synced_block_hash else {
            // No stored masternode list at all - can't do a targeted diff. This
            // should only happen transiently before the first successful sync.
            return Ok(vec![]);
        };

        if base_hash == new_tip_hash {
            return Ok(vec![]);
        }

        self.sync_state.pipeline_mode = PipelineMode::Incremental;
        self.sync_state.mnlistdiff_pipeline.queue_requests(vec![(base_hash, new_tip_hash)]);
        self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;
        Ok(vec![])
    }

    /// Dispatch pipeline completion based on the current `PipelineMode`. Called when
    /// the mnlistdiff pipeline drains, from either the message handler or the tick
    /// handler's timeout-cleanup path.
    pub(super) async fn complete_pipeline(&mut self) -> SyncResult<Vec<SyncEvent>> {
        match std::mem::take(&mut self.sync_state.pipeline_mode) {
            PipelineMode::QuorumValidation {
                qr_info_summary,
            } => self.verify_and_complete(qr_info_summary).await,
            PipelineMode::Incremental => self.complete_incremental_pipeline().await,
        }
    }

    /// Complete the Incremental pipeline: verify non-rotating quorums at the latest
    /// engine height and update progress on success. On verification failure, log at
    /// warn level and return `Ok(vec![])` without changing state - a single failed
    /// tip refresh should not bounce the whole sync into Error.
    async fn complete_incremental_pipeline(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut engine = self.engine.write().await;
        let Some((&height, list)) = engine.masternode_lists.iter().next_back() else {
            return Ok(vec![]);
        };
        let latest_block_hash = list.block_hash;

        if let Err(e) = engine.verify_non_rotating_masternode_list_quorums(height, &[]) {
            tracing::warn!(
                height,
                "Incremental quorum verification failed, keeping previous state: {}",
                e
            );
            drop(engine);
            return Ok(vec![]);
        }
        drop(engine);

        self.sync_state.last_synced_block_hash = Some(latest_block_hash);
        self.progress.update_current_height(height);
        tracing::debug!("Incremental MnListDiff complete at height {}", height);
        Ok(vec![SyncEvent::MasternodeStateUpdated {
            height,
            qr_info_summary: None,
        }])
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

        let (base_hashes, anchor_height, engine_list_count) = {
            let engine = self.engine.read().await;
            let anchor = compute_qrinfo_anchor_hash(&engine, self.network, tip_height);
            let anchor_height = anchor.and_then(|h| {
                engine
                    .masternode_lists
                    .iter()
                    .find(|(_, list)| list.block_hash == h)
                    .map(|(height, _)| *height)
            });
            let list_count = engine.masternode_lists.len();
            (
                match anchor {
                    Some(hash) => vec![hash],
                    None => Vec::new(),
                },
                anchor_height,
                list_count,
            )
        };

        tracing::info!(
            tip_height,
            tip_block_hash = %tip_block_hash,
            base_hash = ?base_hashes.first().map(|h| h.to_string()),
            anchor_height = ?anchor_height,
            engine_list_count,
            state = ?self.state(),
            "Requesting QRInfo for tip"
        );
        requests.request_qr_info(base_hashes, tip_block_hash, true)?;

        self.sync_state.start_waiting_for_qrinfo();

        Ok(vec![])
    }

    /// Verify quorums and mark complete.
    ///
    /// For initial sync (state == Syncing), emits MasternodeStateUpdated and logs completion.
    /// For incremental updates (state == Synced), updates quietly without events.
    pub(super) async fn verify_and_complete(
        &mut self,
        qr_info_summary: Option<QRInfoFeedSummary>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();
        let is_initial_sync = self.state() == SyncState::Syncing;

        let mut engine = self.engine.write().await;

        // Get the latest height from the engine and verify at that height
        if let Some((&height, list)) = engine.masternode_lists.iter().next_back() {
            let latest_block_hash = list.block_hash;
            if let Err(e) = engine.verify_non_rotating_masternode_list_quorums(height, &[]) {
                drop(engine);
                self.set_state(SyncState::Error);
                return Err(SyncError::MasternodeSyncFailed(format!(
                    "Quorum verification failed at height {}: {}",
                    height, e
                )));
            }

            tracing::info!("Non-rotating quorum verification completed at height {}", height);

            self.sync_state.last_synced_block_hash = Some(latest_block_hash);
            self.progress.update_current_height(height);

            events.push(SyncEvent::MasternodeStateUpdated {
                height,
                qr_info_summary,
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

    async fn create_test_manager_for(network: dashcore::Network) -> TestMasternodesManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let engine = Arc::new(RwLock::new(MasternodeListEngine::default_for_network(network)));
        MasternodesManager::new(storage.block_headers(), engine, network).await
    }

    async fn create_test_manager() -> TestMasternodesManager {
        create_test_manager_for(dashcore::Network::Testnet).await
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

    // Regtest `isd_llmq_type` uses `DKG_TEST_DIP0024` (`interval=24`,
    // `mining_window=[12, 20]`). Cycle 48 → window `[60, 68]`; cycle 72 →
    // window `[84, 92]`.
    #[tokio::test]
    async fn test_next_pipeline_mode_fires_qrinfo_once_per_tip() {
        let mut manager = create_test_manager_for(dashcore::Network::Regtest).await;

        // First call inside cycle 48's window fires QRInfo.
        assert!(matches!(manager.next_pipeline_mode(60), PipelineMode::QuorumValidation { .. }));
        assert_eq!(manager.sync_state.current_cycle_attempts, 1);
        assert_eq!(manager.sync_state.last_window_qrinfo_tip, Some(60));

        // Re-entering with the same tip falls through to Incremental; attempts
        // counter does not bump.
        assert!(matches!(manager.next_pipeline_mode(60), PipelineMode::Incremental));
        assert_eq!(manager.sync_state.current_cycle_attempts, 1);

        // A new tip inside the same window fires QRInfo again.
        assert!(matches!(manager.next_pipeline_mode(61), PipelineMode::QuorumValidation { .. }));
        assert_eq!(manager.sync_state.current_cycle_attempts, 2);
        assert_eq!(manager.sync_state.last_window_qrinfo_tip, Some(61));

        // Same tip again: still Incremental.
        assert!(matches!(manager.next_pipeline_mode(61), PipelineMode::Incremental));
        assert_eq!(manager.sync_state.current_cycle_attempts, 2);

        // Cycle rollover to cycle 72 resets the per-tip gate, so the first tip
        // inside the new window fires QRInfo and attempts restarts at 1.
        assert!(matches!(manager.next_pipeline_mode(84), PipelineMode::QuorumValidation { .. }));
        assert_eq!(manager.sync_state.current_cycle_height, Some(72));
        assert_eq!(manager.sync_state.current_cycle_attempts, 1);
        assert_eq!(manager.sync_state.last_window_qrinfo_tip, Some(84));
        assert!(matches!(manager.next_pipeline_mode(84), PipelineMode::Incremental));
    }
}
