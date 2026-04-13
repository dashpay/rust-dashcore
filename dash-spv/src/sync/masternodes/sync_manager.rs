use super::manager::PipelineMode;
use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::BlockHeaderStorage;
use crate::sync::{
    ManagerIdentifier, MasternodesManager, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::SyncError;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_qrinfo::QRInfo;
use dashcore::sml::masternode_list_engine::{
    MasternodeListEngine, QRInfoFeedSummary, RotationChainLockSignatureSlot, WORK_DIFF_DEPTH,
};
use dashcore::sml::quorum_validation_error::QuorumValidationError;
use dashcore::{BlockHash, QuorumHash};
use dashcore_hashes::Hash;
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};

/// Timeout duration for waiting for QRInfo response.
const QRINFO_TIMEOUT_SECS: u64 = 15;

/// Maximum number of retry attempts before giving up.
const MAX_RETRY_ATTEMPTS: u8 = 3;

/// Delay between retries when ChainLock is not yet available for the tip.
/// ChainLocks typically propagate within a few seconds after a block is mined.
const CHAINLOCK_RETRY_DELAY_SECS: u64 = 5;

/// Log a concise summary of what `feed_qr_info` did, using the push-model report it
/// returned. This replaces the older pattern of iterating engine state after-the-fact.
fn log_qrinfo_feed_summary(summary: &QRInfoFeedSummary) {
    match summary.cycle_hash {
        Some(cycle_hash) => tracing::info!(
            "QRInfo processed: cycle {} at height {:?} has {} rotated quorums (freshly_validated={}, reused_from_prior_storage={})",
            cycle_hash,
            summary.cycle_height,
            summary.rotated_quorum_count,
            summary.freshly_validated_count,
            summary.reused_from_prior_storage_count
        ),
        None => tracing::warn!(
            "QRInfo processed: cycle boundary hash unavailable; {} rotated quorums seen (freshly_validated={}, reused_from_prior_storage={})",
            summary.rotated_quorum_count,
            summary.freshly_validated_count,
            summary.reused_from_prior_storage_count
        ),
    }
}

/// Build MnListDiff request pairs (base_hash, target_hash) for quorum validation.
///
/// Chains diffs from known heights where we have masternode lists, per DIP-0004:
/// - Uses all-zeros base for full list requests when no known height exists below target
/// - Finds the nearest known height below the target to use as base
pub(super) async fn build_mnlistdiff_request_pairs<S: BlockHeaderStorage>(
    storage: &S,
    quorum_hashes: &BTreeSet<QuorumHash>,
    known_heights: &BTreeSet<u32>,
) -> SyncResult<Vec<(BlockHash, BlockHash)>> {
    let mut request_pairs = Vec::new();
    let mut seen_targets = HashSet::new();

    for quorum_hash in quorum_hashes {
        let quorum_block_hash = *quorum_hash;

        let quorum_height = match storage.get_header_height_by_hash(&quorum_block_hash).await {
            Ok(Some(height)) => height,
            Ok(None) => {
                tracing::warn!("Height not found for quorum hash {}, skipping", quorum_block_hash);
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to get height for quorum hash {}: {}, skipping",
                    quorum_block_hash,
                    e
                );
                continue;
            }
        };

        let validation_height = quorum_height.saturating_sub(8);

        // Skip if we already have this height
        if known_heights.contains(&validation_height) {
            continue;
        }

        // Skip duplicates
        if seen_targets.contains(&validation_height) {
            continue;
        }
        seen_targets.insert(validation_height);

        // Find nearest known height BELOW validation_height to use as base
        let base_height = known_heights.range(..validation_height).next_back().copied();

        let base_hash = if let Some(height) = base_height {
            match storage.get_header(height).await {
                Ok(Some(h)) => h.block_hash(),
                Ok(None) => {
                    tracing::warn!("Base header not found at height {}, using all-zeros", height);
                    BlockHash::all_zeros()
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to get base header at height {}: {}, using all-zeros",
                        height,
                        e
                    );
                    BlockHash::all_zeros()
                }
            }
        } else {
            // No known height below target - request full list per DIP-0004
            BlockHash::all_zeros()
        };

        let target_hash = match storage.get_header(validation_height).await {
            Ok(Some(h)) => h.block_hash(),
            Ok(None) => {
                tracing::warn!("Target header not found at height {}, skipping", validation_height);
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to get target header at height {}: {}, skipping",
                    validation_height,
                    e
                );
                continue;
            }
        };

        tracing::debug!(
            "Adding MnListDiff request: base_height={:?}, target_height={}",
            base_height,
            validation_height
        );

        request_pairs.push((base_hash, target_hash));
    }

    // Sort by target height for sequential application
    let storage_ref = storage;
    let mut pairs_with_height = Vec::new();
    for (base, target) in request_pairs {
        if let Ok(Some(height)) = storage_ref.get_header_height_by_hash(&target).await {
            pairs_with_height.push((height, base, target));
        }
    }
    pairs_with_height.sort_by_key(|(h, _, _)| *h);

    Ok(pairs_with_height.into_iter().map(|(_, base, target)| (base, target)).collect())
}

/// Feed QRInfo block heights to the engine from storage.
///
/// This feeds all block heights referenced in the QRInfo diffs, plus the cycle boundary
/// height which is needed for rotated quorum storage key calculation.
pub(super) async fn feed_qrinfo_heights_to_engine<S: BlockHeaderStorage>(
    engine: &mut MasternodeListEngine,
    qr_info: &QRInfo,
    storage: &S,
) -> SyncResult<usize> {
    let mut block_hashes = vec![
        qr_info.mn_list_diff_tip.block_hash,
        qr_info.mn_list_diff_h.block_hash,
        qr_info.mn_list_diff_at_h_minus_c.block_hash,
        qr_info.mn_list_diff_at_h_minus_2c.block_hash,
        qr_info.mn_list_diff_at_h_minus_3c.block_hash,
        qr_info.mn_list_diff_tip.base_block_hash,
        qr_info.mn_list_diff_h.base_block_hash,
        qr_info.mn_list_diff_at_h_minus_c.base_block_hash,
        qr_info.mn_list_diff_at_h_minus_2c.base_block_hash,
        qr_info.mn_list_diff_at_h_minus_3c.base_block_hash,
    ];

    if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
        block_hashes.push(diff.block_hash);
        block_hashes.push(diff.base_block_hash);
    }

    for diff in &qr_info.mn_list_diff_list {
        block_hashes.push(diff.block_hash);
        block_hashes.push(diff.base_block_hash);
    }

    // Feed heights for all active rotating quorum block hashes. Each `QuorumEntry::quorum_hash`
    // in `last_commitment_per_index` is the block hash of the block where that quorum's DKG
    // commitment was mined; for rotating LLMQs these are sequential blocks near the cycle
    // boundary (Q[0] at C, Q[1] at C+1, ..., Q[31] at C+31). Quorum formation verification and
    // IS lock signature verification both look up the masternode list at each quorum's height,
    // so every commitment hash must be resolvable in `block_container`.
    for quorum_entry in &qr_info.last_commitment_per_index {
        block_hashes.push(quorum_entry.quorum_hash);
    }

    block_hashes.sort();
    block_hashes.dedup();

    let mut fed_count = 0;
    for block_hash in block_hashes {
        if let Ok(Some(height)) = storage.get_header_height_by_hash(&block_hash).await {
            engine.feed_block_height(height, block_hash);
            fed_count += 1;
            tracing::debug!("Fed height {} for block {}", height, block_hash);
        }
    }

    // Feed cycle boundary heights for all diffs (current and historical cycles)
    // Each diff's block_hash is at the "work block" height; the cycle boundary is WORK_DIFF_DEPTH higher
    let mut work_block_hashes = vec![
        qr_info.mn_list_diff_h.block_hash,
        qr_info.mn_list_diff_at_h_minus_c.block_hash,
        qr_info.mn_list_diff_at_h_minus_2c.block_hash,
        qr_info.mn_list_diff_at_h_minus_3c.block_hash,
    ];

    if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
        work_block_hashes.push(diff.block_hash);
    }

    for work_block_hash in work_block_hashes {
        if let Ok(Some(work_block_height)) =
            storage.get_header_height_by_hash(&work_block_hash).await
        {
            let cycle_boundary_height = work_block_height + WORK_DIFF_DEPTH;
            if let Ok(Some(cycle_boundary_header)) = storage.get_header(cycle_boundary_height).await
            {
                let cycle_boundary_hash = cycle_boundary_header.block_hash();
                engine.feed_block_height(cycle_boundary_height, cycle_boundary_hash);
                fed_count += 1;
                tracing::debug!(
                    "Fed cycle boundary height {} for block {}",
                    cycle_boundary_height,
                    cycle_boundary_hash
                );
            }
        }
    }

    tracing::info!("Fed {} block heights to engine", fed_count);
    Ok(fed_count)
}

#[async_trait]
impl<H: BlockHeaderStorage> SyncManager for MasternodesManager<H> {
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::Masternode
    }

    fn state(&self) -> SyncState {
        self.progress.state()
    }

    fn set_state(&mut self, state: SyncState) {
        self.progress.set_state(state);
    }

    fn update_target_height(&mut self, height: u32) {
        self.progress.update_target_height(height);
    }

    fn wanted_message_types(&self) -> &'static [MessageType] {
        &[MessageType::MnListDiff, MessageType::QRInfo]
    }

    fn clear_in_flight_state(&mut self) {
        self.sync_state.clear_pending();
        self.sync_state.qrinfo_retry_count = 0;
        self.sync_state.chainlock_retry_after = None;
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::QRInfo(qr_info) => {
                tracing::info!("Processing QRInfo message");
                self.sync_state.qrinfo_received();

                // Feed block heights to engine using internal storage
                let storage = self.header_storage.read().await;
                let mut engine = self.engine.write().await;
                let fed = feed_qrinfo_heights_to_engine(&mut engine, qr_info, &*storage).await?;
                drop(storage);
                tracing::info!("Fed {} block heights to engine", fed);

                // Feed QRInfo to engine first to populate masternode lists
                let summary = match engine.feed_qr_info(
                    qr_info.clone(),
                    true,
                    true,
                    None::<
                        fn(
                            &BlockHash,
                        ) -> Result<
                            u32,
                            dashcore::sml::quorum_validation_error::ClientDataRetrievalError,
                        >,
                    >,
                ) {
                    Ok(summary) => summary,
                    Err(e) => {
                        // `sigmtip`-only missing is the expected outcome when the current
                        // cycle's rotated commitment has not been mined yet. In that case
                        // we log and wait for the next event to drive the next attempt:
                        //
                        //   - If we are `Synced` (incremental update path): the next
                        //     `BlockHeadersStored` event will re-run
                        //     `incremental_update_action`, which will fire another QRInfo
                        //     on every block inside the mining window. No time-based retry
                        //     is needed and transitioning out of `Synced` would actually
                        //     break the block-driven retry because the gate only fires
                        //     while `Synced`.
                        //   - If we are in initial sync (state was `Syncing`): schedule a
                        //     short delayed retry via the tick handler. This is the "tip
                        //     block just mined, its ChainLock hasn't propagated yet" case.
                        //
                        // Any other missing-sig combination is a base-hash or protocol bug
                        // we cannot fix by retrying naively, so we fall through to the
                        // generic error path.
                        let is_sigmtip_only_missing = matches!(
                            &e,
                            QuorumValidationError::MissingRotationSignatures { missing }
                                if missing.as_slice()
                                    == [RotationChainLockSignatureSlot::Tip]
                        );

                        if is_sigmtip_only_missing {
                            if self.state() == SyncState::Synced {
                                // QRInfo can't validate rotation yet (the DKG commitment
                                // block hasn't been mined or hasn't propagated). Fall back
                                // to a targeted MnListDiff so the tip masternode list stays
                                // fresh. The next BlockHeadersStored that lands inside the
                                // mining window will retry QRInfo.
                                drop(engine);
                                tracing::debug!(
                                    "QRInfo tip signature not yet available; falling back to \
                                     targeted MnListDiff for tip update"
                                );
                                return self.send_tip_mnlistdiff_update(requests).await;
                            }
                            // Initial sync: `feed_qr_info`'s `apply_diff` calls already
                            // populated the engine with masternode lists even though the
                            // rotated quorum pre-check failed. Treat this as a partial
                            // success — complete the pipeline with non-rotating
                            // verification and transition to Synced. The mining window
                            // mechanism will pick up rotation validation when the DKG
                            // commitment is mined.
                            tracing::info!(
                                "QRInfo tip signature not yet available; completing initial \
                                 sync with non-rotating verification (rotation will be \
                                 validated when the DKG commitment is mined)"
                            );
                            self.sync_state.known_mn_list_heights =
                                engine.masternode_lists.keys().copied().collect();
                            drop(engine);
                            return self.complete_pipeline().await;
                        }

                        // For other errors or max retries reached, fail
                        tracing::error!(
                            "QRInfo failed after {} retries: {}",
                            self.sync_state.qrinfo_retry_count,
                            e
                        );
                        return Err(SyncError::MasternodeSyncFailed(e.to_string()));
                    }
                };

                log_qrinfo_feed_summary(&summary);

                // Populate known_mn_list_heights from engine after QRInfo processing
                self.sync_state.known_mn_list_heights =
                    engine.masternode_lists.keys().copied().collect();
                tracing::debug!(
                    "Engine has masternode lists at {} heights",
                    self.sync_state.known_mn_list_heights.len()
                );

                // Get quorum hashes and build request pairs, chaining from known heights
                let quorum_hashes =
                    engine.latest_masternode_list_non_rotating_quorum_hashes(&[], false);
                let storage = self.header_storage.read().await;
                let request_pairs = build_mnlistdiff_request_pairs(
                    &*storage,
                    &quorum_hashes,
                    &self.sync_state.known_mn_list_heights,
                )
                .await?;

                // Drop locks before potentially long operations
                drop(engine);
                drop(storage);

                // If every rotated quorum in this QRInfo went through the fresh-
                // validation path, mark the cycle validated so
                // `incremental_update_action` will return `MnListDiffOnly` for every
                // subsequent header in this cycle - no more QRInfo requests for this
                // cycle until the next boundary.
                if let Some(cycle_height) = summary.cycle_height {
                    if summary.rotated_quorum_count > 0
                        && summary.freshly_validated_count == summary.rotated_quorum_count
                    {
                        self.mark_cycle_validated(cycle_height);
                    }
                }

                // The historical diffs that follow a QRInfo are the "QuorumValidation"
                // pipeline mode, which is the default - but the pipeline mode may have
                // been Incremental from a previous in-flight tip update, so be explicit.
                self.sync_state.pipeline_mode = PipelineMode::QuorumValidation;
                self.sync_state.mnlistdiff_pipeline.queue_requests(request_pairs);
                self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

                self.progress.bump_last_activity();

                // If no pending requests, complete
                if !self.sync_state.has_pending_requests() {
                    return self.complete_pipeline().await;
                }
            }

            NetworkMessage::MnListDiff(diff) => {
                // Check if this diff matches an in-flight request
                if !self.sync_state.mnlistdiff_pipeline.match_response(diff) {
                    tracing::debug!("Received unexpected MnListDiff for {}", diff.block_hash);
                    return Ok(vec![]);
                }

                tracing::debug!("Processing MnListDiff message for {}", diff.block_hash);

                // Get target height from storage
                let storage = self.header_storage.read().await;
                let target_height = match storage.get_header_height_by_hash(&diff.block_hash).await
                {
                    Ok(Some(h)) => h,
                    Ok(None) => {
                        tracing::warn!(
                            "Height not found for MnListDiff block {}, requeuing for retry",
                            diff.block_hash
                        );
                        self.sync_state.mnlistdiff_pipeline.requeue(diff);
                        self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;
                        return Ok(vec![]);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to get height for MnListDiff block {}: {}, requeuing for retry",
                            diff.block_hash,
                            e
                        );
                        self.sync_state.mnlistdiff_pipeline.requeue(diff);
                        self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;
                        return Ok(vec![]);
                    }
                };
                drop(storage);

                // Apply diff to engine
                let mut engine = self.engine.write().await;
                engine.feed_block_height(target_height, diff.block_hash);

                let apply_ok =
                    match engine.apply_diff(diff.clone(), Some(target_height), false, None) {
                        Ok(_) => {
                            self.sync_state.known_mn_list_heights.insert(target_height);
                            tracing::debug!("Applied MnListDiff at height {}", target_height);
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to apply MnListDiff at height {}: {}",
                                target_height,
                                e
                            );
                            false
                        }
                    };
                drop(engine);

                self.progress.add_diffs_processed(1);
                self.sync_state.mnlistdiff_pipeline.receive(diff);
                self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

                // Check if all responses received
                if self.sync_state.mnlistdiff_pipeline.is_complete() {
                    // In `Incremental` mode, a failed `apply_diff` means the engine
                    // state is unchanged - skip completion to avoid emitting a
                    // spurious `MasternodeStateUpdated` for stale state. The next
                    // `BlockHeadersStored` event will re-drive an incremental update.
                    if !apply_ok && self.sync_state.pipeline_mode == PipelineMode::Incremental {
                        return Ok(vec![]);
                    }
                    tracing::info!("All MnListDiff responses received");
                    return self.complete_pipeline().await;
                }
            }

            _ => {}
        }

        Ok(vec![])
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Track block header tip height as headers come in
        if let SyncEvent::BlockHeadersStored {
            tip_height,
        } = event
        {
            self.progress.update_block_header_tip_height(*tip_height);
            // Keep target_height up to date post-sync
            if *tip_height > self.progress.target_height() {
                self.progress.update_target_height(*tip_height);
            }

            // If Synced but behind, pick the pipeline mode for this tip update. The
            // mode selector fires a full QRInfo only inside the current cycle's DKG
            // mining window (and only while the cycle has not been freshly validated),
            // and uses a targeted `GetMnListDiff` for tip updates in every other case -
            // keeping the masternode list fresh on every new block without re-running
            // rotated quorum validation.
            if self.state() == SyncState::Synced
                && self.progress.current_height() < self.progress.block_header_tip_height()
            {
                match self.next_pipeline_mode(*tip_height) {
                    PipelineMode::QuorumValidation => {
                        if self.sync_state.waiting_for_qrinfo {
                            tracing::debug!(
                                "New headers stored (tip: {}), QRInfo already in flight",
                                tip_height,
                            );
                            return Ok(vec![]);
                        }
                        tracing::debug!(
                            "New headers stored (tip: {}), firing QRInfo from {}",
                            tip_height,
                            self.progress.current_height()
                        );
                        self.sync_state.qrinfo_retry_count = 0;
                        self.sync_state.clear_pending();
                        return self.send_qrinfo_for_tip(requests).await;
                    }
                    PipelineMode::Incremental => {
                        tracing::debug!(
                            "New headers stored (tip: {}), firing targeted MnListDiff from {}",
                            tip_height,
                            self.progress.current_height()
                        );
                        return self.send_tip_mnlistdiff_update(requests).await;
                    }
                }
            }
        }

        // Start masternode sync when headers are fully caught up
        if let SyncEvent::BlockHeaderSyncComplete {
            tip_height,
        } = event
        {
            self.progress.update_block_header_tip_height(*tip_height);
            // Keep target_height up to date post-sync
            if *tip_height > self.progress.target_height() {
                self.progress.update_target_height(*tip_height);
            }

            // Determine if we should (re)start sync:
            // 1. WaitingForConnections: first time starting
            // 2. WaitForEvents: waiting for this event
            // 3. Syncing but stuck at height 0 with no pending requests: timed out before headers ready
            // 4. Synced but behind target: new headers arrived after sync completed
            let should_restart = match self.state() {
                SyncState::WaitingForConnections | SyncState::WaitForEvents => true,
                SyncState::Syncing => {
                    self.progress.current_height() == 0 && !self.sync_state.has_pending_requests()
                }
                SyncState::Synced => {
                    self.progress.current_height() < self.progress.block_header_tip_height()
                }
                _ => false,
            };

            if should_restart {
                // A `BlockHeaderSyncComplete` event fires whenever the header pipeline
                // catches up to the latest known tip, including after brief lags during
                // normal runtime - so this branch runs both for initial sync AND for
                // catch-ups from `Synced`. The two cases need different dispatch:
                //
                // - Initial sync (`WaitingForConnections` / `WaitForEvents` / stuck
                //   `Syncing`): fire a full QRInfo unconditionally to seed the
                //   masternode list engine from scratch.
                // - Catch-up from `Synced`: route through `next_pipeline_mode` so that
                //   the gate picks QRInfo vs targeted `GetMnListDiff` based on where
                //   the tip sits relative to the current cycle's DKG mining window,
                //   matching the `BlockHeadersStored` per-block path. Bypassing the
                //   gate here would cause a full QRInfo on every batch catch-up,
                //   which fires several times per cycle even when the cycle is
                //   already freshly-validated and the tip should just be refreshed
                //   with a targeted mnlistdiff.
                if self.state() == SyncState::Synced {
                    tracing::debug!(
                        "Headers sync complete at {}, updating masternode list",
                        self.progress.block_header_tip_height()
                    );
                    match self.next_pipeline_mode(*tip_height) {
                        PipelineMode::QuorumValidation => {
                            if self.sync_state.waiting_for_qrinfo {
                                tracing::debug!(
                                    "Headers sync complete at {}, QRInfo already in flight",
                                    self.progress.block_header_tip_height()
                                );
                                return Ok(vec![]);
                            }
                            self.sync_state.qrinfo_retry_count = 0;
                            self.sync_state.clear_pending();
                            return self.send_qrinfo_for_tip(requests).await;
                        }
                        PipelineMode::Incremental => {
                            return self.send_tip_mnlistdiff_update(requests).await;
                        }
                    }
                }
                tracing::info!(
                    "Headers sync complete at {}, starting masternode sync",
                    self.progress.block_header_tip_height()
                );
                self.sync_state.qrinfo_retry_count = 0;
                self.sync_state.clear_pending();
                return self.send_qrinfo_for_tip(requests).await;
            }
        }

        Ok(vec![])
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // Handle ticks for both Syncing (initial) and Synced (incremental updates)
        if !matches!(self.state(), SyncState::Syncing | SyncState::Synced) {
            return Ok(vec![]);
        }

        // If Synced with no pending requests, check whether new headers arrived
        // while the initial sync was in progress. BlockHeadersStored events that
        // landed during Syncing state updated block_header_tip_height but couldn't
        // trigger an incremental update (the handler requires Synced). The tick
        // catches this gap and fires the appropriate pipeline.
        if self.state() == SyncState::Synced && !self.sync_state.has_pending_requests() {
            if self.progress.current_height() < self.progress.block_header_tip_height() {
                let tip = self.progress.block_header_tip_height();
                match self.next_pipeline_mode(tip) {
                    PipelineMode::QuorumValidation => {
                        if !self.sync_state.waiting_for_qrinfo {
                            self.sync_state.qrinfo_retry_count = 0;
                            self.sync_state.clear_pending();
                            return self.send_qrinfo_for_tip(requests).await;
                        }
                    }
                    PipelineMode::Incremental => {
                        return self.send_tip_mnlistdiff_update(requests).await;
                    }
                }
            }
            return Ok(vec![]);
        }

        // Check for ChainLock retry (tip didn't have ChainLock yet)
        if let Some(retry_after) = self.sync_state.chainlock_retry_after {
            if Instant::now() >= retry_after {
                tracing::info!("Retrying QRInfo after ChainLock delay");
                self.sync_state.chainlock_retry_after = None;
                return self.send_qrinfo_for_tip(requests).await;
            }
            // Still waiting for retry delay
            return Ok(vec![]);
        }

        // Check for QRInfo timeout
        if self.sync_state.waiting_for_qrinfo {
            if let Some(wait_start) = self.sync_state.qrinfo_wait_start {
                let timeout = Duration::from_secs(QRINFO_TIMEOUT_SECS);
                if wait_start.elapsed() > timeout {
                    if self.sync_state.qrinfo_retry_count < MAX_RETRY_ATTEMPTS {
                        tracing::warn!("Timeout waiting for QRInfo response, retrying...");
                        self.sync_state.qrinfo_retry_count += 1;
                        self.sync_state.clear_pending();
                        return self.send_qrinfo_for_tip(requests).await;
                    } else {
                        tracing::warn!(
                            "QRInfo timeout after {} retries, skipping masternode sync",
                            MAX_RETRY_ATTEMPTS
                        );
                        self.sync_state.clear_pending();
                        return self.complete_pipeline().await;
                    }
                }
            }
            return Ok(vec![]);
        }

        // Check for MnListDiff timeouts via pipeline
        if self.sync_state.mnlistdiff_pipeline.active_count() > 0 {
            self.sync_state.mnlistdiff_pipeline.handle_timeouts();

            // Send any re-queued requests
            self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

            // Check if complete after handling timeouts
            if self.sync_state.mnlistdiff_pipeline.is_complete() {
                tracing::info!("MnListDiff pipeline complete");
                return self.complete_pipeline().await;
            }
        }

        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Masternodes(self.progress.clone())
    }
}
