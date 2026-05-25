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
use dashcore::sml::masternode_list_engine::{MasternodeListEngine, WORK_DIFF_DEPTH};
use dashcore::{BlockHash, QuorumHash};
use dashcore_hashes::Hash;
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

/// Per-attempt timeout schedule for QRInfo, indexed by the in-flight attempt's
/// retry count (0 = initial send, N = N-th retry). Round-robin peer selection in
/// the network manager rotates peers naturally on every send, so a short first
/// timeout fails over fast when one peer drops the request silently while the
/// later, longer timeouts give a slow but responsive network room to answer.
///
/// Total worst-case wall clock if every attempt times out:
/// `sum(QRINFO_TIMEOUT_SCHEDULE_SECS) = 100s`.
const QRINFO_TIMEOUT_SCHEDULE_SECS: [u64; 3] = [10, 30, 60];

/// Maximum number of in-flight attempts (initial send plus retries) before
/// giving up. Equal to `QRINFO_TIMEOUT_SCHEDULE_SECS.len()`.
const MAX_RETRY_ATTEMPTS: u8 = QRINFO_TIMEOUT_SCHEDULE_SECS.len() as u8;

/// Returns the timeout for the in-flight QRInfo attempt with the given retry count.
///
/// `retry_count == 0` is the initial send; values past the last entry clamp to
/// the slowest schedule slot. `MAX_RETRY_ATTEMPTS` already prevents going past
/// the array, but the clamp is defensive in case the constants drift.
fn qrinfo_timeout_for(retry_count: u8) -> Duration {
    let idx = (retry_count as usize).min(QRINFO_TIMEOUT_SCHEDULE_SECS.len() - 1);
    Duration::from_secs(QRINFO_TIMEOUT_SCHEDULE_SECS[idx])
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
/// Resolves heights for every hash enumerated by
/// [`MasternodeListEngine::qr_info_referenced_block_hashes`], plus the cycle boundary
/// block for each work-block diff (`work_height + WORK_DIFF_DEPTH`), which is needed
/// for rotated quorum storage key calculation.
pub(super) async fn feed_qrinfo_heights_to_engine<S: BlockHeaderStorage>(
    engine: &mut MasternodeListEngine,
    qr_info: &QRInfo,
    storage: &S,
) -> SyncResult<usize> {
    let mut fed_count = 0;
    for block_hash in MasternodeListEngine::qr_info_referenced_block_hashes(qr_info) {
        if let Ok(Some(height)) = storage.get_header_height_by_hash(&block_hash).await {
            engine.feed_block_height(height, block_hash);
            fed_count += 1;
            tracing::debug!("Fed height {} for block {}", height, block_hash);
        }
    }

    // Feed cycle boundary heights for all diffs (current and historical cycles).
    // Each diff's block_hash is at the "work block" height; the cycle boundary is
    // WORK_DIFF_DEPTH higher.
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

    fn on_disconnect(&mut self) {
        self.sync_state.clear_pending();
        self.sync_state.qrinfo_retry_count = 0;
        self.sync_state.last_processed_qrinfo_tip = None;
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::QRInfo(qr_info) => {
                if !self.sync_state.should_process_qrinfo(qr_info) {
                    return Ok(vec![]);
                }
                tracing::info!("Processing QRInfo message");
                self.sync_state.qrinfo_received();

                // Feed block heights to engine using internal storage
                let storage = self.header_storage.read().await;
                let mut engine = self.engine.write().await;
                let fed = feed_qrinfo_heights_to_engine(&mut engine, qr_info, &*storage).await?;
                drop(storage);
                tracing::info!("Fed {} block heights to engine", fed);

                // Feed QRInfo to engine first to populate masternode lists
                let qr_info_result = match engine.feed_qr_info(qr_info.clone(), true, true) {
                    Ok(qr_info_result) => qr_info_result,
                    Err(e) => {
                        tracing::error!("QRInfo feed into engine failed: {}", e);
                        return Err(SyncError::MasternodeSyncFailed(e.to_string()));
                    }
                };

                // Record the successfully processed tip so a late straggler carrying
                // the same tip hash is dropped by `should_process_qrinfo`.
                self.sync_state.last_processed_qrinfo_tip =
                    Some(qr_info.mn_list_diff_tip.block_hash);

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

                if let Some(ref qr_info_result) = qr_info_result {
                    tracing::info!(
                        "QRInfo processed: stored_cycle_height={:?}, rotated_quorum_count={}, fully_verified_count={}, newly_qualified_count={}",
                        qr_info_result.stored_cycle_height,
                        qr_info_result.rotated_quorum_count,
                        qr_info_result.fully_verified_count,
                        qr_info_result.newly_qualified_count,
                    );
                    // If every rotated quorum in this QRInfo ended up Verified,
                    // mark the cycle validated so `next_pipeline_mode` will
                    // return `Incremental` for every subsequent header in this
                    // cycle. No more QRInfo requests for this cycle until the
                    // next boundary.
                    if qr_info_result.all_fully_verified() {
                        if let Some(ref stored_cycle_height) = qr_info_result.stored_cycle_height {
                            self.mark_cycle_validated(*stored_cycle_height);
                        }
                    }
                }

                // The historical diffs that follow a QRInfo run under QuorumValidation.
                // Carry the result on the mode so `complete_pipeline` can pass it
                // into the resulting `MasternodeStateUpdated` event.
                self.sync_state.pipeline_mode = PipelineMode::QuorumValidation {
                    qr_info_result,
                };
                self.sync_state.mnlistdiff_pipeline.queue_requests(request_pairs);
                self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

                self.progress.bump_last_activity();

                // If no pending requests, complete
                if !self.sync_state.has_pending_requests() {
                    return self.complete_pipeline(requests).await;
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
                    // state is unchanged. Skip completion to avoid emitting a
                    // spurious `MasternodeStateUpdated` for stale state. The next
                    // `BlockHeadersStored` event will re-drive an incremental update.
                    if !apply_ok
                        && matches!(self.sync_state.pipeline_mode, PipelineMode::Incremental)
                    {
                        return Ok(vec![]);
                    }
                    tracing::info!("All MnListDiff responses received");
                    return self.complete_pipeline(requests).await;
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
                // A previous pipeline (QRInfo + draining historical MnListDiffs, or an
                // earlier incremental update) may still be in flight. Starting a new
                // pipeline here would overwrite `pipeline_mode` and append into the same
                // queue, so when the shared pipeline completes the wrong completion path
                // runs and any pending `qr_info_result` is discarded. The `tick` handler
                // re-fires once the pipeline drains.
                if self.sync_state.has_pending_requests() {
                    return Ok(vec![]);
                }

                match self.next_pipeline_mode(*tip_height) {
                    PipelineMode::QuorumValidation {
                        ..
                    } => {
                        if self.sync_state.qrinfo_in_flight.is_some() {
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
                // normal runtime, so this branch runs both for initial sync and for
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
                    // Same guard as the `BlockHeadersStored` Synced arm above: never
                    // start a new pipeline while an earlier one is still draining,
                    // otherwise the shared queue and `pipeline_mode` get clobbered.
                    if self.sync_state.has_pending_requests() {
                        return Ok(vec![]);
                    }
                    tracing::debug!(
                        "Headers sync complete at {}, updating masternode list",
                        self.progress.block_header_tip_height()
                    );
                    match self.next_pipeline_mode(*tip_height) {
                        PipelineMode::QuorumValidation {
                            ..
                        } => {
                            if self.sync_state.qrinfo_in_flight.is_some() {
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
                    PipelineMode::QuorumValidation {
                        ..
                    } => {
                        if self.sync_state.qrinfo_in_flight.is_none() {
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

        // Check for QRInfo timeout
        if let Some(in_flight) = self.sync_state.qrinfo_in_flight {
            let timeout = qrinfo_timeout_for(self.sync_state.qrinfo_retry_count);
            if in_flight.wait_start.elapsed() > timeout {
                if self.sync_state.qrinfo_retry_count < MAX_RETRY_ATTEMPTS - 1 {
                    tracing::warn!(
                        timeout_secs = timeout.as_secs(),
                        retry_count = self.sync_state.qrinfo_retry_count,
                        "Timeout waiting for QRInfo response, retrying..."
                    );
                    self.sync_state.qrinfo_retry_count += 1;
                    self.sync_state.clear_pending();
                    return self.send_qrinfo_for_tip(requests).await;
                } else {
                    tracing::warn!(
                        "QRInfo timeout after {} retries, skipping masternode sync",
                        MAX_RETRY_ATTEMPTS
                    );
                    self.sync_state.clear_pending();
                    return self.complete_pipeline(requests).await;
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
                return self.complete_pipeline(requests).await;
            }
        }

        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Masternodes(self.progress.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::manager::{MasternodeSyncState, QRInfoInFlight};
    use super::{
        feed_qrinfo_heights_to_engine, qrinfo_timeout_for, MAX_RETRY_ATTEMPTS,
        QRINFO_TIMEOUT_SCHEDULE_SECS,
    };
    use crate::error::StorageResult;
    use crate::storage::{BlockHeaderStorage, BlockHeaderTip};
    use crate::types::HashedBlockHeader;
    use async_trait::async_trait;
    use dashcore::block::Header as BlockHeader;
    use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use dashcore::hash_types::QuorumVVecHash;
    use dashcore::network::message_qrinfo::{MNSkipListMode, QRInfo, QuorumSnapshot};
    use dashcore::network::message_sml::MnListDiff;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::sml::masternode_list_engine::MasternodeListEngine;
    use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
    use dashcore::{BlockHash, Network, Transaction};
    use dashcore_hashes::Hash;
    use std::collections::HashMap;
    use std::ops::Range;
    use std::time::Instant;

    struct MockHeaderStorage(HashMap<BlockHash, u32>);

    #[async_trait]
    impl BlockHeaderStorage for MockHeaderStorage {
        async fn store_headers(&mut self, _: &[BlockHeader]) -> StorageResult<()> {
            Ok(())
        }
        async fn store_headers_at_height(
            &mut self,
            _: &[BlockHeader],
            _: u32,
        ) -> StorageResult<()> {
            Ok(())
        }
        async fn store_hashed_headers(&mut self, _: &[HashedBlockHeader]) -> StorageResult<()> {
            Ok(())
        }
        async fn store_hashed_headers_at_height(
            &mut self,
            _: &[HashedBlockHeader],
            _: u32,
        ) -> StorageResult<()> {
            Ok(())
        }
        async fn load_headers(&self, _: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
            Ok(vec![])
        }
        async fn get_tip_height(&self) -> Option<u32> {
            None
        }
        async fn get_tip(&self) -> Option<BlockHeaderTip> {
            None
        }
        async fn get_start_height(&self) -> Option<u32> {
            None
        }
        async fn get_stored_headers_len(&self) -> u32 {
            0
        }
        async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
            Ok(self.0.get(hash).copied())
        }
        async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
            self.0.retain(|_, h| *h <= target_height);
            Ok(())
        }
    }

    fn make_diff(base_byte: u8, tip_byte: u8) -> MnListDiff {
        MnListDiff {
            version: 1,
            base_block_hash: BlockHash::from_slice(&[base_byte; 32]).unwrap(),
            block_hash: BlockHash::from_slice(&[tip_byte; 32]).unwrap(),
            total_transactions: 0,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx: Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            quorums_chainlock_signatures: vec![],
        }
    }

    fn make_quorum_entry(hash_byte: u8, index: i16) -> QuorumEntry {
        QuorumEntry {
            version: 1,
            llmq_type: LLMQType::Llmqtype50_60,
            quorum_hash: BlockHash::from_slice(&[hash_byte; 32]).unwrap(),
            quorum_index: Some(index),
            signers: vec![],
            valid_members: vec![],
            quorum_public_key: BLSPublicKey::from([0u8; 48]),
            quorum_vvec_hash: QuorumVVecHash::from_slice(&[0u8; 32]).unwrap(),
            threshold_sig: BLSSignature::from([0u8; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([0u8; 96]),
        }
    }

    fn make_snapshot() -> QuorumSnapshot {
        QuorumSnapshot {
            skip_list_mode: MNSkipListMode::NoSkipping,
            active_quorum_members: vec![],
            skip_list: vec![],
        }
    }

    /// Verifies that `feed_qrinfo_heights_to_engine` feeds the engine's
    /// `block_container` with heights for every hash source in a `QRInfo` message:
    /// - base and tip hashes for each of the five standard diffs
    /// - base and tip hashes for the optional h-minus-4c diff
    /// - base and tip hashes for each entry in `mn_list_diff_list`
    /// - every `QuorumEntry::quorum_hash` in `last_commitment_per_index`
    ///
    /// The last category is the invariant the parent commit fixed: before that,
    /// only Q[0] (the cycle boundary, already present as a diff endpoint) was
    /// fed. Q[1]..Q[N-1] were silently missing, causing lookup failures during IS
    /// lock and rotated quorum formation verification.
    #[tokio::test]
    async fn test_feed_qrinfo_heights_to_engine_covers_every_hash_source() {
        // Each hash category uses a distinct leading byte so failures are easy to diagnose.
        // Diffs:        0x01..0x0E  (base/tip pairs for each diff field)
        // Commitments:  0x80..0x83  (last_commitment_per_index quorum hashes)
        let expected_hashes: &[u8] = &[
            0x01, 0x02, // mn_list_diff_tip:          base, tip
            0x03, 0x04, // mn_list_diff_h:             base, tip
            0x05, 0x06, // mn_list_diff_at_h_minus_c:  base, tip
            0x07, 0x08, // mn_list_diff_at_h_minus_2c: base, tip
            0x09, 0x0A, // mn_list_diff_at_h_minus_3c: base, tip
            0x0B, 0x0C, // mn_list_diff_at_h_minus_4c: base, tip  (optional)
            0x0D, 0x0E, // mn_list_diff_list[0]:       base, tip
            0x80, 0x81, 0x82, 0x83, // last_commitment_per_index Q[0]..Q[3]
        ];

        let mut height_map = HashMap::new();
        for (i, &b) in expected_hashes.iter().enumerate() {
            height_map.insert(BlockHash::from_slice(&[b; 32]).unwrap(), 100 + i as u32);
        }

        let qr_info = QRInfo {
            quorum_snapshot_at_h_minus_c: make_snapshot(),
            quorum_snapshot_at_h_minus_2c: make_snapshot(),
            quorum_snapshot_at_h_minus_3c: make_snapshot(),
            mn_list_diff_tip: make_diff(0x01, 0x02),
            mn_list_diff_h: make_diff(0x03, 0x04),
            mn_list_diff_at_h_minus_c: make_diff(0x05, 0x06),
            mn_list_diff_at_h_minus_2c: make_diff(0x07, 0x08),
            mn_list_diff_at_h_minus_3c: make_diff(0x09, 0x0A),
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c: Some((
                make_snapshot(),
                make_diff(0x0B, 0x0C),
            )),
            mn_list_diff_list: vec![make_diff(0x0D, 0x0E)],
            last_commitment_per_index: [0x80u8, 0x81, 0x82, 0x83]
                .iter()
                .enumerate()
                .map(|(i, &b)| make_quorum_entry(b, i as i16))
                .collect(),
            quorum_snapshot_list: vec![make_snapshot()],
        };

        let mut engine = MasternodeListEngine {
            network: Network::Testnet,
            ..Default::default()
        };
        feed_qrinfo_heights_to_engine(&mut engine, &qr_info, &MockHeaderStorage(height_map))
            .await
            .unwrap();

        for &b in expected_hashes {
            let hash = BlockHash::from_slice(&[b; 32]).unwrap();
            assert!(
                engine.block_container.contains_hash(&hash),
                "hash 0x{:02X} not fed to engine.block_container",
                b
            );
        }
    }

    /// The QRInfo retry budget escalates: a tight first timeout fails over
    /// fast when one peer drops the request silently, while later attempts
    /// get progressively more headroom so a genuinely slow but responsive
    /// network still gets to answer.
    #[test]
    fn test_qrinfo_timeout_schedule() {
        assert_eq!(QRINFO_TIMEOUT_SCHEDULE_SECS.len(), MAX_RETRY_ATTEMPTS as usize);

        // First attempt fails over fast so a single bad peer does not block sync.
        assert_eq!(qrinfo_timeout_for(0).as_secs(), 10);

        // Schedule escalates monotonically so a slow but responsive network
        // still gets enough time to answer.
        let schedule: Vec<u64> =
            (0..MAX_RETRY_ATTEMPTS).map(|n| qrinfo_timeout_for(n).as_secs()).collect();
        assert!(
            schedule.windows(2).all(|w| w[0] <= w[1]),
            "timeout schedule must be non-decreasing, got {:?}",
            schedule
        );

        // Out-of-range retry counts must clamp to the slowest slot rather than
        // panic, in case the constants drift relative to MAX_RETRY_ATTEMPTS.
        let last = *QRINFO_TIMEOUT_SCHEDULE_SECS.last().unwrap();
        assert_eq!(qrinfo_timeout_for(MAX_RETRY_ATTEMPTS).as_secs(), last);
        assert_eq!(qrinfo_timeout_for(u8::MAX).as_secs(), last);
    }

    /// Build a minimal `QRInfo` whose `mn_list_diff_tip.block_hash` is `[tip_byte; 32]`.
    /// Only the tip hash is read by `should_process_qrinfo`; every other field is filler.
    fn qrinfo_with_tip(tip_byte: u8) -> QRInfo {
        QRInfo {
            quorum_snapshot_at_h_minus_c: make_snapshot(),
            quorum_snapshot_at_h_minus_2c: make_snapshot(),
            quorum_snapshot_at_h_minus_3c: make_snapshot(),
            mn_list_diff_tip: make_diff(0x00, tip_byte),
            mn_list_diff_h: make_diff(0x00, 0x00),
            mn_list_diff_at_h_minus_c: make_diff(0x00, 0x00),
            mn_list_diff_at_h_minus_2c: make_diff(0x00, 0x00),
            mn_list_diff_at_h_minus_3c: make_diff(0x00, 0x00),
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c: None,
            mn_list_diff_list: vec![],
            last_commitment_per_index: vec![],
            quorum_snapshot_list: vec![],
        }
    }

    /// `should_process_qrinfo` is the dedup gate at the QRInfo handler entry. It
    /// must:
    /// 1. Drop a response carrying the same `mn_list_diff_tip.block_hash` as the
    ///    last successfully processed one (defends against a late straggler from
    ///    a previous request whose response already won, even when the in-flight
    ///    gate is open for a newer request).
    /// 2. Drop an unsolicited response (no QRInfo currently in flight).
    /// 3. Allow a fresh response that matches the active in-flight request tip.
    /// 4. Drop a response whose tip does not match the active in-flight request
    ///    tip (late straggler from a previous tip whose request was rotated by a
    ///    timeout retry).
    #[test]
    fn test_should_process_qrinfo_dedup_gate() {
        let tip_a = BlockHash::from_slice(&[0xAA; 32]).unwrap();
        let tip_b = BlockHash::from_slice(&[0xBB; 32]).unwrap();
        let in_flight_b = QRInfoInFlight {
            tip: tip_b,
            wait_start: Instant::now(),
        };

        // Same-tip duplicate is dropped even when a request is in flight.
        let state = MasternodeSyncState {
            qrinfo_in_flight: Some(in_flight_b),
            last_processed_qrinfo_tip: Some(tip_a),
            ..Default::default()
        };
        assert!(
            !state.should_process_qrinfo(&qrinfo_with_tip(0xAA)),
            "duplicate of last processed tip must be dropped"
        );

        // Unsolicited response (no request in flight) is dropped, even for a
        // fresh tip.
        let state = MasternodeSyncState::default();
        assert!(state.qrinfo_in_flight.is_none());
        assert!(
            !state.should_process_qrinfo(&qrinfo_with_tip(0xBB)),
            "unsolicited response must be dropped"
        );

        // Response matching the active in-flight tip is accepted.
        let state = MasternodeSyncState {
            qrinfo_in_flight: Some(in_flight_b),
            last_processed_qrinfo_tip: Some(tip_a),
            ..Default::default()
        };
        assert!(
            state.should_process_qrinfo(&qrinfo_with_tip(0xBB)),
            "response matching the active request tip must be accepted"
        );

        // Same-tip dedup wins over the in-flight check: even if the flag has
        // already been cleared (e.g. a sibling response just flipped it), the
        // straggler must not be processed twice.
        let state = MasternodeSyncState {
            qrinfo_in_flight: None,
            last_processed_qrinfo_tip: Some(tip_a),
            ..Default::default()
        };
        assert!(
            !state.should_process_qrinfo(&qrinfo_with_tip(0xAA)),
            "duplicate must be dropped even when no request is in flight"
        );

        // Late straggler from a previous tip whose request was rotated by a
        // timeout retry: the in-flight gate is open for tip B, but tip C
        // arrives. Dropped because the tip does not match the active request.
        let state = MasternodeSyncState {
            qrinfo_in_flight: Some(in_flight_b),
            last_processed_qrinfo_tip: Some(tip_a),
            ..Default::default()
        };
        assert!(
            !state.should_process_qrinfo(&qrinfo_with_tip(0xCC)),
            "response for non-active request tip must be dropped"
        );
    }
}
