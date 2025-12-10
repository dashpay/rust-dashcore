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
                if let Err(e) = engine.feed_qr_info(
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
                    // Check if this is a tip ChainLock error (h - 0 means the tip block)
                    // The QRInfo response always includes `mn_list_diff_tip` which is the current
                    // chain tip. If the tip was just mined, the ChainLock hasn't propagated yet.
                    let is_tip_chainlock_error = matches!(
                        e,
                        QuorumValidationError::RequiredRotatedChainLockSigNotPresent(0, _)
                    );

                    if is_tip_chainlock_error {
                        self.sync_state.qrinfo_retry_count += 1;

                        if self.sync_state.qrinfo_retry_count <= MAX_RETRY_ATTEMPTS {
                            tracing::info!(
                                "ChainLock not yet available for tip, scheduling retry {}/{} in {}s",
                                self.sync_state.qrinfo_retry_count,
                                MAX_RETRY_ATTEMPTS,
                                CHAINLOCK_RETRY_DELAY_SECS
                            );
                            // Schedule a delayed retry - the tick handler will trigger it
                            self.sync_state.chainlock_retry_after = Some(
                                Instant::now() + Duration::from_secs(CHAINLOCK_RETRY_DELAY_SECS),
                            );
                            drop(engine);
                            self.set_state(SyncState::Syncing);
                            return Ok(vec![]);
                        }
                    }

                    // For other errors or max retries reached, fail
                    tracing::error!(
                        "QRInfo failed after {} retries: {}",
                        self.sync_state.qrinfo_retry_count,
                        e
                    );
                    return Err(SyncError::MasternodeSyncFailed(e.to_string()));
                }

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

                // Queue and send MnListDiff requests via pipeline
                self.sync_state.mnlistdiff_pipeline.queue_requests(request_pairs);
                self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

                // Track last processed block hash
                let block_hash = qr_info.mn_list_diff_h.block_hash;
                self.sync_state.known_block_hashes.insert(block_hash);
                self.sync_state.last_qrinfo_block_hash = Some(block_hash);

                self.progress.bump_last_activity();

                // If no pending requests, complete
                if !self.sync_state.has_pending_requests() {
                    return self.verify_and_complete().await;
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
                            "Height not found for MnListDiff block {}, skipping apply",
                            diff.block_hash
                        );
                        self.sync_state.mnlistdiff_pipeline.receive(diff);
                        return Ok(vec![]);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to get height for MnListDiff block {}: {}, skipping apply",
                            diff.block_hash,
                            e
                        );
                        self.sync_state.mnlistdiff_pipeline.receive(diff);
                        return Ok(vec![]);
                    }
                };
                drop(storage);

                // Apply diff to engine
                let mut engine = self.engine.write().await;
                engine.feed_block_height(target_height, diff.block_hash);

                match engine.apply_diff(diff.clone(), Some(target_height), false, None) {
                    Ok(_) => {
                        self.sync_state.known_mn_list_heights.insert(target_height);
                        self.sync_state.known_block_hashes.insert(diff.block_hash);
                        tracing::debug!("Applied MnListDiff at height {}", target_height);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to apply MnListDiff at height {}: {}",
                            target_height,
                            e
                        );
                    }
                }
                drop(engine);

                self.progress.add_diffs_processed(1);
                self.sync_state.mnlistdiff_pipeline.receive(diff);
                self.sync_state.mnlistdiff_pipeline.send_pending(requests)?;

                // Check if all responses received
                if self.sync_state.mnlistdiff_pipeline.is_complete() {
                    tracing::info!("All MnListDiff responses received");
                    return self.verify_and_complete().await;
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

            // If Synced but behind, trigger incremental update to catch up with new blocks
            if self.state() == SyncState::Synced
                && self.progress.current_height() < self.progress.block_header_tip_height()
            {
                tracing::debug!(
                    "New headers stored (tip: {}), updating masternode list from {}",
                    tip_height,
                    self.progress.current_height()
                );
                self.sync_state.qrinfo_retry_count = 0;
                self.sync_state.clear_pending();
                return self.send_qrinfo_for_tip(requests).await;
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
                // Use debug for incremental updates (when already Synced)
                if self.state() == SyncState::Synced {
                    tracing::debug!(
                        "Headers sync complete at {}, updating masternode list",
                        self.progress.block_header_tip_height()
                    );
                } else {
                    tracing::info!(
                        "Headers sync complete at {}, starting masternode sync",
                        self.progress.block_header_tip_height()
                    );
                }
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

        // If Synced with no pending requests, nothing to do
        if self.state() == SyncState::Synced && !self.sync_state.has_pending_requests() {
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
                        return self.verify_and_complete().await;
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
                return self.verify_and_complete().await;
            }
        }

        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Masternodes(self.progress.clone())
    }
}
