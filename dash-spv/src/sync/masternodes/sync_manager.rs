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
                if let Err(e) = engine.feed_qr_info(qr_info.clone(), true, true) {
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

                match engine.apply_diff(diff.clone(), Some(target_height), false, None) {
                    Ok(_) => {
                        self.sync_state.known_mn_list_heights.insert(target_height);
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

#[cfg(test)]
mod tests {
    use super::feed_qrinfo_heights_to_engine;
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
}
