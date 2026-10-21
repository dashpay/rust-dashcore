use super::manager::PipelineMode;
use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::sml_engine::FeedError;
use crate::storage::BlockHeaderStorage;
use crate::sync::{
    ManagerIdentifier, MasternodesManager, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::SyncError;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::sml::error::SmlError;
use std::time::{Duration, Instant};

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

/// How long the manager may sit in `Syncing` with no QRInfo in flight and an empty
/// MnListDiff pipeline before `tick` re-dispatches a QRInfo.
///
/// That combination is a dead state: every retry path in `tick` is armed solely by
/// `qrinfo_in_flight`, so once the slot is empty while `Syncing`, nothing fires
/// again and masternode sync is stranded for the life of the process - which also
/// strands InstantSend verification and every other masternode-list consumer.
///
/// Chosen shorter than the full retry ladder (`sum(QRINFO_TIMEOUT_SCHEDULE_SECS)
/// = 100s`) because the two can never overlap: the ladder only runs while the slot
/// is occupied, the watchdog only while it is empty.
const QRINFO_STALL_WATCHDOG: Duration = Duration::from_secs(60);

/// Whether a diff the engine did not take failed on our own header chain or
/// lists rather than on the response, so the peer that sent it is not to
/// blame.
fn is_local_gap(error: &FeedError<SmlError>) -> bool {
    matches!(
        error,
        FeedError::HeaderStorage(_)
            | FeedError::Refused(
                SmlError::BlockHashLookupFailed(_) | SmlError::MissingStartMasternodeList(_)
            )
    )
}

/// Returns the timeout for the in-flight QRInfo attempt with the given retry count.
///
/// `retry_count == 0` is the initial send; values past the last entry clamp to
/// the slowest schedule slot. `MAX_RETRY_ATTEMPTS` already prevents going past
/// the array, but the clamp is defensive in case the constants drift.
fn qrinfo_timeout_for(retry_count: u8) -> Duration {
    let idx = (retry_count as usize).min(QRINFO_TIMEOUT_SCHEDULE_SECS.len() - 1);
    Duration::from_secs(QRINFO_TIMEOUT_SCHEDULE_SECS[idx])
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

    /// Keep the masternode work across a disconnect and invalidate only the
    /// peer-bound network slots. See `MasternodeSyncState::requeue_in_flight`.
    fn on_disconnect(&mut self) {
        self.sync_state.requeue_in_flight();
        // A fresh peer set earns a fresh retry budget, and the dedup guard must not
        // reject a response for a tip whose earlier attempt died with the old peer.
        self.sync_state.qrinfo_retry_count = 0;
        self.sync_state.last_processed_qrinfo_tip = None;
        // Nor do the refusals of the old peers count against the new ones.
        self.sync_state.mnlistdiff_pipeline.forget_attempts();
        self.sync_state.forget_qrinfo_refusers();
        self.sync_state.given_up_tip = None;
    }

    fn on_peer_disconnect(&mut self) {
        // The QRInfo request is tracked outside the pipeline with its own
        // escalating timeout and attempt budget, so it is left to that path.
        self.sync_state.requeue_in_flight();
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
                let peer = msg.peer_address();
                if self.sync_state.has_refused_qrinfo(qr_info.mn_list_diff_tip.block_hash, peer) {
                    tracing::debug!(
                        "Ignoring QRInfo from {peer}, whose earlier one for this tip was rejected"
                    );
                    return Ok(vec![]);
                }
                tracing::info!("Processing QRInfo message");

                let mut engine = self.engine.write().await;
                let qr_info_result = match engine.feed_qr_info((**qr_info).clone()).await {
                    Ok(qr_info_result) => qr_info_result,
                    Err(e) => {
                        tracing::error!("QRInfo feed into engine failed: {}", e);
                        drop(engine);
                        // The response is unusable, but the request slot has to stay
                        // occupied. It is the only thing arming `tick`'s retry
                        // ladder, so releasing it here - as this handler used to,
                        // before the fallible steps - leaves the manager `Syncing`
                        // with no QRInfo in flight and an empty diff pipeline, a
                        // combination `tick` has no branch for. Masternode sync then
                        // never resumes for the life of the process, taking
                        // InstantSend verification and every other masternode-list
                        // consumer with it. Flag the attempt instead: `tick` rotates
                        // to the next peer, and the existing budget still gives up on
                        // a deterministically-bad response after MAX_RETRY_ATTEMPTS.
                        // The retries avoid this peer. The blocks a QRInfo
                        // names are the peer's choice, so even one our header
                        // chain does not hold counts against it. Our header
                        // storage failing to read does not, and the peer's
                        // next QRInfo for the tip is processed.
                        if let FeedError::Refused(_) = e {
                            self.sync_state.qrinfo_refused_by(peer);
                        }
                        self.sync_state.qrinfo_rejected();
                        return Err(SyncError::MasternodeSyncFailed(e.to_string()));
                    }
                };

                let request_pairs = engine.readable_missing_work_block_list_requests().await;
                let tip_height = engine.height_if_known(&qr_info.mn_list_diff_tip.block_hash).await;
                drop(engine);

                if let Some(height) = tip_height {
                    if let Err(e) = self.store_qr_info(height, qr_info).await {
                        tracing::warn!(
                            "Could not store QRInfo at {height}, a restart syncs it again: {e}"
                        );
                    }
                }

                tracing::info!(
                    "QRInfo processed: stored_cycle_height={:?}, rotated_quorum_count={}/{}, fully_verified_count={}",
                    qr_info_result.stored_cycle_height,
                    qr_info_result.rotated_quorum_count,
                    qr_info_result.expected_rotated_quorum_count,
                    qr_info_result.fully_verified_count,
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

                // The historical diffs that follow a QRInfo run under QuorumValidation.
                // Carry the result on the mode so `complete_pipeline` can pass it
                // into the resulting `MasternodeStateUpdated` event.
                self.sync_state.pipeline_mode = PipelineMode::QuorumValidation {
                    qr_info_result: Some(qr_info_result),
                };

                // Every fallible step has now succeeded, so the request slot can
                // finally be released. This must happen before the
                // `has_pending_requests` check below, which reads it.
                //
                // Only now record the processed tip for `should_process_qrinfo`'s
                // dedup gate. Recording it any earlier - between fallible steps -
                // turns the gate against the retry ladder: the slot stays armed
                // after the error, but every retried response for the same tip is
                // dropped at the handler entry, so the budget burns down with no
                // way to succeed. A straggler can only arrive after this handler
                // returns, so deferring the record loses nothing.
                self.sync_state.last_processed_qrinfo_tip =
                    Some(qr_info.mn_list_diff_tip.block_hash);
                self.sync_state.qrinfo_received();
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
                    tracing::debug!(
                        "Received unexpected MnListDiff for {} from {}",
                        diff.block_hash,
                        diff.base_block_hash
                    );
                    return Ok(vec![]);
                }
                let peer = msg.peer_address();
                if self.sync_state.mnlistdiff_pipeline.has_refused(diff.block_hash, peer) {
                    tracing::debug!(
                        "Ignoring MnListDiff for {} from {peer}, whose earlier one was refused",
                        diff.block_hash
                    );
                    return Ok(vec![]);
                }

                tracing::debug!("Processing MnListDiff message for {}", diff.block_hash);

                let mut engine = self.engine.write().await;
                // Only a tip update builds on the newest list. The work-block
                // lists it may ask for below build on older ones.
                let extends_tip = engine
                    .latest_masternode_list()
                    .is_some_and(|list| list.block_hash == diff.base_block_hash);
                let Some(target_height) = engine.height_if_known(&diff.block_hash).await else {
                    drop(engine);
                    tracing::warn!(
                        "Height not found for MnListDiff block {}, asking again",
                        diff.block_hash
                    );
                    return self
                        .retry_or_give_up(diff.block_hash, None, extends_tip, requests)
                        .await;
                };
                if let Err(e) = engine.apply_diff((**diff).clone()).await {
                    drop(engine);
                    tracing::warn!(
                        "Failed to apply MnListDiff at height {} from {peer}: {}",
                        target_height,
                        e
                    );
                    let refused_by = (!is_local_gap(&e)).then_some(peer);
                    return self
                        .retry_or_give_up(diff.block_hash, refused_by, extends_tip, requests)
                        .await;
                }
                tracing::debug!("Applied MnListDiff at height {}", target_height);
                // A tip update can bring a quorum whose work block lies below
                // every list the engine built since its last QRInfo, as the
                // first quorum after a start does. Fetch those lists now, as
                // the QRInfo path does, instead of leaving the quorum
                // `Skipped(MissedList)` until the next QRInfo, a rotation cycle
                // later. The pipeline completes only once they are applied.
                // The work-block lists given up before are asked for again
                // with each tip update, those a quorum still needs, from the
                // nearest list the engine still holds.
                let mut work_block_lists = Vec::new();
                if extends_tip {
                    work_block_lists = engine.missing_work_block_list_requests_for(diff).await;
                    let given_up = std::mem::take(&mut self.sync_state.given_up_work_lists);
                    if !given_up.is_empty() {
                        let still_needed =
                            engine.missing_work_block_list_requests().await.unwrap_or_else(|e| {
                                tracing::warn!(
                                    "Could not read the header chain for the work-block lists \
                                     given up: {e}"
                                );
                                Vec::new()
                            });
                        for (base, target) in still_needed {
                            if given_up.contains(&target)
                                && !work_block_lists.iter().any(|(_, asked)| *asked == target)
                            {
                                work_block_lists.push((base, target));
                            }
                        }
                    }
                }
                drop(engine);

                if let Err(e) = self.store_diff(target_height, diff).await {
                    tracing::warn!(
                        "Could not store MnListDiff at {target_height}, a restart syncs it \
                         again: {e}"
                    );
                }

                self.progress.add_diffs_processed(1);
                self.sync_state.mnlistdiff_pipeline.receive(diff);
                if !work_block_lists.is_empty() {
                    self.sync_state.mnlistdiff_pipeline.queue_requests(work_block_lists);
                }
                return self.continue_diff_pipeline(false, requests).await;
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
            // A tip update given up waits for the next block, so the mode
            // selector below is not consulted, and does not log, on every tick.
            if self.progress.current_height() < self.progress.block_header_tip_height()
                && !self.tip_update_given_up().await
            {
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

        // Check for a QRInfo attempt that is over: either the peer never answered
        // (timeout), or it answered with something the engine rejected. Both
        // consumed an attempt without producing any state, so both retry against
        // the next peer on the same budget. A rejected response skips the
        // remaining timeout - that peer has already had its turn.
        if let Some(in_flight) = self.sync_state.qrinfo_in_flight {
            let timeout = qrinfo_timeout_for(self.sync_state.qrinfo_retry_count);
            let timed_out = in_flight.wait_start.elapsed() > timeout;
            if timed_out || in_flight.rejected {
                if self.sync_state.qrinfo_retry_count < MAX_RETRY_ATTEMPTS - 1 {
                    if in_flight.rejected {
                        tracing::warn!(
                            retry_count = self.sync_state.qrinfo_retry_count,
                            "QRInfo response rejected by the engine, retrying against another peer..."
                        );
                    } else {
                        tracing::warn!(
                            timeout_secs = timeout.as_secs(),
                            retry_count = self.sync_state.qrinfo_retry_count,
                            "Timeout waiting for QRInfo response, retrying..."
                        );
                    }
                    self.sync_state.qrinfo_retry_count += 1;
                    self.sync_state.clear_pending();
                    return self.send_qrinfo_for_tip(requests).await;
                } else {
                    tracing::warn!(
                        attempts = MAX_RETRY_ATTEMPTS,
                        last_attempt_rejected = in_flight.rejected,
                        "QRInfo failed on every attempt, skipping masternode sync"
                    );
                    self.sync_state.clear_pending();
                    return self.complete_pipeline(requests).await;
                }
            }
            return Ok(vec![]);
        }

        // Check for MnListDiff timeouts via pipeline. Gate on outstanding work
        // rather than in-flight requests: a peer disconnect requeues in-flight
        // items as pending, and this send is the only path that reissues them.
        if !self.sync_state.mnlistdiff_pipeline.is_complete() {
            let given_up = self.sync_state.mnlistdiff_pipeline.handle_timeouts();
            let mut gave_up_tip_update = false;
            if !given_up.is_empty() {
                let newest =
                    self.engine.read().await.latest_masternode_list().map(|list| list.block_hash);
                for (base, target) in given_up {
                    tracing::warn!(
                        "Giving up on the MnListDiff for {target}: its last attempt timed \
                         out or its lifetime ran out"
                    );
                    self.progress.add_diffs_processed(1);
                    if Some(base) == newest {
                        gave_up_tip_update = true;
                        self.sync_state.given_up_tip = Some(target);
                    } else {
                        self.sync_state.given_up_work_lists.insert(target);
                    }
                }
            }
            return self.continue_diff_pipeline(gave_up_tip_update, requests).await;
        }

        // Stall watchdog. `Syncing` with no QRInfo in flight and an empty diff
        // pipeline is a dead state: nothing outstanding will ever call back, and
        // every branch above is gated on one of those two, so no code path can move
        // this manager again. The known routes in are `send_qrinfo_for_tip`'s early
        // returns - no stored tip, or a tip at genesis - which return `Ok` without
        // dispatching after the caller has already cleared the slot. (A peerless
        // send is not such a route: `request_qr_info` pushes onto an unbounded
        // channel and only errors once the channel is closed, so it fails later in
        // the network task with the slot still armed for the timeout ladder.) The
        // watchdog also covers any future path that drops the slot without
        // dispatching. It cannot race the retry ladder above, which only runs
        // while the slot is occupied.
        if self.state() == SyncState::Syncing
            && self.sync_state.qrinfo_in_flight.is_none()
            && self.sync_state.mnlistdiff_pipeline.is_complete()
            && self
                .sync_state
                .last_qrinfo_dispatch
                .is_some_and(|dispatched| dispatched.elapsed() > QRINFO_STALL_WATCHDOG)
        {
            tracing::warn!(
                stalled_for_secs = self
                    .sync_state
                    .last_qrinfo_dispatch
                    .map(|d| d.elapsed().as_secs())
                    .unwrap_or_default(),
                "Masternode sync stalled in Syncing with nothing in flight, re-dispatching QRInfo"
            );
            // Re-stamp before dispatching so a dispatch that returns without
            // sending (no stored tip, tip at genesis) re-arms the watchdog for
            // another full interval instead of retrying on every 100ms tick.
            self.sync_state.last_qrinfo_dispatch = Some(Instant::now());
            self.sync_state.qrinfo_retry_count = 0;
            self.sync_state.clear_pending();
            return self.send_qrinfo_for_tip(requests).await;
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
    use super::super::pipeline::{Attempt, MAX_MNLISTDIFF_ATTEMPTS};
    use super::{
        qrinfo_timeout_for, MAX_RETRY_ATTEMPTS, QRINFO_STALL_WATCHDOG, QRINFO_TIMEOUT_SCHEDULE_SECS,
    };
    use crate::error::{StorageError, StorageResult};
    use crate::network::{Message, NetworkRequest, RequestSender};
    use crate::sml_engine::test_support::quorum_entry;
    use crate::sml_engine::{MasternodeListEngine, QRInfoFeedResult};
    use crate::storage::{
        BlockHeaderStorage, BlockHeaderTip, DiskStorageManager, PersistentBlockHeaderStorage,
        PersistentStorage, StorageManager,
    };
    use crate::sync::{MasternodesManager, SyncEvent, SyncManager, SyncState};
    use crate::test_utils::test_socket_address;
    use crate::types::HashedBlockHeader;
    use crate::{ClientConfig, SyncError};
    use dashcore::block::Header;
    use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_qrinfo::QRInfo;
    use dashcore::network::message_sml::{
        DeletedQuorum, GetMnListDiff, MnListDiff, QuorumCLSigObject,
    };
    use dashcore::sml::llmq_entry_verification::{
        LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
    };
    use dashcore::sml::llmq_type::{LLMQType, QUORUM_MEMBER_LIST_OFFSET};
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
    use dashcore::{BlockHash, Network, QuorumHash};
    use dashcore_hashes::Hash;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;
    use test_case::test_case;
    use tokio::sync::{mpsc, RwLock};

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
            rejected: false,
        };

        // Same-tip duplicate is dropped even when a request is in flight.
        let state = MasternodeSyncState {
            qrinfo_in_flight: Some(in_flight_b),
            last_processed_qrinfo_tip: Some(tip_a),
            ..Default::default()
        };
        assert!(
            !state.should_process_qrinfo(&QRInfo::dummy(0xAA)),
            "duplicate of last processed tip must be dropped"
        );

        // Unsolicited response (no request in flight) is dropped, even for a
        // fresh tip.
        let state = MasternodeSyncState::default();
        assert!(state.qrinfo_in_flight.is_none());
        assert!(
            !state.should_process_qrinfo(&QRInfo::dummy(0xBB)),
            "unsolicited response must be dropped"
        );

        // Response matching the active in-flight tip is accepted.
        let state = MasternodeSyncState {
            qrinfo_in_flight: Some(in_flight_b),
            last_processed_qrinfo_tip: Some(tip_a),
            ..Default::default()
        };
        assert!(
            state.should_process_qrinfo(&QRInfo::dummy(0xBB)),
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
            !state.should_process_qrinfo(&QRInfo::dummy(0xAA)),
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
            !state.should_process_qrinfo(&QRInfo::dummy(0xCC)),
            "response for non-active request tip must be dropped"
        );
    }

    /// [`QRInfo::dummy`] aimed at whatever tip a live manager actually requested.
    fn qrinfo_with_tip_hash(tip: BlockHash) -> QRInfo {
        let mut qr_info = QRInfo::dummy(0x00);
        qr_info.mn_list_diff_tip.block_hash = tip;
        qr_info
    }

    type TestMasternodesManager = MasternodesManager<PersistentBlockHeaderStorage>;

    /// Build a regtest manager whose header storage holds dummy headers up to
    /// `tip`, then fire the initial QRInfo so it sits in `Syncing` with a real
    /// in-flight request, exactly as a fresh wallet does once headers catch up.
    ///
    /// Returns the manager, the `RequestSender`, the matching receiver (the caller
    /// must bind it - the channel closes when it drops), and the tip hash the
    /// in-flight request was made for. A response has to echo that hash to get
    /// past `should_process_qrinfo`. The initial `GetQRInfo` is drained from the
    /// receiver so callers only see what they trigger themselves.
    async fn syncing_manager_awaiting_qrinfo(
        tip: u32,
    ) -> (TestMasternodesManager, RequestSender, mpsc::UnboundedReceiver<NetworkRequest>, BlockHash)
    {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let block_headers = storage.block_headers();
        block_headers
            .write()
            .await
            .store_headers(
                &Header::dummy_batch(0..tip + 1)
                    .iter()
                    .map(HashedBlockHeader::from)
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        let engine = MasternodeListEngine::new(Network::Regtest, Arc::clone(&block_headers));
        let mut manager = MasternodesManager::new(
            block_headers,
            Arc::new(RwLock::new(engine)),
            Network::Regtest,
            None,
        )
        .await;
        manager.progress.update_block_header_tip_height(tip);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let requests = RequestSender::new(tx);
        manager.send_qrinfo_for_tip(&requests).await.expect("initial QRInfo dispatch succeeds");
        assert_eq!(manager.state(), SyncState::Syncing);
        let tip_hash = manager.sync_state.qrinfo_in_flight.expect("QRInfo in flight").tip;
        rx.try_recv().expect("initial GetQRInfo is queued");
        (manager, requests, rx, tip_hash)
    }

    /// Diffs are stored only until the sync reaches the tip. Once synced,
    /// nothing is, and the next start catches up from the last stored message.
    #[test_case(SyncState::Syncing, true; "while syncing")]
    #[test_case(SyncState::Synced, false; "once synced")]
    #[tokio::test]
    async fn a_diff_is_stored_only_until_the_sync_reaches_the_tip(state: SyncState, stored: bool) {
        let dir = tempfile::TempDir::new().unwrap();
        let storage =
            DiskStorageManager::new(&ClientConfig::testnet().with_storage_path(dir.path()))
                .await
                .unwrap();
        let (mut manager, engine, requests, _rx, hashes) =
            manager_after_a_tip_update_request(&storage, true, |hashes| {
                vec![MasternodeList::empty(hashes[TIP as usize], TIP)]
            })
            .await;
        manager.set_state(state);

        let diff = MnListDiff {
            base_block_hash: hashes[TIP as usize],
            block_hash: hashes[TIP as usize + 1],
            ..MnListDiff::dummy_between(0, 0)
        };
        deliver(&mut manager, &requests, diff).await;

        assert!(engine.read().await.masternode_lists.contains_key(&(TIP + 1)));
        let file = dir.path().join("masternodes").join(format!("diff_{}.dat", TIP + 1));
        assert_eq!(file.exists(), stored);
    }

    /// A synced manager over `storage`, whose header chain runs to `TIP + 1`
    /// and whose engine holds the lists `lists` builds from the block hashes,
    /// once it sent the tip update from `TIP` to `TIP + 1`. With
    /// `store_diffs`, it stores diffs in `storage`. Returns the manager, its
    /// engine, the request channel, and the block hash at each height.
    async fn manager_after_a_tip_update_request(
        storage: &DiskStorageManager,
        store_diffs: bool,
        lists: impl FnOnce(&[BlockHash]) -> Vec<MasternodeList>,
    ) -> (
        MasternodesManager<PersistentBlockHeaderStorage>,
        Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>,
        RequestSender,
        mpsc::UnboundedReceiver<NetworkRequest>,
        Vec<BlockHash>,
    ) {
        let headers = Header::dummy_batch(0..TIP + 2);
        let block_headers = storage.block_headers();
        block_headers
            .write()
            .await
            .store_headers(&headers.iter().map(HashedBlockHeader::from).collect::<Vec<_>>())
            .await
            .unwrap();
        let hashes: Vec<BlockHash> = headers.iter().map(|header| header.block_hash()).collect();
        let mut engine = MasternodeListEngine::new(Network::Regtest, Arc::clone(&block_headers));
        for list in lists(&hashes) {
            engine.masternode_lists.insert(list.known_height, list);
        }
        let engine = Arc::new(RwLock::new(engine));
        let mut manager = MasternodesManager::new(
            block_headers,
            Arc::clone(&engine),
            Network::Regtest,
            store_diffs.then(|| storage.masternodes()),
        )
        .await;
        manager.set_state(SyncState::Synced);
        manager.progress.update_block_header_tip_height(TIP + 1);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let requests = RequestSender::new(tx);
        manager.send_tip_mnlistdiff_update(&requests).await.unwrap();
        rx.try_recv().expect("the tip update is sent");
        (manager, engine, requests, rx, hashes)
    }

    /// A synced manager that sent a tip update from `TIP` to `TIP + 1`, whose
    /// response brings a non-rotating quorum mined at `MINED`. The base list
    /// already holds an older unverified quorum mined at `OLD_MINED`, and the
    /// engine holds no list at either quorum's work block, only one at
    /// `OLDER`. Returns the manager, its engine, the request channel, the
    /// response, and the block hash at each height.
    async fn manager_awaiting_a_tip_update_with_a_new_quorum() -> (
        MasternodesManager<PersistentBlockHeaderStorage>,
        Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>,
        RequestSender,
        mpsc::UnboundedReceiver<NetworkRequest>,
        MnListDiff,
        Vec<BlockHash>,
    ) {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let (manager, engine, requests, rx, hashes) =
            manager_after_a_tip_update_request(&storage, false, |hashes| {
                let old = Arc::new(test_quorum(hashes[OLD_MINED as usize]).into());
                let quorums = BTreeMap::from([(
                    LLMQType::LlmqtypeTest,
                    BTreeMap::from([(quorum_hash_at(hashes, OLD_MINED), old)]),
                )]);
                vec![
                    MasternodeList::empty(hashes[OLDER as usize], OLDER),
                    MasternodeList::build(BTreeMap::new(), quorums, hashes[TIP as usize], TIP)
                        .build(),
                ]
            })
            .await;

        let tip_update = MnListDiff {
            base_block_hash: hashes[TIP as usize],
            block_hash: hashes[TIP as usize + 1],
            new_quorums: vec![test_quorum(hashes[MINED as usize])],
            quorums_chainlock_signatures: vec![QuorumCLSigObject {
                signature: BLSSignature::from([2; 96]),
                index_set: vec![0],
            }],
            ..MnListDiff::dummy_between(0, 0)
        };
        (manager, engine, requests, rx, tip_update, hashes)
    }

    const OLDER: u32 = 70;
    const OLD_MINED: u32 = 84;
    const MINED: u32 = 96;
    const TIP: u32 = 100;

    fn test_quorum(mined_in: BlockHash) -> QuorumEntry {
        QuorumEntry {
            version: 1,
            signers: vec![true; 3],
            valid_members: vec![true; 3],
            quorum_public_key: BLSPublicKey::from([1; 48]),
            threshold_sig: BLSSignature::from([1; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([1; 96]),
            ..quorum_entry(
                LLMQType::LlmqtypeTest,
                QuorumHash::from_byte_array(mined_in.to_byte_array()),
                None,
            )
        }
    }

    fn quorum_hash_at(hashes: &[BlockHash], height: u32) -> QuorumHash {
        QuorumHash::from_byte_array(hashes[height as usize].to_byte_array())
    }

    /// The work-block list request the manager sent next, if any.
    fn next_diff_request(
        rx: &mut mpsc::UnboundedReceiver<NetworkRequest>,
    ) -> Option<(BlockHash, BlockHash)> {
        next_diff_request_avoiding(rx).map(|(request, _)| request)
    }

    /// [`next_diff_request`] with the peers it asks to avoid.
    fn next_diff_request_avoiding(
        rx: &mut mpsc::UnboundedReceiver<NetworkRequest>,
    ) -> Option<((BlockHash, BlockHash), Vec<SocketAddr>)> {
        let (message, avoided) = match rx.try_recv() {
            Ok(NetworkRequest::SendMessage(message)) => (message, Vec::new()),
            Ok(NetworkRequest::SendMessageAvoiding(message, avoided)) => (message, avoided),
            _ => return None,
        };
        match message {
            NetworkMessage::GetMnListD(GetMnListDiff {
                base_block_hash,
                block_hash,
            }) => Some(((base_block_hash, block_hash), avoided)),
            _ => None,
        }
    }

    fn peer(id: u8) -> SocketAddr {
        test_socket_address(id)
    }

    async fn deliver(
        manager: &mut MasternodesManager<PersistentBlockHeaderStorage>,
        requests: &RequestSender,
        diff: MnListDiff,
    ) -> Vec<SyncEvent> {
        deliver_from(manager, requests, peer(1), diff).await
    }

    async fn deliver_from(
        manager: &mut MasternodesManager<PersistentBlockHeaderStorage>,
        requests: &RequestSender,
        peer: SocketAddr,
        diff: MnListDiff,
    ) -> Vec<SyncEvent> {
        manager
            .handle_message(
                Message::new(peer, NetworkMessage::MnListDiff(Box::new(diff))),
                requests,
            )
            .await
            .unwrap()
    }

    /// A tip update that brings a non-rotating quorum it cannot verify for
    /// want of the work-block list fetches that list before the update
    /// completes, instead of leaving the quorum `Skipped(MissedList)` until the
    /// next QRInfo. This is the first quorum mined after a start: its work
    /// block lies below every list the engine built since its QRInfo. A quorum
    /// the update did not bring is left to the QRInfo path.
    #[tokio::test]
    async fn a_tip_update_fetches_the_work_block_list_of_a_quorum_it_brings() {
        let (mut manager, engine, requests, mut rx, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let work = MINED - QUORUM_MEMBER_LIST_OFFSET;

        let events = deliver(&mut manager, &requests, tip_update).await;

        assert_eq!(
            engine.read().await.latest_masternode_list().unwrap().quorums[&LLMQType::LlmqtypeTest]
                [&quorum_hash_at(&hashes, MINED)]
                .verified,
            LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(work)),
            "the tip list cannot verify the quorum without its work-block list"
        );
        assert!(events.is_empty(), "the update must not complete before the work-block list");
        let request = next_diff_request(&mut rx);
        assert_eq!(
            request,
            Some((hashes[OLDER as usize], hashes[work as usize])),
            "the tip update must ask for the new quorum's work-block list"
        );
        assert_eq!(next_diff_request(&mut rx), None, "the older quorum is not asked for");

        let (base_block_hash, block_hash) = request.unwrap();
        let work_list = MnListDiff {
            base_block_hash,
            block_hash,
            ..MnListDiff::dummy_between(0, 0)
        };
        let events = deliver(&mut manager, &requests, work_list).await;

        let engine = engine.read().await;
        let status = &engine.latest_masternode_list().unwrap().quorums[&LLMQType::LlmqtypeTest]
            [&quorum_hash_at(&hashes, MINED)]
            .verified;
        assert!(
            matches!(
                status,
                LLMQEntryVerificationStatus::Verified | LLMQEntryVerificationStatus::Invalid(_)
            ),
            "the quorum is checked again against its work-block list, got {status:?}"
        );
        assert!(
            engine.masternode_lists.contains_key(&work),
            "the work-block list is kept until it ages out, whatever the verdict"
        );
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "the update completes at the tip once the work-block list is applied, got {events:?}"
        );
        assert!(rx.try_recv().is_err(), "nothing more to fetch");
    }

    /// A tip update the engine refuses leaves the state unchanged and is asked
    /// again from a peer that has not refused it. The same peer refusing again
    /// spends nothing. Once three peers refused it, it is given up without
    /// publishing anything or asking for a work-block list.
    #[tokio::test]
    async fn a_refused_tip_update_is_retried_on_other_peers_then_given_up() {
        let (mut manager, engine, requests, mut rx, tip_update, _hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let refused = MnListDiff {
            // A new quorum needs a ChainLock signature to be applied.
            quorums_chainlock_signatures: Vec::new(),
            ..tip_update
        };

        let events = deliver_from(&mut manager, &requests, peer(1), refused.clone()).await;
        assert!(events.is_empty(), "a refused tip update must not complete, got {events:?}");
        assert_eq!(
            next_diff_request_avoiding(&mut rx).map(|(_, avoided)| avoided),
            Some(vec![peer(1)]),
            "the retry avoids the refusing peer"
        );

        deliver_from(&mut manager, &requests, peer(1), refused.clone()).await;
        assert!(rx.try_recv().is_err(), "a repeat refusal from the same peer spends nothing");

        deliver_from(&mut manager, &requests, peer(2), refused.clone()).await;
        assert_eq!(
            next_diff_request_avoiding(&mut rx).map(|(_, avoided)| avoided),
            Some(vec![peer(1), peer(2)])
        );

        let events = deliver_from(&mut manager, &requests, peer(3), refused).await;
        assert!(events.is_empty(), "a given-up tip update must not complete, got {events:?}");
        assert!(rx.try_recv().is_err(), "a given-up tip update asks for nothing more");
        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());
        assert_eq!(engine.read().await.latest_masternode_list().unwrap().known_height, TIP);
    }

    /// A tip update given up is not asked for again, which the `Synced` tick
    /// would do every 100 ms for as long as the header tip stays put. The next
    /// header tip is asked for as usual.
    #[tokio::test]
    async fn a_given_up_tip_update_is_not_asked_again_until_the_tip_moves() {
        let (mut manager, _engine, requests, mut rx, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let refused = MnListDiff {
            quorums_chainlock_signatures: Vec::new(),
            ..tip_update
        };
        for refusing in [peer(1), peer(2), peer(3)] {
            deliver_from(&mut manager, &requests, refusing, refused.clone()).await;
        }
        while rx.try_recv().is_ok() {}

        manager.send_tip_mnlistdiff_update(&requests).await.expect("nothing to send");
        for _ in 0..5 {
            manager.tick(&requests).await.expect("tick succeeds");
        }
        assert!(rx.try_recv().is_err(), "the given-up tip update is not asked again");

        let next_tip = Header::dummy(TIP + 2);
        manager
            .header_storage
            .write()
            .await
            .store_headers(&[HashedBlockHeader::from(&next_tip)])
            .await
            .unwrap();
        manager.progress.update_block_header_tip_height(TIP + 2);
        manager.tick(&requests).await.expect("tick succeeds");
        assert_eq!(
            next_diff_request(&mut rx),
            Some((hashes[TIP as usize], next_tip.block_hash())),
            "the next header tip is asked for"
        );
    }

    /// A tip update no peer answers is given up after three timeouts like one
    /// three peers refused: it publishes nothing and waits for the next tip.
    #[tokio::test]
    async fn a_tip_update_no_peer_answers_is_given_up_until_the_tip_moves() {
        let (mut manager, engine, requests, mut rx, _tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        manager.sync_state.mnlistdiff_pipeline.set_timeout(Duration::from_millis(1));

        for attempt in 1..=3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let events = manager.tick(&requests).await.expect("tick succeeds");
            assert!(events.is_empty(), "a tip update no peer answers publishes nothing");
            assert_eq!(next_diff_request(&mut rx).is_some(), attempt < 3, "attempt {attempt}");
        }

        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());
        assert_eq!(manager.sync_state.given_up_tip, Some(hashes[TIP as usize + 1]));
        manager.tick(&requests).await.expect("tick succeeds");
        assert!(rx.try_recv().is_err(), "the given-up tip update is not asked again");
        assert_eq!(engine.read().await.latest_masternode_list().unwrap().known_height, TIP);
    }

    /// A peer dropping before the request times out spends no attempt of it,
    /// so the request goes to another peer at once. Peers dropping one after
    /// another still cannot keep the target in flight, and every tip update
    /// and QRInfo behind it waiting, for longer than its attempts take when
    /// each one times out.
    #[tokio::test]
    async fn a_tip_update_whose_peers_keep_dropping_is_given_up_within_its_lifetime() {
        let (mut manager, engine, requests, mut rx, _tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let lifetime = Duration::from_millis(300);
        manager.sync_state.mnlistdiff_pipeline.set_lifetime(lifetime);
        let started = Instant::now();

        let mut sends = 1;
        while !manager.sync_state.mnlistdiff_pipeline.is_complete() {
            assert!(
                started.elapsed() < lifetime * 10,
                "sent {sends} times and still not given up after {:?}",
                started.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
            manager.on_peer_disconnect();
            let events = manager.tick(&requests).await.expect("tick succeeds");
            assert!(events.is_empty(), "a tip update no peer answers publishes nothing");
            sends += usize::from(next_diff_request(&mut rx).is_some());
        }

        assert!(
            sends > MAX_MNLISTDIFF_ATTEMPTS as usize,
            "a dropping peer spends no attempt, sent only {sends} times"
        );
        assert_eq!(manager.sync_state.given_up_tip, Some(hashes[TIP as usize + 1]));
        manager.tick(&requests).await.expect("tick succeeds");
        assert!(rx.try_recv().is_err(), "the given-up tip update is not asked again");
        assert_eq!(engine.read().await.latest_masternode_list().unwrap().known_height, TIP);
    }

    /// A work-block list given up after three refusing peers leaves the tip
    /// update it was fetched for applied, so the update completes.
    #[tokio::test]
    async fn a_tip_update_completes_when_its_work_block_list_is_given_up() {
        let (mut manager, _engine, requests, mut rx, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        deliver(&mut manager, &requests, tip_update).await;
        let (base_block_hash, block_hash) =
            next_diff_request(&mut rx).expect("the work-block list is asked for");

        let unusable = MnListDiff {
            base_block_hash,
            block_hash,
            // A new quorum without its ChainLock signature is refused.
            new_quorums: vec![test_quorum(hashes[MINED as usize])],
            ..MnListDiff::dummy_between(0, 0)
        };
        for refusing in [peer(1), peer(2)] {
            let events = deliver_from(&mut manager, &requests, refusing, unusable.clone()).await;
            assert!(events.is_empty(), "the work-block list is still asked for");
            assert!(next_diff_request(&mut rx).is_some());
        }
        let events = deliver_from(&mut manager, &requests, peer(3), unusable).await;

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "a given-up work-block list must not hold back the tip update, got {events:?}"
        );
    }

    /// Gives up the work-block list the tip update to `TIP + 1` asks for,
    /// after three timeouts or three refusing peers, then has the header tip
    /// move to `TIP + 2` and returns the tip update to it, which brings no
    /// quorum.
    async fn give_up_the_work_block_list_then_move_the_tip(
        manager: &mut MasternodesManager<PersistentBlockHeaderStorage>,
        requests: &RequestSender,
        rx: &mut mpsc::UnboundedReceiver<NetworkRequest>,
        tip_update: MnListDiff,
        hashes: &[BlockHash],
        by_timeouts: bool,
    ) -> MnListDiff {
        deliver(manager, requests, tip_update).await;
        let (base_block_hash, block_hash) =
            next_diff_request(rx).expect("the work-block list is asked for");
        let mut events = Vec::new();
        if by_timeouts {
            manager.sync_state.mnlistdiff_pipeline.set_timeout(Duration::from_millis(1));
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                events = manager.tick(requests).await.expect("tick succeeds");
            }
            manager.sync_state.mnlistdiff_pipeline.set_timeout(Duration::from_secs(15));
        } else {
            let unusable = MnListDiff {
                base_block_hash,
                block_hash,
                new_quorums: vec![test_quorum(hashes[MINED as usize])],
                ..MnListDiff::dummy_between(0, 0)
            };
            for refusing in [peer(1), peer(2), peer(3)] {
                events = deliver_from(manager, requests, refusing, unusable.clone()).await;
            }
        }
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "the tip update completes without its work-block list, got {events:?}"
        );
        while rx.try_recv().is_ok() {}
        for _ in 0..3 {
            manager.tick(requests).await.expect("tick succeeds");
        }
        assert!(rx.try_recv().is_err(), "no tick asks for the work-block list again");

        let next_tip = Header::dummy(TIP + 2);
        manager
            .header_storage
            .write()
            .await
            .store_headers(&[HashedBlockHeader::from(&next_tip)])
            .await
            .unwrap();
        manager.progress.update_block_header_tip_height(TIP + 2);
        manager.tick(requests).await.expect("tick succeeds");
        assert_eq!(
            next_diff_request(rx),
            Some((hashes[TIP as usize + 1], next_tip.block_hash())),
            "the next header tip is asked for"
        );
        MnListDiff {
            base_block_hash: hashes[TIP as usize + 1],
            block_hash: next_tip.block_hash(),
            ..MnListDiff::dummy_between(0, 0)
        }
    }

    /// A work-block list no peer answered is given up, and asked for again,
    /// with fresh attempts, along with the next tip update, though that update
    /// does not bring the quorum needing it again. Otherwise the quorum would
    /// stay `Skipped(MissedList)` until the next QRInfo, a rotation cycle
    /// later.
    #[tokio::test]
    async fn a_given_up_work_block_list_is_asked_again_with_the_next_tip_update() {
        let (mut manager, engine, requests, mut rx, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let work = MINED - QUORUM_MEMBER_LIST_OFFSET;
        let next_tip_update = give_up_the_work_block_list_then_move_the_tip(
            &mut manager,
            &requests,
            &mut rx,
            tip_update,
            &hashes,
            true,
        )
        .await;

        let events = deliver(&mut manager, &requests, next_tip_update).await;

        assert!(events.is_empty(), "the update waits for the work-block list, got {events:?}");
        let request = next_diff_request_avoiding(&mut rx);
        assert_eq!(
            request,
            Some(((hashes[OLDER as usize], hashes[work as usize]), vec![])),
            "the work-block list is asked for again, from the list below it, avoiding no one"
        );
        let ((base_block_hash, block_hash), _) = request.unwrap();
        let work_list = MnListDiff {
            base_block_hash,
            block_hash,
            ..MnListDiff::dummy_between(0, 0)
        };
        let events = deliver(&mut manager, &requests, work_list).await;

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 2
            ),
            "the update completes once the work-block list is applied, got {events:?}"
        );
        let engine = engine.read().await;
        let status = &engine.latest_masternode_list().unwrap().quorums[&LLMQType::LlmqtypeTest]
            [&quorum_hash_at(&hashes, MINED)]
            .verified;
        assert!(
            matches!(
                status,
                LLMQEntryVerificationStatus::Verified | LLMQEntryVerificationStatus::Invalid(_)
            ),
            "the quorum is checked against its work-block list, got {status:?}"
        );
    }

    /// A work-block list three peers refused is given up, and not asked for
    /// again once no quorum of the newest list needs it, but forgotten.
    #[tokio::test]
    async fn a_given_up_work_block_list_no_quorum_needs_is_forgotten() {
        let (mut manager, _engine, requests, mut rx, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let next_tip_update = give_up_the_work_block_list_then_move_the_tip(
            &mut manager,
            &requests,
            &mut rx,
            tip_update,
            &hashes,
            false,
        )
        .await;
        let removing_the_quorum = MnListDiff {
            deleted_quorums: vec![DeletedQuorum {
                llmq_type: LLMQType::LlmqtypeTest,
                quorum_hash: quorum_hash_at(&hashes, MINED),
            }],
            ..next_tip_update
        };

        let events = deliver(&mut manager, &requests, removing_the_quorum).await;

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 2
            ),
            "the update completes at once, got {events:?}"
        );
        assert!(rx.try_recv().is_err(), "the work-block list is not asked for");
        assert!(manager.sync_state.given_up_work_lists.is_empty(), "and is forgotten");
    }

    /// A work-block list no peer answers is given up after three timeouts,
    /// and the tip update it was fetched for completes.
    #[tokio::test]
    async fn a_tip_update_completes_when_no_peer_answers_its_work_block_list() {
        let (mut manager, _engine, requests, mut rx, tip_update, _hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        deliver(&mut manager, &requests, tip_update).await;
        assert!(next_diff_request(&mut rx).is_some(), "the work-block list is asked for");
        manager.sync_state.mnlistdiff_pipeline.set_timeout(Duration::from_millis(1));

        let mut events = Vec::new();
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            events = manager.tick(&requests).await.expect("tick succeeds");
        }

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "the tip update completes once its work-block list is given up, got {events:?}"
        );
    }

    /// A response is matched to its request by base as well as target: a diff
    /// from another base is not what was asked for, and spends nothing.
    #[tokio::test]
    async fn an_mnlistdiff_from_another_base_is_ignored() {
        let (mut manager, engine, requests, mut rx, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let from_another_base = MnListDiff {
            base_block_hash: hashes[OLDER as usize],
            ..tip_update.clone()
        };

        let events = deliver(&mut manager, &requests, from_another_base).await;

        assert!(events.is_empty());
        assert!(rx.try_recv().is_err());
        assert_eq!(engine.read().await.latest_masternode_list().unwrap().known_height, TIP);

        deliver(&mut manager, &requests, tip_update).await;
        assert_eq!(engine.read().await.latest_masternode_list().unwrap().known_height, TIP + 1);
    }

    /// A diff whose block the header chain cannot place is asked again, but
    /// three times in all: the block may have left the chain, and asking
    /// forever would keep the pipeline busy.
    #[tokio::test]
    async fn an_mnlistdiff_whose_block_stays_unknown_is_given_up_after_three_attempts() {
        let (mut manager, requests, mut rx, _) = syncing_manager_awaiting_qrinfo(200).await;
        manager.sync_state.qrinfo_received();
        let base = BlockHash::from_byte_array([0x11; 32]);
        let unknown = BlockHash::from_byte_array([0x22; 32]);
        manager.sync_state.mnlistdiff_pipeline.queue_requests(vec![(base, unknown)]);
        manager.sync_state.mnlistdiff_pipeline.send_pending(&requests).unwrap();
        while rx.try_recv().is_ok() {}
        let diff = MnListDiff {
            base_block_hash: base,
            block_hash: unknown,
            ..MnListDiff::dummy_between(0, 0)
        };

        for attempt in 1..=3 {
            let response =
                Message::new(peer(1), NetworkMessage::MnListDiff(Box::new(diff.clone())));
            let _ = manager.handle_message(response, &requests).await;
            let asked_again = next_diff_request_avoiding(&mut rx);
            assert_eq!(asked_again.is_some(), attempt < 3, "attempt {attempt}");
            if let Some((_, avoided)) = asked_again {
                assert!(avoided.is_empty(), "our own lookup gap is not the peer's fault");
            }
        }
        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());
    }

    /// A QRInfo the engine rejects must not release the request slot.
    ///
    /// `qrinfo_in_flight` is the only thing that arms `tick`'s retry ladder, so
    /// the pre-fix ordering - release the slot, *then* run the fallible engine
    /// feed - left the manager `Syncing` with nothing in flight and an empty diff
    /// pipeline on any validation failure. `tick` has no branch for that state, so
    /// masternode sync never resumed: observed once on testnet and twice on
    /// mainnet as a frozen `Masternodes: Syncing 0/N | diffs_processed: 0,
    /// qr_infos_requested: 1` for as long as the process lived, with InstantSend
    /// verification and every masternode-list consumer dead behind it.
    ///
    /// With the slot kept armed and the attempt flagged, `tick` retries on the
    /// existing budget. Each dispatch avoids the peers that served a rejected
    /// response, and a deterministically-bad response still terminates - after
    /// `MAX_RETRY_ATTEMPTS` dispatches answered by as many peers, not silently
    /// and not never.
    #[tokio::test]
    async fn test_rejected_qrinfo_retries_against_another_peer_then_gives_up() {
        let (mut manager, requests, mut rx, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;
        let bad_response = |attempt: u8| {
            Message::new(
                peer(attempt + 1),
                NetworkMessage::QRInfo(Box::new(qrinfo_with_tip_hash(tip_hash))),
            )
        };

        for attempt in 0..MAX_RETRY_ATTEMPTS - 1 {
            let err = manager
                .handle_message(bad_response(attempt), &requests)
                .await
                .expect_err("the engine must reject this filler QRInfo");
            assert!(
                matches!(err, SyncError::MasternodeSyncFailed(_)),
                "expected MasternodeSyncFailed, got {:?}",
                err
            );

            let in_flight = manager
                .sync_state
                .qrinfo_in_flight
                .expect("a rejected response must NOT release the request slot");
            assert!(in_flight.rejected, "the spent attempt must be flagged for retry");
            assert_eq!(
                manager.sync_state.qrinfo_retry_count, attempt,
                "the handler must not consume budget itself; `tick` owns the counter"
            );

            manager.tick(&requests).await.expect("tick retries the rejected attempt");
            assert_eq!(manager.sync_state.qrinfo_retry_count, attempt + 1);
            assert!(
                matches!(
                    rx.try_recv().expect("tick must dispatch a retry GetQRInfo"),
                    NetworkRequest::SendMessageAvoiding(NetworkMessage::GetQRInfo(_), avoided)
                        if avoided.len() == usize::from(attempt) + 1
                ),
                "the retry must be a GetQRInfo avoiding every peer that was rejected"
            );
            assert!(
                !manager.sync_state.qrinfo_in_flight.expect("slot re-armed").rejected,
                "the retry must start as a clean attempt"
            );
        }

        // Budget spent. The last rejection must terminate rather than dispatch
        // again, and leaves the manager `Syncing` with nothing in flight, for
        // the stall watchdog.
        manager
            .handle_message(bad_response(MAX_RETRY_ATTEMPTS - 1), &requests)
            .await
            .expect_err("the engine must reject this filler QRInfo");
        let _ = manager.tick(&requests).await;
        assert!(
            rx.try_recv().is_err(),
            "the retry budget must stop dispatching after MAX_RETRY_ATTEMPTS"
        );
        assert_eq!(
            manager.progress.qr_infos_requested(),
            MAX_RETRY_ATTEMPTS as u32,
            "exactly MAX_RETRY_ATTEMPTS dispatches: the initial one plus its retries"
        );
        assert!(
            manager.state() == SyncState::Syncing && manager.sync_state.qrinfo_in_flight.is_none(),
            "giving up on an empty engine leaves the manager to the stall watchdog"
        );
    }

    /// A peer whose QRInfo was rejected cannot spend the budget again: the
    /// retry avoids it, and another QRInfo from it for the same tip is ignored.
    #[tokio::test]
    async fn a_peer_whose_qrinfo_was_rejected_is_avoided_and_ignored() {
        let (mut manager, requests, mut rx, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;
        let response = |peer| {
            Message::new(peer, NetworkMessage::QRInfo(Box::new(qrinfo_with_tip_hash(tip_hash))))
        };

        manager.handle_message(response(peer(1)), &requests).await.expect_err("rejected");
        manager.tick(&requests).await.expect("tick retries the rejected attempt");
        assert!(
            matches!(
                rx.try_recv(),
                Ok(NetworkRequest::SendMessageAvoiding(NetworkMessage::GetQRInfo(_), avoided))
                    if avoided == vec![peer(1)]
            ),
            "the retry avoids the rejecting peer"
        );

        let events = manager
            .handle_message(response(peer(1)), &requests)
            .await
            .expect("a repeat from the rejecting peer is ignored");
        assert!(events.is_empty());
        assert!(
            !manager.sync_state.qrinfo_in_flight.expect("still in flight").rejected,
            "the repeat spends nothing"
        );
        assert_eq!(manager.sync_state.qrinfo_retry_count, 1);
    }

    /// Header storage that defers to `inner`, except that reading a header
    /// fails while `unreadable` is set, as it does while the segment holding
    /// it cannot be opened or read.
    struct UnreadableHeaders {
        inner: PersistentBlockHeaderStorage,
        unreadable: bool,
    }

    impl UnreadableHeaders {
        fn read<T>(&self, read: StorageResult<T>) -> StorageResult<T> {
            if self.unreadable {
                return Err(StorageError::ReadFailed("the header segment is unreadable".into()));
            }
            read
        }
    }

    #[async_trait::async_trait]
    impl BlockHeaderStorage for UnreadableHeaders {
        async fn store_headers(&mut self, headers: &[HashedBlockHeader]) -> StorageResult<()> {
            self.inner.store_headers(headers).await
        }
        async fn store_headers_at_height(
            &mut self,
            headers: &[HashedBlockHeader],
            height: u32,
        ) -> StorageResult<()> {
            self.inner.store_headers_at_height(headers, height).await
        }
        async fn load_headers(
            &self,
            range: std::ops::Range<u32>,
        ) -> StorageResult<Vec<HashedBlockHeader>> {
            self.read(self.inner.load_headers(range).await)
        }
        async fn get_header(&self, height: u32) -> StorageResult<Option<HashedBlockHeader>> {
            self.read(self.inner.get_header(height).await)
        }
        async fn get_tip_height(&self) -> Option<u32> {
            self.inner.get_tip_height().await
        }
        async fn get_tip(&self) -> Option<BlockHeaderTip> {
            self.inner.get_tip().await
        }
        async fn get_start_height(&self) -> Option<u32> {
            self.inner.get_start_height().await
        }
        async fn get_stored_headers_len(&self) -> u32 {
            self.inner.get_stored_headers_len().await
        }
        async fn get_header_height_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
            self.read(self.inner.get_header_height_by_hash(hash).await)
        }
        async fn truncate_above(&mut self, target_height: u32) -> StorageResult<()> {
            self.inner.truncate_above(target_height).await
        }
    }

    /// The work blocks a QRInfo for `TIP` builds its cycle lists at, oldest
    /// first: 8 blocks below the base of the tip's cycle and of each of the
    /// three cycles before it, 24 blocks apart on regtest.
    const CYCLE_WORK_BLOCKS: [u32; 4] = [16, 40, 64, 88];

    /// Where the list every diff of [`qr_info_for_tip`] builds on is, below
    /// every cycle work block.
    const QR_INFO_BASE: u32 = 8;

    /// A QRInfo for `TIP` whose diffs all build on the list at
    /// [`QR_INFO_BASE`], one to each of [`CYCLE_WORK_BLOCKS`] and one to the
    /// tip, given the block hash at each height. Every diff is empty, so an
    /// engine holding an empty list at `QR_INFO_BASE` applies them all.
    fn qr_info_for_tip(hashes: &[BlockHash]) -> QRInfo {
        let diff = |height: u32| MnListDiff {
            base_block_hash: hashes[QR_INFO_BASE as usize],
            block_hash: hashes[height as usize],
            ..MnListDiff::dummy_between(0, 0)
        };
        let [h_minus_3c, h_minus_2c, h_minus_c, h] = CYCLE_WORK_BLOCKS.map(diff);
        QRInfo {
            mn_list_diff_tip: diff(TIP),
            mn_list_diff_h: h,
            mn_list_diff_at_h_minus_c: h_minus_c,
            mn_list_diff_at_h_minus_2c: h_minus_2c,
            mn_list_diff_at_h_minus_3c: h_minus_3c,
            ..QRInfo::dummy(0x00)
        }
    }

    /// A QRInfo the engine could not judge because our header storage did not
    /// read is not the peer's fault: the peer is not recorded as a refuser,
    /// and its QRInfo is processed once the storage reads again. A block the
    /// header chain does not hold is the peer's choice, so a QRInfo naming one
    /// still counts against it.
    #[tokio::test]
    async fn a_qr_info_our_header_storage_could_not_read_is_not_held_against_its_peer() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut inner = PersistentBlockHeaderStorage::open(dir.path()).await.unwrap();
        let headers = Header::dummy_batch(0..TIP + 1);
        inner
            .store_headers(&headers.iter().map(HashedBlockHeader::from).collect::<Vec<_>>())
            .await
            .unwrap();
        let hashes: Vec<BlockHash> = headers.iter().map(|header| header.block_hash()).collect();
        let header_storage = Arc::new(RwLock::new(UnreadableHeaders {
            inner,
            unreadable: false,
        }));
        let mut engine = MasternodeListEngine::new(Network::Regtest, Arc::clone(&header_storage));
        engine.masternode_lists.insert(
            QR_INFO_BASE,
            MasternodeList::empty(hashes[QR_INFO_BASE as usize], QR_INFO_BASE),
        );
        let mut manager = MasternodesManager::new(
            Arc::clone(&header_storage),
            Arc::new(RwLock::new(engine)),
            Network::Regtest,
            None,
        )
        .await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let requests = RequestSender::new(tx);
        manager.send_qrinfo_for_tip(&requests).await.expect("the QRInfo is sent");
        let tip = hashes[TIP as usize];
        let honest = qr_info_for_tip(&hashes);
        let response = |peer, qr_info: &QRInfo| {
            Message::new(peer, NetworkMessage::QRInfo(Box::new(qr_info.clone())))
        };

        let mut naming_an_unknown_block = honest.clone();
        naming_an_unknown_block.mn_list_diff_h.block_hash = BlockHash::from_byte_array([0x33; 32]);
        manager
            .handle_message(response(peer(2), &naming_an_unknown_block), &requests)
            .await
            .expect_err("a QRInfo naming a block the chain does not hold is refused");
        assert!(manager.sync_state.has_refused_qrinfo(tip, peer(2)));
        manager.tick(&requests).await.expect("tick retries the refused QRInfo");

        header_storage.write().await.unreadable = true;
        manager
            .handle_message(response(peer(1), &honest), &requests)
            .await
            .expect_err("a QRInfo is not taken while the header storage cannot be read");
        assert!(
            !manager.sync_state.has_refused_qrinfo(tip, peer(1)),
            "our storage failing is not the peer's refusal"
        );
        assert_eq!(manager.state(), SyncState::Syncing);

        header_storage.write().await.unreadable = false;
        manager.tick(&requests).await.expect("tick retries the QRInfo");
        while rx.try_recv().is_ok() {}
        let events = manager
            .handle_message(response(peer(1), &honest), &requests)
            .await
            .expect("the same QRInfo is taken once the storage reads");
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, qr_info_result: Some(_) }]
                    if *height == TIP
            ),
            "the QRInfo completes the sync, got {events:?}"
        );
        assert_eq!(manager.state(), SyncState::Synced);
    }

    /// An initial sync whose QRInfo was taken ends once the work-block lists
    /// it asked for are applied or given up: a given-up list must not keep it
    /// `Syncing`, where the stall watchdog would start the QRInfo over. It
    /// publishes the newest list with the QRInfo's result.
    #[test_case(true; "after three timeouts")]
    #[test_case(false; "after three refusing peers")]
    #[tokio::test]
    async fn an_initial_sync_completes_when_a_work_block_list_is_given_up(by_timeouts: bool) {
        let (mut manager, requests, mut rx, _) = syncing_manager_awaiting_qrinfo(TIP).await;
        let hashes: Vec<BlockHash> =
            Header::dummy_batch(0..TIP + 1).iter().map(|header| header.block_hash()).collect();
        manager.engine.write().await.masternode_lists.insert(
            QR_INFO_BASE,
            MasternodeList::empty(hashes[QR_INFO_BASE as usize], QR_INFO_BASE),
        );
        let mut qr_info = qr_info_for_tip(&hashes);
        qr_info.mn_list_diff_tip.new_quorums = vec![test_quorum(hashes[OLD_MINED as usize])];
        qr_info.mn_list_diff_tip.quorums_chainlock_signatures = vec![QuorumCLSigObject {
            signature: BLSSignature::from([2; 96]),
            index_set: vec![0],
        }];
        let events = manager
            .handle_message(
                Message::new(peer(1), NetworkMessage::QRInfo(Box::new(qr_info))),
                &requests,
            )
            .await
            .expect("the QRInfo is taken");
        assert!(events.is_empty(), "the sync waits for the work-block list, got {events:?}");
        let (base_block_hash, block_hash) =
            next_diff_request(&mut rx).expect("the work-block list of the new quorum is asked for");
        assert_eq!(block_hash, hashes[(OLD_MINED - QUORUM_MEMBER_LIST_OFFSET) as usize]);

        let mut events = Vec::new();
        if by_timeouts {
            manager.sync_state.mnlistdiff_pipeline.set_timeout(Duration::from_millis(1));
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                events = manager.tick(&requests).await.expect("tick succeeds");
            }
        } else {
            let unusable = MnListDiff {
                base_block_hash,
                block_hash,
                new_quorums: vec![test_quorum(hashes[MINED as usize])],
                ..MnListDiff::dummy_between(0, 0)
            };
            for refusing in [peer(1), peer(2), peer(3)] {
                events = deliver_from(&mut manager, &requests, refusing, unusable.clone()).await;
            }
        }

        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated {
                    height,
                    qr_info_result: Some(QRInfoFeedResult {
                        rotated_quorum_count: 0,
                        fully_verified_count: 0,
                        stored_cycle_height: None,
                        ..
                    }),
                }] if *height == TIP
            ),
            "the sync publishes the tip list with the QRInfo's result, got {events:?}"
        );
        assert_eq!(manager.state(), SyncState::Synced);
    }

    /// When every QRInfo attempt fails before the engine holds any list, the
    /// manager stays `Syncing`: `Error` has no way out, while the stall
    /// watchdog starts a fresh budget once the last attempt is old enough.
    #[tokio::test]
    async fn qrinfo_attempts_exhausted_on_an_empty_engine_are_retried_by_the_watchdog() {
        let (mut manager, requests, mut rx, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;
        for attempt in 0..MAX_RETRY_ATTEMPTS {
            let refused = Message::new(
                peer(attempt + 1),
                NetworkMessage::QRInfo(Box::new(qrinfo_with_tip_hash(tip_hash))),
            );
            let _ = manager.handle_message(refused, &requests).await;
            let _ = manager.tick(&requests).await;
        }
        while rx.try_recv().is_ok() {}

        assert!(manager.engine.read().await.masternode_lists.is_empty());
        assert_eq!(manager.state(), SyncState::Syncing, "giving up must not end in Error");
        assert!(manager.sync_state.qrinfo_in_flight.is_none());

        manager.sync_state.last_qrinfo_dispatch = Some(
            Instant::now()
                .checked_sub(QRINFO_STALL_WATCHDOG + Duration::from_secs(1))
                .expect("test host uptime must exceed the watchdog interval"),
        );
        manager.tick(&requests).await.expect("the watchdog re-dispatch succeeds");
        assert!(
            matches!(
                rx.try_recv(),
                Ok(NetworkRequest::SendMessageAvoiding(NetworkMessage::GetQRInfo(_), avoided))
                    if avoided.len() == usize::from(MAX_RETRY_ATTEMPTS)
            ),
            "the watchdog must start a fresh QRInfo budget, still avoiding the rejecting peers"
        );
        assert_eq!(manager.sync_state.qrinfo_retry_count, 0);
    }

    /// The stall watchdog is the backstop for every route into the stranded state
    /// that keeping the in-flight flag cannot cover - notably a
    /// `send_qrinfo_for_tip` that returns without dispatching *after* its caller
    /// already cleared the slot, which is exactly what `tick`'s own retry path
    /// does. `Syncing` with nothing in flight and an empty diff pipeline has no
    /// other exit.
    #[tokio::test]
    async fn test_tick_watchdog_redispatches_after_stall() {
        let (mut manager, requests, mut rx, _) = syncing_manager_awaiting_qrinfo(200).await;

        // Strand the manager the way a dispatch failure would.
        manager.sync_state.clear_pending();
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(manager.sync_state.qrinfo_in_flight.is_none());
        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());

        manager.tick(&requests).await.expect("tick succeeds");
        assert!(
            rx.try_recv().is_err(),
            "the watchdog must stay quiet until its interval has elapsed"
        );

        manager.sync_state.last_qrinfo_dispatch = Some(
            Instant::now()
                .checked_sub(QRINFO_STALL_WATCHDOG + Duration::from_secs(1))
                .expect("test host uptime must exceed the watchdog interval"),
        );

        manager.tick(&requests).await.expect("the watchdog re-dispatch succeeds");
        assert!(
            matches!(
                rx.try_recv().expect("the watchdog must re-dispatch a GetQRInfo"),
                NetworkRequest::SendMessage(NetworkMessage::GetQRInfo(_))
            ),
            "the watchdog must re-dispatch a GetQRInfo"
        );
        assert!(
            manager.sync_state.qrinfo_in_flight.is_some(),
            "the re-dispatch must re-arm the request slot"
        );
        assert_eq!(manager.sync_state.qrinfo_retry_count, 0, "recovery starts a fresh budget");
    }

    /// A disconnect must not throw masternode work away. `BlocksManager` and
    /// `FiltersManager` both requeue their in-flight network slots; the masternode
    /// manager used to call `clear_pending()`, which dropped the queued
    /// `GetMnListDiff`s, the QRInfo slot, and any `qr_info_result` carried on
    /// `pipeline_mode`, forcing a full QRInfo re-run on every reconnect.
    #[tokio::test]
    async fn test_on_disconnect_requeues_instead_of_clearing() {
        let (mut manager, requests, _rx, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;

        let base = BlockHash::from_slice(&[0x11; 32]).unwrap();
        let target = BlockHash::from_slice(&[0x22; 32]).unwrap();
        manager.sync_state.mnlistdiff_pipeline.queue_requests(vec![(base, target)]);
        manager.sync_state.mnlistdiff_pipeline.send_pending(&requests).expect("send succeeds");
        assert_eq!(manager.sync_state.mnlistdiff_pipeline.active_count(), 1);

        manager.on_disconnect();

        assert_eq!(
            manager.sync_state.mnlistdiff_pipeline.active_count(),
            0,
            "the dead peer's network slot must be released"
        );
        assert!(
            !manager.sync_state.mnlistdiff_pipeline.is_complete(),
            "but the request itself must survive, back in the pending queue"
        );
        assert_eq!(
            manager.sync_state.qrinfo_in_flight.map(|in_flight| in_flight.tip),
            Some(tip_hash),
            "the QRInfo slot must stay armed so tick's ladder re-dispatches it"
        );
        assert_eq!(
            manager.sync_state.qrinfo_retry_count, 0,
            "a fresh peer set earns a fresh retry budget"
        );
        assert_eq!(
            manager.sync_state.last_processed_qrinfo_tip, None,
            "the dedup guard must not reject the reconnect's response"
        );
    }

    /// A disconnect from every peer forgets what the old peers refused: the
    /// next peers get every attempt of every diff, are not avoided or ignored
    /// for a QRInfo, and are asked for the tip update that was given up.
    #[tokio::test]
    async fn a_full_disconnect_forgets_the_refusals_of_the_old_peers() {
        let (mut manager, requests, _rx, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;
        let base = BlockHash::from_byte_array([0x11; 32]);
        let target = BlockHash::from_byte_array([0x22; 32]);
        let pipeline = &mut manager.sync_state.mnlistdiff_pipeline;
        pipeline.queue_requests(vec![(base, target)]);
        pipeline.send_pending(&requests).expect("send succeeds");
        pipeline.retry_or_give_up(target, Some(peer(1)));
        manager.sync_state.qrinfo_refused_by(peer(2));
        manager.sync_state.given_up_tip = Some(tip_hash);

        manager.on_disconnect();

        let pipeline = &mut manager.sync_state.mnlistdiff_pipeline;
        assert!(!pipeline.has_refused(target, peer(1)));
        for _ in 0..2 {
            pipeline.send_pending(&requests).expect("send succeeds");
            assert_eq!(
                pipeline.retry_or_give_up(target, None),
                Attempt::Retried,
                "the attempt spent before the disconnect no longer counts"
            );
        }
        assert!(!manager.sync_state.has_refused_qrinfo(tip_hash, peer(2)));
        assert_eq!(manager.sync_state.given_up_tip, None);
    }

    /// `tick` must reissue MnListDiff requests that a disconnect moved back to
    /// pending. Nothing else can: every other `send_pending` call site hangs off a
    /// response handler, and after a disconnect no response is coming.
    #[tokio::test]
    async fn test_tick_reissues_requeued_mnlistdiffs() {
        let (mut manager, requests, mut rx, _) = syncing_manager_awaiting_qrinfo(200).await;
        manager.sync_state.qrinfo_received();

        let base = BlockHash::from_slice(&[0x11; 32]).unwrap();
        let target = BlockHash::from_slice(&[0x22; 32]).unwrap();
        manager.sync_state.mnlistdiff_pipeline.queue_requests(vec![(base, target)]);
        manager.sync_state.mnlistdiff_pipeline.send_pending(&requests).expect("send succeeds");
        while rx.try_recv().is_ok() {}

        manager.on_disconnect();
        assert_eq!(manager.sync_state.mnlistdiff_pipeline.active_count(), 0);

        manager.tick(&requests).await.expect("tick reissues the requeued request");
        assert!(
            matches!(
                rx.try_recv().expect("tick must reissue the GetMnListDiff"),
                NetworkRequest::SendMessage(NetworkMessage::GetMnListD(_))
            ),
            "the reissued request must be a GetMnListDiff"
        );
        assert_eq!(
            manager.sync_state.mnlistdiff_pipeline.active_count(),
            1,
            "the reissued request must be tracked in flight again"
        );
    }
}
