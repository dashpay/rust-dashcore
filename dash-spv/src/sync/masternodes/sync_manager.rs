use super::manager::{DiffOutcome, PipelineMode};
use super::pipeline::{DiffKind, MNLISTDIFF_DEADLINE};
use crate::error::SyncResult;
use crate::network::{InboundMessage, MessageType, NetworkManager};
use crate::storage::BlockHeaderStorage;
use crate::sync::{
    ManagerIdentifier, MasternodesManager, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::SyncError;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use std::net::SocketAddr;
use std::sync::Arc;
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
        &[MessageType::MnListDiff, MessageType::QrInfo]
    }

    /// The QRInfo slot is left armed on purpose: it has its own timeout ladder in `tick`.
    fn on_disconnect(&mut self) {
        // A fresh peer set earns a fresh retry budget, and the dedup guard must not
        // reject a response for a tip whose earlier attempt died with the old peer.
        self.sync_state.qrinfo_retry_count = 0;
        self.sync_state.last_processed_qrinfo_tip = None;
        self.sync_state.given_up_tip = None;
    }

    async fn handle_message(
        &mut self,
        peer: SocketAddr,
        msg: InboundMessage,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        match &*msg {
            NetworkMessage::QRInfo(qr_info) => {
                if !self.sync_state.should_process_qrinfo(qr_info) {
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
                        self.sync_state.qrinfo_rejected();
                        return Err(SyncError::MasternodeSyncFailed(e.to_string()));
                    }
                };

                let request_pairs = engine.readable_missing_work_block_list_requests().await;
                drop(engine);

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
                self.sync_state
                    .mnlistdiff_pipeline
                    .queue_requests(DiffKind::WorkBlockList, request_pairs, network)
                    .await;
                self.sync_state.mnlistdiff_pipeline.send_pending(network).await?;

                self.progress.bump_last_activity();

                // If no pending requests, complete
                if !self.sync_state.has_pending_requests() {
                    return self.complete_pipeline(network).await;
                }
            }

            NetworkMessage::MnListDiff(diff) => {
                let Some(kind) = self.sync_state.mnlistdiff_pipeline.match_response(diff) else {
                    tracing::debug!("Received unexpected MnListDiff for {}", diff.block_hash);
                    return Ok(vec![]);
                };

                tracing::debug!("Processing MnListDiff message for {}", diff.block_hash);

                let mut engine = self.engine.write().await;
                let outcome = match engine.apply_diff((**diff).clone()).await {
                    Ok(()) => {
                        tracing::debug!("Applied MnListDiff for {}", diff.block_hash);
                        DiffOutcome::Applied
                    }
                    Err(e) if e.blames_peer() => {
                        drop(engine);
                        // Kept wanted. The ban closes the connection and the broker sends
                        // the request to another peer.
                        tracing::warn!(
                            "Banning {} for an MnListDiff the engine refused: {}",
                            peer,
                            e
                        );
                        network.ban_peer(peer).await;
                        return Err(SyncError::MasternodeSyncFailed(e.to_string()));
                    }
                    Err(e) => {
                        tracing::warn!("Giving up MnListDiff for {}: {}", diff.block_hash, e);
                        DiffOutcome::GivenUp
                    }
                };
                // A tip update can bring a quorum whose work block lies below
                // every list the engine built since its last QRInfo, as the
                // first quorum after a start does. Fetch those lists now, as
                // the QRInfo path does, instead of leaving the quorum
                // `Skipped(MissedList)` until the next QRInfo, a rotation cycle
                // later. The pipeline completes only once they are applied or
                // given up.
                let work_block_lists =
                    if outcome == DiffOutcome::Applied && kind == DiffKind::TipUpdate {
                        engine.missing_work_block_list_requests_for(diff).await
                    } else {
                        Vec::new()
                    };
                drop(engine);

                if !work_block_lists.is_empty() {
                    self.sync_state
                        .mnlistdiff_pipeline
                        .queue_requests(DiffKind::WorkBlockList, work_block_lists, network)
                        .await;
                    self.sync_state.mnlistdiff_pipeline.send_pending(network).await?;
                }
                return self.settle_diff(diff.block_hash, outcome, network).await;
            }

            _ => {}
        }

        Ok(vec![])
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        network: &Arc<dyn NetworkManager>,
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
                        self.sync_state.clear_pending(network).await;
                        return self.send_qrinfo_for_tip(network).await;
                    }
                    PipelineMode::Incremental => {
                        tracing::debug!(
                            "New headers stored (tip: {}), firing targeted MnListDiff from {}",
                            tip_height,
                            self.progress.current_height()
                        );
                        return self.send_tip_mnlistdiff_update(network).await;
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
                            self.sync_state.clear_pending(network).await;
                            return self.send_qrinfo_for_tip(network).await;
                        }
                        PipelineMode::Incremental => {
                            return self.send_tip_mnlistdiff_update(network).await;
                        }
                    }
                }
                tracing::info!(
                    "Headers sync complete at {}, starting masternode sync",
                    self.progress.block_header_tip_height()
                );
                self.sync_state.qrinfo_retry_count = 0;
                self.sync_state.clear_pending(network).await;
                return self.send_qrinfo_for_tip(network).await;
            }
        }

        Ok(vec![])
    }

    async fn tick(&mut self, network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
        self.tick_at(Instant::now(), network).await
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Masternodes(self.progress.clone())
    }
}

impl<H: BlockHeaderStorage> MasternodesManager<H> {
    /// `tick` at a given time, so tests can pass a future instant to reach the diff deadline.
    /// The trait `tick` passes `Instant::now()`.
    pub(super) async fn tick_at(
        &mut self,
        now: Instant,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Handle ticks for both Syncing (initial) and Synced (incremental updates)
        if !matches!(self.state(), SyncState::Syncing | SyncState::Synced) {
            return Ok(vec![]);
        }

        if self
            .sync_state
            .given_up_tip
            .is_some_and(|(_, at)| now.saturating_duration_since(at) > MNLISTDIFF_DEADLINE)
        {
            self.sync_state.given_up_tip = None;
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
                            self.sync_state.clear_pending(network).await;
                            return self.send_qrinfo_for_tip(network).await;
                        }
                    }
                    PipelineMode::Incremental => {
                        return self.send_tip_mnlistdiff_update(network).await;
                    }
                }
            }
            return Ok(vec![]);
        }

        // The broker does not track QRInfo, so its timeout/retry lives here.
        // Check for a QRInfo attempt that is over: either the peer never answered
        // (timeout), or it answered with something the engine rejected. Both
        // consumed an attempt without producing any state, so both retry against
        // the next peer on the same budget. A rejected response skips the
        // remaining timeout - that peer has already had its turn.
        if let Some(in_flight) = self.sync_state.qrinfo_in_flight {
            let timeout = qrinfo_timeout_for(self.sync_state.qrinfo_retry_count);
            let timed_out = now.saturating_duration_since(in_flight.wait_start) > timeout;
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
                    self.sync_state.clear_pending(network).await;
                    return self.send_qrinfo_for_tip(network).await;
                } else {
                    tracing::warn!(
                        attempts = MAX_RETRY_ATTEMPTS,
                        last_attempt_rejected = in_flight.rejected,
                        "QRInfo failed on every attempt, skipping masternode sync"
                    );
                    self.sync_state.clear_pending(network).await;
                    return self.complete_pipeline(network).await;
                }
            }
            return Ok(vec![]);
        }

        // Re-declare outstanding MnListDiff work. The broker paces and retries it but never
        // gives a request up, so diffs past their deadline are given up here first.
        if !self.sync_state.mnlistdiff_pipeline.is_complete() {
            let events = self.give_up_expired_diffs(now, network).await?;
            self.sync_state.mnlistdiff_pipeline.send_pending(network).await?;
            return Ok(events);
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
            && self.sync_state.last_qrinfo_dispatch.is_some_and(|dispatched| {
                now.saturating_duration_since(dispatched) > QRINFO_STALL_WATCHDOG
            })
        {
            tracing::warn!(
                stalled_for_secs = self
                    .sync_state
                    .last_qrinfo_dispatch
                    .map(|d| now.saturating_duration_since(d).as_secs())
                    .unwrap_or_default(),
                "Masternode sync stalled in Syncing with nothing in flight, re-dispatching QRInfo"
            );
            // Re-stamp before dispatching so a dispatch that returns without
            // sending (no stored tip, tip at genesis) re-arms the watchdog for
            // another full interval instead of retrying on every 100ms tick.
            self.sync_state.last_qrinfo_dispatch = Some(now);
            self.sync_state.qrinfo_retry_count = 0;
            self.sync_state.clear_pending(network).await;
            return self.send_qrinfo_for_tip(network).await;
        }

        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::super::manager::{MasternodeSyncState, QRInfoInFlight};
    use super::super::pipeline::{DiffKind, MNLISTDIFF_DEADLINE};
    use super::{
        qrinfo_timeout_for, MAX_RETRY_ATTEMPTS, QRINFO_STALL_WATCHDOG, QRINFO_TIMEOUT_SCHEDULE_SECS,
    };
    use crate::network::{InboundMessage, NetworkManager, RequestKey};
    use crate::sml_engine::test_support::quorum_entry;
    use crate::sml_engine::MasternodeListEngine;
    use crate::storage::{
        BlockHeaderStorage, DiskStorageManager, PersistentBlockHeaderStorage, StorageManager,
    };
    use crate::sync::{MasternodesManager, SyncEvent, SyncManager, SyncState};
    use crate::test_utils::{test_socket_address, MockNetworkManager};
    use crate::types::HashedBlockHeader;
    use crate::SyncError;
    use dashcore::block::Header;
    use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_qrinfo::QRInfo;
    use dashcore::network::message_sml::{MnListDiff, QuorumCLSigObject};
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
    use tokio::sync::RwLock;

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
    /// The returned tip hash must be echoed by a response to pass
    /// `should_process_qrinfo`. The initial `GetQRInfo` is cleared from the mock.
    async fn syncing_manager_awaiting_qrinfo(
        tip: u32,
    ) -> (TestMasternodesManager, Arc<dyn NetworkManager>, Arc<MockNetworkManager>, BlockHash) {
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
        let engine = MasternodeListEngine::new_without_validation(
            Network::Regtest,
            Arc::clone(&block_headers),
        );
        let mut manager = MasternodesManager::new(
            block_headers,
            Arc::new(RwLock::new(engine)),
            Network::Regtest,
            None,
        )
        .await;
        manager.progress.update_block_header_tip_height(tip);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        manager.send_qrinfo_for_tip(&network).await.expect("initial QRInfo dispatch succeeds");
        assert_eq!(manager.state(), SyncState::Syncing);
        let tip_hash = manager.sync_state.qrinfo_in_flight.expect("QRInfo in flight").tip;
        assert!(
            mock.sent_messages().await.iter().any(|m| matches!(m, NetworkMessage::GetQRInfo(_))),
            "initial GetQRInfo is queued"
        );
        mock.clear_sent().await;
        (manager, network, mock, tip_hash)
    }

    /// A synced manager over `storage`, whose header chain runs to `TIP + 1`
    /// and whose engine holds the lists `lists` builds from the block hashes,
    /// once it sent the tip update from `TIP` to `TIP + 1`. Returns the manager, its
    /// engine, the request channel, and the block hash at each height.
    async fn manager_after_a_tip_update_request(
        storage: &DiskStorageManager,
        lists: impl FnOnce(&[BlockHash]) -> Vec<MasternodeList>,
    ) -> (
        MasternodesManager<PersistentBlockHeaderStorage>,
        Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>,
        Arc<dyn NetworkManager>,
        Arc<MockNetworkManager>,
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
        let mut engine = MasternodeListEngine::new_without_validation(
            Network::Regtest,
            Arc::clone(&block_headers),
        );
        for list in lists(&hashes) {
            engine.masternode_lists.insert(list.known_height, list);
        }
        let engine = Arc::new(RwLock::new(engine));
        let mut manager =
            MasternodesManager::new(block_headers, Arc::clone(&engine), Network::Regtest, None)
                .await;
        manager.set_state(SyncState::Synced);
        manager.progress.update_block_header_tip_height(TIP + 1);
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        manager.send_tip_mnlistdiff_update(&network).await.unwrap();
        assert_eq!(diff_requests(&mock).await.len(), 1, "the tip update is sent");
        (manager, engine, network, mock, hashes)
    }

    /// A synced manager that sent a tip update from `TIP` to `TIP + 1`, whose
    /// response brings a non-rotating quorum mined at `MINED`. The base list
    /// already holds an older unverified quorum mined at `OLD_MINED`, and the
    /// engine holds no list at either quorum's work block, only one at
    /// `OLDER`.
    async fn manager_awaiting_a_tip_update_with_a_new_quorum() -> (
        MasternodesManager<PersistentBlockHeaderStorage>,
        Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>,
        Arc<dyn NetworkManager>,
        Arc<MockNetworkManager>,
        MnListDiff,
        Vec<BlockHash>,
    ) {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let (manager, engine, network, mock, hashes) =
            manager_after_a_tip_update_request(&storage, |hashes| {
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
        (manager, engine, network, mock, tip_update, hashes)
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

    /// Drains the `(base, target)` MnListDiff requests sent so far.
    async fn diff_requests(mock: &MockNetworkManager) -> Vec<(BlockHash, BlockHash)> {
        let requests = mock
            .sent_messages()
            .await
            .into_iter()
            .filter_map(|msg| match msg {
                NetworkMessage::GetMnListD(get) => Some((get.base_block_hash, get.block_hash)),
                _ => None,
            })
            .collect();
        mock.clear_sent().await;
        requests
    }

    async fn deliver(
        manager: &mut MasternodesManager<PersistentBlockHeaderStorage>,
        network: &Arc<dyn NetworkManager>,
        diff: MnListDiff,
    ) -> Vec<SyncEvent> {
        deliver_from(manager, network, test_socket_address(1), diff).await
    }

    async fn deliver_from(
        manager: &mut MasternodesManager<PersistentBlockHeaderStorage>,
        network: &Arc<dyn NetworkManager>,
        peer: SocketAddr,
        diff: MnListDiff,
    ) -> Vec<SyncEvent> {
        manager
            .handle_message(peer, NetworkMessage::MnListDiff(Box::new(diff)).into(), network)
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
        let (mut manager, engine, network, mock, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let work = MINED - QUORUM_MEMBER_LIST_OFFSET;

        let events = deliver(&mut manager, &network, tip_update).await;

        assert_eq!(
            engine.read().await.latest_masternode_list().unwrap().quorums[&LLMQType::LlmqtypeTest]
                [&quorum_hash_at(&hashes, MINED)]
                .verified,
            LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(work)),
            "the tip list cannot verify the quorum without its work-block list"
        );
        assert!(events.is_empty(), "the update must not complete before the work-block list");
        let requests = diff_requests(&mock).await;
        assert_eq!(
            requests,
            vec![(hashes[OLDER as usize], hashes[work as usize])],
            "the tip update must ask for the new quorum's work-block list, not the older one's"
        );

        let (base_block_hash, block_hash) = requests[0];
        let work_list = MnListDiff {
            base_block_hash,
            block_hash,
            ..MnListDiff::dummy_between(0, 0)
        };
        let events = deliver(&mut manager, &network, work_list).await;

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
        assert!(diff_requests(&mock).await.is_empty(), "nothing more to fetch");
    }

    /// A refused tip update changes nothing, so it publishes nothing and asks for no work-block
    /// list. A missing ChainLock signature can come from our own activation heights, so the
    /// update is given up without banning the peer.
    #[tokio::test]
    async fn a_refused_tip_update_is_given_up_without_a_ban() {
        let (mut manager, engine, network, mock, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let target = hashes[TIP as usize + 1];
        let refused = MnListDiff {
            // A new quorum needs a ChainLock signature to be applied.
            quorums_chainlock_signatures: Vec::new(),
            ..tip_update
        };

        let events = deliver(&mut manager, &network, refused).await;

        assert!(events.is_empty(), "a given-up tip update publishes nothing, got {events:?}");
        assert_eq!(mock.released_keys().await, vec![RequestKey::MnListDiff(target)]);
        assert_eq!(engine.read().await.latest_masternode_list().unwrap().known_height, TIP);
        assert!(diff_requests(&mock).await.is_empty(), "a refused tip update asks for nothing");
        assert!(mock.banned_peers().await.is_empty(), "the peer is not proven wrong");
    }

    /// A work-block list with a ChainLock signature for a quorum it does not contain contradicts
    /// itself, so its peer is banned. The list stays wanted, and another peer's answer completes
    /// the tip update.
    #[tokio::test]
    async fn a_work_block_list_that_contradicts_itself_bans_its_peer() {
        let (mut manager, _engine, network, mock, tip_update, _hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        deliver(&mut manager, &network, tip_update).await;
        let (base_block_hash, block_hash) =
            *diff_requests(&mock).await.first().expect("the work-block list is asked for");
        let contradictory = MnListDiff {
            base_block_hash,
            block_hash,
            quorums_chainlock_signatures: vec![QuorumCLSigObject {
                signature: BLSSignature::from([2; 96]),
                index_set: vec![0],
            }],
            ..MnListDiff::dummy_between(0, 0)
        };

        let result = manager
            .handle_message(
                test_socket_address(1),
                NetworkMessage::MnListDiff(Box::new(contradictory)).into(),
                &network,
            )
            .await;

        assert!(matches!(result, Err(SyncError::MasternodeSyncFailed(_))), "got {result:?}");
        assert_eq!(mock.banned_peers().await, vec![test_socket_address(1)]);
        assert!(
            !mock.released_keys().await.contains(&RequestKey::MnListDiff(block_hash)),
            "the work-block list must stay at the broker"
        );

        let honest = MnListDiff {
            base_block_hash,
            block_hash,
            ..MnListDiff::dummy_between(0, 0)
        };
        let events = deliver_from(&mut manager, &network, test_socket_address(2), honest).await;
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "the honest answer completes the tip update, got {events:?}"
        );
    }

    /// A tip update that fails on our side, here because the engine dropped its base list, is
    /// given up without blaming the peer. It is not asked for again on every tick, only once
    /// the header tip moves.
    #[tokio::test]
    async fn a_tip_update_given_up_is_not_asked_again_until_the_tip_moves() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let (mut manager, engine, network, mock, hashes) =
            manager_after_a_tip_update_request(&storage, |hashes| {
                vec![
                    MasternodeList::empty(hashes[OLDER as usize], OLDER),
                    MasternodeList::empty(hashes[TIP as usize], TIP),
                ]
            })
            .await;
        engine.write().await.masternode_lists.remove(&TIP);
        let tip_update = MnListDiff {
            base_block_hash: hashes[TIP as usize],
            block_hash: hashes[TIP as usize + 1],
            ..MnListDiff::dummy_between(0, 0)
        };

        deliver(&mut manager, &network, tip_update).await;
        assert!(mock.banned_peers().await.is_empty(), "a gap of ours is not the peer's fault");

        manager.tick(&network).await.unwrap();
        assert!(diff_requests(&mock).await.is_empty(), "the given-up tip is not asked again");

        let next = announce_tip(&mut manager, &network, TIP + 2).await;
        assert_eq!(
            diff_requests(&mock).await,
            vec![(hashes[OLDER as usize], next)],
            "a new tip is asked for from the newest list left"
        );
    }

    /// A work-block list that fails to apply leaves the tip update it was
    /// fetched for applied, so the update still completes.
    #[tokio::test]
    async fn a_tip_update_completes_when_its_work_block_list_fails() {
        let (mut manager, engine, network, mock, tip_update, hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        deliver(&mut manager, &network, tip_update).await;
        let (base_block_hash, block_hash) =
            *diff_requests(&mock).await.first().expect("the work-block list is asked for");

        let from_another_base = MnListDiff {
            base_block_hash: hashes[1],
            block_hash,
            ..MnListDiff::dummy_between(0, 0)
        };
        let events = deliver(&mut manager, &network, from_another_base).await;
        assert!(events.is_empty(), "a diff from another base answers nothing, got {events:?}");
        assert!(
            !manager.sync_state.mnlistdiff_pipeline.is_complete(),
            "the work-block list is still wanted"
        );

        // Remove the base list so the engine cannot apply the work-block list.
        engine.write().await.masternode_lists.remove(&OLDER);
        let unusable = MnListDiff {
            base_block_hash,
            block_hash,
            ..MnListDiff::dummy_between(0, 0)
        };
        let events = deliver(&mut manager, &network, unusable).await;

        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "a failed work-block list must not hold back the tip update, got {events:?}"
        );
    }

    /// A diff no peer answers is given up at its deadline and released from the broker, which
    /// would otherwise retry it forever. A given-up work-block list lets its tip update
    /// complete. A given-up tip update publishes nothing.
    #[tokio::test]
    async fn an_unanswered_diff_is_given_up_at_its_deadline() {
        let (mut manager, _engine, network, mock, tip_update, _hashes) =
            manager_awaiting_a_tip_update_with_a_new_quorum().await;
        let before_queued = Instant::now();
        deliver(&mut manager, &network, tip_update).await;
        let after_queued = Instant::now();
        let (_, work_target) =
            *diff_requests(&mock).await.first().expect("the work-block list is asked for");

        let events = manager.tick_at(before_queued + MNLISTDIFF_DEADLINE, &network).await.unwrap();
        assert!(events.is_empty(), "not given up before its deadline, got {events:?}");
        assert!(!manager.sync_state.mnlistdiff_pipeline.is_complete());

        let events = manager
            .tick_at(after_queued + MNLISTDIFF_DEADLINE + Duration::from_secs(1), &network)
            .await
            .unwrap();
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::MasternodeStateUpdated { height, .. }] if *height == TIP + 1
            ),
            "the tip update completes once its work-block list is given up, got {events:?}"
        );
        assert!(mock.released_keys().await.contains(&RequestKey::MnListDiff(work_target)));
        assert!(mock.banned_peers().await.is_empty(), "silence is not a refusal");
        assert_eq!(manager.progress.diffs_processed(), 1, "a silent minute is not progress");

        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let (mut manager, _engine, network, mock, hashes) =
            manager_after_a_tip_update_request(&storage, |hashes| {
                vec![MasternodeList::empty(hashes[TIP as usize], TIP)]
            })
            .await;
        let after_queued = Instant::now();
        let target = hashes[TIP as usize + 1];

        let events = manager
            .tick_at(after_queued + MNLISTDIFF_DEADLINE + Duration::from_secs(1), &network)
            .await
            .unwrap();
        assert!(events.is_empty(), "a given-up tip update publishes nothing, got {events:?}");
        assert_eq!(mock.released_keys().await, vec![RequestKey::MnListDiff(target)]);

        // The header tip stays put, like on a chain with no new blocks, so the given-up tip
        // update is asked for again only after its own deadline passes.
        manager.tick(&network).await.unwrap();
        assert!(diff_requests(&mock).await.is_empty(), "not asked for again at once");
        manager
            .tick_at(Instant::now() + MNLISTDIFF_DEADLINE + Duration::from_secs(1), &network)
            .await
            .unwrap();
        assert_eq!(diff_requests(&mock).await, vec![(hashes[TIP as usize], target)]);
    }

    /// Stores the header at `height` and tells the manager it is the new
    /// tip. Returns its hash.
    async fn announce_tip(
        manager: &mut MasternodesManager<PersistentBlockHeaderStorage>,
        network: &Arc<dyn NetworkManager>,
        height: u32,
    ) -> BlockHash {
        let header = Header::dummy(height);
        manager
            .header_storage
            .write()
            .await
            .store_headers(&[HashedBlockHeader::from(&header)])
            .await
            .unwrap();
        manager
            .handle_sync_event(
                &SyncEvent::BlockHeadersStored {
                    tip_height: height,
                },
                network,
            )
            .await
            .unwrap();
        header.block_hash()
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
    /// existing budget. Each dispatch goes out through `send_distributed`, whose
    /// round-robin lands it on a different peer than the one that served the bad
    /// response, and a deterministically-bad response still terminates - after
    /// `MAX_RETRY_ATTEMPTS` dispatches, not silently and not never.
    #[tokio::test]
    async fn test_rejected_qrinfo_retries_against_another_peer_then_gives_up() {
        let (mut manager, network, mock, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;
        let peer = "127.0.0.1:19999".parse().unwrap();
        let bad_response = || {
            InboundMessage::new(NetworkMessage::QRInfo(Box::new(qrinfo_with_tip_hash(tip_hash))))
        };

        for attempt in 0..MAX_RETRY_ATTEMPTS - 1 {
            let err = manager
                .handle_message(peer, bad_response(), &network)
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

            manager.tick(&network).await.expect("tick retries the rejected attempt");
            assert_eq!(manager.sync_state.qrinfo_retry_count, attempt + 1);
            assert!(
                mock.sent_messages()
                    .await
                    .iter()
                    .any(|m| matches!(m, NetworkMessage::GetQRInfo(_))),
                "tick must dispatch a retry GetQRInfo"
            );
            assert!(
                !manager.sync_state.qrinfo_in_flight.expect("slot re-armed").rejected,
                "the retry must start as a clean attempt"
            );
            mock.clear_sent().await;
        }

        // Budget spent. The last rejection must terminate rather than dispatch
        // again, and must not park the manager in `Syncing` forever.
        manager
            .handle_message(peer, bad_response(), &network)
            .await
            .expect_err("the engine must reject this filler QRInfo");
        let _ = manager.tick(&network).await;
        assert!(
            !mock.sent_messages().await.iter().any(|m| matches!(m, NetworkMessage::GetQRInfo(_))),
            "the retry budget must stop dispatching after MAX_RETRY_ATTEMPTS"
        );
        assert_eq!(
            manager.progress.qr_infos_requested(),
            MAX_RETRY_ATTEMPTS as u32,
            "exactly MAX_RETRY_ATTEMPTS dispatches: the initial one plus its retries"
        );
        assert_ne!(
            manager.state(),
            SyncState::Syncing,
            "giving up must resolve the state, not leave it silently Syncing"
        );
    }

    /// The stall watchdog is the backstop for every route into the stranded state
    /// that keeping the in-flight flag cannot cover - notably a
    /// `send_qrinfo_for_tip` that returns without dispatching *after* its caller
    /// already cleared the slot, which is exactly what `tick`'s own retry path
    /// does. `Syncing` with nothing in flight and an empty diff pipeline has no
    /// other exit.
    #[tokio::test]
    async fn test_tick_watchdog_redispatches_after_stall() {
        let (mut manager, network, mock, _) = syncing_manager_awaiting_qrinfo(200).await;

        // Strand the manager the way a dispatch failure would.
        manager.sync_state.clear_pending(&network).await;
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(manager.sync_state.qrinfo_in_flight.is_none());
        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());

        manager.tick(&network).await.expect("tick succeeds");
        assert!(
            !mock.sent_messages().await.iter().any(|m| matches!(m, NetworkMessage::GetQRInfo(_))),
            "the watchdog must stay quiet until its interval has elapsed"
        );

        manager.sync_state.last_qrinfo_dispatch = Some(
            Instant::now()
                .checked_sub(QRINFO_STALL_WATCHDOG + Duration::from_secs(1))
                .expect("test host uptime must exceed the watchdog interval"),
        );

        manager.tick(&network).await.expect("the watchdog re-dispatch succeeds");
        assert!(
            mock.sent_messages().await.iter().any(|m| matches!(m, NetworkMessage::GetQRInfo(_))),
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
        let (mut manager, network, mock, tip_hash) = syncing_manager_awaiting_qrinfo(200).await;

        let base = BlockHash::from_slice(&[0x11; 32]).unwrap();
        let target = BlockHash::from_slice(&[0x22; 32]).unwrap();
        manager
            .sync_state
            .mnlistdiff_pipeline
            .queue_requests(DiffKind::WorkBlockList, vec![(base, target)], &network)
            .await;
        manager.sync_state.mnlistdiff_pipeline.send_pending(&network).await.expect("send succeeds");

        manager.on_disconnect();

        assert!(
            !manager.sync_state.mnlistdiff_pipeline.is_complete(),
            "the request itself must survive; the broker reissues it"
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

        // A reconnect restarts the sync from a fresh QRInfo and drops the diff. It must be
        // released too, or the broker keeps retrying it and kicks every peer whose answer we
        // ignore.
        manager.stop_sync();
        manager
            .handle_sync_event(
                &SyncEvent::BlockHeaderSyncComplete {
                    tip_height: 200,
                },
                &network,
            )
            .await
            .expect("the restart succeeds");
        assert!(manager.sync_state.mnlistdiff_pipeline.is_complete());
        assert_eq!(mock.requests_in_play().await, 0, "the dropped diff must be released");
    }

    /// `tick` must reissue MnListDiff requests that a disconnect moved back to
    /// pending. Nothing else can: every other `send_pending` call site hangs off a
    /// response handler, and after a disconnect no response is coming.
    #[tokio::test]
    async fn test_tick_reissues_requeued_mnlistdiffs() {
        let (mut manager, network, mock, _) = syncing_manager_awaiting_qrinfo(200).await;
        manager.sync_state.qrinfo_received();

        let base = BlockHash::from_slice(&[0x11; 32]).unwrap();
        let target = BlockHash::from_slice(&[0x22; 32]).unwrap();
        manager
            .sync_state
            .mnlistdiff_pipeline
            .queue_requests(DiffKind::WorkBlockList, vec![(base, target)], &network)
            .await;
        manager.sync_state.mnlistdiff_pipeline.send_pending(&network).await.expect("send succeeds");
        mock.clear_sent().await;

        manager.on_disconnect();
        assert!(
            !manager.sync_state.mnlistdiff_pipeline.is_complete(),
            "the disconnect must leave the request outstanding, not drop it"
        );
        // The broker drops a keyed duplicate while the original is in play; releasing
        // the slots mirrors what it does on a real disconnect.
        mock.release_requests_in_play().await;

        manager.tick(&network).await.expect("tick reissues the requeued request");
        assert!(
            mock.sent_messages().await.iter().any(|m| matches!(m, NetworkMessage::GetMnListD(_))),
            "tick must reissue the GetMnListDiff"
        );
    }
}
