use crate::error::SyncResult;
use crate::network::{Message, MessageType, NetworkEvent, RequestSender};
use crate::storage::{BlockHeaderStorage, MetadataStorage};
use crate::sync::sync_manager::ensure_not_started;
use crate::sync::{
    BlockHeadersManager, ManagerIdentifier, ProgressPercentage, SyncEvent, SyncManager,
    SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;
use std::time::{Duration, Instant};

/// Timeout waiting for unsolicited header messages after a block announcement.
pub(super) const UNSOLICITED_HEADERS_WAIT_TIMEOUT: Duration = Duration::from_secs(3);

#[async_trait]
impl<H: BlockHeaderStorage, M: MetadataStorage> SyncManager for BlockHeadersManager<H, M> {
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::BlockHeader
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
        &[MessageType::Headers, MessageType::Inv]
    }

    fn clear_in_flight_state(&mut self) {
        // Drop only per-peer in-flight bookkeeping. Segment topology and
        // validated chain state per segment (current_tip_hash, current_height,
        // buffered_headers, complete) are preserved so a reconnect can resume
        // from where the disconnected peer left off without re-fetching headers
        // we already have.
        self.pipeline.clear_in_flight();
        self.pending_announcements.clear();
        self.announced_peers.clear();
    }

    async fn start_sync(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        ensure_not_started(self.state(), self.identifier())?;
        self.progress.set_state(SyncState::Syncing);

        if !self.pipeline.is_initialized() {
            let tip = self.tip().await?;
            let target_height = self.progress.target_height();

            // Initialize the pipeline with checkpoint-based segments
            self.pipeline.init(tip.height(), *tip.hash(), target_height);

            tracing::info!(
                "Starting parallel header sync from {} to {} ({} segments)",
                tip.height(),
                target_height,
                self.pipeline.segment_count()
            );
        } else {
            // Resume path: if we previously synced past the tip the open-ended
            // segment is marked complete and `send_pending` would skip it.
            // Reset it so a fresh GetHeaders is fired from the preserved
            // `current_tip_hash`. No-op if the tip is still mid-sync.
            self.pipeline.reset_tip_segment();
            tracing::info!(
                "Resuming parallel header sync ({} segments, {} buffered)",
                self.pipeline.segment_count(),
                self.pipeline.total_buffered()
            );
        }

        // Send initial batch of requests
        let sent = self.pipeline.send_pending(requests)?;
        tracing::info!("Pipeline: sent {} initial requests", sent);

        Ok(vec![SyncEvent::SyncStart {
            identifier: self.identifier(),
        }])
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::Headers(headers) => {
                // Always route through pipeline when initialized
                self.handle_headers_pipeline(headers, requests).await
            }

            NetworkMessage::Inv(inv) => {
                self.handle_inventory(inv, requests).await?;
                Ok(vec![])
            }

            _ => Ok(vec![]),
        }
    }

    async fn handle_sync_event(
        &mut self,
        _event: &SyncEvent,
        _requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // BlockHeadersManager doesn't react to events from other managers
        Ok(vec![])
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        if !self.pipeline.is_initialized() {
            return Ok(vec![]);
        }

        self.pipeline.handle_timeouts();

        // During initial sync, send more requests and log progress
        if self.state() == SyncState::Syncing {
            let sent = self.pipeline.send_pending(requests)?;
            if sent > 0 {
                tracing::debug!("Tick: pipeline sent {} more requests", sent);
            }

            return Ok(vec![]);
        }

        // Post-sync: check for stale block announcements
        if self.state() == SyncState::Synced {
            let now = Instant::now();
            let stale: Vec<BlockHash> = self
                .pending_announcements
                .iter()
                .filter(|(_, announced_at)| {
                    now.duration_since(**announced_at) > UNSOLICITED_HEADERS_WAIT_TIMEOUT
                })
                .map(|(hash, _)| *hash)
                .collect();

            if !stale.is_empty() {
                tracing::info!(
                    "Sending fallback GetHeaders for {} stale announcements",
                    stale.len()
                );

                // Reset tip segment and send requests via pipeline
                self.pipeline.reset_tip_segment();
                self.pipeline.send_pending(requests)?;

                for hash in stale {
                    self.pending_announcements.remove(&hash);
                }
            }
        }

        Ok(vec![])
    }

    async fn handle_network_event(
        &mut self,
        event: &NetworkEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            NetworkEvent::PeerConnected {
                address,
            } => {
                // When synced, send GetHeaders to new peers so Dash Core learns our tip
                // and sends header announcements instead of inv. Skip when the
                // pipeline has an active catch-up request to avoid the empty
                // response prematurely completing the tip segment.
                if self.state() == SyncState::Synced
                    && self.pipeline.is_initialized()
                    && !self.announced_peers.contains(address)
                    && !self.pipeline.tip_segment_has_pending_request()
                {
                    let tip = self.tip().await?;
                    tracing::info!("Announcing tip {} to new peer {}", tip.height(), address);
                    requests.request_block_headers_from_peer(*tip.hash(), *address)?;
                    self.announced_peers.insert(*address);
                }
            }
            NetworkEvent::PeerDisconnected {
                address,
            } => {
                self.announced_peers.remove(address);
            }
            NetworkEvent::PeersUpdated {
                connected_count,
                best_height,
                ..
            } => {
                if let Some(best_height) = best_height {
                    self.progress.update_target_height(*best_height);
                    let mut metadata_storage = self.metadata_storage.write().await;
                    metadata_storage.store_last_target_height(*best_height).await?;
                }
                if *connected_count == 0 {
                    self.stop_sync();
                } else if *connected_count > 0 {
                    if self.state() == SyncState::WaitingForConnections {
                        return self.start_sync(requests).await;
                    }
                    // When already synced but behind peer height, request missing headers
                    if self.state() == SyncState::Synced {
                        if let Some(best_height) = best_height {
                            if *best_height > self.progress.tip_height()
                                && !self.pipeline.tip_segment_has_pending_request()
                            {
                                tracing::info!(
                                    "Peer height {} > our height {}, requesting headers to catch up",
                                    best_height,
                                    self.progress.tip_height()
                                );
                                // Reset tip segment and send requests via pipeline
                                self.pipeline.reset_tip_segment();
                                self.pipeline.send_pending(requests)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        let mut progress = self.progress.clone();
        progress.update_buffered(self.pipeline.total_buffered());
        SyncManagerProgress::BlockHeaders(progress)
    }
}
