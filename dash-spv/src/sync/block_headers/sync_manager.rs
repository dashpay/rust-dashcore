use crate::error::SyncResult;
use crate::network::{Message, MessageType, NetworkEvent, RequestSender};
use crate::storage::BlockHeaderStorage;
use crate::sync::{
    BlockHeadersManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::SyncError;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use dashcore::BlockHash;
use std::time::{Duration, Instant};

/// Timeout waiting for unsolicited header messages after a block announcement.
pub(super) const UNSOLICITED_HEADERS_WAIT_TIMEOUT: Duration = Duration::from_secs(3);

#[async_trait]
impl<H: BlockHeaderStorage> SyncManager for BlockHeadersManager<H> {
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

    async fn initialize(&mut self) -> SyncResult<()> {
        let tip = self
            .header_storage
            .read()
            .await
            .get_tip()
            .await
            .ok_or_else(|| SyncError::MissingDependency("No tip in storage".to_string()))?;

        self.progress.set_state(SyncState::WaitingForConnections);
        self.progress.update_current_height(tip.height());
        self.progress.update_target_height(tip.height());

        tracing::info!("BlockHeadersManager initialized at height {}", tip.height());

        Ok(())
    }

    async fn start_sync(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        if self.state() != SyncState::WaitingForConnections {
            tracing::warn!("{} sync already started.", self.identifier());
            return Ok(vec![]);
        }
        self.progress.set_state(SyncState::Syncing);

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
        if let NetworkEvent::PeersUpdated {
            connected_count,
            best_height,
            ..
        } = event
        {
            if let Some(best_height) = best_height {
                self.progress.update_target_height(*best_height);
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
                        if *best_height > self.progress.current_height()
                            && !self.pipeline.tip_segment_has_pending_request()
                        {
                            tracing::info!(
                                "Peer height {} > our height {}, requesting headers to catch up",
                                best_height,
                                self.progress.current_height()
                            );
                            // Reset tip segment and send requests via pipeline
                            self.pipeline.reset_tip_segment();
                            self.pipeline.send_pending(requests)?;
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
