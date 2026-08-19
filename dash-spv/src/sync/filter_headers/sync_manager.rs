use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage};
use crate::sync::filter_headers::pipeline::FilterHeadersPipeline;
use crate::sync::progress::ProgressPercentage;
use crate::sync::{
    FilterHeadersManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::SyncError;
use async_trait::async_trait;

#[async_trait]
impl<H: BlockHeaderStorage, FH: FilterHeaderStorage> SyncManager for FilterHeadersManager<H, FH> {
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::FilterHeader
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
        &[MessageType::CFHeaders]
    }

    fn on_disconnect(&mut self) {
        self.pipeline = FilterHeadersPipeline::default();
        self.checkpoint_start_height = None;
        self.block_headers_synced = false;
    }

    fn on_peer_disconnect(&mut self) {
        self.pipeline.requeue_in_flight();
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Match response to get start height
        let Some((start_height, cfheaders)) = self.pipeline.match_response(msg.inner()) else {
            if self.pipeline.is_complete() {
                if let Some(event) = self.try_complete_sync() {
                    return Ok(vec![event]);
                }
            }
            return Ok(vec![]);
        };

        let mut events = Vec::new();

        // Try to receive (may buffer if out of order)
        if let Some(data) = self.pipeline.receive(start_height, cfheaders) {
            // In order - process immediately
            let count = self.process_cfheaders(&data, start_height).await?;
            if count == 0 {
                return Err(SyncError::Network("CFHeaders batch contained no headers".to_string()));
            }
            let batch_start = start_height;
            let batch_end = start_height + count.saturating_sub(1);

            // Advance and capture any buffered batches that are now ready
            let mut ready_batches = self.pipeline.advance(count);
            self.progress.update_current_height(self.pipeline.next_expected().saturating_sub(1));

            tracing::debug!(
                "Processed {} filter headers at {}, now at {}/{}",
                count,
                start_height,
                self.progress.current_height(),
                self.progress.block_header_tip_height()
            );

            // Emit event for this batch
            events.push(SyncEvent::FilterHeadersStored {
                start_height: batch_start,
                end_height: batch_end,
                tip_height: self.progress.current_height(),
            });

            // Process buffered responses (including any returned by first advance)
            while !ready_batches.is_empty() {
                // Take ownership and process each batch
                for (height, data) in std::mem::take(&mut ready_batches) {
                    let count = self.process_cfheaders(&data, height).await?;
                    if count == 0 {
                        return Err(SyncError::Network(
                            "CFHeaders batch contained no headers".to_string(),
                        ));
                    }
                    // Get more ready batches (advance returns any that are now ready)
                    let more_ready = self.pipeline.advance(count);
                    ready_batches.extend(more_ready);
                    self.progress
                        .update_current_height(self.pipeline.next_expected().saturating_sub(1));

                    events.push(SyncEvent::FilterHeadersStored {
                        start_height: height,
                        end_height: height + count.saturating_sub(1),
                        tip_height: self.progress.current_height(),
                    });
                }
            }
        } else {
            tracing::debug!(
                "Buffered out-of-order CFHeaders at {} (expecting {})",
                start_height,
                self.pipeline.next_expected()
            );
        }

        // Send more requests
        self.pipeline.send_pending(requests)?;

        if self.pipeline.is_complete() {
            if let Some(event) = self.try_complete_sync() {
                events.push(event);
            }
        }

        Ok(events)
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            SyncEvent::BlockHeaderSyncComplete {
                tip_height,
            } => {
                self.block_headers_synced = true;
                self.handle_new_headers(*tip_height, requests).await
            }
            SyncEvent::BlockHeadersStored {
                tip_height,
            } => self.handle_new_headers(*tip_height, requests).await,
            _ => Ok(vec![]),
        }
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // Handle timed out requests (re-queues them for retry)
        self.pipeline.handle_timeouts();

        // Send pending requests (including retries)
        self.pipeline.send_pending(requests)?;

        // Re-read the block-header tip and extend from here if it moved.
        //
        // `handle_new_headers` — the only thing that ever extends the
        // CFHeaders queue — runs solely off `BlockHeaderSyncComplete` and
        // `BlockHeadersStored`. Header storage can advance without either
        // reaching this manager: a segment that completes out of order
        // promotes a run of buffered headers, and on a mainnet scan that is
        // how the last stretch of the chain lands. When it does, this
        // manager keeps the target it was last told about, its queue drains,
        // and nothing re-arms it — filter headers stop for good while block
        // headers, ChainLocks and inv announcements carry on, so the client
        // looks alive while sync is frozen. Observed on a mainnet restore:
        // the queue was last extended to height 2_398_000, block headers
        // reached 2_523_515 twenty-four minutes later, and filter headers
        // never moved again.
        //
        // Same fix as promoting finished header segments from the tick
        // (#960): trust the tick, not the message.
        if let Some(tip) = self.stored_block_header_tip().await {
            if tip > self.progress.block_header_tip_height() {
                return self.handle_new_headers(tip, requests).await;
            }
        }

        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::FilterHeaders(self.progress.clone())
    }
}
