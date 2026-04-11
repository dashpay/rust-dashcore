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

    fn clear_in_flight_state(&mut self) {
        self.pipeline = FilterHeadersPipeline::default();
        self.checkpoint_start_height = None;
        self.block_headers_synced = false;
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
        // Handle timed out requests
        let failed = self.pipeline.handle_timeouts();
        if !failed.is_empty() {
            return Err(SyncError::Timeout(format!(
                "CFHeaders batches exceeded max retries at heights: {:?}",
                failed
            )));
        }

        // Send pending requests (including retries)
        self.pipeline.send_pending(requests)?;

        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::FilterHeaders(self.progress.clone())
    }
}
