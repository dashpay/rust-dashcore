use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage, FilterStorage};
use crate::sync::{
    FiltersManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::collections::HashSet;

#[async_trait]
impl<
        H: BlockHeaderStorage,
        FH: FilterHeaderStorage,
        F: FilterStorage,
        W: WalletInterface + 'static,
    > SyncManager for FiltersManager<H, FH, F, W>
{
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::Filter
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
        &[MessageType::CFilter]
    }

    async fn initialize(&mut self) -> SyncResult<()> {
        let wallet = self.wallet.read().await;
        let synced_height = wallet.synced_height();
        drop(wallet);

        self.progress.update_current_height(synced_height);
        self.set_state(SyncState::WaitingForConnections);

        tracing::info!(
            "FiltersManager initialized at height {}, waiting for filter headers",
            self.progress.current_height()
        );

        Ok(())
    }

    async fn start_sync(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        if self.state() != SyncState::WaitingForConnections {
            tracing::warn!("{} sync already started.", self.identifier());
            return Ok(vec![]);
        }

        // Check if there are already stored filters we need to process
        // This handles restart where filters are persisted but wallet state isn't
        let stored_filters_tip = self.filter_storage.read().await.filter_tip_height().await?;

        if stored_filters_tip > self.progress.current_height() {
            tracing::info!(
                "FiltersManager: wallet at height {}, stored filters at {} - starting rescan of stored filters",
                self.progress.current_height(),
                stored_filters_tip
            );
            // Set filter header tip to stored filters tip - we only scan what's already stored
            self.progress.update_filter_header_tip_height(stored_filters_tip);
            let mut events = vec![SyncEvent::SyncStart {
                identifier: self.identifier(),
            }];
            events.extend(self.start_download(requests).await?);
            return Ok(events);
        }

        // Already at or beyond stored filters tip - check if fully synced
        if stored_filters_tip > 0 && stored_filters_tip == self.progress.current_height() {
            self.progress.update_filter_header_tip_height(stored_filters_tip);
            // Only emit SyncComplete if we've also reached the chain tip
            if self.progress.current_height() >= self.progress.target_height() {
                self.set_state(SyncState::Synced);
                tracing::info!(
                    "FiltersManager: already synced at height {}",
                    self.progress.current_height()
                );
                return Ok(vec![SyncEvent::FiltersSyncComplete {
                    tip_height: stored_filters_tip,
                }]);
            }
            // Caught up to stored filters but chain tip not reached yet
            self.set_state(SyncState::WaitForEvents);
            return Ok(vec![]);
        }

        // No stored filters to process - wait for FilterHeadersSyncComplete events
        self.set_state(SyncState::WaitForEvents);
        Ok(vec![])
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        let NetworkMessage::CFilter(cfilter) = msg.inner() else {
            return Ok(vec![]);
        };

        // Find height for this filter
        let height =
            self.header_storage.read().await.get_header_height_by_hash(&cfilter.block_hash).await?;

        let Some(h) = height else {
            return Ok(vec![]);
        };

        // Buffer filter in pipeline
        self.filter_pipeline.receive_with_data(h, cfilter.block_hash, &cfilter.filter);

        // Send more requests if there are free slots
        let header_storage = self.header_storage.read().await;
        self.filter_pipeline.send_pending(requests, &*header_storage).await?;
        drop(header_storage);

        Ok(self.store_and_match_batches().await?)
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            SyncEvent::FilterHeadersSyncComplete {
                tip_height,
            } => {
                return self.handle_new_filter_headers(*tip_height, requests).await;
            }

            SyncEvent::FilterHeadersStored {
                tip_height,
                ..
            } => {
                return self.handle_new_filter_headers(*tip_height, requests).await;
            }

            // React to BlockProcessed events from the BlocksManager
            SyncEvent::BlockProcessed {
                block_hash,
                height,
                new_addresses,
                ..
            } => {
                // Check if this block is part of our tracked blocks
                if let Some((_, batch_start)) = self.blocks_remaining.remove(block_hash) {
                    // Decrement this batch's pending_blocks count
                    if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                        batch.decrement_pending_blocks();
                        tracing::debug!(
                            "Block {} at height {} processed, batch {} has {} blocks remaining",
                            block_hash,
                            height,
                            batch_start,
                            batch.pending_blocks()
                        );
                    }

                    // Handle new addresses: rescan current batch AND later batches immediately
                    if !new_addresses.is_empty() {
                        let mut events = Vec::new();
                        let addresses_set: HashSet<_> = new_addresses.iter().cloned().collect();

                        // Rescan the CURRENT batch immediately to find blocks that may have
                        // been missed. This is critical when loading from storage where all
                        // blocks are processed in one go - we need to queue any newly
                        // discovered blocks BEFORE processing remaining blocks in the batch.
                        if let Some(batch) = self.active_batches.get(&batch_start) {
                            if batch.scanned() {
                                events.extend(
                                    self.rescan_batch(batch_start, addresses_set.clone()).await?,
                                );
                            }
                        }

                        // Also rescan LATER batches that were already scanned
                        let later_batches: Vec<u32> = self
                            .active_batches
                            .iter()
                            .filter(|(&start, batch)| start > batch_start && batch.scanned())
                            .map(|(&start, _)| start)
                            .collect();

                        for later_start in later_batches {
                            events.extend(
                                self.rescan_batch(later_start, addresses_set.clone()).await?,
                            );
                        }

                        if !events.is_empty() {
                            return Ok(events);
                        }
                    }

                    // Try to commit/scan/create batches
                    return self.try_process_batch().await;
                }
            }

            _ => {}
        }

        Ok(vec![])
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // TODO: Get rid of the send pending in here? Or decouple it from the header storage?
        // Run tick when Syncing OR when Synced with pending work (new blocks arriving)
        let has_pending_work = !self.active_batches.is_empty();
        let should_tick = match self.state() {
            SyncState::Syncing => true,
            SyncState::Synced => has_pending_work,
            _ => false,
        };
        if !should_tick {
            return Ok(vec![]);
        }

        // Handle timeouts
        let timed_out = self.filter_pipeline.handle_timeouts();
        if !timed_out.is_empty() {
            tracing::debug!("Re-queued {} timed out filter batches", timed_out.len());
        }

        // Send pending requests (decoupled from processing)
        let header_storage = self.header_storage.read().await;
        self.filter_pipeline.send_pending(requests, &*header_storage).await?;
        drop(header_storage);

        // Store completed batches and do speculative matching
        let mut events = self.store_and_match_batches().await?;

        // Try to process blocks in current batch
        events.extend(self.try_process_batch().await?);

        Ok(events)
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Filters(self.progress.clone())
    }
}
