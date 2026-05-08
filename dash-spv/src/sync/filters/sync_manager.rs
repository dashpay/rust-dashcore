use crate::error::{SyncError, SyncResult};
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage, FilterStorage};
use crate::sync::progress::ProgressPercentage;
use crate::sync::sync_manager::ensure_not_started;
use crate::sync::{
    FiltersManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;

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

    /// Keep `active_batches`, the block-match tracker, pending verified
    /// batches, and the filter pipeline's per-batch trackers. Move in-flight
    /// `getcfilters` slots back to pending so the next `send_pending` reissues
    /// them to the new peer immediately. Without this preservation, a re-scan
    /// after reconnect would re-track the same block hashes and leak
    /// `pending_blocks` counters that never reach zero.
    fn on_disconnect(&mut self) {
        self.filter_pipeline.requeue_in_flight();
    }

    async fn start_sync(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        ensure_not_started(self.state(), self.identifier())?;

        // Resume in-progress work preserved across a disconnect cycle.
        // `on_disconnect` keeps `active_batches`, the block-match tracker, and
        // any pending verified batches; calling `start_download` here would
        // insert a fresh batch at `scan_start` and clobber the existing one,
        // leaking its `pending_blocks` counter forever.
        if !self.active_batches.is_empty() {
            self.filter_pipeline.send_pending(requests, &*self.header_storage.read().await).await?;
            self.set_state(SyncState::Syncing);
            return Ok(vec![]);
        }

        // Check if there are already stored filters we need to process
        // This handles restart where filters are persisted but wallet state isn't
        let stored_filters_tip = self.filter_storage.read().await.filter_tip_height().await?;

        if stored_filters_tip > self.progress.committed_height() {
            tracing::info!(
                "FiltersManager: wallet at height {}, stored filters at {} - starting rescan of stored filters",
                self.progress.committed_height(),
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
        if stored_filters_tip > 0 && stored_filters_tip == self.progress.committed_height() {
            self.progress.update_filter_header_tip_height(stored_filters_tip);
            // Initialize the pipeline at the current tip. On full disconnect in-flight state gets
            // reset, so we need to initialize the pipeline otherwise it would re-queue from height 1.
            self.filter_pipeline.init(stored_filters_tip + 1, stored_filters_tip);
            // Only emit SyncComplete if we've also reached the chain tip
            if self.progress.committed_height() >= self.progress.target_height() {
                self.set_state(SyncState::Synced);
                tracing::info!(
                    "FiltersManager: already synced at height {}",
                    self.progress.committed_height()
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
            tracing::warn!(
                block_hash = %cfilter.block_hash,
                peer = %msg.peer_address(),
                "Received CFilter for unknown block hash, rejecting as invalid"
            );
            // TODO: should we penalize the peer a bit?
            return Err(SyncError::Validation(format!(
                "CFilter references unknown block hash {}",
                cfilter.block_hash
            )));
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
                wallets,
                new_addresses,
                ..
            } => {
                // Record per-wallet processing so a future scan can give a
                // late-added wallet its own pass at this block via the
                // `tracker.track` residual.
                self.tracker.record_processed(*height, *block_hash, wallets);

                // Check if this block is part of our tracked blocks
                if let Some((_, batch_start)) = self.tracker.finish_in_flight(block_hash) {
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

                    // Collect per-wallet new addresses for deferred rescan at commit time.
                    for (wallet_id, addrs) in new_addresses {
                        if addrs.is_empty() {
                            continue;
                        }
                        if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                            batch.add_addresses_for_wallet(*wallet_id, addrs.iter().cloned());
                        }
                    }

                    return self.try_process_batch().await;
                }
            }

            _ => {}
        }

        Ok(vec![])
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // Detect a wallet that was added behind our scan progress and rescan
        // from its `synced_height`. Reset committed_height to the lowest
        // synced_height across the stale wallets only, so already-synced
        // wallets are not re-scanned from scratch.
        if matches!(self.state(), SyncState::Syncing | SyncState::Synced | SyncState::WaitForEvents)
        {
            let committed = self.progress.committed_height();
            let wallet_read = self.wallet.read().await;
            let behind = wallet_read.wallets_behind(committed);
            let stale_min_synced =
                behind.iter().map(|id| wallet_read.wallet_synced_height(id)).min();
            drop(wallet_read);
            if let Some(stale_min_synced) = stale_min_synced {
                tracing::info!(
                    "Wallet synced_height {} fell below filter committed_height {}, restarting scan",
                    stale_min_synced,
                    committed
                );
                self.reset_for_rescan();
                self.progress.update_committed_height(stale_min_synced);
                return self.start_download(requests).await;
            }
        }

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
        self.filter_pipeline.handle_timeouts();

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
