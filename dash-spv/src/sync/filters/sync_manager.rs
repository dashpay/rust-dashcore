use crate::error::{SyncError, SyncResult};
use crate::network::{MessageType, NetworkManager, RequestKey};
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage, FilterStorage};
use crate::sync::sync_manager::ensure_not_started;
use crate::sync::{
    FiltersManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;
use std::net::SocketAddr;
use std::sync::Arc;

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

    /// Keep `active_batches`, the block-match tracker, pending verified batches,
    /// and the filter pipeline's per-batch trackers across the disconnect.
    /// In-flight `getcfilters` slots are re-queued by the network manager itself,
    /// and the pipeline's wanted set is preserved so the next `send_pending`
    /// reissues them to the new peer. Without this preservation, a re-scan after
    /// reconnect would re-track the same block hashes and leak `pending_blocks`
    /// counters that never reach zero.
    fn on_disconnect(&mut self) {}

    async fn start_sync(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        ensure_not_started(self.state(), self.identifier())?;

        // Resume in-progress work preserved across a disconnect cycle.
        // `on_disconnect` keeps `active_batches`, the block-match tracker, and
        // any pending verified batches; calling `start_download` here would
        // insert a fresh batch at `scan_start` and clobber the existing one,
        // leaking its `pending_blocks` counter forever.
        if !self.active_batches.is_empty() {
            self.filter_pipeline.send_pending(network, &*self.header_storage.read().await).await?;
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
            events.extend(self.start_download(network).await?);
            return Ok(events);
        }

        // Already at or beyond stored filters tip - delegate to start_download,
        // whose early-return path anchors the store and processing cursors at
        // the frontier and parks the idle pipeline there. Unlike the branch
        // above this must not emit a SyncStart.
        if stored_filters_tip > 0 && stored_filters_tip == self.progress.committed_height() {
            self.progress.update_filter_header_tip_height(stored_filters_tip);
            return self.start_download(network).await;
        }

        // No stored filters to process - wait for FilterHeadersSyncComplete events
        self.set_state(SyncState::WaitForEvents);
        Ok(vec![])
    }

    async fn handle_message(
        &mut self,
        peer: SocketAddr,
        msg: NetworkMessage,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let NetworkMessage::CFilter(cfilter) = &msg else {
            return Ok(vec![]);
        };

        // Find height for this filter
        let height =
            self.header_storage.read().await.get_header_height_by_hash(&cfilter.block_hash).await?;

        let Some(h) = height else {
            tracing::warn!(
                block_hash = %cfilter.block_hash,
                peer = %peer,
                "Received CFilter for unknown block hash, rejecting as invalid"
            );
            // TODO: should we penalize the peer a bit?
            return Err(SyncError::Validation(format!(
                "CFilter references unknown block hash {}",
                cfilter.block_hash
            )));
        };

        // Buffer filter in pipeline
        let batch_completed =
            self.filter_pipeline.receive_with_data(h, cfilter.block_hash, &cfilter.filter);

        // A completed batch == one `getcfilters` request fully answered: free that
        // peer's in-flight unit (the reader skips per-`cfilter` decrements) and stop
        // the network manager tracking the batch for timeout.
        if let Some(batch_start) = batch_completed {
            network.request_completed(peer, 1).await;
            network.request_answered(RequestKey::CFilters(batch_start)).await;
        }

        // No `send_pending` here: the whole wanted set is already declared to the
        // broker, which paces it out as capacity frees. Re-declaring per received
        // `cfilter` would re-scan every wanted batch on the hot path. The tick
        // re-declares to pick up newly-available batches.

        Ok(self.store_and_match_batches().await?)
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            SyncEvent::FilterHeadersSyncComplete {
                tip_height,
            } => {
                return self.handle_new_filter_headers(*tip_height, network).await;
            }

            SyncEvent::FilterHeadersStored {
                tip_height,
                ..
            } => {
                return self.handle_new_filter_headers(*tip_height, network).await;
            }

            // React to BlockProcessed events from the BlocksManager
            SyncEvent::BlockProcessed {
                block_hash,
                height,
                wallets,
                new_scripts,
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

                    // Collect per-wallet new scripts for deferred rescan at commit time.
                    for (wallet_id, scripts) in new_scripts {
                        if scripts.is_empty() {
                            continue;
                        }
                        if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                            batch.add_scripts_for_wallet(*wallet_id, scripts.iter().cloned());
                        }
                    }

                    return self.try_process_batch().await;
                }
            }

            _ => {}
        }

        Ok(vec![])
    }

    async fn tick(&mut self, network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
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
            let birth_height = wallet_read.earliest_required_height().await;
            drop(wallet_read);
            if let Some(stale_min_synced) = stale_min_synced {
                // Where a restart would actually resume: `start_download` floors the
                // scan at the wallets' birth heights and at the stored headers' start.
                let scan_floor = birth_height
                    .max(self.header_storage.read().await.get_start_height().await.unwrap_or(0));
                let restart_at = stale_min_synced.saturating_add(1).max(scan_floor);
                // Restart only if that reaches below the committed frontier. Comparing
                // the raw `synced_height` instead would fire on every tick for a wallet
                // that reports 0 yet needs nothing below the floor, wiping the in-flight
                // filter batches before any can complete.
                if restart_at <= committed {
                    tracing::info!(
                        "Wallet synced_height {} fell below filter committed_height {}, restarting scan at {}",
                        stale_min_synced,
                        committed,
                        restart_at
                    );
                    self.reset_for_rescan();
                    self.progress.update_committed_height(stale_min_synced);
                    return self.start_download(network).await;
                }
            }
        }

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

        // Timeouts/retry are the network manager's job now (the broker re-injects);
        // just (re-)declare pending requests (decoupled from processing).
        let header_storage = self.header_storage.read().await;
        self.filter_pipeline.send_pending(network, &*header_storage).await?;
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
