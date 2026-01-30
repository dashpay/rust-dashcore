//! Message handlers for synchronization phases.

use dashcore::bip158::BlockFilter;
use dashcore::block::Block;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use std::collections::HashMap;
use std::time::Instant;

use super::manager::SyncManager;
use super::phases::SyncPhase;
use crate::error::{SyncError, SyncResult};
use crate::network::{Message, NetworkManager};
use crate::storage::StorageManager;
use key_wallet_manager::wallet_interface::WalletInterface;
use key_wallet_manager::wallet_manager::{check_compact_filters_for_addresses, FilterMatchKey};

impl<S: StorageManager, N: NetworkManager, W: WalletInterface> SyncManager<S, N, W> {
    /// Handle incoming network messages with phase filtering
    pub async fn handle_message(
        &mut self,
        message: &Message,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Special handling for blocks - they can arrive at any time due to filter matches
        if let NetworkMessage::Block(block) = message.inner() {
            // Always handle blocks when they arrive, regardless of phase
            // This is important because we request blocks when filters match
            tracing::info!(
                "📦 Received block {} (current phase: {})",
                block.block_hash(),
                self.current_phase.name()
            );

            // If we're in the DownloadingBlocks phase, handle it there
            return if matches!(self.current_phase, SyncPhase::DownloadingBlocks { .. }) {
                self.handle_block_message(block, network, storage).await
            } else if matches!(self.current_phase, SyncPhase::DownloadingMnList { .. }) {
                // During masternode sync, blocks are not processed
                tracing::debug!("Block received during MnList phase - ignoring");
                Ok(())
            } else {
                // Otherwise, just track that we received it but don't process for phase transitions
                // The block will be processed by the client's block processor
                tracing::debug!("Block received outside of DownloadingBlocks phase - will be processed by block processor");
                Ok(())
            };
        }

        // Check if this message is expected in the current phase
        if !self.is_message_expected_in_phase(message.inner()) {
            tracing::debug!(
                "Ignoring unexpected {:?} message in phase {}",
                std::mem::discriminant(message.inner()),
                self.current_phase.name()
            );
            return Ok(());
        }

        // Route to appropriate handler based on current phase
        match (&mut self.current_phase, message.inner()) {
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers(headers),
            ) => {
                self.handle_headers_message(headers, network, storage).await?;
            }
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::MnListDiff(diff),
            ) => {
                self.handle_mnlistdiff_message(diff, network, storage).await?;
            }

            (
                SyncPhase::DownloadingCFHeaders {
                    ..
                },
                NetworkMessage::CFHeaders(cfheaders),
            ) => {
                tracing::debug!(
                    "📨 Received CFHeaders ({} headers) from {} (stop_hash={})",
                    cfheaders.filter_hashes.len(),
                    message.peer_address(),
                    cfheaders.stop_hash
                );
                self.handle_cfheaders_message(cfheaders, network, storage).await?;
            }

            (
                SyncPhase::DownloadingFilters {
                    ..
                },
                NetworkMessage::CFilter(cfilter),
            ) => {
                self.handle_cfilter_message(cfilter, network, storage).await?;
            }

            // Handle headers when fully synced (from new block announcements)
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers(headers),
            ) => {
                self.handle_new_headers(headers, network, storage).await?;
            }

            // Handle filter headers when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFHeaders(cfheaders),
            ) => {
                self.handle_post_sync_cfheaders(cfheaders, network, storage).await?;
            }

            // Handle filters when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFilter(cfilter),
            ) => {
                self.handle_post_sync_cfilter(cfilter, network, storage).await?;
            }

            // Handle masternode diffs when fully synced (for ChainLock validation)
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::MnListDiff(diff),
            ) => {
                self.handle_post_sync_mnlistdiff(diff, network, storage).await?;
            }

            // Handle QRInfo in masternode downloading phase
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::QRInfo(qr_info),
            ) => {
                self.handle_qrinfo_message(qr_info, network, storage).await?;
            }

            // Handle QRInfo when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::QRInfo(qr_info),
            ) => {
                self.handle_qrinfo_message(qr_info, network, storage).await?;
            }

            _ => {
                tracing::debug!("Message type not handled in current phase");
            }
        }

        Ok(())
    }

    /// Check if a message is expected in the current phase
    fn is_message_expected_in_phase(&self, message: &NetworkMessage) -> bool {
        match (&self.current_phase, message) {
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers(_),
            ) => true,
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::MnListDiff(_),
            ) => true,
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::QRInfo(_),
            ) => true, // Allow QRInfo during masternode sync
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::Block(_),
            ) => true, // Allow blocks during masternode sync
            (
                SyncPhase::DownloadingCFHeaders {
                    ..
                },
                NetworkMessage::CFHeaders(_),
            ) => true,
            (
                SyncPhase::DownloadingFilters {
                    ..
                },
                NetworkMessage::CFilter(_),
            ) => true,
            (
                SyncPhase::DownloadingBlocks {
                    ..
                },
                NetworkMessage::Block(_),
            ) => true,
            // During FullySynced phase, we need to accept sync maintenance messages
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFHeaders(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFilter(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::MnListDiff(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::QRInfo(_),
            ) => true, // Allow QRInfo when fully synced
            _ => false,
        }
    }

    pub(super) async fn handle_headers_message(
        &mut self,
        headers: &[dashcore::block::Header],
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync =
            self.header_sync.handle_headers_message(headers, storage, network).await?;

        self.finalize_headers_sync(
            continue_sync,
            headers.len() as u32,
            network,
            storage,
            "Headers sync complete",
        )
        .await
    }

    /// Common logic for finalizing header sync after processing headers (regular or compressed).
    /// Updates phase state, marks completion, and triggers phase transition if needed.
    async fn finalize_headers_sync(
        &mut self,
        continue_sync: bool,
        headers_count: u32,
        network: &mut N,
        storage: &mut S,
        transition_reason: &str,
    ) -> SyncResult<()> {
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await;

        let should_transition = if let SyncPhase::DownloadingHeaders {
            current_height,
            headers_downloaded,
            start_time,
            headers_per_second,
            received_empty_response,
            last_progress,
            ..
        } = &mut self.current_phase
        {
            *current_height = blockchain_height;

            *headers_downloaded += headers_count;
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                *headers_per_second = *headers_downloaded as f64 / elapsed;
            }

            // Mark sync complete - this flag is checked by are_headers_complete() during transition
            if !continue_sync {
                *received_empty_response = true;
            }

            *last_progress = Instant::now();

            !continue_sync
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, network, transition_reason).await?;
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    pub(super) async fn handle_mnlistdiff_message(
        &mut self,
        diff: &dashcore::network::message_sml::MnListDiff,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        self.masternode_sync.handle_mnlistdiff_message(diff, storage, network).await?;

        // Update phase state
        if let SyncPhase::DownloadingMnList {
            current_height,
            diffs_processed,
            ..
        } = &mut self.current_phase
        {
            // Update current height from storage
            if let Ok(Some(state)) = storage.load_masternode_state().await {
                *current_height = state.last_height;
            }

            *diffs_processed += 1;
            self.current_phase.update_progress();

            // Check if phase is complete by verifying masternode sync is no longer in progress
            // This ensures we wait for all pending MnListDiff requests to be received
            if !self.masternode_sync.is_syncing() {
                // Masternode sync has completed - ensure phase state reflects this
                // by updating target_height to match current_height before transition
                if let SyncPhase::DownloadingMnList {
                    current_height,
                    target_height,
                    ..
                } = &mut self.current_phase
                {
                    // Force completion state by ensuring current >= target
                    if *current_height < *target_height {
                        *target_height = *current_height;
                    }
                }

                tracing::info!("✅ All MnListDiff requests completed, transitioning to next phase");
                self.transition_to_next_phase(storage, network, "Masternode sync complete").await?;

                // Execute the next phase
                self.execute_current_phase(network, storage).await?;
            }
        }

        Ok(())
    }

    pub(super) async fn handle_qrinfo_message(
        &mut self,
        qr_info: &dashcore::network::message_qrinfo::QRInfo,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        tracing::info!("🔄 Sequential sync manager handling QRInfo message (unified processing)");

        // Get sync base height for height conversion
        let sync_base_height = self.header_sync.get_sync_base_height();
        tracing::debug!(
            "Using sync_base_height={} for masternode validation height conversion",
            sync_base_height
        );

        // Process QRInfo with full block height feeding and comprehensive processing
        self.masternode_sync.handle_qrinfo_message(qr_info.clone(), storage, network).await;

        // Check if QRInfo processing completed successfully
        if let Some(error) = self.masternode_sync.last_error() {
            tracing::error!("❌ QRInfo processing failed: {}", error);
            return Err(SyncError::Validation(error.to_string()));
        }

        // Update phase state
        if let SyncPhase::DownloadingMnList {
            current_height,
            diffs_processed,
            ..
        } = &mut self.current_phase
        {
            // Update current height from storage
            if let Ok(Some(state)) = storage.load_masternode_state().await {
                *current_height = state.last_height;
            }
            *diffs_processed += 1;
            self.current_phase.update_progress();

            // Check if masternode sync is complete (all pending MnListDiff requests received)
            if !self.masternode_sync.is_syncing() {
                tracing::info!("✅ QRInfo processing completed with all MnListDiff requests, masternode sync phase finished");

                // Transition to next phase (filter headers)
                self.transition_to_next_phase(storage, network, "QRInfo processing completed")
                    .await?;

                // Immediately execute the next phase so CFHeaders begins without delay
                self.execute_current_phase(network, storage).await?;
            } else {
                tracing::info!(
                    "⏳ QRInfo processing completed, waiting for pending MnListDiff responses before transitioning"
                );
            }
        }

        Ok(())
    }

    pub(super) async fn handle_cfheaders_message(
        &mut self,
        cfheaders: &dashcore::network::message_filter::CFHeaders,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync =
            self.filter_sync.handle_cfheaders_message(cfheaders.clone(), storage, network).await?;

        // Update phase state
        if let SyncPhase::DownloadingCFHeaders {
            current_height,
            cfheaders_downloaded,
            start_time,
            cfheaders_per_second,
            ..
        } = &mut self.current_phase
        {
            // Update current height
            if let Ok(Some(tip)) = storage.get_filter_tip_height().await {
                *current_height = tip;
            }

            // Update progress
            *cfheaders_downloaded += cfheaders.filter_hashes.len() as u32;
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                *cfheaders_per_second = *cfheaders_downloaded as f64 / elapsed;
            }

            self.current_phase.update_progress();

            // Check if phase is complete
            if !continue_sync {
                self.transition_to_next_phase(storage, network, "Filter headers sync complete")
                    .await?;

                // Execute the next phase
                self.execute_current_phase(network, storage).await?;
            }
        }

        Ok(())
    }

    pub(super) async fn handle_cfilter_message(
        &mut self,
        cfilter: &dashcore::network::message_filter::CFilter,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        tracing::debug!("📨 Received CFilter for block {}", cfilter.block_hash);

        // Check filter against wallet if available
        // First, verify filter data matches expected filter header chain
        let height = storage
            .get_header_height_by_hash(&cfilter.block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter block height: {}", e)))?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "Block height not found for cfilter block {}",
                    cfilter.block_hash
                ))
            })?;

        let header_ok = self
            .filter_sync
            .verify_cfilter_against_headers(&cfilter.filter, height, &*storage)
            .await?;

        if !header_ok {
            tracing::warn!(
                "Rejecting CFilter for block {} at height {} due to header mismatch",
                cfilter.block_hash,
                height
            );
            return Ok(());
        }

        // Store the verified filter to disk
        storage
            .store_filter(height, &cfilter.filter)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store filter: {}", e)))?;

        self.wallet.write().await.update_synced_height(height);

        let key = FilterMatchKey::new(height, cfilter.block_hash);
        let input = HashMap::from([(key, BlockFilter::new(&cfilter.filter))]);
        let addresses = self.wallet.read().await.monitored_addresses();
        let matches = check_compact_filters_for_addresses(&input, addresses);

        if !matches.is_empty() {
            tracing::info!("🎯 Filter match found! Requesting block {}", cfilter.block_hash);
            // Request the full block
            let inv = Inventory::Block(cfilter.block_hash);
            network
                .send_message(NetworkMessage::GetData(vec![inv]))
                .await
                .map_err(|e| SyncError::Network(format!("Failed to request block: {}", e)))?;
        }

        // Handle filter message tracking
        self.filter_sync.mark_filter_received(cfilter.block_hash, storage).await?;

        // Send more filter requests from the queue if we have available slots
        if self.filter_sync.has_pending_filter_requests() {
            let available_slots = self.filter_sync.get_available_request_slots();
            if available_slots > 0 {
                tracing::debug!(
                    "Sending more filter requests: {} slots available, {} pending",
                    available_slots,
                    self.filter_sync.pending_download_count()
                );
                self.filter_sync.send_next_filter_batch(network).await?;
            } else {
                tracing::trace!(
                    "No available slots for more filter requests (all {} slots in use)",
                    self.filter_sync.active_request_count()
                );
            }
        } else {
            tracing::trace!("No more pending filter requests in queue");
        }

        // Update phase state
        if let SyncPhase::DownloadingFilters {
            completed_heights,
            batches_processed,
            total_filters,
            ..
        } = &mut self.current_phase
        {
            // Mark this height as completed
            if let Ok(Some(height)) = storage.get_header_height_by_hash(&cfilter.block_hash).await {
                completed_heights.insert(height);

                // Log progress periodically
                if completed_heights.len() % 100 == 0
                    || completed_heights.len() == *total_filters as usize
                {
                    tracing::info!(
                        "📊 Filter download progress: {}/{} filters received",
                        completed_heights.len(),
                        total_filters
                    );
                }
            }

            *batches_processed += 1;
            self.current_phase.update_progress();

            // Check if all filters are downloaded
            // We need to track actual completion, not just request status
            if let SyncPhase::DownloadingFilters {
                total_filters,
                completed_heights,
                ..
            } = &self.current_phase
            {
                // We need to check:
                // 1. All expected filters have been received (completed_heights matches total_filters)
                // 2. No more active or pending requests
                let has_pending = self.filter_sync.pending_download_count() > 0
                    || self.filter_sync.active_request_count() > 0;

                let all_received =
                    *total_filters > 0 && completed_heights.len() >= *total_filters as usize;

                // Only transition when we've received all filters AND no requests are pending
                if all_received && !has_pending {
                    tracing::info!(
                        "All {} filters received and processed",
                        completed_heights.len()
                    );
                    self.transition_to_next_phase(storage, network, "All filters downloaded")
                        .await?;

                    // Execute the next phase
                    self.execute_current_phase(network, storage).await?;
                } else if *total_filters == 0 && !has_pending {
                    // Edge case: no filters to download
                    self.transition_to_next_phase(storage, network, "No filters to download")
                        .await?;

                    // Execute the next phase
                    self.execute_current_phase(network, storage).await?;
                } else {
                    tracing::trace!(
                        "Filter sync progress: {}/{} received, {} active requests",
                        completed_heights.len(),
                        total_filters,
                        self.filter_sync.active_request_count()
                    );
                }
            }
        }

        Ok(())
    }

    pub(super) async fn handle_block_message(
        &mut self,
        block: &Block,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let block_hash = block.block_hash();

        // Process the block through the wallet if available
        let mut wallet = self.wallet.write().await;

        // Get the block height from storage
        let block_height = storage
            .get_header_height_by_hash(&block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get block height: {}", e)))?
            .unwrap_or(0);

        let result = wallet.process_block(block, block_height).await;

        drop(wallet);

        let total_relevant = result.relevant_tx_count();
        if total_relevant > 0 {
            tracing::info!(
                "Found {} relevant transactions ({} new, {} existing) in block {} at height {}",
                total_relevant,
                result.new_txids.len(),
                result.existing_txids.len(),
                block_hash,
                block_height
            );
            for txid in result.relevant_txids() {
                tracing::debug!("  - Transaction: {}", txid);
            }
        }

        // Handle block download and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingBlocks {
            downloading,
            completed,
            last_progress,
            ..
        } = &mut self.current_phase
        {
            // Remove from downloading
            downloading.remove(&block_hash);

            // Add to completed
            completed.push(block_hash);

            // Update progress time
            *last_progress = Instant::now();

            // Check if all blocks are downloaded
            downloading.is_empty() && self.no_more_pending_blocks()
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, network, "All blocks downloaded").await?;

            // Execute the next phase (if any)
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }
}
