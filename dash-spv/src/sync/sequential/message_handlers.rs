//! Message handlers for synchronization phases.

use std::ops::DerefMut;
use std::time::Instant;

use dashcore::block::Block;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;

use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::PeerId;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::manager::SequentialSyncManager;
use super::phases::SyncPhase;

impl<
        S: StorageManager + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        W: WalletInterface,
    > SequentialSyncManager<S, N, W>
{
    /// Handle incoming network messages with phase filtering
    pub async fn handle_message(
        &mut self,
        message: NetworkMessage,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Special handling for blocks - they can arrive at any time due to filter matches
        if let NetworkMessage::Block(block) = message {
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
        if !self.is_message_expected_in_phase(&message) {
            tracing::debug!(
                "Ignoring unexpected {:?} message in phase {}",
                std::mem::discriminant(&message),
                self.current_phase.name()
            );
            return Ok(());
        }

        // Route to appropriate handler based on current phase
        match (&mut self.current_phase, message) {
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers(headers),
            ) => {
                self.handle_headers_message(headers, network, storage).await?;
            }

            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers2(headers2),
            ) => {
                // Get the actual peer ID from the network manager
                let peer_id = network.get_last_message_peer_id().await;
                self.handle_headers2_message(headers2, peer_id, network, storage).await?;
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

            // Handle compressed headers when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers2(headers2),
            ) => {
                let peer_id = network.get_last_message_peer_id().await;
                self.handle_headers2_message(headers2, peer_id, network, storage).await?;
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
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers2(_),
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
                NetworkMessage::Headers2(_),
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

    pub(super) async fn handle_headers2_message(
        &mut self,
        headers2: dashcore::network::message_headers2::Headers2Message,
        peer_id: PeerId,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync = match self
            .header_sync
            .handle_headers2_message(headers2, peer_id, storage, network)
            .await
        {
            Ok(continue_sync) => continue_sync,
            Err(SyncError::Headers2DecompressionFailed(e)) => {
                // Headers2 decompression failed - we should fall back to regular headers
                tracing::warn!("Headers2 decompression failed: {} - peer may not properly support headers2 or connection issue", e);
                // For now, just return the error. In the future, we could trigger a fallback here
                return Err(SyncError::Headers2DecompressionFailed(e));
            }
            Err(e) => return Err(e),
        };

        // Calculate blockchain height before borrowing self.current_phase
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await.unwrap_or(0);

        // Update phase state and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingHeaders {
            current_height,

            last_progress,
            ..
        } = &mut self.current_phase
        {
            // Update current height - use blockchain height for checkpoint awareness
            *current_height = blockchain_height;

            // Note: We can't easily track headers_downloaded for compressed headers
            // without decompressing first, so we rely on the header sync manager's internal stats

            // Update progress time
            *last_progress = Instant::now();

            // Check if phase is complete
            !continue_sync
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, network, "Headers sync complete via Headers2")
                .await?;

            // Execute the next phase
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    pub(super) async fn handle_headers_message(
        &mut self,
        headers: Vec<dashcore::block::Header>,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync =
            self.header_sync.handle_headers_message(headers.clone(), storage, network).await?;

        // Calculate blockchain height before borrowing self.current_phase
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await.unwrap_or(0);

        // Update phase state and check if we need to transition
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
            // Update current height - use blockchain height for checkpoint awareness
            *current_height = blockchain_height;

            // Update progress
            *headers_downloaded += headers.len() as u32;
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                *headers_per_second = *headers_downloaded as f64 / elapsed;
            }

            // Check if we received empty response (sync complete)
            if headers.is_empty() {
                *received_empty_response = true;
            }

            // Update progress time
            *last_progress = Instant::now();

            // Check if phase is complete
            !continue_sync || *received_empty_response
        } else {
            false
        };

        if should_transition {
            // Flush the header index to disk after headers phase completes
            // This ensures all block hash→height mappings are persisted before moving to next phase
            // Critical for masternode sync which relies on looking up block heights by hash
            if let Some(disk_storage) =
                storage.as_any_mut().downcast_mut::<crate::storage::disk::DiskStorageManager>()
            {
                if let Err(e) = disk_storage.flush_header_index().await {
                    tracing::warn!("⚠️ Failed to flush header index after headers sync: {}", e);
                } else {
                    tracing::info!("💾 Flushed header index after headers sync completion");
                }
            }

            self.transition_to_next_phase(storage, network, "Headers sync complete").await?;

            // Execute the next phase
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    pub(super) async fn handle_mnlistdiff_message(
        &mut self,
        diff: dashcore::network::message_sml::MnListDiff,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync =
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

            // Check if phase is complete
            if !continue_sync {
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

                self.transition_to_next_phase(storage, network, "Masternode sync complete").await?;

                // Execute the next phase
                self.execute_current_phase(network, storage).await?;
            }
        }

        Ok(())
    }

    pub(super) async fn handle_qrinfo_message(
        &mut self,
        qr_info: dashcore::network::message_qrinfo::QRInfo,
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

        // Update phase state - QRInfo processing should complete the masternode sync phase
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

            tracing::info!("✅ QRInfo processing completed, masternode sync phase finished");

            // Transition to next phase (filter headers)
            self.transition_to_next_phase(storage, network, "QRInfo processing completed").await?;

            // Immediately execute the next phase so CFHeaders begins without delay
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    pub(super) async fn handle_cfheaders_message(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Log source peer for CFHeaders batches when possible
        if let Some(addr) = network.get_last_message_peer_addr().await {
            tracing::debug!(
                "📨 Received CFHeaders ({} headers) from {} (stop_hash={})",
                cfheaders.filter_hashes.len(),
                addr,
                cfheaders.stop_hash
            );
        }
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
        cfilter: dashcore::network::message_filter::CFilter,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Include peer address when available for diagnostics
        let peer_addr = network.get_last_message_peer_addr().await;
        match peer_addr {
            Some(addr) => {
                tracing::debug!(
                    "📨 Received CFilter for block {} from {}",
                    cfilter.block_hash,
                    addr
                );
            }
            None => {
                tracing::debug!("📨 Received CFilter for block {}", cfilter.block_hash);
            }
        }

        let mut wallet = self.wallet.write().await;

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

        let matches = self
            .filter_sync
            .check_filter_for_matches(
                &cfilter.filter,
                &cfilter.block_hash,
                wallet.deref_mut(),
                self.config.network,
            )
            .await?;

        drop(wallet);

        if matches {
            // Update filter match statistics
            {
                let mut stats = self.stats.write().await;
                stats.filters_matched += 1;
            }

            tracing::info!("🎯 Filter match found! Requesting block {}", cfilter.block_hash);
            // Request the full block
            let inv = Inventory::Block(cfilter.block_hash);
            network
                .send_message(NetworkMessage::GetData(vec![inv]))
                .await
                .map_err(|e| SyncError::Network(format!("Failed to request block: {}", e)))?;
        }

        // Handle filter message tracking
        let completed_ranges =
            self.filter_sync.mark_filter_received(cfilter.block_hash, storage).await?;

        // Process any newly completed ranges
        if !completed_ranges.is_empty() {
            tracing::debug!("Completed {} filter request ranges", completed_ranges.len());

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
                // For flow control, we need to check:
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
        block: Block,
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

        let relevant_txids = wallet.process_block(&block, block_height, self.config.network).await;

        drop(wallet);

        if !relevant_txids.is_empty() {
            tracing::info!(
                "💰 Found {} relevant transactions in block {} at height {}",
                relevant_txids.len(),
                block_hash,
                block_height
            );
            for txid in &relevant_txids {
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
