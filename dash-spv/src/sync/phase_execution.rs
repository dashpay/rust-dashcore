//! Phase execution, transitions, timeout handling, and recovery logic.

use std::time::Instant;

use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::manager::SyncManager;
use super::phases::SyncPhase;

impl<S: StorageManager, N: NetworkManager, W: WalletInterface> SyncManager<S, N, W> {
    /// Execute the current sync phase
    pub(super) async fn execute_current_phase(
        &mut self,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                tracing::info!("📥 Starting header download phase");
                // Don't call start_sync if already prepared - just send the request
                if self.header_sync.is_syncing() {
                    // Already prepared, just send the initial request
                    let base_hash = self.get_base_hash_from_storage(storage).await?;

                    self.header_sync.request_headers(network, base_hash, storage).await?;
                } else {
                    // Not prepared yet, start sync normally
                    self.header_sync.start_sync(network, storage).await?;
                }
            }

            SyncPhase::DownloadingMnList {
                ..
            } => {
                tracing::info!("📥 Starting masternode list download phase");

                // Start masternode sync (unified processing)
                match self.masternode_sync.start_sync(network, storage).await {
                    Ok(_) => {
                        tracing::info!("🚀 Masternode sync initiated successfully, will complete when QRInfo arrives");
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to start masternode sync: {}", e);
                        return Err(e);
                    }
                }
            }

            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                tracing::info!("📥 Starting filter header download phase");

                // Get sync base height from header sync
                let sync_base_height = self.header_sync.get_sync_base_height();
                if sync_base_height > 0 {
                    tracing::info!(
                        "Setting filter sync base height to {} for checkpoint sync",
                        sync_base_height
                    );
                    self.filter_sync.set_sync_base_height(sync_base_height);
                }

                let sync_started =
                    self.filter_sync.start_sync_filter_headers(network, storage).await?;

                if !sync_started {
                    // No peers support compact filters or already up to date
                    tracing::info!("Filter header sync not started (no peers support filters or already synced)");
                    // Transition to next phase immediately
                    self.transition_to_next_phase(
                        storage,
                        network,
                        "Filter sync skipped - no peer support",
                    )
                    .await?;
                    // Return early to let the main sync loop execute the next phase
                    return Ok(());
                }
            }

            SyncPhase::DownloadingFilters {
                ..
            } => {
                tracing::info!("📥 Starting filter download phase");

                // Get the range of filters to download
                // Note: get_filter_tip_height() now returns absolute blockchain height
                let filter_header_tip = storage
                    .get_filter_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
                    .unwrap_or(0);

                if filter_header_tip > 0 {
                    // Download all filters for complete blockchain history
                    // This ensures the wallet can find transactions from any point in history
                    let start_height = self.header_sync.get_sync_base_height().max(1);
                    let count = filter_header_tip - start_height + 1;

                    tracing::info!(
                        "Starting filter download from height {} to {} ({} filters)",
                        start_height,
                        filter_header_tip,
                        count
                    );

                    // Update the phase to track the expected total
                    if let SyncPhase::DownloadingFilters {
                        total_filters,
                        ..
                    } = &mut self.current_phase
                    {
                        *total_filters = count;
                    }

                    // Use the filter sync manager to download filters
                    self.filter_sync
                        .sync_filters(network, storage, Some(start_height), Some(count))
                        .await?;
                } else {
                    // No filter headers available, skip to next phase
                    self.transition_to_next_phase(storage, network, "No filter headers available")
                        .await?;
                }
            }

            SyncPhase::DownloadingBlocks {
                ..
            } => {
                tracing::info!("📥 Starting block download phase");
                // Block download will be initiated based on filter matches
                // For now, we'll complete the sync
                self.transition_to_next_phase(storage, network, "No blocks to download").await?;
            }

            SyncPhase::Idle
            | SyncPhase::FullySynced {
                ..
            } => {
                // Nothing to execute
            }
        }

        Ok(())
    }

    /// Transition to the next phase
    pub(super) async fn transition_to_next_phase(
        &mut self,
        storage: &mut S,
        network: &N,
        reason: &str,
    ) -> SyncResult<()> {
        // Get the next phase
        let next_phase =
            self.transition_manager.get_next_phase(&self.current_phase, storage, network).await?;

        if let Some(next) = next_phase {
            // Check if transition is allowed
            if !self
                .transition_manager
                .can_transition_to(&self.current_phase, &next, storage)
                .await?
            {
                return Err(SyncError::Validation(format!(
                    "Invalid phase transition from {} to {}",
                    self.current_phase.name(),
                    next.name()
                )));
            }

            // Create transition record
            let transition = self.transition_manager.create_transition(
                &self.current_phase,
                &next,
                reason.to_string(),
            );

            tracing::info!(
                "🔄 Phase transition: {} → {} (reason: {})",
                transition.from_phase,
                transition.to_phase,
                transition.reason
            );

            // Log final progress of the phase
            if let Some(ref progress) = transition.final_progress {
                tracing::info!(
                    "📊 Phase {} completed: {} items in {:?} ({:.1} items/sec)",
                    transition.from_phase,
                    progress.items_completed,
                    progress.elapsed,
                    progress.rate
                );
            }

            self.phase_history.push(transition);
            self.current_phase = next;
            self.current_phase_retries = 0;

            // Start the next phase
            // Note: We can't execute the next phase here as we don't have network access
            // The caller will need to execute the next phase
        } else {
            tracing::info!("✅ Sequential sync complete!");

            // Calculate total sync stats
            if let Some(start_time) = self.sync_start_time {
                let total_time = start_time.elapsed();
                let headers_synced = self.calculate_total_headers_synced();
                let filters_synced = self.calculate_total_filters_synced();
                let blocks_downloaded = self.calculate_total_blocks_downloaded();

                self.current_phase = SyncPhase::FullySynced {
                    sync_completed_at: Instant::now(),
                    total_sync_time: total_time,
                    headers_synced,
                    filters_synced,
                    blocks_downloaded,
                };

                tracing::info!(
                    "🎉 Sync completed in {:?} - {} headers, {} filters, {} blocks",
                    total_time,
                    headers_synced,
                    filters_synced,
                    blocks_downloaded
                );
            }
        }

        Ok(())
    }

    /// Check for timeouts and handle recovery
    pub async fn check_timeout(&mut self, network: &mut N, storage: &mut S) -> SyncResult<()> {
        // First check if the current phase needs to be executed (e.g., after a transition)
        if self.current_phase_needs_execution() {
            tracing::info!("Executing phase {} after transition", self.current_phase.name());
            self.execute_current_phase(network, storage).await?;
            return Ok(());
        }

        if let Some(last_progress) = self.current_phase.last_progress_time() {
            if last_progress.elapsed() > self.phase_timeout {
                tracing::warn!(
                    "⏰ Phase {} timed out after {:?}",
                    self.current_phase.name(),
                    self.phase_timeout
                );

                // Attempt recovery
                self.recover_from_timeout(network, storage).await?;
            }
        }

        // Also check phase-specific timeouts
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                self.header_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                self.filter_sync.check_cfheader_request_timeouts(network, storage).await?;
            }
            SyncPhase::DownloadingMnList {
                ..
            } => {
                self.masternode_sync.check_sync_timeout(storage, network).await?;

                // After checking timeout, see if sync completed (either normally or via timeout)
                if !self.masternode_sync.is_syncing() {
                    tracing::info!("Masternode sync completed (detected in timeout check), transitioning to next phase");
                    self.transition_to_next_phase(storage, network, "Masternode sync complete")
                        .await?;
                    self.execute_current_phase(network, storage).await?;
                }
            }
            SyncPhase::DownloadingFilters {
                ..
            } => {
                // Always check for timed out filter requests, not just during phase timeout
                self.filter_sync.check_filter_request_timeouts(network, storage).await?;

                // For filter downloads, we need custom timeout handling
                // since the filter sync manager's timeout is for filter headers
                if let Some(last_progress) = self.current_phase.last_progress_time() {
                    if last_progress.elapsed() > self.phase_timeout {
                        tracing::warn!(
                            "⏰ Filter download phase timed out after {:?}",
                            self.phase_timeout
                        );

                        // Check if we have any active requests
                        let active_count = self.filter_sync.active_request_count();
                        let pending_count = self.filter_sync.pending_download_count();

                        tracing::warn!(
                            "Filter sync status: {} active requests, {} pending",
                            active_count,
                            pending_count
                        );

                        // First check for timed out filter requests
                        self.filter_sync.check_filter_request_timeouts(network, storage).await?;

                        // Try to recover by sending more requests if we have pending ones
                        if self.filter_sync.has_pending_filter_requests() && active_count < 10 {
                            tracing::info!("Attempting to recover by sending more filter requests");
                            self.filter_sync.send_next_filter_batch(network).await?;
                            self.current_phase.update_progress();
                        } else if active_count == 0
                            && !self.filter_sync.has_pending_filter_requests()
                        {
                            // No active requests and no pending - we're stuck
                            tracing::error!(
                                "Filter sync stalled with no active or pending requests"
                            );

                            // Check if we received some filters but not all
                            let received_count = self.filter_sync.get_received_filter_count();
                            if let SyncPhase::DownloadingFilters {
                                total_filters,
                                ..
                            } = &self.current_phase
                            {
                                if received_count > 0 && received_count < *total_filters {
                                    tracing::warn!(
                                        "Filter sync stalled at {}/{} filters - attempting recovery",
                                        received_count, total_filters
                                    );

                                    // Retry the entire filter sync phase
                                    self.current_phase_retries += 1;
                                    if self.current_phase_retries <= self.max_phase_retries {
                                        tracing::info!(
                                            "🔄 Retrying filter sync (attempt {}/{})",
                                            self.current_phase_retries,
                                            self.max_phase_retries
                                        );

                                        // Clear the filter sync state and restart
                                        self.filter_sync.reset();
                                        self.filter_sync.set_syncing_filters(false); // Allow restart

                                        // Update progress to prevent immediate timeout
                                        self.current_phase.update_progress();

                                        // Re-execute the phase
                                        self.execute_current_phase(network, storage).await?;
                                        return Ok(());
                                    } else {
                                        tracing::error!(
                                            "Filter sync failed after {} retries, forcing completion",
                                            self.max_phase_retries
                                        );
                                    }
                                }
                            }

                            // Force transition to next phase to avoid permanent stall
                            self.transition_to_next_phase(
                                storage,
                                network,
                                "Filter sync timeout - forcing completion",
                            )
                            .await?;
                            self.execute_current_phase(network, storage).await?;
                        }
                    }
                }
            }
            SyncPhase::Idle
            | SyncPhase::FullySynced {
                ..
            }
            | SyncPhase::DownloadingBlocks {
                ..
            } => {
                // Nothing to execute
            }
        }

        Ok(())
    }

    /// Recover from a timeout
    async fn recover_from_timeout(&mut self, network: &mut N, storage: &mut S) -> SyncResult<()> {
        self.current_phase_retries += 1;

        if self.current_phase_retries > self.max_phase_retries {
            return Err(SyncError::Timeout(format!(
                "Phase {} failed after {} retries",
                self.current_phase.name(),
                self.max_phase_retries
            )));
        }

        tracing::warn!(
            "🔄 Retrying phase {} (attempt {}/{})",
            self.current_phase.name(),
            self.current_phase_retries,
            self.max_phase_retries
        );

        // Update progress time to prevent immediate re-timeout
        self.current_phase.update_progress();

        // Execute phase-specific recovery
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                self.header_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingMnList {
                ..
            } => {
                self.masternode_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                self.filter_sync.check_cfheader_request_timeouts(network, storage).await?;
            }
            SyncPhase::Idle
            | SyncPhase::DownloadingFilters {
                ..
            }
            | SyncPhase::DownloadingBlocks {
                ..
            }
            | SyncPhase::FullySynced {
                ..
            } => {
                // For other phases, we'll need phase-specific recovery
            }
        }

        Ok(())
    }

    // Helper methods for calculating totals

    pub(super) fn calculate_total_headers_synced(&self) -> u32 {
        self.phase_history
            .iter()
            .find(|t| t.from_phase == "Downloading Headers")
            .and_then(|t| t.final_progress.as_ref())
            .map(|p| p.items_completed)
            .unwrap_or(0)
    }

    pub(super) fn calculate_total_filters_synced(&self) -> u32 {
        self.phase_history
            .iter()
            .find(|t| t.from_phase == "Downloading Filters")
            .and_then(|t| t.final_progress.as_ref())
            .map(|p| p.items_completed)
            .unwrap_or(0)
    }

    pub(super) fn calculate_total_blocks_downloaded(&self) -> u32 {
        self.phase_history
            .iter()
            .find(|t| t.from_phase == "Downloading Blocks")
            .and_then(|t| t.final_progress.as_ref())
            .map(|p| p.items_completed)
            .unwrap_or(0)
    }

    pub(super) fn no_more_pending_blocks(&self) -> bool {
        // This would check if there are more blocks to download
        // For now, return true
        true
    }
}
