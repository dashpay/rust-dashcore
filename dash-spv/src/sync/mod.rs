//! Synchronization management for the Dash SPV client.
//!
//! This module provides different sync strategies:
//!
//! 1. **Sequential sync**: Headers first, then filter headers, then filters on-demand
//! 2. **Interleaved sync**: Headers and filter headers synchronized simultaneously
//!    for better responsiveness and efficiency
//!
//! The interleaved sync mode requests filter headers immediately after each batch
//! of headers is received and stored, providing better user experience during
//! initial sync operations.

pub mod filters;
pub mod headers;
pub mod masternodes;
pub mod state;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;
use dashcore::network::constants::NetworkExt;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;

pub use filters::FilterSyncManager;
pub use headers::HeaderSyncManager;
pub use masternodes::MasternodeSyncManager;
pub use state::SyncState;

/// Coordinates all synchronization activities.
pub struct SyncManager {
    header_sync: HeaderSyncManager,
    filter_sync: FilterSyncManager,
    masternode_sync: MasternodeSyncManager,
    state: SyncState,
    config: ClientConfig,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new(
        config: &ClientConfig,
        received_filter_heights: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    ) -> Self {
        Self {
            header_sync: HeaderSyncManager::new(config),
            filter_sync: FilterSyncManager::new(config, received_filter_heights),
            masternode_sync: MasternodeSyncManager::new(config),
            state: SyncState::new(),
            config: config.clone(),
        }
    }

    /// Handle a Headers message by routing it to the header sync manager.
    /// If filter headers are enabled, also requests filter headers for new blocks.
    pub async fn handle_headers_message(
        &mut self,
        headers: Vec<dashcore::block::Header>,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        // First, let the header sync manager process the headers
        let continue_sync =
            self.header_sync.handle_headers_message(headers.clone(), storage, network).await?;

        // If filters are enabled and we received new headers, request filter headers for them
        if self.config.enable_filters && !headers.is_empty() {
            // Get the height range of the newly stored headers
            let first_header_hash = headers[0].block_hash();
            let last_header_hash = headers.last().unwrap().block_hash();

            // Find heights for these headers
            if let Some(first_height) =
                storage.get_header_height_by_hash(&first_header_hash).await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to get first header height: {}", e))
                })?
            {
                if let Some(last_height) =
                    storage.get_header_height_by_hash(&last_header_hash).await.map_err(|e| {
                        SyncError::SyncFailed(format!("Failed to get last header height: {}", e))
                    })?
                {
                    // Check if we need filter headers for this range
                    let current_filter_tip = storage
                        .get_filter_tip_height()
                        .await
                        .map_err(|e| {
                            SyncError::SyncFailed(format!("Failed to get filter tip: {}", e))
                        })?
                        .unwrap_or(0);

                    // Only request filter headers if we're behind by more than 1 block
                    // (within 1 block is considered "caught up" to handle edge cases)
                    if current_filter_tip + 1 < last_height {
                        let start_height = (current_filter_tip + 1).max(first_height);
                        tracing::info!(
                            "🔄 Requesting filter headers for new blocks: heights {} to {}",
                            start_height,
                            last_height
                        );

                        // Always ensure filter header requests are sent for new blocks
                        if !self.filter_sync.is_syncing_filter_headers() {
                            tracing::debug!("Starting filter header sync to catch up with headers");
                            if let Err(e) =
                                self.filter_sync.start_sync_headers(network, storage).await
                            {
                                tracing::warn!("Failed to start filter header sync: {}", e);
                            }
                        } else {
                            // Filter header sync is already active and will handle new ranges automatically
                            // The filter sync manager's handle_cfheaders_message will request next batches
                            tracing::debug!("Filter header sync already active, relying on automatic batch progression");
                        }
                    } else if current_filter_tip == last_height {
                        tracing::debug!(
                            "Filter headers already caught up to block headers at height {}",
                            last_height
                        );
                    }
                }
            }
        }

        Ok(continue_sync)
    }

    /// Handle a CFHeaders message by routing it to the filter sync manager.
    pub async fn handle_cfheaders_message(
        &mut self,
        cf_headers: dashcore::network::message_filter::CFHeaders,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        self.filter_sync.handle_cfheaders_message(cf_headers, storage, network).await
    }

    /// Handle a CFilter message for sync coordination (tracking filter downloads).
    /// Only needs the block hash to track completion, not the full filter data.
    pub async fn handle_cfilter_message(
        &mut self,
        block_hash: dashcore::BlockHash,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        // Check if this completes any active filter requests
        let completed_requests = self.filter_sync.mark_filter_received(block_hash, storage).await?;

        // Process next queued requests for any completed batches
        if !completed_requests.is_empty() {
            let (pending_count, active_count, _enabled) =
                self.filter_sync.get_flow_control_status();
            tracing::debug!(
                "🎯 Filter batch completion triggered processing of {} queued requests ({} active)",
                pending_count,
                active_count
            );
            self.filter_sync.process_next_queued_requests(network).await?;
        }

        tracing::trace!(
            "Processed CFilter for block {} - flow control coordination completed",
            block_hash
        );
        Ok(())
    }

    /// Handle an MnListDiff message by routing it to the masternode sync manager.
    pub async fn handle_mnlistdiff_message(
        &mut self,
        diff: dashcore::network::message_sml::MnListDiff,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        self.masternode_sync.handle_mnlistdiff_message(diff, storage, network).await
    }

    /// Check for sync timeouts and handle recovery across all sync managers.
    pub async fn check_sync_timeouts(
        &mut self,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        // Check all sync managers for timeouts
        let _ = self.header_sync.check_sync_timeout(storage, network).await;
        let _ = self.filter_sync.check_sync_timeout(storage, network).await;
        let _ = self.masternode_sync.check_sync_timeout(storage, network).await;

        // Check for filter request timeouts with flow control
        let _ = self.filter_sync.check_filter_request_timeouts(network, storage).await;

        Ok(())
    }

    /// Get a reference to the masternode list engine.
    pub fn masternode_list_engine(&self) -> Option<&MasternodeListEngine> {
        self.masternode_sync.engine()
    }

    /// Synchronize all components to the tip.
    pub async fn sync_all(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        let mut progress = SyncProgress::default();

        // Step 1: Sync headers and filter headers (interleaved if both enabled)
        if self.config.validation_mode != crate::types::ValidationMode::None
            && self.config.enable_filters
        {
            // Use interleaved sync for better responsiveness and efficiency
            progress = self.sync_headers_and_filter_headers_impl(network, storage).await?;
        } else if self.config.validation_mode != crate::types::ValidationMode::None {
            // Headers only
            progress = self.sync_headers(network, storage).await?;
        } else if self.config.enable_filters {
            // Filter headers only (unusual case)
            progress = self.sync_filter_headers(network, storage).await?;

            // Note: Compact filter downloading is skipped during initial sync
            // Use sync_and_check_filters() when you have specific watch items to check
            tracing::info!("💡 Headers and filter headers synced. Use sync_and_check_filters() to download and check specific filters");
        }

        // Step 3: Sync masternode list if enabled
        if self.config.enable_masternodes {
            progress = self.sync_masternodes(network, storage).await?;
        }

        progress.last_update = std::time::SystemTime::now();
        Ok(progress)
    }

    /// Synchronize headers using the new state-based approach.
    pub async fn sync_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        // Check if header sync is already in progress using the HeaderSyncManager's internal state
        if self.header_sync.is_syncing() {
            return Err(SyncError::SyncInProgress);
        }

        // Start header sync
        let sync_started = self.header_sync.start_sync(network, storage).await?;

        if !sync_started {
            // Already up to date - no need to call state.finish_sync since we never started
            let final_height = storage
                .get_tip_height()
                .await
                .map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to get final tip height: {}", e))
                })?
                .unwrap_or(0);

            return Ok(SyncProgress {
                header_height: final_height,
                headers_synced: true,
                ..SyncProgress::default()
            });
        }

        // Note: The actual sync now happens through the monitoring loop
        // calling handle_headers_message() and check_sync_timeout()
        tracing::info!("Header sync started - will be completed through monitoring loop");

        // Don't call finish_sync here! The sync is still in progress.
        // It will be finished when handle_headers_message() returns false (sync complete)

        let final_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get final tip height: {}", e)))?
            .unwrap_or(0);

        Ok(SyncProgress {
            header_height: final_height,
            headers_synced: false, // Sync is in progress, will complete asynchronously
            ..SyncProgress::default()
        })
    }

    /// Implementation of sequential header and filter header sync using the new state-based approach.
    async fn sync_headers_and_filter_headers_impl(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        tracing::info!("Starting sequential header and filter header synchronization");

        // Get current header tip
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        let current_filter_tip_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip height: {}", e)))?
            .unwrap_or(0);

        tracing::info!(
            "Starting sync - headers: {}, filter headers: {}",
            current_tip_height,
            current_filter_tip_height
        );

        // Step 1: Start header sync
        tracing::info!("🎯 About to call header_sync.start_sync()");
        let header_sync_started = self.header_sync.start_sync(network, storage).await?;
        if header_sync_started {
            tracing::info!(
                "✅ Header sync started successfully - will complete through monitoring loop"
            );
            // The header sync manager already sets its internal syncing_headers flag
            // Don't duplicate sync state tracking here
        } else {
            tracing::info!("📊 Headers already up to date (start_sync returned false)");
        }

        // Step 2: Start filter header sync
        let filter_sync_started = self.filter_sync.start_sync_headers(network, storage).await?;
        if filter_sync_started {
            tracing::info!("Filter header sync started - will complete through monitoring loop");
        }

        // Note: The actual sync now happens through the monitoring loop
        // calling handle_headers_message(), handle_cfheaders_message(), and check_sync_timeout()

        let final_header_height = storage
            .get_tip_height()
            .await
            .map_err(|e| {
                SyncError::SyncFailed(format!("Failed to get final header height: {}", e))
            })?
            .unwrap_or(0);

        let final_filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| {
                SyncError::SyncFailed(format!("Failed to get final filter height: {}", e))
            })?
            .unwrap_or(0);

        // Check filter sync availability
        let filter_sync_available = self.filter_sync.is_filter_sync_available(network).await;
        
        Ok(SyncProgress {
            header_height: final_header_height,
            filter_header_height: final_filter_height,
            headers_synced: !header_sync_started, // If sync didn't start, we're already up to date
            filter_headers_synced: !filter_sync_started, // If sync didn't start, we're already up to date
            filter_sync_available,
            ..SyncProgress::default()
        })
    }

    /// Synchronize filter headers using the new state-based approach.
    pub async fn sync_filter_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.state.is_syncing(SyncComponent::FilterHeaders) {
            return Err(SyncError::SyncInProgress);
        }

        self.state.start_sync(SyncComponent::FilterHeaders);

        // Start filter header sync
        let sync_started = self.filter_sync.start_sync_headers(network, storage).await?;

        if !sync_started {
            // Already up to date
            self.state.finish_sync(SyncComponent::FilterHeaders);

            let final_filter_height = storage
                .get_filter_tip_height()
                .await
                .map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to get filter tip height: {}", e))
                })?
                .unwrap_or(0);

            let filter_sync_available = self.filter_sync.is_filter_sync_available(network).await;
            
            return Ok(SyncProgress {
                filter_header_height: final_filter_height,
                filter_headers_synced: true,
                filter_sync_available,
                ..SyncProgress::default()
            });
        }

        // Note: The actual sync now happens through the monitoring loop
        // calling handle_cfheaders_message() and check_sync_timeout()
        tracing::info!("Filter header sync started - will be completed through monitoring loop");

        // Don't call finish_sync here! The sync is still in progress.
        // It will be finished when handle_cfheaders_message() returns false (sync complete)

        let final_filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip height: {}", e)))?
            .unwrap_or(0);

        let filter_sync_available = self.filter_sync.is_filter_sync_available(network).await;
        
        Ok(SyncProgress {
            filter_header_height: final_filter_height,
            filter_headers_synced: false, // Sync is in progress, will complete asynchronously
            filter_sync_available,
            ..SyncProgress::default()
        })
    }

    /// Synchronize compact filters.
    pub async fn sync_filters(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> SyncResult<SyncProgress> {
        if self.state.is_syncing(SyncComponent::Filters) {
            return Err(SyncError::SyncInProgress);
        }

        self.state.start_sync(SyncComponent::Filters);

        let result = self.filter_sync.sync_filters(network, storage, start_height, count).await;

        self.state.finish_sync(SyncComponent::Filters);

        let progress = result?;
        Ok(progress)
    }

    /// Check filters for matches against watch items.
    pub async fn check_filter_matches(
        &self,
        storage: &dyn StorageManager,
        watch_items: &[crate::types::WatchItem],
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<Vec<crate::types::FilterMatch>> {
        self.filter_sync
            .check_filters_for_matches(storage, watch_items, start_height, end_height)
            .await
    }

    /// Request block downloads for filter matches.
    pub async fn request_block_downloads(
        &mut self,
        filter_matches: Vec<crate::types::FilterMatch>,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<Vec<crate::types::FilterMatch>> {
        self.filter_sync.process_filter_matches_and_download(filter_matches, network).await
    }

    /// Handle a downloaded block.
    pub async fn handle_downloaded_block(
        &mut self,
        block: &dashcore::block::Block,
    ) -> SyncResult<Option<crate::types::FilterMatch>> {
        self.filter_sync.handle_downloaded_block(block).await
    }

    /// Check if there are pending block downloads.
    pub fn has_pending_downloads(&self) -> bool {
        self.filter_sync.has_pending_downloads()
    }

    /// Get the number of pending block downloads.
    pub fn pending_download_count(&self) -> usize {
        self.filter_sync.pending_download_count()
    }

    /// Synchronize masternode list using the new state-based approach.
    pub async fn sync_masternodes(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.state.is_syncing(SyncComponent::Masternodes) {
            return Err(SyncError::SyncInProgress);
        }

        self.state.start_sync(SyncComponent::Masternodes);

        // Start masternode sync
        let sync_started = self.masternode_sync.start_sync(network, storage).await?;

        if !sync_started {
            // Already up to date
            self.state.finish_sync(SyncComponent::Masternodes);

            let final_height = match storage.load_masternode_state().await {
                Ok(Some(state)) => state.last_height,
                _ => 0,
            };

            return Ok(SyncProgress {
                masternode_height: final_height,
                masternodes_synced: true,
                ..SyncProgress::default()
            });
        }

        // Note: The actual sync now happens through the monitoring loop
        // calling handle_mnlistdiff_message() and check_sync_timeout()
        tracing::info!("Masternode sync started - will be completed through monitoring loop");

        // Don't call finish_sync here! The sync is still in progress.
        // It will be finished when handle_mnlistdiff_message() returns false

        let final_height = match storage.load_masternode_state().await {
            Ok(Some(state)) => state.last_height,
            _ => 0,
        };

        Ok(SyncProgress {
            masternode_height: final_height,
            masternodes_synced: false, // Sync is in progress, will complete asynchronously
            ..SyncProgress::default()
        })
    }

    /// Get current sync state.
    pub fn sync_state(&self) -> &SyncState {
        &self.state
    }

    /// Get mutable sync state.
    pub fn sync_state_mut(&mut self) -> &mut SyncState {
        &mut self.state
    }

    /// Check if any sync is in progress.
    pub fn is_syncing(&self) -> bool {
        self.state.is_any_syncing()
    }

    /// Get a reference to the masternode engine for validation.
    pub fn masternode_engine(
        &self,
    ) -> Option<&dashcore::sml::masternode_list_engine::MasternodeListEngine> {
        self.masternode_sync.engine()
    }

    /// Get a reference to the header sync manager.
    pub fn header_sync(&self) -> &HeaderSyncManager {
        &self.header_sync
    }

    /// Get a mutable reference to the header sync manager.
    pub fn header_sync_mut(&mut self) -> &mut HeaderSyncManager {
        &mut self.header_sync
    }

    /// Get a mutable reference to the filter sync manager.
    pub fn filter_sync_mut(&mut self) -> &mut FilterSyncManager {
        &mut self.filter_sync
    }

    /// Get a reference to the filter sync manager.
    pub fn filter_sync(&self) -> &FilterSyncManager {
        &self.filter_sync
    }

    /// Recover from sync stalls by re-sending appropriate requests based on current state.
    async fn recover_sync_requests(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        headers_sync_completed: bool,
        current_header_tip: u32,
    ) -> SyncResult<()> {
        tracing::info!(
            "🔄 Recovering sync requests - headers_completed: {}, current_tip: {}",
            headers_sync_completed,
            current_header_tip
        );

        // Always try to advance headers if not complete
        if !headers_sync_completed {
            // Get the current tip hash to request headers after it
            let tip_hash = if current_header_tip > 0 {
                storage
                    .get_header(current_header_tip)
                    .await
                    .map_err(|e| {
                        SyncError::SyncFailed(format!(
                            "Failed to get tip header for recovery: {}",
                            e
                        ))
                    })?
                    .map(|h| h.block_hash())
            } else {
                // Start from genesis
                Some(
                    self.config
                        .network
                        .known_genesis_block_hash()
                        .expect("unable to get genesis block hash"),
                )
            };

            tracing::info!("🔄 Re-requesting headers from tip: {:?}", tip_hash);
            self.header_sync.request_headers(network, tip_hash).await?;
        }

        // Check if filter headers are lagging behind block headers and request catch-up
        let header_height = storage
            .get_tip_height()
            .await
            .map_err(|e| {
                SyncError::SyncFailed(format!("Failed to get header tip for recovery: {}", e))
            })?
            .unwrap_or(0);
        let filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| {
                SyncError::SyncFailed(format!("Failed to get filter tip for recovery: {}", e))
            })?
            .unwrap_or(0);

        tracing::info!(
            "🔄 Sync state check - headers: {}, filter headers: {}",
            header_height,
            filter_height
        );

        if filter_height < header_height {
            let start_height = filter_height + 1;
            let batch_size = 1999; // Match existing batch size
            let end_height = (start_height + batch_size - 1).min(header_height);

            if let Some(stop_header) = storage.get_header(end_height).await.map_err(|e| {
                SyncError::SyncFailed(format!("Failed to get stop header for recovery: {}", e))
            })? {
                let stop_hash = stop_header.block_hash();
                tracing::info!(
                    "🔄 Re-requesting filter headers from {} to {} (stop: {})",
                    start_height,
                    end_height,
                    stop_hash
                );

                self.filter_sync.request_filter_headers(network, start_height, stop_hash).await?;
            }
        }

        Ok(())
    }
}

/// Sync component types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncComponent {
    Headers,
    FilterHeaders,
    Filters,
    Masternodes,
}
