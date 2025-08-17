//! Synchronization management for the Dash SPV client.
//!
//! This module provides sequential sync strategy:
//! Headers first, then filter headers, then filters on-demand

pub mod chainlock_validation;
pub mod discovery;
pub mod embedded_data;
pub mod filters;
pub mod headers;
pub mod headers2_state;
pub mod headers_with_reorg;
pub mod masternodes;
pub mod sequential;
pub mod state;
pub mod validation;
pub mod validation_state;

#[cfg(test)]
mod validation_test;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;

pub use filters::FilterSyncManager;
pub use headers::HeaderSyncManager;
pub use headers_with_reorg::{HeaderSyncManagerWithReorg, ReorgConfig};
pub use masternodes::MasternodeSyncManager;
pub use state::SyncState;

/// Legacy sync manager - kept for compatibility but simplified.
/// Use SequentialSyncManager for all synchronization needs.
#[deprecated(note = "Use SequentialSyncManager instead")]
pub struct SyncManager<S: StorageManager, N: NetworkManager> {
    header_sync: HeaderSyncManagerWithReorg<S, N>,
    filter_sync: FilterSyncManager<S, N>,
    masternode_sync: MasternodeSyncManager<S, N>,
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_n: std::marker::PhantomData<N>,
    state: SyncState,
    config: ClientConfig,
}

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    SyncManager<S, N>
{
    /// Create a new sync manager.
    pub fn new(
        config: &ClientConfig,
        received_filter_heights: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    ) -> SyncResult<Self> {
        // Create reorg config with sensible defaults
        let reorg_config = ReorgConfig::default();

        Ok(Self {
            header_sync: HeaderSyncManagerWithReorg::new(config, reorg_config).map_err(|e| {
                SyncError::InvalidState(format!("Failed to create header sync manager: {}", e))
            })?,
            filter_sync: FilterSyncManager::new(config, received_filter_heights),
            masternode_sync: MasternodeSyncManager::new(config),
            state: SyncState::new(),
            config: config.clone(),
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        })
    }

    /// Handle a Headers message by routing it to the header sync manager.
    pub async fn handle_headers_message(
        &mut self,
        headers: Vec<dashcore::block::Header>,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        // Simply forward to the header sync manager
        self.header_sync.handle_headers_message(headers, storage, network).await
    }

    /// Handle a CFHeaders message by routing it to the filter sync manager.
    pub async fn handle_cfheaders_message(
        &mut self,
        cf_headers: dashcore::network::message_filter::CFHeaders,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        self.filter_sync.handle_cfheaders_message(cf_headers, storage, network).await
    }

    /// Handle a CFilter message for sync coordination (tracking filter downloads).
    /// Only needs the block hash to track completion, not the full filter data.
    pub async fn handle_cfilter_message(
        &mut self,
        block_hash: dashcore::BlockHash,
        storage: &mut S,
        network: &mut N,
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
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        self.masternode_sync.handle_mnlistdiff_message(diff, storage, network).await
    }

    /// Check for sync timeouts and handle recovery across all sync managers.
    pub async fn check_sync_timeouts(
        &mut self,
        storage: &mut S,
        network: &mut N,
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
    /// This method is deprecated - use SequentialSyncManager instead.
    pub async fn sync_all(&mut self, network: &mut N, storage: &mut S) -> SyncResult<SyncProgress> {
        let mut progress = SyncProgress::default();

        // Sequential sync: headers first, then filter headers, then masternodes
        if self.config.validation_mode != crate::types::ValidationMode::None {
            progress = self.sync_headers(network, storage).await?;
        }

        if self.config.enable_filters {
            progress = self.sync_filter_headers(network, storage).await?;
        }

        if self.config.enable_masternodes {
            progress = self.sync_masternodes(network, storage).await?;
        }

        progress.last_update = std::time::SystemTime::now();
        Ok(progress)
    }

    /// Synchronize headers using the new state-based approach.
    pub async fn sync_headers(
        &mut self,
        network: &mut N,
        storage: &mut S,
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
                .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
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
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        Ok(SyncProgress {
            header_height: final_height,
            headers_synced: false, // Sync is in progress, will complete asynchronously
            ..SyncProgress::default()
        })
    }

    /// Implementation of sequential header and filter header sync.
    /// This method is deprecated and only kept for compatibility.
    async fn sync_headers_and_filter_headers_impl(
        &mut self,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<SyncProgress> {
        tracing::info!("Starting sequential header and filter header synchronization");

        // Get current header tip
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        let current_filter_tip_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
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
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        let final_filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
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
        network: &mut N,
        storage: &mut S,
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
                .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
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
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
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
        network: &mut N,
        storage: &mut S,
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
        storage: &S,
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
        network: &mut N,
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
        network: &mut N,
        storage: &mut S,
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
    pub fn header_sync(&self) -> &HeaderSyncManagerWithReorg<S, N> {
        &self.header_sync
    }

    /// Get a mutable reference to the header sync manager.
    pub fn header_sync_mut(&mut self) -> &mut HeaderSyncManagerWithReorg<S, N> {
        &mut self.header_sync
    }

    /// Get a mutable reference to the filter sync manager.
    pub fn filter_sync_mut(&mut self) -> &mut FilterSyncManager<S, N> {
        &mut self.filter_sync
    }

    /// Get a reference to the filter sync manager.
    pub fn filter_sync(&self) -> &FilterSyncManager<S, N> {
        &self.filter_sync
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
