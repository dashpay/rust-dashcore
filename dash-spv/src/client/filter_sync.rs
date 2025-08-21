//! Filter synchronization and management for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::sequential::SequentialSyncManager;
use crate::types::SpvStats;
use crate::types::{FilterMatch, WatchItem};

/// Filter synchronization manager for coordinating filter downloads and checking.
pub struct FilterSyncCoordinator<'a, S: StorageManager, N: NetworkManager> {
    sync_manager: &'a mut SequentialSyncManager<S, N>,
    storage: &'a mut S,
    network: &'a mut N,
    watch_items: &'a Arc<RwLock<std::collections::HashSet<WatchItem>>>,
    stats: &'a Arc<RwLock<SpvStats>>,
    running: &'a Arc<RwLock<bool>>,
}

impl<'a, S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    FilterSyncCoordinator<'a, S, N>
{
    /// Create a new filter sync coordinator.
    pub fn new(
        sync_manager: &'a mut SequentialSyncManager<S, N>,
        storage: &'a mut S,
        network: &'a mut N,
        watch_items: &'a Arc<RwLock<std::collections::HashSet<WatchItem>>>,
        stats: &'a Arc<RwLock<SpvStats>>,
        running: &'a Arc<RwLock<bool>>,
    ) -> Self {
        Self {
            sync_manager,
            storage,
            network,
            watch_items,
            stats,
            running,
        }
    }

    /// Sync compact filters for recent blocks and check for matches.
    /// Sync and check filters with internal monitoring loop management.
    /// This method automatically handles the monitoring loop required for CFilter message processing.
    pub async fn sync_and_check_filters_with_monitoring(
        &mut self,
        num_blocks: Option<u32>,
    ) -> Result<Vec<FilterMatch>> {
        // Just delegate to the regular method for now - the real fix is in sync_filters_coordinated
        self.sync_and_check_filters(num_blocks).await
    }

    pub async fn sync_and_check_filters(
        &mut self,
        num_blocks: Option<u32>,
    ) -> Result<Vec<FilterMatch>> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);

        // Get current filter tip height to determine range (use filter headers, not block headers)
        // This ensures consistency between range calculation and progress tracking
        let tip_height =
            self.storage.get_filter_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0);

        // Get current watch items to determine earliest height needed
        let watch_items = self.get_watch_items().await;

        if watch_items.is_empty() {
            tracing::info!("No watch items configured, skipping filter sync");
            return Ok(Vec::new());
        }

        // Find the earliest height among all watch items
        let earliest_height = watch_items
            .iter()
            .filter_map(|item| item.earliest_height())
            .min()
            .unwrap_or(tip_height.saturating_sub(99)); // Default to last 100 blocks if no earliest_height set

        let num_blocks = num_blocks.unwrap_or(100);
        let default_start = tip_height.saturating_sub(num_blocks - 1);
        let start_height = earliest_height.min(default_start); // Go back to the earliest required height
        let actual_count = tip_height - start_height + 1; // Actual number of blocks available

        tracing::info!(
            "Requesting filters from height {} to {} ({} blocks based on filter tip height)",
            start_height,
            tip_height,
            actual_count
        );
        tracing::info!("Filter processing and matching will happen automatically in background thread as CFilter messages arrive");

        // Send filter requests - processing will happen automatically in the background
        self.sync_filters_coordinated(start_height, actual_count).await?;

        // Return empty vector since matching happens asynchronously in the filter processor thread
        // Actual matches will be processed and blocks requested automatically when CFilter messages arrive
        Ok(Vec::new())
    }

    /// Sync filters for a specific height range.
    pub async fn sync_filters_range(
        &mut self,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> Result<()> {
        // Get filter tip height to determine default values
        let filter_tip_height =
            self.storage.get_filter_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0);

        let start = start_height.unwrap_or(filter_tip_height.saturating_sub(99));
        let num_blocks = count.unwrap_or(100);

        tracing::info!(
            "Starting filter sync for specific range from height {} ({} blocks)",
            start,
            num_blocks
        );

        self.sync_filters_coordinated(start, num_blocks).await
    }

    /// Sync filters in coordination with the monitoring loop using flow control processing
    async fn sync_filters_coordinated(&mut self, start_height: u32, count: u32) -> Result<()> {
        tracing::info!("Starting coordinated filter sync with flow control from height {} to {} ({} filters expected)", 
                      start_height, start_height + count - 1, count);

        // Start tracking filter sync progress
        crate::sync::filters::FilterSyncManager::<S, N>::start_filter_sync_tracking(
            self.stats,
            count as u64,
        )
        .await;

        // Use the new flow control method
        self.sync_manager
            .filter_sync_mut()
            .sync_filters_with_flow_control(
                &mut *self.network,
                &mut *self.storage,
                Some(start_height),
                Some(count),
            )
            .await
            .map_err(SpvError::Sync)?;

        let (pending_count, active_count, flow_enabled) =
            self.sync_manager.filter_sync().get_flow_control_status();
        tracing::info!("✅ Filter sync with flow control initiated (flow control enabled: {}, {} requests queued, {} active)", 
                      flow_enabled, pending_count, active_count);

        Ok(())
    }

    /// Get all watch items.
    async fn get_watch_items(&self) -> Vec<WatchItem> {
        let watch_items = self.watch_items.read().await;
        watch_items.iter().cloned().collect()
    }

}
