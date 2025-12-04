//! Filter synchronization and management for the Dash SPV client.

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncManager;
use crate::types::FilterMatch;
use crate::types::SpvStats;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Filter synchronization manager for coordinating filter downloads and checking.
pub struct FilterSyncCoordinator<'a, S: StorageManager, N: NetworkManager, W: WalletInterface> {
    sync_manager: &'a mut SyncManager<S, N, W>,
    storage: &'a mut S,
    network: &'a mut N,
    stats: &'a Arc<RwLock<SpvStats>>,
    running: &'a Arc<RwLock<bool>>,
}

impl<
        'a,
        S: StorageManager + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        W: WalletInterface,
    > FilterSyncCoordinator<'a, S, N, W>
{
    /// Create a new filter sync coordinator.
    pub fn new(
        sync_manager: &'a mut SyncManager<S, N, W>,
        storage: &'a mut S,
        network: &'a mut N,
        stats: &'a Arc<RwLock<SpvStats>>,
        running: &'a Arc<RwLock<bool>>,
    ) -> Self {
        Self {
            sync_manager,
            storage,
            network,
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

        // Determine how many blocks to request
        let num_blocks = num_blocks.unwrap_or(100).max(1);
        let default_start = tip_height.saturating_sub(num_blocks - 1);

        // Ask the wallet for an earliest rescan height, falling back to the default window.
        let wallet_hint = self.sync_manager.wallet_birth_height_hint().await;
        let mut start_height = wallet_hint.unwrap_or(default_start).min(default_start);

        // Respect any user-provided start height hint from the configuration.
        if let Some(config_start) = self.sync_manager.config_start_height() {
            let capped = config_start.min(tip_height);
            start_height = start_height.max(capped);
        }

        // Make sure we never request past the current tip
        start_height = start_height.min(tip_height);

        let actual_count = if start_height <= tip_height {
            tip_height - start_height + 1
        } else {
            0
        };

        tracing::info!(
            "Requesting filters from height {} to {} ({} blocks based on filter tip height)",
            start_height,
            tip_height,
            actual_count
        );
        if let Some(hint) = wallet_hint {
            tracing::debug!("Wallet hint for earliest required height: {}", hint);
        }
        tracing::info!("Filter processing and matching will happen automatically in background thread as CFilter messages arrive");

        // Send filter requests - processing will happen automatically in the background
        if actual_count > 0 {
            self.sync_filters_coordinated(start_height, actual_count).await?;
        } else {
            tracing::debug!("No filters requested because calculated range is empty");
        }

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
}
