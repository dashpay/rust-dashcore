//! Statistics and progress tracking for filter synchronization.

use super::types::*;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::BlockHash;

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    super::manager::FilterSyncManager<S, N>
{
    /// Get flow control status (pending count, active count, enabled).
    pub fn get_flow_control_status(&self) -> (usize, usize, bool) {
        (
            self.pending_filter_requests.len(),
            self.active_filter_requests.len(),
            self.flow_control_enabled,
        )
    }

    /// Get number of available request slots for flow control.
    pub fn get_available_request_slots(&self) -> usize {
        MAX_CONCURRENT_FILTER_REQUESTS.saturating_sub(self.active_filter_requests.len())
    }

    /// Get the total number of filters received.
    pub fn get_received_filter_count(&self) -> u32 {
        match self.received_filter_heights.try_lock() {
            Ok(heights) => heights.len() as u32,
            Err(_) => 0,
        }
    }

    /// Start tracking filter sync progress.
    ///
    /// If a sync session is already in progress, adds to the existing count.
    /// Otherwise, starts a fresh tracking session.
    pub async fn start_filter_sync_tracking(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
        total_filters_requested: u64,
    ) {
        let mut stats_lock = stats.write().await;

        // If we're starting a new sync session while one is already in progress,
        // add to the existing count instead of resetting
        if stats_lock.filter_sync_start_time.is_some() {
            // Accumulate the new request count
            stats_lock.filters_requested += total_filters_requested;
            tracing::info!(
                "📊 Added {} filters to existing sync tracking (total: {} filters requested)",
                total_filters_requested,
                stats_lock.filters_requested
            );
        } else {
            // Fresh start - reset everything
            stats_lock.filters_requested = total_filters_requested;
            stats_lock.filters_received = 0;
            stats_lock.filter_sync_start_time = Some(std::time::Instant::now());
            stats_lock.last_filter_received_time = None;
            // Clear the received heights tracking for a fresh start
            let received_filter_heights = stats_lock.received_filter_heights.clone();
            drop(stats_lock); // Release the RwLock before awaiting the mutex
            let mut heights = received_filter_heights.lock().await;
            heights.clear();
            tracing::info!(
                "📊 Started new filter sync tracking: {} filters requested",
                total_filters_requested
            );
        }
    }

    /// Complete filter sync tracking (marks the sync session as complete).
    pub async fn complete_filter_sync_tracking(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) {
        let mut stats_lock = stats.write().await;
        stats_lock.filter_sync_start_time = None;
        tracing::info!("📊 Completed filter sync tracking");
    }

    /// Update filter reception tracking.
    pub async fn update_filter_received(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) {
        let mut stats_lock = stats.write().await;
        stats_lock.filters_received += 1;
        stats_lock.last_filter_received_time = Some(std::time::Instant::now());
    }

    /// Record filter received at specific height (used by processing thread).
    pub async fn record_filter_received_at_height(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
        storage: &S,
        block_hash: &BlockHash,
    ) {
        // Look up height for the block hash
        if let Ok(Some(height)) = storage.get_header_height_by_hash(block_hash).await {
            // Increment the received counter so high-level progress reflects the update
            Self::update_filter_received(stats).await;

            // Get the shared filter heights arc from stats
            let stats_lock = stats.read().await;
            let received_filter_heights = stats_lock.received_filter_heights.clone();
            drop(stats_lock); // Release the stats lock before acquiring the mutex

            // Now lock the heights and insert
            let mut heights = received_filter_heights.lock().await;
            heights.insert(height);
            tracing::trace!(
                "📊 Recorded filter received at height {} for block {}",
                height,
                block_hash
            );
        } else {
            tracing::warn!("Could not find height for filter block hash {}", block_hash);
        }
    }

    /// Get filter sync progress as percentage.
    pub async fn get_filter_sync_progress(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> f64 {
        let stats_lock = stats.read().await;
        if stats_lock.filters_requested == 0 {
            return 0.0;
        }
        (stats_lock.filters_received as f64 / stats_lock.filters_requested as f64) * 100.0
    }

    /// Check if filter sync has timed out (no filters received for 30+ seconds).
    pub async fn check_filter_sync_timeout(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> bool {
        let stats_lock = stats.read().await;
        if let Some(last_received) = stats_lock.last_filter_received_time {
            last_received.elapsed() > std::time::Duration::from_secs(30)
        } else if let Some(sync_start) = stats_lock.filter_sync_start_time {
            // No filters received yet, check if we've been waiting too long
            sync_start.elapsed() > std::time::Duration::from_secs(30)
        } else {
            false
        }
    }

    /// Get filter sync status information.
    ///
    /// Returns: (filters_requested, filters_received, progress_percentage, is_timeout)
    pub async fn get_filter_sync_status(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> (u64, u64, f64, bool) {
        let stats_lock = stats.read().await;
        let progress = if stats_lock.filters_requested == 0 {
            0.0
        } else {
            (stats_lock.filters_received as f64 / stats_lock.filters_requested as f64) * 100.0
        };

        let timeout = if let Some(last_received) = stats_lock.last_filter_received_time {
            last_received.elapsed() > std::time::Duration::from_secs(30)
        } else if let Some(sync_start) = stats_lock.filter_sync_start_time {
            sync_start.elapsed() > std::time::Duration::from_secs(30)
        } else {
            false
        };

        (stats_lock.filters_requested, stats_lock.filters_received, progress, timeout)
    }

    /// Get enhanced filter sync status with gap information.
    ///
    /// This function provides comprehensive filter sync status by combining:
    /// 1. Basic progress tracking (filters_received vs filters_requested)
    /// 2. Gap analysis of active filter requests
    /// 3. Correction logic for tracking inconsistencies
    ///
    /// The function addresses a bug where completion could be incorrectly reported
    /// when active request tracking (requested_filter_ranges) was empty but
    /// basic progress indicated incomplete sync. This could happen when filter
    /// range requests were marked complete but individual filters within those
    /// ranges were never actually received.
    ///
    /// Returns: (filters_requested, filters_received, basic_progress, timeout, total_missing, actual_coverage, missing_ranges)
    pub async fn get_filter_sync_status_with_gaps(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
        filter_sync: &super::manager::FilterSyncManager<S, N>,
    ) -> (u64, u64, f64, bool, u32, f64, Vec<(u32, u32)>) {
        let stats_lock = stats.read().await;
        let basic_progress = if stats_lock.filters_requested == 0 {
            0.0
        } else {
            (stats_lock.filters_received as f64 / stats_lock.filters_requested as f64) * 100.0
        };

        let timeout = if let Some(last_received) = stats_lock.last_filter_received_time {
            last_received.elapsed() > std::time::Duration::from_secs(30)
        } else if let Some(sync_start) = stats_lock.filter_sync_start_time {
            sync_start.elapsed() > std::time::Duration::from_secs(30)
        } else {
            false
        };

        // Get gap information from active requests
        let missing_ranges = filter_sync.find_missing_ranges();
        let total_missing = filter_sync.get_total_missing_filters();
        let actual_coverage = filter_sync.get_actual_coverage_percentage();

        // If active request tracking shows no gaps but basic progress indicates incomplete sync,
        // we may have a tracking inconsistency. In this case, trust the basic progress calculation.
        let corrected_total_missing = if total_missing == 0
            && stats_lock.filters_received < stats_lock.filters_requested
        {
            // Gap detection failed, but basic stats show incomplete sync
            tracing::debug!(
                "Gap detection shows complete ({}), but basic progress shows {}/{} - treating as incomplete",
                total_missing,
                stats_lock.filters_received,
                stats_lock.filters_requested
            );
            (stats_lock.filters_requested - stats_lock.filters_received) as u32
        } else {
            total_missing
        };

        (
            stats_lock.filters_requested,
            stats_lock.filters_received,
            basic_progress,
            timeout,
            corrected_total_missing,
            actual_coverage,
            missing_ranges,
        )
    }
}
