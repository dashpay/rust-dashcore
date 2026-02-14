//! CFilters pipeline implementation.
//!
//! Handles pipelined download of compact block filters (BIP 157/158).
//! Uses DownloadCoordinator for batch-level tracking, with additional
//! per-batch tracking for individual filter responses.
//!
//! Filters are buffered in a HashMap<FilterMatchKey, BlockFilter> until the entire batch
//! is complete, enabling batch verification and direct wallet matching.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use dashcore::BlockHash;

use crate::error::{SyncError, SyncResult};
use crate::network::RequestSender;
use crate::storage::BlockHeaderStorage;
use crate::sync::download_coordinator::{DownloadConfig, DownloadCoordinator};
use crate::sync::filters::batch::FiltersBatch;
use crate::sync::filters::batch_tracker::BatchTracker;

/// Batch size for filter requests.
const FILTER_BATCH_SIZE: u32 = 1000;

/// Maximum concurrent filter batch requests.
const MAX_CONCURRENT_FILTER_BATCHES: usize = 20;

/// Timeout for filter batch requests.
/// Each batch requires 1000 individual filter messages, so allow plenty of time.
const FILTER_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of retries for CFilter requests.
const FILTERS_MAX_RETRIES: u32 = 3;

/// Pipeline for downloading compact block filters.
///
/// Uses DownloadCoordinator<u32> for batch-level download mechanics,
/// with BatchTracker for tracking individual filters within
/// each batch.
///
/// Filters are buffered until the entire batch is complete, then returned
/// via `take_completed_batches()` for verification and matching.
#[derive(Debug)]
pub(super) struct FiltersPipeline {
    /// Core coordinator tracks batch start heights.
    coordinator: DownloadCoordinator<u32>,
    /// Tracks individual filter receipts per batch (start_height -> tracker).
    batch_trackers: HashMap<u32, BatchTracker>,
    /// Completed filter batches.
    completed_batches: BTreeSet<FiltersBatch>,
    /// Target height for sync.
    target_height: u32,
    /// Planned end heights for each queued batch (start_height -> end_height).
    /// Fixed at queue time so `send_pending` respects the original boundaries
    /// regardless of later `target_height` changes from `extend_target`.
    planned_ends: HashMap<u32, u32>,
    /// Total filters received.
    filters_received: u32,
    /// Highest filter height received.
    highest_received: u32,
}

impl Default for FiltersPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl FiltersPipeline {
    /// Create a new CFilters pipeline.
    pub(super) fn new() -> Self {
        Self {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(MAX_CONCURRENT_FILTER_BATCHES)
                    .with_timeout(FILTER_TIMEOUT)
                    .with_max_retries(FILTERS_MAX_RETRIES),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 0,
            planned_ends: HashMap::new(),
            filters_received: 0,
            highest_received: 0,
        }
    }

    /// Take completed batches with their buffered filter data for processing.
    pub(super) fn take_completed_batches(&mut self) -> BTreeSet<FiltersBatch> {
        std::mem::take(&mut self.completed_batches)
    }

    /// Initialize the pipeline for a sync range.
    ///
    /// Pre-queues all batches for the range using the coordinator's pending queue.
    pub(super) fn init(&mut self, start_height: u32, target_height: u32) {
        self.coordinator.clear();
        self.batch_trackers.clear();
        self.completed_batches.clear();
        self.planned_ends.clear();
        self.target_height = target_height;
        self.highest_received = start_height.saturating_sub(1);
        self.filters_received = 0;

        // Pre-queue all batches with their planned end heights
        let mut current = start_height;
        while current <= target_height {
            let batch_end = (current + FILTER_BATCH_SIZE - 1).min(target_height);
            self.coordinator.enqueue([current]);
            self.planned_ends.insert(current, batch_end);
            current = batch_end + 1;
        }
    }

    /// Extend the target height without resetting pipeline state.
    ///
    /// Queues additional batches from the old target boundary to the new target.
    /// Each batch stores its planned end height so `send_pending` uses the
    /// correct boundary regardless of further target extensions.
    pub(super) fn extend_target(&mut self, new_target: u32) {
        if new_target <= self.target_height {
            return;
        }

        let old_target = self.target_height;
        self.target_height = new_target;

        // Queue new batches from (old_target + 1) to new_target
        let mut current = old_target + 1;
        while current <= new_target {
            let batch_end = (current + FILTER_BATCH_SIZE - 1).min(new_target);
            self.coordinator.enqueue([current]);
            self.planned_ends.insert(current, batch_end);
            current = batch_end + 1;
        }
    }

    /// Send pending filter requests up to the concurrency limit.
    pub(super) async fn send_pending(
        &mut self,
        requests: &RequestSender,
        storage: &impl BlockHeaderStorage,
    ) -> SyncResult<usize> {
        let count = self.coordinator.available_to_send();
        if count == 0 {
            return Ok(0);
        }

        let start_heights = self.coordinator.take_pending(count);
        let mut sent = 0;

        for start_height in start_heights {
            // Use the planned end from queue time, falling back to dynamic computation
            let batch_end =
                self.planned_ends.get(&start_height).copied().unwrap_or_else(|| {
                    (start_height + FILTER_BATCH_SIZE - 1).min(self.target_height)
                });

            // Get stop hash for this batch
            let stop_hash = storage
                .get_header(batch_end)
                .await?
                .ok_or_else(|| {
                    SyncError::Storage(format!("Missing header at height {}", batch_end))
                })?
                .block_hash();

            requests.request_filters(start_height, stop_hash)?;

            // Track in coordinator and batch tracker (reuse existing tracker if present)
            self.coordinator.mark_sent(&[start_height]);
            self.batch_trackers.entry(start_height).or_insert_with(|| BatchTracker::new(batch_end));

            tracing::debug!(
                "Sent GetCFilters: {} to {} ({} active batches)",
                start_height,
                batch_end,
                self.coordinator.active_count()
            );

            sent += 1;
        }

        Ok(sent)
    }

    /// Handle a received CFilter message with filter data.
    ///
    /// Buffers the filter data for batch verification and wallet matching.
    /// Returns `Some(height)` when a batch completes, `None` otherwise.
    pub(super) fn receive_with_data(
        &mut self,
        height: u32,
        block_hash: BlockHash,
        filter_data: &[u8],
    ) -> Option<u32> {
        // Find which batch this filter belongs to
        let batch_start = self.find_batch_for_height(height)?;

        let tracker = self.batch_trackers.get_mut(&batch_start)?;
        tracker.insert_filter(height, block_hash, filter_data);
        self.filters_received += 1;
        self.highest_received = self.highest_received.max(height);

        // Check if batch is complete
        if !tracker.is_complete(batch_start) {
            // Log progress toward completion
            let received = tracker.received();
            let expected = (tracker.end_height() - batch_start + 1) as usize;
            if received > 0 && received % 100 == 0 {
                tracing::debug!(
                    "Filter batch {} progress: {}/{} filters received",
                    batch_start,
                    received,
                    expected
                );
            }
            return None;
        }

        let end_height = tracker.end_height();
        // Take the filters before removing the tracker
        let filters =
            self.batch_trackers.get_mut(&batch_start).map(|t| t.take_filters()).unwrap_or_default();

        self.batch_trackers.remove(&batch_start);
        self.coordinator.receive(&batch_start);

        tracing::info!(
            "Filter batch {}-{} complete ({} filters)",
            batch_start,
            end_height,
            filters.len()
        );
        let batch = FiltersBatch::new(batch_start, end_height, filters);
        self.completed_batches.insert(batch);

        Some(height)
    }

    /// Find which batch a filter height belongs to.
    fn find_batch_for_height(&self, height: u32) -> Option<u32> {
        for (&start, tracker) in &self.batch_trackers {
            if height >= start && height <= tracker.end_height() {
                return Some(start);
            }
        }
        None
    }

    /// Check for timed out batches and handle retries.
    ///
    /// Returns batch starts that timed out and were re-queued.
    /// Uses coordinator's retry mechanism to avoid duplicate requests.
    /// Note: Does not remove batch trackers - keeps them to receive any late-arriving filters.
    pub(super) fn handle_timeouts(&mut self) -> Vec<u32> {
        let mut timed_out_starts = Vec::new();

        for start in self.coordinator.check_timeouts() {
            if self.coordinator.enqueue_retry(start) {
                tracing::warn!("Filter batch at {} timed out, queued for retry", start);
                timed_out_starts.push(start);
            } else {
                // Max retries exceeded - remove tracker, log error
                tracing::error!("Filter batch at {} exceeded max retries, giving up", start);
                self.batch_trackers.remove(&start);
            }
        }

        timed_out_starts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkRequest, RequestSender};
    use crate::storage::{PersistentBlockHeaderStorage, PersistentStorage};
    use dashcore::bip158::BlockFilter;
    use dashcore::block::Header;
    use dashcore::network::message::NetworkMessage;
    use dashcore_hashes::Hash;
    use key_wallet_manager::wallet_manager::FilterMatchKey;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::mpsc::unbounded_channel;
    // =========================================================================
    // Helper functions
    // =========================================================================

    /// Create a pipeline with short timeout for testing timeouts.
    fn create_pipeline_with_short_timeout() -> FiltersPipeline {
        FiltersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(3),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 0,
            planned_ends: HashMap::new(),
            filters_received: 0,
            highest_received: 0,
        }
    }

    /// Create a test request sender with its receiver.
    fn create_test_request_sender(
    ) -> (RequestSender, tokio::sync::mpsc::UnboundedReceiver<NetworkRequest>) {
        let (tx, rx) = unbounded_channel();
        (RequestSender::new(tx), rx)
    }

    /// Generate dummy filter data for testing.
    fn dummy_filter_data(height: u32) -> Vec<u8> {
        vec![height as u8, (height >> 8) as u8, 0x01, 0x02]
    }

    // =========================================================================
    // FiltersPipeline Construction Tests
    // =========================================================================

    #[test]
    fn test_pipeline_new() {
        let pipeline = FiltersPipeline::new();

        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert!(pipeline.batch_trackers.is_empty());
        assert!(pipeline.completed_batches.is_empty());
        assert_eq!(pipeline.target_height, 0);
        assert_eq!(pipeline.filters_received, 0);
        assert_eq!(pipeline.highest_received, 0);
    }

    #[test]
    fn test_pipeline_default_trait() {
        let default_pipeline = FiltersPipeline::default();
        let new_pipeline = FiltersPipeline::new();

        assert_eq!(
            default_pipeline.coordinator.active_count(),
            new_pipeline.coordinator.active_count()
        );
        assert_eq!(default_pipeline.target_height, new_pipeline.target_height);
    }

    #[test]
    fn test_pipeline_init() {
        let mut pipeline = FiltersPipeline::new();

        pipeline.init(100, 500);

        // Should have 1 batch queued (100-500 is 401 filters, fits in 1 batch)
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert_eq!(pipeline.target_height, 500);
        assert_eq!(pipeline.highest_received, 99);
        assert_eq!(pipeline.filters_received, 0);
    }

    #[test]
    fn test_pipeline_init_resets_state() {
        let mut pipeline = FiltersPipeline::new();

        // Add some state
        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.completed_batches.insert(FiltersBatch::new(100, 199, HashMap::new()));
        pipeline.coordinator.mark_sent(&[0]);
        pipeline.filters_received = 50;

        // Init should clear everything
        pipeline.init(200, 300);

        assert!(pipeline.batch_trackers.is_empty());
        assert!(pipeline.completed_batches.is_empty());
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.filters_received, 0);
        // 1 batch queued for heights 200-300
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert_eq!(pipeline.target_height, 300);
    }

    // =========================================================================
    // Target Extension Tests
    // =========================================================================

    #[test]
    fn test_extend_target_increases() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 100);

        pipeline.extend_target(200);

        assert_eq!(pipeline.target_height, 200);
    }

    #[tokio::test]
    async fn test_extend_target_no_overlap_no_gap() {
        // Verify that init + extend_target produces contiguous, non-overlapping batches.
        // The init's last batch is truncated (3000-3500), and extend_target fills from 3501.
        // send_pending respects planned_ends so the truncated batch stays at 3000-3500.
        let headers = Header::dummy_batch(0..6000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 3500);
        assert_eq!(pipeline.coordinator.pending_count(), 4); // 0, 1000, 2000, 3000

        // Extend target — new batches start at 3501
        pipeline.extend_target(5000);
        assert_eq!(pipeline.coordinator.pending_count(), 6); // + 3501, 4501

        let (sender, _rx) = create_test_request_sender();
        pipeline.send_pending(&sender, &storage).await.unwrap();

        // Verify batch trackers have no overlapping ranges and no gaps
        let mut ranges: Vec<(u32, u32)> = pipeline
            .batch_trackers
            .iter()
            .map(|(&start, tracker)| (start, tracker.end_height()))
            .collect();
        ranges.sort_by_key(|&(start, _)| start);

        for window in ranges.windows(2) {
            assert!(
                window[0].1 < window[1].0,
                "Overlapping batches: {}-{} and {}-{}",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1
            );
            assert_eq!(
                window[0].1 + 1,
                window[1].0,
                "Gap between batches: {}-{} and {}-{}",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1
            );
        }

        // Verify: 0-999, 1000-1999, 2000-2999, 3000-3500, 3501-4500, 4501-5000
        assert_eq!(ranges[0], (0, 999));
        assert_eq!(ranges[3], (3000, 3500)); // kept at planned end, not expanded
        assert_eq!(ranges[4], (3501, 4500));
        assert_eq!(ranges[5], (4501, 5000));
    }

    #[tokio::test]
    async fn test_extend_target_after_send_no_gap() {
        // Verify that when the last init batch is sent BEFORE extend_target,
        // there's no gap. The sent batch uses its planned end (truncated),
        // and extend_target fills from old_target + 1.
        let headers = Header::dummy_batch(0..6000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 3500);

        let (sender, _rx) = create_test_request_sender();

        // Send all init batches first
        pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(pipeline.batch_trackers.get(&3000).unwrap().end_height(), 3500);

        // Now extend target
        pipeline.extend_target(5000);

        // Send the new batches
        pipeline.send_pending(&sender, &storage).await.unwrap();

        let mut ranges: Vec<(u32, u32)> = pipeline
            .batch_trackers
            .iter()
            .map(|(&start, tracker)| (start, tracker.end_height()))
            .collect();
        ranges.sort_by_key(|&(start, _)| start);

        // Verify contiguous: 0-999, 1000-1999, 2000-2999, 3000-3500, 3501-4500, 4501-5000
        for window in ranges.windows(2) {
            assert!(
                window[0].1 < window[1].0,
                "Overlapping batches: {}-{} and {}-{}",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1
            );
            assert_eq!(
                window[0].1 + 1,
                window[1].0,
                "Gap between batches: {}-{} and {}-{}",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1
            );
        }
    }

    #[test]
    fn test_extend_target_ignores_lower() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 100);

        pipeline.extend_target(50);

        assert_eq!(pipeline.target_height, 100);

        pipeline.extend_target(100);

        assert_eq!(pipeline.target_height, 100);
    }

    // =========================================================================
    // Receive Tests
    // =========================================================================

    #[test]
    fn test_receive_single_filter() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 99;

        // Set up batch tracker manually (simulating an in-flight batch)
        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.coordinator.mark_sent(&[0]);

        let height = 50;
        let hash = Header::dummy(height).block_hash();
        let result = pipeline.receive_with_data(height, hash, &dummy_filter_data(height));

        // Returns None since batch is not complete (only 1 of 100 filters received)
        assert_eq!(result, None);
        // But counters are updated
        assert_eq!(pipeline.filters_received, 1);
        assert_eq!(pipeline.highest_received, 50);
    }

    #[test]
    fn test_receive_unknown_height() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 99;

        // No batch tracker set up - filter is unexpected
        let hash = Header::dummy(50).block_hash();
        let result = pipeline.receive_with_data(50, hash, &dummy_filter_data(50));

        assert_eq!(result, None);
        assert_eq!(pipeline.filters_received, 0);
    }

    #[test]
    fn test_receive_batch_completion() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 2;

        // Set up a small batch (3 filters: 0, 1, 2)
        pipeline.batch_trackers.insert(0, BatchTracker::new(2));
        pipeline.coordinator.mark_sent(&[0]);

        // Receive all filters
        for h in 0..=2 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        // Batch should be complete and moved to completed_batches
        assert!(pipeline.batch_trackers.is_empty());
        assert_eq!(pipeline.completed_batches.len(), 1);

        let completed = pipeline.take_completed_batches();
        assert_eq!(completed.len(), 1);
        let batch = completed.into_iter().next().unwrap();
        assert_eq!(batch.start_height(), 0);
        assert_eq!(batch.end_height(), 2);
        assert_eq!(batch.filters().len(), 3);
    }

    #[test]
    fn test_receive_out_of_order() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 4;

        pipeline.batch_trackers.insert(0, BatchTracker::new(4));
        pipeline.coordinator.mark_sent(&[0]);

        // Receive out of order
        for h in [3, 1, 4, 0, 2] {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        // Should complete successfully
        assert!(pipeline.batch_trackers.is_empty());
        assert_eq!(pipeline.completed_batches.len(), 1);
    }

    #[test]
    fn test_receive_updates_counters() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 99;

        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.coordinator.mark_sent(&[0]);

        // Receive some filters
        for h in [10, 5, 20, 15] {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        assert_eq!(pipeline.filters_received, 4);
        assert_eq!(pipeline.highest_received, 20);
    }

    #[test]
    fn test_receive_small_batch_at_target() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 1005;

        // Small batch of 6 filters (1000-1005)
        pipeline.batch_trackers.insert(1000, BatchTracker::new(1005));
        pipeline.coordinator.mark_sent(&[1000]);

        // Receive all 6 filters
        for h in 1000..=1005 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        assert_eq!(pipeline.completed_batches.len(), 1);
        let batch = pipeline.completed_batches.iter().next().unwrap();
        assert_eq!(batch.filters().len(), 6);
    }

    #[test]
    fn test_receive_multiple_batches() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 9;

        // Set up two batches manually
        pipeline.batch_trackers.insert(0, BatchTracker::new(4));
        pipeline.batch_trackers.insert(5, BatchTracker::new(9));
        pipeline.coordinator.mark_sent(&[0, 5]);

        // Receive first batch
        for h in 0..=4 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        assert_eq!(pipeline.completed_batches.len(), 1);
        assert_eq!(pipeline.batch_trackers.len(), 1);

        // Receive second batch
        for h in 5..=9 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        assert_eq!(pipeline.completed_batches.len(), 2);
        assert!(pipeline.batch_trackers.is_empty());
    }

    // =========================================================================
    // find_batch_for_height Tests
    // =========================================================================

    #[test]
    fn test_find_batch_for_height_found() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.batch_trackers.insert(0, BatchTracker::new(999));
        pipeline.batch_trackers.insert(1000, BatchTracker::new(1999));

        assert_eq!(pipeline.find_batch_for_height(500), Some(0));
        assert_eq!(pipeline.find_batch_for_height(1500), Some(1000));
    }

    #[test]
    fn test_find_batch_for_height_none() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.batch_trackers.insert(100, BatchTracker::new(199));

        // Below range
        assert_eq!(pipeline.find_batch_for_height(50), None);
        // Above range
        assert_eq!(pipeline.find_batch_for_height(250), None);
    }

    #[test]
    fn test_find_batch_for_height_boundary() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.batch_trackers.insert(100, BatchTracker::new(199));

        // First height in batch
        assert_eq!(pipeline.find_batch_for_height(100), Some(100));
        // Last height in batch
        assert_eq!(pipeline.find_batch_for_height(199), Some(100));
    }

    // =========================================================================
    // Timeout Tests
    // =========================================================================

    #[test]
    fn test_handle_timeouts_no_batches() {
        let mut pipeline = FiltersPipeline::new();
        let timed_out = pipeline.handle_timeouts();
        assert!(timed_out.is_empty());
    }

    #[test]
    fn test_handle_timeouts_requeue() {
        let mut pipeline = create_pipeline_with_short_timeout();
        pipeline.target_height = 999;

        // Set up batch and mark as in-flight (simulating a sent request)
        pipeline.batch_trackers.insert(0, BatchTracker::new(999));
        pipeline.coordinator.mark_sent(&[0]);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        let timed_out = pipeline.handle_timeouts();

        assert_eq!(timed_out, vec![0]);
        // Batch should be re-queued in coordinator's pending queue
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert_eq!(pipeline.coordinator.active_count(), 0);
    }

    #[test]
    fn test_handle_timeouts_keeps_tracker() {
        let mut pipeline = create_pipeline_with_short_timeout();
        pipeline.target_height = 99;

        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.coordinator.mark_sent(&[0]);

        // Receive some filters before timeout
        for h in 0..10 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        std::thread::sleep(Duration::from_millis(5));

        let timed_out = pipeline.handle_timeouts();

        // Should timeout but tracker is preserved for late arrivals
        assert_eq!(timed_out, vec![0]);
        assert!(pipeline.batch_trackers.contains_key(&0));
        assert_eq!(pipeline.batch_trackers.get(&0).unwrap().received(), 10);
    }

    #[test]
    fn test_timeout_does_not_duplicate_inflight_batches() {
        // This test verifies the bug fix: when an early batch times out,
        // only that batch is re-queued, not later in-flight batches.
        let mut pipeline = FiltersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(3)
                    .with_max_concurrent(10),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 2999,
            planned_ends: HashMap::new(),
            filters_received: 0,
            highest_received: 0,
        };

        // Simulate 3 in-flight batches: 0-999, 1000-1999, 2000-2999
        pipeline.batch_trackers.insert(0, BatchTracker::new(999));
        pipeline.batch_trackers.insert(1000, BatchTracker::new(1999));
        pipeline.batch_trackers.insert(2000, BatchTracker::new(2999));
        pipeline.coordinator.mark_sent(&[0, 1000, 2000]);

        assert_eq!(pipeline.coordinator.active_count(), 3);
        assert_eq!(pipeline.coordinator.pending_count(), 0);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        // Handle timeouts - all 3 should timeout and be re-queued
        let timed_out = pipeline.handle_timeouts();
        assert_eq!(timed_out.len(), 3);

        // All 3 batches should be in the pending queue, not duplicated
        assert_eq!(pipeline.coordinator.pending_count(), 3);
        assert_eq!(pipeline.coordinator.active_count(), 0);

        // Take pending items - should get exactly 3, not more
        let pending = pipeline.coordinator.take_pending(10);
        assert_eq!(pending.len(), 3);
        assert!(pending.contains(&0));
        assert!(pending.contains(&1000));
        assert!(pending.contains(&2000));
    }

    // =========================================================================
    // send_pending Tests
    // =========================================================================

    #[tokio::test]
    async fn test_send_pending_single_batch() {
        let headers = Header::dummy_batch(0..1000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 999);

        let (sender, mut rx) = create_test_request_sender();

        let count = pipeline.send_pending(&sender, &storage).await.unwrap();

        assert_eq!(count, 1);
        assert_eq!(pipeline.coordinator.active_count(), 1);
        assert!(pipeline.batch_trackers.contains_key(&0));
        // No more pending since the single batch was sent
        assert_eq!(pipeline.coordinator.pending_count(), 0);

        // Verify message was sent
        let request = rx.try_recv().unwrap();
        let NetworkRequest::SendMessage(msg) = request;
        if let NetworkMessage::GetCFilters(gcf) = msg {
            assert_eq!(gcf.start_height, 0);
            assert_eq!(gcf.filter_type, 0);
        } else {
            panic!("Expected GetCFilters message");
        }
    }

    #[tokio::test]
    async fn test_send_pending_respects_limit() {
        // Create enough headers for many batches
        let headers = Header::dummy_batch(0..25000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 24999);

        let (sender, _rx) = create_test_request_sender();

        let count = pipeline.send_pending(&sender, &storage).await.unwrap();

        // Should respect MAX_CONCURRENT_FILTER_BATCHES (20)
        // 25 batches needed, but only 20 can be in-flight at once
        assert_eq!(count, MAX_CONCURRENT_FILTER_BATCHES);
        assert_eq!(pipeline.coordinator.active_count(), MAX_CONCURRENT_FILTER_BATCHES);
        assert_eq!(pipeline.batch_trackers.len(), MAX_CONCURRENT_FILTER_BATCHES);
        // 5 batches still pending
        assert_eq!(pipeline.coordinator.pending_count(), 5);
    }

    #[tokio::test]
    async fn test_send_pending_calculates_end() {
        let headers = Header::dummy_batch(0..1500);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        // Target is 1200, so second batch ends at 1200 not 1999
        pipeline.init(0, 1200);

        let (sender, _rx) = create_test_request_sender();

        let count = pipeline.send_pending(&sender, &storage).await.unwrap();

        assert_eq!(count, 2);

        // First batch: 0-999
        assert!(pipeline.batch_trackers.contains_key(&0));
        assert_eq!(pipeline.batch_trackers.get(&0).unwrap().end_height(), 999);

        // Second batch: 1000-1200 (capped by target)
        assert!(pipeline.batch_trackers.contains_key(&1000));
        assert_eq!(pipeline.batch_trackers.get(&1000).unwrap().end_height(), 1200);
    }

    #[tokio::test]
    async fn test_send_pending_sends_all_queued() {
        let headers = Header::dummy_batch(0..3000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 2500);

        let (sender, _rx) = create_test_request_sender();

        let count = pipeline.send_pending(&sender, &storage).await.unwrap();

        // Should send all 3 batches: 0-999, 1000-1999, 2000-2500
        assert_eq!(count, 3);
        assert_eq!(pipeline.coordinator.active_count(), 3);
        assert_eq!(pipeline.coordinator.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_send_pending_no_work_when_queue_empty() {
        let headers = Header::dummy_batch(0..100);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 50);

        let (sender, _rx) = create_test_request_sender();

        // First send exhausts the queue
        let count = pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(count, 1);

        // Second send has nothing to do
        let count = pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(count, 0);
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[tokio::test]
    async fn test_full_batch_lifecycle() {
        let headers = Header::dummy_batch(0..100);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 99);

        let (sender, _rx) = create_test_request_sender();

        // Send request
        let sent = pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(sent, 1);
        assert_eq!(pipeline.coordinator.active_count(), 1);

        // Receive all filters
        for h in 0..=99 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        // Batch should be complete
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.completed_batches.len(), 1);
        assert_eq!(pipeline.filters_received, 100);
        assert_eq!(pipeline.highest_received, 99);

        // Take completed
        let completed = pipeline.take_completed_batches();
        assert_eq!(completed.len(), 1);
        assert!(pipeline.completed_batches.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_and_retry_flow() {
        let headers = Header::dummy_batch(0..1000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = create_pipeline_with_short_timeout();
        pipeline.init(0, 999);

        let (sender, _rx) = create_test_request_sender();

        // Send initial request
        pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(pipeline.coordinator.active_count(), 1);
        assert_eq!(pipeline.coordinator.pending_count(), 0);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        // Handle timeout - should re-queue the batch via coordinator
        let timed_out = pipeline.handle_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert_eq!(pipeline.coordinator.active_count(), 0);

        // Tracker should still exist for late arrivals
        assert!(pipeline.batch_trackers.contains_key(&0));

        // Can retry by sending again
        pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(pipeline.coordinator.active_count(), 1);

        // Existing tracker is reused (not replaced)
        assert!(pipeline.batch_trackers.contains_key(&0));
    }

    #[test]
    fn test_take_completed_batches_clears() {
        let mut pipeline = FiltersPipeline::new();

        // Add some completed batches
        pipeline.completed_batches.insert(FiltersBatch::new(0, 99, HashMap::new()));
        pipeline.completed_batches.insert(FiltersBatch::new(100, 199, HashMap::new()));

        let taken = pipeline.take_completed_batches();
        assert_eq!(taken.len(), 2);
        assert!(pipeline.completed_batches.is_empty());
    }

    #[test]
    fn test_filters_batch_filters_mut() {
        let mut batch = FiltersBatch::new(0, 0, HashMap::new());

        batch
            .filters_mut()
            .insert(FilterMatchKey::new(0, BlockHash::all_zeros()), BlockFilter::new(&[0x01]));

        assert_eq!(batch.filters().len(), 1);
    }

    // =========================================================================
    // Boundary batch with deferred send tests
    // =========================================================================

    #[tokio::test]
    async fn test_boundary_batch_planned_end_survives_extend_target() {
        // Reproduce the exact scenario from the flaky test:
        // init(0, 26000) creates 27 batches, but only 20 can be sent (max concurrent).
        // Batch 26000 (the boundary batch with planned_end=26000) stays in the queue.
        // Then extend_target is called multiple times, changing target_height to 40000.
        // When batch 26000 is finally dequeued, planned_ends[26000] must still be 26000.
        let headers = Header::dummy_batch(0..41000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 26000);

        // Verify init created correct planned ends
        assert_eq!(pipeline.planned_ends.get(&0), Some(&999));
        assert_eq!(pipeline.planned_ends.get(&25000), Some(&25999));
        assert_eq!(pipeline.planned_ends.get(&26000), Some(&26000));
        assert_eq!(pipeline.coordinator.pending_count(), 27);

        let (sender, _rx) = create_test_request_sender();

        // Send first 20 batches (max concurrent)
        pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(pipeline.coordinator.active_count(), 20);
        assert_eq!(pipeline.coordinator.pending_count(), 7); // 20000-26000

        // Verify planned_ends[26000] still exists after initial send
        assert_eq!(pipeline.planned_ends.get(&26000), Some(&26000));

        // Extend target multiple times (simulates FilterHeadersStored events)
        pipeline.extend_target(28000);
        assert_eq!(pipeline.planned_ends.get(&26000), Some(&26000));
        assert_eq!(pipeline.planned_ends.get(&26001), Some(&27000));

        pipeline.extend_target(30000);
        pipeline.extend_target(32000);
        pipeline.extend_target(34000);
        pipeline.extend_target(36000);
        pipeline.extend_target(38000);
        pipeline.extend_target(40000);

        // After all extends, planned_ends[26000] must still be 26000
        assert_eq!(
            pipeline.planned_ends.get(&26000),
            Some(&26000),
            "planned_ends[26000] was corrupted by extend_target"
        );
        assert_eq!(pipeline.target_height, 40000);

        // Simulate batches completing and dequeuing remaining items.
        // Complete batches 0-6000 (7 batches) to free slots for 20000-26000.
        for batch_start in (0..7000).step_by(1000) {
            let end = batch_start + 999;
            // Feed all filters for this batch
            for h in batch_start..=end {
                let hash = headers[h as usize].block_hash();
                pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
            }
            // Each completion frees a slot; send_pending dequeues the next item
            pipeline.send_pending(&sender, &storage).await.unwrap();
        }

        // Now batches 20000-26000 should have been sent.
        // Check the batch tracker for 26000 to verify it was sent with the correct end.
        let tracker_26000 = pipeline.batch_trackers.get(&26000);
        assert!(tracker_26000.is_some(), "Batch 26000 should have been sent");
        assert_eq!(
            tracker_26000.unwrap().end_height(),
            26000,
            "Batch 26000 should have end_height 26000 (from planned_ends), not 26999 (from fallback)"
        );
    }
}
