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
                    .with_timeout(FILTER_TIMEOUT),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 0,
            filters_received: 0,
            highest_received: 0,
        }
    }

    /// Returns true if the pipeline has no in-flight or pending work.
    pub(super) fn is_idle(&self) -> bool {
        self.coordinator.active_count() == 0 && self.coordinator.pending_count() == 0
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
        self.target_height = target_height;
        self.highest_received = start_height.saturating_sub(1);
        self.filters_received = 0;

        // Pre-queue all batches
        let mut current = start_height;
        while current <= target_height {
            self.coordinator.enqueue([current]);
            let batch_end = (current + FILTER_BATCH_SIZE - 1).min(target_height);
            self.batch_trackers.insert(current, BatchTracker::new(batch_end));
            current = batch_end + 1;
        }
    }

    /// Extend the target height without resetting pipeline state.
    ///
    /// Queues additional batches from the old target boundary to the new target.
    pub(super) fn extend_target(&mut self, new_target: u32) {
        if new_target <= self.target_height {
            return;
        }

        let old_target = self.target_height;
        self.target_height = new_target;

        // Queue new batches from (old_target + 1) to new_target
        let mut current = old_target + 1;
        while current <= new_target {
            self.coordinator.enqueue([current]);
            let batch_end = (current + FILTER_BATCH_SIZE - 1).min(new_target);
            self.batch_trackers.insert(current, BatchTracker::new(batch_end));
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
            let batch_end = match self.batch_trackers.get(&start_height) {
                Some(tracker) => tracker.end_height(),
                None => {
                    return Err(SyncError::InvalidState(format!(
                        "missing batch tracker for start_height {}",
                        start_height
                    )));
                }
            };

            // Get stop hash for this batch
            let stop_hash = storage
                .get_header(batch_end)
                .await?
                .ok_or_else(|| {
                    SyncError::Storage(format!("Missing header at height {}", batch_end))
                })?
                .block_hash();

            requests.request_filters(start_height, stop_hash)?;

            self.coordinator.mark_sent(&[start_height]);

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
        if !self.coordinator.receive(&batch_start) {
            self.coordinator.cancel_pending(&batch_start);
        }

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
    /// Does not remove batch trackers — keeps them to receive any late-arriving filters.
    pub(super) fn handle_timeouts(&mut self) {
        for start in self.coordinator.check_timeouts() {
            self.coordinator.enqueue_retry(start);
        }
    }

    /// Move in-flight `getcfilters` requests back to pending after a peer
    /// disconnect so the next `send_pending` reissues them to the new peer.
    /// Per-batch trackers and any partially-received filters within them are
    /// preserved — `BatchTracker::insert_filter` is idempotent, so duplicates
    /// from the new peer are harmless.
    pub(super) fn requeue_in_flight(&mut self) {
        self.coordinator.requeue_in_flight();
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
    use key_wallet_manager::FilterMatchKey;
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
                DownloadConfig::default().with_timeout(Duration::from_millis(1)),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 0,
            filters_received: 0,
            highest_received: 0,
        }
    }

    /// Create a pipeline with max_concurrent=2 for testing deferred sends.
    fn create_pipeline_with_low_concurrency() -> FiltersPipeline {
        FiltersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default().with_max_concurrent(2).with_timeout(FILTER_TIMEOUT),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 0,
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
    fn test_is_idle() {
        let mut pipeline = FiltersPipeline::new();
        assert!(pipeline.is_idle());

        pipeline.init(0, 999);
        assert!(!pipeline.is_idle());
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

        // Init should clear old state and set up new batches
        pipeline.init(200, 300);

        assert!(pipeline.completed_batches.is_empty());
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.filters_received, 0);
        // 1 batch queued for heights 200-300
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert_eq!(pipeline.batch_trackers.len(), 1);
        assert_eq!(pipeline.batch_trackers.get(&200).unwrap().end_height(), 300);
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
    async fn test_extend_target_contiguous_batches() {
        // init's last batch is truncated (3000-3500), extend_target fills from 3501.
        // Verify all batches are contiguous after sending.
        let headers = Header::dummy_batch(0..6000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 3500);
        pipeline.extend_target(5000);

        let (sender, _rx) = create_test_request_sender();
        pipeline.send_pending(&sender, &storage).await.unwrap();

        let mut ranges: Vec<(u32, u32)> = pipeline
            .batch_trackers
            .iter()
            .map(|(&start, tracker)| (start, tracker.end_height()))
            .collect();
        ranges.sort_by_key(|&(start, _)| start);

        // Verify contiguous: 0-999, 1000-1999, 2000-2999, 3000-3500, 3501-4500, 4501-5000
        for window in ranges.windows(2) {
            assert_eq!(
                window[0].1 + 1,
                window[1].0,
                "gap or overlap between batches: {}-{} and {}-{}",
                window[0].0,
                window[0].1,
                window[1].0,
                window[1].1
            );
        }
        assert_eq!(ranges[3], (3000, 3500));
        assert_eq!(ranges[4], (3501, 4500));
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
    fn test_requeue_in_flight_preserves_partial_batch_receipts() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 99;

        // One batch in-flight (start_height 0). Receive a filter so the
        // tracker has partial state.
        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.coordinator.mark_sent(&[0]);
        let hash = Header::dummy(50).block_hash();
        pipeline.receive_with_data(50, hash, &dummy_filter_data(50));
        assert_eq!(pipeline.filters_received, 1);
        assert_eq!(pipeline.coordinator.active_count(), 1);

        pipeline.requeue_in_flight();

        // Batch is back in pending; tracker (and the partial filter inside it)
        // is preserved so the new peer's response merges idempotently.
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        let tracker = pipeline.batch_trackers.get(&0).expect("tracker preserved");
        assert_eq!(tracker.received(), 1);
        assert_eq!(pipeline.filters_received, 1);
        assert_eq!(pipeline.highest_received, 50);
    }

    #[test]
    fn test_late_filter_after_requeue_completes_batch_without_orphaning_pending() {
        // Regression: a late `cfilter` from the disconnected peer can complete
        // a batch after `requeue_in_flight` moved it back to pending. Without
        // the cancel-pending hook, the key would linger in `pending` while the
        // tracker was gone, and the next `send_pending` would error with
        // `SyncError::InvalidState`.
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 2;

        pipeline.batch_trackers.insert(0, BatchTracker::new(2));
        pipeline.coordinator.mark_sent(&[0]);

        // Two filters arrive before disconnect.
        for h in 0..=1 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        pipeline.requeue_in_flight();
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert_eq!(pipeline.coordinator.active_count(), 0);

        // Late buffered filter from old peer completes the batch.
        let hash = Header::dummy(2).block_hash();
        pipeline.receive_with_data(2, hash, &dummy_filter_data(2));

        assert_eq!(pipeline.completed_batches.len(), 1);
        assert!(pipeline.batch_trackers.is_empty());
        // The orphaned pending key must be gone so `send_pending` does not
        // resurrect a finished batch.
        assert_eq!(pipeline.coordinator.pending_count(), 0);
        assert_eq!(pipeline.coordinator.active_count(), 0);
    }

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
        pipeline.handle_timeouts();
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

        pipeline.handle_timeouts();

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

        pipeline.handle_timeouts();

        // Should timeout but tracker is preserved for late arrivals
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
                    .with_max_concurrent(10),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 2999,
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
        pipeline.handle_timeouts();

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
        let NetworkRequest::SendMessage(msg) = request else {
            panic!("Expected SendMessage variant");
        };
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

        // 25 batches needed, but only 20 can be in-flight at once
        assert_eq!(count, MAX_CONCURRENT_FILTER_BATCHES);
        assert_eq!(pipeline.coordinator.active_count(), MAX_CONCURRENT_FILTER_BATCHES);
        assert_eq!(pipeline.batch_trackers.len(), 25);
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
        pipeline.handle_timeouts();
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

    #[tokio::test]
    async fn test_deferred_batch_keeps_end_height_after_extend() {
        // init(0, 2500) creates 3 batches but only 2 can be sent (max concurrent=2).
        // The boundary batch (2000-2500) stays queued. After extend_target changes
        // target_height to 4000, the deferred batch must still use end_height=2500.
        let headers = Header::dummy_batch(0..5000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = create_pipeline_with_low_concurrency();
        pipeline.init(0, 2500);
        assert_eq!(pipeline.coordinator.pending_count(), 3); // 0, 1000, 2000

        let (sender, _rx) = create_test_request_sender();

        // Only 2 batches sent, batch 2000 stays queued
        pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(pipeline.coordinator.active_count(), 2);
        assert_eq!(pipeline.coordinator.pending_count(), 1);

        // Extend target — batch 2000's tracker must keep end_height=2500
        pipeline.extend_target(4000);

        // Complete batch 0 to free a slot, then send deferred batch
        for h in 0..1000 {
            let hash = headers[h as usize].block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }
        pipeline.send_pending(&sender, &storage).await.unwrap();

        assert_eq!(
            pipeline.batch_trackers.get(&2000).unwrap().end_height(),
            2500,
            "deferred batch should use its original end height"
        );
    }
}
