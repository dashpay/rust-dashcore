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
    /// Next height to request.
    next_request_height: u32,
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
                    .with_timeout(FILTER_TIMEOUT)
                    .with_max_retries(FILTERS_MAX_RETRIES),
            ),
            batch_trackers: HashMap::new(),
            completed_batches: BTreeSet::new(),
            next_request_height: 0,
            target_height: 0,
            filters_received: 0,
            highest_received: 0,
        }
    }

    /// Get the number of active batches.
    pub(super) fn active_count(&self) -> usize {
        self.coordinator.active_count()
    }

    /// Take completed batches with their buffered filter data for processing.
    pub(super) fn take_completed_batches(&mut self) -> BTreeSet<FiltersBatch> {
        std::mem::take(&mut self.completed_batches)
    }

    /// Initialize the pipeline for a sync range.
    pub(super) fn init(&mut self, start_height: u32, target_height: u32) {
        self.coordinator.clear();
        self.batch_trackers.clear();
        self.completed_batches.clear();
        self.next_request_height = start_height;
        self.target_height = target_height;
        self.highest_received = start_height.saturating_sub(1);
        self.filters_received = 0;
    }

    /// Extend the target height without resetting pipeline state.
    pub(super) fn extend_target(&mut self, new_target: u32) {
        if new_target > self.target_height {
            self.target_height = new_target;
        }
    }

    /// Send pending filter requests up to the concurrency limit.
    pub(super) async fn send_pending(
        &mut self,
        requests: &RequestSender,
        storage: &impl BlockHeaderStorage,
    ) -> SyncResult<usize> {
        let mut count = 0;

        while self.coordinator.active_count() < MAX_CONCURRENT_FILTER_BATCHES
            && self.next_request_height <= self.target_height
        {
            let start_height = self.next_request_height;
            let batch_end = (start_height + FILTER_BATCH_SIZE - 1).min(self.target_height);

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

            self.next_request_height = batch_end + 1;
            count += 1;
        }

        Ok(count)
    }

    /// Handle a received CFilter message with filter data.
    ///
    /// Buffers the filter data for batch verification and wallet matching.
    /// Returns `Some(height)` if the filter was tracked, or `None` if unexpected.
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
    /// Returns batch starts that timed out.
    /// Resets next_request_height to re-fetch entire timed-out batches.
    /// Note: Does not remove batch trackers - keeps them to receive any late-arriving filters.
    pub(super) fn handle_timeouts(&mut self) -> Vec<u32> {
        let timed_out = self.coordinator.check_timeouts();
        let mut timed_out_starts = Vec::new();

        for start in timed_out {
            // Don't remove tracker - keep it to receive any late-arriving filters
            if let Some(tracker) = self.batch_trackers.get(&start) {
                let missing = tracker.missing_heights(start);
                let received_count = tracker.received();

                if received_count > 0 {
                    tracing::warn!(
                        "Filter batch at {} timed out: {} received, {} missing - will re-fetch",
                        start,
                        received_count,
                        missing.len()
                    );
                } else {
                    tracing::debug!(
                        "Filter batch at {} timed out with {} missing filters",
                        start,
                        missing.len()
                    );
                }

                timed_out_starts.push(start);
            }
        }

        // Re-queue by resetting next_request_height to earliest timed-out batch start
        if let Some(&earliest) = timed_out_starts.iter().min() {
            if earliest < self.next_request_height {
                self.next_request_height = earliest;
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
            next_request_height: 0,
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

        assert_eq!(pipeline.active_count(), 0);
        assert!(pipeline.batch_trackers.is_empty());
        assert!(pipeline.completed_batches.is_empty());
        assert_eq!(pipeline.next_request_height, 0);
        assert_eq!(pipeline.target_height, 0);
        assert_eq!(pipeline.filters_received, 0);
        assert_eq!(pipeline.highest_received, 0);
    }

    #[test]
    fn test_pipeline_default_trait() {
        let default_pipeline = FiltersPipeline::default();
        let new_pipeline = FiltersPipeline::new();

        assert_eq!(default_pipeline.active_count(), new_pipeline.active_count());
        assert_eq!(default_pipeline.next_request_height, new_pipeline.next_request_height);
        assert_eq!(default_pipeline.target_height, new_pipeline.target_height);
    }

    #[test]
    fn test_pipeline_init() {
        let mut pipeline = FiltersPipeline::new();

        pipeline.init(100, 500);

        assert_eq!(pipeline.next_request_height, 100);
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
        assert_eq!(pipeline.active_count(), 0);
        assert_eq!(pipeline.filters_received, 0);
        assert_eq!(pipeline.next_request_height, 200);
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
        pipeline.init(0, 99);

        // Set up batch tracker manually
        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.coordinator.mark_sent(&[0]);

        let height = 50;
        let hash = Header::dummy(height).block_hash();
        let result = pipeline.receive_with_data(height, hash, &dummy_filter_data(height));

        assert_eq!(result, Some(50));
        assert_eq!(pipeline.filters_received, 1);
        assert_eq!(pipeline.highest_received, 50);
    }

    #[test]
    fn test_receive_unknown_height() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 99);

        // No batch tracker set up
        let hash = Header::dummy(50).block_hash();
        let result = pipeline.receive_with_data(50, hash, &dummy_filter_data(50));

        assert_eq!(result, None);
        assert_eq!(pipeline.filters_received, 0);
    }

    #[test]
    fn test_receive_batch_completion() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 2);

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
        pipeline.init(0, 4);

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
        pipeline.init(0, 99);

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
        // Target at 1005 means the second batch is only 6 filters (1000-1005)
        pipeline.init(1000, 1005);

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
        pipeline.init(0, 9);

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
        pipeline.init(0, 999);

        // Set up batch and mark as in-flight
        pipeline.batch_trackers.insert(0, BatchTracker::new(999));
        pipeline.coordinator.mark_sent(&[0]);
        pipeline.next_request_height = 1000;

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        let timed_out = pipeline.handle_timeouts();

        assert_eq!(timed_out, vec![0]);
        // next_request_height should be reset to re-fetch
        assert_eq!(pipeline.next_request_height, 0);
    }

    #[test]
    fn test_handle_timeouts_keeps_tracker() {
        let mut pipeline = create_pipeline_with_short_timeout();
        pipeline.init(0, 99);

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
        assert_eq!(pipeline.active_count(), 1);
        assert!(pipeline.batch_trackers.contains_key(&0));
        assert_eq!(pipeline.next_request_height, 1000);

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
        let headers = Header::dummy_batch(0..15000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 14999);

        let (sender, _rx) = create_test_request_sender();

        let count = pipeline.send_pending(&sender, &storage).await.unwrap();

        // Should respect MAX_CONCURRENT_FILTER_BATCHES (10)
        assert_eq!(count, 10);
        assert_eq!(pipeline.active_count(), 10);
        assert_eq!(pipeline.batch_trackers.len(), 10);
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
    async fn test_send_pending_advances_height() {
        let headers = Header::dummy_batch(0..3000);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 2500);

        let (sender, _rx) = create_test_request_sender();

        pipeline.send_pending(&sender, &storage).await.unwrap();

        // After sending 3 batches: 0-999, 1000-1999, 2000-2500
        // next_request_height should be 2501
        assert_eq!(pipeline.next_request_height, 2501);
    }

    #[tokio::test]
    async fn test_send_pending_no_work_past_target() {
        let headers = Header::dummy_batch(0..100);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage.store_headers(&headers).await.unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 50);
        pipeline.next_request_height = 51;

        let (sender, _rx) = create_test_request_sender();

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
        assert_eq!(pipeline.active_count(), 1);

        // Receive all filters
        for h in 0..=99 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        // Batch should be complete
        assert_eq!(pipeline.active_count(), 0);
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
        assert_eq!(pipeline.active_count(), 1);
        assert_eq!(pipeline.next_request_height, 1000);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        // Handle timeout - should reset next_request_height
        let timed_out = pipeline.handle_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(pipeline.next_request_height, 0);
        assert_eq!(pipeline.active_count(), 0);

        // Tracker should still exist for late arrivals
        assert!(pipeline.batch_trackers.contains_key(&0));

        // Can retry by sending again
        pipeline.send_pending(&sender, &storage).await.unwrap();
        assert_eq!(pipeline.active_count(), 1);

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
}
