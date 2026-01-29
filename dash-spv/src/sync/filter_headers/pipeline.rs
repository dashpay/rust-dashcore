//! CFHeaders pipeline implementation.
//!
//! Handles pipelined download of compact block filter headers (BIP 157/158).
//! Uses DownloadCoordinator for batch tracking with out-of-order buffering.

use dashcore::network::message::NetworkMessage;
use dashcore::network::message_filter::CFHeaders;
use dashcore::BlockHash;
use std::collections::HashMap;
use std::time::Duration;

use crate::error::{SyncError, SyncResult};
use crate::network::RequestSender;
use crate::storage::BlockHeaderStorage;
use crate::sync::download_coordinator::{DownloadConfig, DownloadCoordinator};

/// Batch size for filter header requests.
const FILTER_HEADERS_BATCH_SIZE: u32 = 2000;

/// Maximum concurrent CFHeaders requests.
const MAX_CONCURRENT_CFHEADERS_REQUESTS: usize = 10;

/// Timeout for CFHeaders requests (shorter for faster retry on multi-peer).
/// Timeout for CFHeaders requests. Single response but allow time for network latency.
const FILTER_HEADERS_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum number of retries for CFHeaders requests.
const FILTER_HEADERS_MAX_RETRIES: u32 = 3;

/// Pipeline for downloading compact block filter headers.
///
/// Uses DownloadCoordinator<BlockHash> for batch-level tracking (keyed by stop_hash),
/// with a HashMap buffer for out-of-order responses that need sequential processing.
#[derive(Debug)]
pub(super) struct FilterHeadersPipeline {
    /// Core coordinator tracks batches by stop_hash.
    coordinator: DownloadCoordinator<BlockHash>,
    /// Maps stop_hash -> start_height for each batch.
    batch_starts: HashMap<BlockHash, u32>,
    /// Out-of-order response buffer (start_height -> data).
    buffered: HashMap<u32, CFHeaders>,
    /// Next height to process sequentially.
    next_expected: u32,
    /// Target height for sync.
    target_height: u32,
}

impl Default for FilterHeadersPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterHeadersPipeline {
    /// Create a new CFHeaders pipeline.
    pub(super) fn new() -> Self {
        Self {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(MAX_CONCURRENT_CFHEADERS_REQUESTS)
                    .with_timeout(FILTER_HEADERS_TIMEOUT)
                    .with_max_retries(FILTER_HEADERS_MAX_RETRIES),
            ),
            batch_starts: HashMap::new(),
            buffered: HashMap::new(),
            next_expected: 0,
            target_height: 0,
        }
    }

    /// Extend the pipeline to a new target height.
    ///
    /// Queues additional batches from the current target to the new target.
    pub(super) async fn extend_target(
        &mut self,
        storage: &impl BlockHeaderStorage,
        new_target: u32,
    ) -> SyncResult<()> {
        let old_target = self.target_height;
        if new_target <= old_target {
            return Ok(());
        }

        self.target_height = new_target;

        // Queue batches from (old_target + 1) to new_target
        let mut current = old_target + 1;
        let mut added = 0;

        while current <= new_target {
            let batch_end = (current + FILTER_HEADERS_BATCH_SIZE - 1).min(new_target);

            // Get stop hash for this batch
            let stop_hash = storage
                .get_header(batch_end)
                .await?
                .ok_or_else(|| {
                    SyncError::Storage(format!("Missing header at height {}", batch_end))
                })?
                .block_hash();

            self.coordinator.enqueue([stop_hash]);
            self.batch_starts.insert(stop_hash, current);
            added += 1;

            current = batch_end + 1;
        }

        if added > 0 {
            tracing::info!(
                "Extended CFHeaders queue: +{} batches for heights {} to {}",
                added,
                old_target + 1,
                new_target
            );
        }

        Ok(())
    }

    /// Get the next expected height for sequential processing.
    pub(super) fn next_expected(&self) -> u32 {
        self.next_expected
    }

    /// Check if the pipeline is complete.
    pub(super) fn is_complete(&self) -> bool {
        self.coordinator.is_empty()
            && self.buffered.is_empty()
            && (self.target_height == 0 || self.next_expected > self.target_height)
    }

    /// Initialize the pipeline for a sync range.
    pub(super) async fn init(
        &mut self,
        storage: &impl BlockHeaderStorage,
        start_height: u32,
        target_height: u32,
    ) -> SyncResult<()> {
        self.coordinator.clear();
        self.batch_starts.clear();
        self.buffered.clear();
        self.next_expected = start_height;
        self.target_height = target_height;

        // Build request queue
        let mut current = start_height;
        while current <= target_height {
            let batch_end = (current + FILTER_HEADERS_BATCH_SIZE - 1).min(target_height);

            // Get stop hash for this batch
            let stop_hash = storage
                .get_header(batch_end)
                .await?
                .ok_or_else(|| {
                    SyncError::Storage(format!("Missing header at height {}", batch_end))
                })?
                .block_hash();

            self.coordinator.enqueue([stop_hash]);
            self.batch_starts.insert(stop_hash, current);

            current = batch_end + 1;
        }

        tracing::info!(
            "Built CFHeaders request queue: {} batches for heights {} to {}",
            self.coordinator.pending_count(),
            start_height,
            target_height
        );

        Ok(())
    }

    /// Send pending requests using a RequestSender (synchronous).
    pub(super) fn send_pending(&mut self, requests: &RequestSender) -> SyncResult<usize> {
        let count = self.coordinator.available_to_send();
        if count == 0 {
            return Ok(0);
        }

        let stop_hashes = self.coordinator.take_pending(count);
        let mut sent = 0;

        for stop_hash in stop_hashes {
            let Some(&start_height) = self.batch_starts.get(&stop_hash) else {
                continue;
            };

            requests.request_filter_headers(start_height, stop_hash)?;

            self.coordinator.mark_sent(&[stop_hash]);

            tracing::debug!(
                "Sent GetCFHeaders: start={}, stop={} ({} active, {} pending)",
                start_height,
                stop_hash,
                self.coordinator.active_count(),
                self.coordinator.pending_count()
            );

            sent += 1;
        }

        Ok(sent)
    }

    /// Try to match an incoming message to a pipeline response.
    ///
    /// Returns `Some((start_height, data))` if matched, `None` otherwise.
    pub(super) fn match_response(&self, msg: &NetworkMessage) -> Option<(u32, CFHeaders)> {
        let NetworkMessage::CFHeaders(cfheaders) = msg else {
            return None;
        };

        if cfheaders.filter_hashes.is_empty() {
            return None;
        }

        // Match by stop_hash - the response includes it
        if !self.coordinator.is_in_flight(&cfheaders.stop_hash) {
            return None;
        }

        let start_height = *self.batch_starts.get(&cfheaders.stop_hash)?;
        Some((start_height, cfheaders.clone()))
    }

    /// Handle a received response.
    ///
    /// Returns `Some(data)` if this response is the next expected and should
    /// be processed immediately. Returns `None` if buffered for later.
    pub(super) fn receive(&mut self, start_height: u32, data: CFHeaders) -> Option<CFHeaders> {
        self.coordinator.receive(&data.stop_hash);
        self.batch_starts.remove(&data.stop_hash);

        if start_height == self.next_expected {
            Some(data)
        } else if start_height > self.next_expected {
            // Out-of-order - buffer for later
            self.buffered.insert(start_height, data);
            None
        } else {
            // Already processed (duplicate)
            None
        }
    }

    /// Advance to the next expected height after processing.
    ///
    /// Returns any buffered responses that are now ready.
    pub(super) fn advance(&mut self, processed_count: u32) -> Vec<(u32, CFHeaders)> {
        self.next_expected += processed_count;

        // Check if next_expected is now in the buffer
        let mut ready = Vec::new();
        if let Some(data) = self.buffered.remove(&self.next_expected) {
            ready.push((self.next_expected, data));
        }
        ready
    }

    /// Re-enqueue timed out requests for retry.
    ///
    /// Returns heights that exceeded max retries and were permanently dropped.
    pub(super) fn handle_timeouts(&mut self) -> Vec<u32> {
        let mut failed = Vec::new();
        for stop_hash in self.coordinator.check_timeouts() {
            if !self.coordinator.enqueue_retry(stop_hash) {
                if let Some(&start_height) = self.batch_starts.get(&stop_hash) {
                    tracing::warn!(
                        "CFHeaders batch at height {} exceeded max retries, dropping",
                        start_height
                    );
                    failed.push(start_height);
                }
            }
        }
        failed
    }
}

#[cfg(test)]
mod tests {
    use dashcore_hashes::Hash;

    use super::*;

    #[test]
    fn test_cfheaders_pipeline_new() {
        let pipeline = FilterHeadersPipeline::new();
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_match_response_empty() {
        let pipeline = FilterHeadersPipeline::new();

        let empty_cfheaders = CFHeaders {
            filter_type: 0,
            stop_hash: dashcore::BlockHash::all_zeros(),
            previous_filter_header: dashcore::hash_types::FilterHeader::all_zeros(),
            filter_hashes: vec![],
        };

        // Empty response should return None
        assert!(pipeline.match_response(&NetworkMessage::CFHeaders(empty_cfheaders)).is_none());
    }

    #[test]
    fn test_match_response_wrong_message() {
        let pipeline = FilterHeadersPipeline::new();

        // Wrong message type should return None
        assert!(pipeline.match_response(&NetworkMessage::Verack).is_none());
    }

    #[test]
    fn test_receive_in_order() {
        use dashcore::hash_types::FilterHash;

        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 100;

        let stop_hash = BlockHash::all_zeros();

        // Mark batch as in-flight (by stop_hash)
        pipeline.coordinator.mark_sent(&[stop_hash]);
        pipeline.batch_starts.insert(stop_hash, 1);

        let cfheaders = CFHeaders {
            filter_type: 0,
            stop_hash,
            previous_filter_header: dashcore::hash_types::FilterHeader::all_zeros(),
            filter_hashes: vec![FilterHash::all_zeros()],
        };

        // Should return data immediately
        let result = pipeline.receive(1, cfheaders.clone());
        assert!(result.is_some());
    }

    #[test]
    fn test_receive_out_of_order() {
        use dashcore::hash_types::FilterHash;

        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 4000;

        let stop_hash = BlockHash::all_zeros();

        // Mark batch as in-flight (by stop_hash)
        pipeline.coordinator.mark_sent(&[stop_hash]);
        pipeline.batch_starts.insert(stop_hash, 2000);

        let cfheaders = CFHeaders {
            filter_type: 0,
            stop_hash,
            previous_filter_header: dashcore::hash_types::FilterHeader::all_zeros(),
            filter_hashes: vec![FilterHash::all_zeros()],
        };

        // Should buffer (out of order)
        let result = pipeline.receive(2000, cfheaders);
        assert!(result.is_none());
        assert_eq!(pipeline.buffered.len(), 1);
    }

    #[test]
    fn test_advance_returns_buffered() {
        use dashcore::hash_types::FilterHash;

        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 4000;

        // Buffer a response at height 2000
        let cfheaders = CFHeaders {
            filter_type: 0,
            stop_hash: BlockHash::all_zeros(),
            previous_filter_header: dashcore::hash_types::FilterHeader::all_zeros(),
            filter_hashes: vec![FilterHash::all_zeros()],
        };
        pipeline.buffered.insert(2000, cfheaders);

        // Advance to 2000
        let ready = pipeline.advance(1999);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0, 2000);
        assert_eq!(pipeline.buffered.len(), 0);
    }

    #[test]
    fn test_handle_timeouts_basic_retry() {
        use std::time::Duration;

        let mut pipeline = FilterHeadersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(3),
            ),
            batch_starts: HashMap::new(),
            buffered: HashMap::new(),
            next_expected: 1,
            target_height: 2000,
        };

        let stop_hash = BlockHash::all_zeros();
        pipeline.coordinator.mark_sent(&[stop_hash]);
        pipeline.batch_starts.insert(stop_hash, 1);

        std::thread::sleep(Duration::from_millis(5));

        let failed = pipeline.handle_timeouts();
        assert!(failed.is_empty()); // First retry succeeds
        assert_eq!(pipeline.coordinator.pending_count(), 1);
    }

    #[test]
    fn test_handle_timeouts_max_retries_exceeded() {
        use std::time::Duration;

        let mut pipeline = FilterHeadersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(1),
            ),
            batch_starts: HashMap::new(),
            buffered: HashMap::new(),
            next_expected: 100,
            target_height: 2000,
        };

        let stop_hash = BlockHash::from_byte_array([0x01; 32]);
        pipeline.batch_starts.insert(stop_hash, 100);

        // First timeout + retry
        pipeline.coordinator.mark_sent(&[stop_hash]);
        std::thread::sleep(Duration::from_millis(5));
        let failed = pipeline.handle_timeouts();
        assert!(failed.is_empty());

        // Re-send retry
        let items = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&items);

        // Second timeout exceeds max
        std::thread::sleep(Duration::from_millis(5));
        let failed = pipeline.handle_timeouts();
        assert_eq!(failed, vec![100]);
    }

    #[test]
    fn test_handle_timeouts_multiple_batches() {
        use std::time::Duration;

        let mut pipeline = FilterHeadersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(0),
            ),
            batch_starts: HashMap::new(),
            buffered: HashMap::new(),
            next_expected: 1,
            target_height: 4000,
        };

        let hash1 = BlockHash::from_byte_array([0x01; 32]);
        let hash2 = BlockHash::from_byte_array([0x02; 32]);

        pipeline.coordinator.mark_sent(&[hash1, hash2]);
        pipeline.batch_starts.insert(hash1, 1);
        pipeline.batch_starts.insert(hash2, 2001);

        std::thread::sleep(Duration::from_millis(5));

        let mut failed = pipeline.handle_timeouts();
        failed.sort();
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&1));
        assert!(failed.contains(&2001));
    }
}
