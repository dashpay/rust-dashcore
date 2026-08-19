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
                    .with_timeout(FILTER_HEADERS_TIMEOUT),
            ),
            batch_starts: HashMap::new(),
            buffered: HashMap::new(),
            next_expected: 0,
            target_height: 0,
        }
    }

    /// Resolve the stop hash and start height of every batch covering
    /// `[start_height, target_height]`, without touching pipeline state.
    ///
    /// The stop-hash lookups are the only fallible step in `init` and
    /// `extend_target`, and resolving them all up front lets those callers
    /// commit their state changes in one infallible pass — so a missing header
    /// leaves the pipeline exactly as it was and the caller can retry cleanly
    /// instead of advancing `target_height` past batches that never got queued.
    async fn resolve_batches(
        storage: &impl BlockHeaderStorage,
        start_height: u32,
        target_height: u32,
    ) -> SyncResult<Vec<(BlockHash, u32)>> {
        let mut batches = Vec::new();
        let mut current = start_height;
        while current <= target_height {
            let batch_end = (current + FILTER_HEADERS_BATCH_SIZE - 1).min(target_height);

            let stop_hash =
                storage.get_header(batch_end).await?.map(|h| *h.hash()).ok_or_else(|| {
                    SyncError::Storage(format!("Missing header at height {}", batch_end))
                })?;

            batches.push((stop_hash, current));
            current = batch_end + 1;
        }
        Ok(batches)
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

        // Resolve every batch before mutating state: `target_height` must not
        // advance past batches a failed lookup left unqueued, or a later
        // `extend_target(new_target)` returns early (`new_target <= old_target`)
        // and the gap is never filled.
        let batches = Self::resolve_batches(storage, old_target + 1, new_target).await?;
        let added = batches.len();

        for (stop_hash, start) in batches {
            self.coordinator.enqueue([stop_hash]);
            self.batch_starts.insert(stop_hash, start);
        }
        self.target_height = new_target;

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
        // Resolve every stop hash before clearing and rebuilding state, so a
        // missing header leaves the pipeline untouched and the caller retries
        // cleanly rather than resuming from a half-built queue.
        let batches = Self::resolve_batches(storage, start_height, target_height).await?;

        self.coordinator.clear();
        self.batch_starts.clear();
        self.buffered.clear();
        self.next_expected = start_height;
        self.target_height = target_height;

        for (stop_hash, start) in batches {
            self.coordinator.enqueue([stop_hash]);
            self.batch_starts.insert(stop_hash, start);
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
                return Err(SyncError::InvalidState(format!(
                    "No batch_starts entry for pending stop_hash {}",
                    stop_hash
                )));
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

    /// Re-track a batch whose processing failed so a later `send_pending`
    /// reissues it.
    ///
    /// `receive` clears a batch from the coordinator and `batch_starts` the
    /// moment the bytes arrive, before the caller runs the fallible
    /// `process_cfheaders`. If that storage write fails the batch would
    /// otherwise vanish from every tracker while `next_expected` stays pinned
    /// to it, and `extend_target` only ever appends above `target_height` — so
    /// the hole is never revisited and filter-header sync stalls. Putting the
    /// batch back on the retry queue with its start height restored makes the
    /// next tick request it again.
    pub(super) fn requeue_failed(&mut self, start_height: u32, stop_hash: BlockHash) {
        self.batch_starts.insert(stop_hash, start_height);
        self.coordinator.enqueue_retry(stop_hash);
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

    /// Move in-flight `getcfheaders` requests back to pending after a peer
    /// disconnect so the next `send_pending` reissues them.
    ///
    /// `batch_starts` must survive, since `send_pending` errors out on a pending
    /// stop hash with no start height. `next_expected` and the out-of-order
    /// buffer survive too, so already-received batches are not re-downloaded.
    pub(super) fn requeue_in_flight(&mut self) {
        self.coordinator.requeue_in_flight();
    }

    /// Re-enqueue timed out requests for retry.
    pub(super) fn handle_timeouts(&mut self) {
        for stop_hash in self.coordinator.check_timeouts() {
            self.coordinator.enqueue_retry(stop_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use dashcore_hashes::Hash;

    use super::*;
    use crate::network::NetworkRequest;
    use dashcore::hash_types::{FilterHash, FilterHeader};
    use dashcore::network::message_filter::GetCFHeaders;
    use tokio::sync::mpsc::unbounded_channel;

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
                DownloadConfig::default().with_timeout(Duration::from_millis(1)),
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

        pipeline.handle_timeouts();
        assert_eq!(pipeline.coordinator.pending_count(), 1);
    }

    #[test]
    fn test_send_pending_errors_on_missing_batch_starts() {
        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 2000;

        let hash_without_entry = BlockHash::from_byte_array([0x02; 32]);

        // Enqueue a stop_hash without a corresponding batch_starts entry
        pipeline.coordinator.enqueue([hash_without_entry]);

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let requests = RequestSender::new(tx);

        let err = pipeline.send_pending(&requests).unwrap_err();
        assert!(matches!(err, SyncError::InvalidState(_)));
    }

    /// A peer disconnect requeues in-flight batches without discarding what the
    /// pipeline has already made of the ones that came back, so the reissued
    /// requests carry their original start heights and nothing is re-downloaded.
    #[test]
    fn test_requeue_in_flight_reissues_batches_and_keeps_progress() {
        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 6000;

        let hash1 = BlockHash::from_byte_array([0x01; 32]);
        let hash2 = BlockHash::from_byte_array([0x02; 32]);
        pipeline.coordinator.mark_sent(&[hash1, hash2]);
        pipeline.batch_starts.insert(hash1, 1);
        pipeline.batch_starts.insert(hash2, 2001);

        // A third batch already came back out of order and is waiting for the
        // two above to be processed first.
        pipeline.buffered.insert(
            4001,
            CFHeaders {
                filter_type: 0,
                stop_hash: BlockHash::from_byte_array([0x03; 32]),
                previous_filter_header: FilterHeader::all_zeros(),
                filter_hashes: vec![FilterHash::all_zeros()],
            },
        );

        pipeline.requeue_in_flight();
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.coordinator.pending_count(), 2);

        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);
        assert_eq!(pipeline.send_pending(&requests).unwrap(), 2);

        let mut reissued = Vec::new();
        while let Ok(request) = rx.try_recv() {
            match request {
                NetworkRequest::SendMessage(NetworkMessage::GetCFHeaders(GetCFHeaders {
                    start_height,
                    stop_hash,
                    ..
                })) => reissued.push((start_height, stop_hash)),
                other => panic!("Expected GetCFHeaders, got {:?}", other),
            }
        }
        reissued.sort();
        assert_eq!(reissued, vec![(1, hash1), (2001, hash2)]);

        assert_eq!(pipeline.next_expected(), 1);
        assert_eq!(pipeline.buffered.len(), 1);
        assert_eq!(pipeline.target_height, 6000);
    }

    /// A batch whose `process_cfheaders` fails after `receive` already dropped
    /// it from the trackers must be retryable: `requeue_failed` puts it back so
    /// the next `send_pending` reissues it, and nothing is stranded with
    /// `next_expected` pinned to a batch nothing tracks. (#964)
    #[test]
    fn test_requeue_failed_makes_a_dropped_batch_retryable() {
        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 2000;

        let stop_hash = BlockHash::from_byte_array([0x07; 32]);
        pipeline.coordinator.mark_sent(&[stop_hash]);
        pipeline.batch_starts.insert(stop_hash, 1);

        let cfheaders = CFHeaders {
            filter_type: 0,
            stop_hash,
            previous_filter_header: FilterHeader::all_zeros(),
            filter_hashes: vec![FilterHash::all_zeros()],
        };

        // In-order receive hands the batch to the caller and drops it from
        // every tracker.
        assert!(pipeline.receive(1, cfheaders).is_some());
        assert!(!pipeline.coordinator.is_in_flight(&stop_hash));
        assert!(!pipeline.batch_starts.contains_key(&stop_hash));

        // Processing failed downstream: re-track the batch.
        pipeline.requeue_failed(1, stop_hash);

        // The next send_pending reissues exactly that batch with its original
        // start height, and progress is untouched.
        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);
        assert_eq!(pipeline.send_pending(&requests).unwrap(), 1);

        let mut reissued = Vec::new();
        while let Ok(request) = rx.try_recv() {
            match request {
                NetworkRequest::SendMessage(NetworkMessage::GetCFHeaders(GetCFHeaders {
                    start_height,
                    stop_hash,
                    ..
                })) => reissued.push((start_height, stop_hash)),
                other => panic!("Expected GetCFHeaders, got {:?}", other),
            }
        }
        assert_eq!(reissued, vec![(1, stop_hash)]);
        assert_eq!(pipeline.next_expected(), 1);
    }

    /// A missing header mid-`extend_target` must leave `target_height` and the
    /// queue untouched, or a later `extend_target` to the same target returns
    /// early (`new_target <= old_target`) and the unqueued batches are lost —
    /// filter-header sync stalls with the watermark parked above them. (#964)
    #[tokio::test]
    async fn test_extend_target_is_atomic_on_a_missing_header() {
        use crate::storage::{BlockHeaderStorage, DiskStorageManager, StorageManager};
        use crate::types::HashedBlockHeader;
        use dashcore::{block::Version, BlockHash, CompactTarget, Header as BlockHeader};

        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let header_storage = storage.block_headers();

        // Store headers up to height 2000 only.
        let mut headers = Vec::new();
        let mut prev = BlockHash::from_byte_array([0u8; 32]);
        for nonce in 0..2001u32 {
            let header = HashedBlockHeader::from(BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: prev,
                merkle_root: dashcore::TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2100ffff),
                nonce,
            });
            prev = *header.hash();
            headers.push(header);
        }
        header_storage.write().await.store_headers_at_height(&headers, 0).await.unwrap();

        let mut pipeline = FilterHeadersPipeline::new();
        {
            let guard = header_storage.read().await;
            pipeline.init(&*guard, 1, 2000).await.expect("init within stored range");
        }
        assert_eq!(pipeline.target_height, 2000);
        let pending_after_init = pipeline.coordinator.pending_count();

        // Extending past the stored headers fails at the first missing stop hash.
        {
            let guard = header_storage.read().await;
            assert!(pipeline.extend_target(&*guard, 5000).await.is_err());
        }
        assert_eq!(
            pipeline.target_height, 2000,
            "a failed extend must not advance target_height past unqueued batches"
        );
        assert_eq!(
            pipeline.coordinator.pending_count(),
            pending_after_init,
            "a failed extend must not enqueue a partial set of batches"
        );

        // Once the headers exist, the same extend succeeds and advances.
        let mut more = Vec::new();
        for nonce in 2001..5001u32 {
            let header = HashedBlockHeader::from(BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: prev,
                merkle_root: dashcore::TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2100ffff),
                nonce,
            });
            prev = *header.hash();
            more.push(header);
        }
        header_storage.write().await.store_headers_at_height(&more, 2001).await.unwrap();
        {
            let guard = header_storage.read().await;
            pipeline.extend_target(&*guard, 5000).await.expect("extend within stored range");
        }
        assert_eq!(pipeline.target_height, 5000);
    }

    #[test]
    fn test_handle_timeouts_multiple_batches() {
        use std::time::Duration;

        let mut pipeline = FilterHeadersPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default().with_timeout(Duration::from_millis(1)),
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

        pipeline.handle_timeouts();
        // Both batches re-queued
        assert_eq!(pipeline.coordinator.pending_count(), 2);
        assert!(pipeline.batch_starts.contains_key(&hash1));
        assert!(pipeline.batch_starts.contains_key(&hash2));
    }
}
