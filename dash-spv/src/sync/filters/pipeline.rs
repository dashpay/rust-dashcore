//! CFilters pipeline implementation.
//!
//! Handles pipelined download of compact block filters (BIP 157/158).
//! Declares wanted batches to the network manager's request broker, plus
//! per-batch tracking for individual filter responses.
//!
//! Filters are buffered in a HashMap<FilterMatchKey, BlockFilter> until the entire batch
//! is complete, enabling batch verification and direct wallet matching.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use dashcore::network::message::NetworkMessage;
use dashcore::network::message_filter::GetCFilters;
use dashcore::BlockHash;

use crate::error::SyncResult;
use crate::network::NetworkManager;
use crate::storage::BlockHeaderStorage;
use crate::sync::filters::batch::FiltersBatch;
use crate::sync::filters::batch_tracker::BatchTracker;

/// Batch size for filter requests.
const FILTER_BATCH_SIZE: u32 = 1000;

/// Pipeline for downloading compact block filters.
#[derive(Debug)]
pub(super) struct FiltersPipeline {
    /// Tracks individual filter receipts per batch (start_height -> tracker).
    /// Doubles as the "which batches are still wanted?" set.
    batch_trackers: HashMap<u32, BatchTracker>,
    /// Cached stop hash per wanted batch (start_height -> stop_hash), so
    /// re-declaring the wanted set each tick doesn't re-read storage per batch.
    /// Filled lazily in `send_pending` as headers become available.
    batch_stops: HashMap<u32, BlockHash>,
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
            batch_trackers: HashMap::new(),
            batch_stops: HashMap::new(),
            completed_batches: BTreeSet::new(),
            target_height: 0,
            filters_received: 0,
            highest_received: 0,
        }
    }

    /// Returns true if the pipeline has no wanted batches left.
    pub(super) fn is_idle(&self) -> bool {
        self.batch_trackers.is_empty()
    }

    /// Take completed batches with their buffered filter data for processing.
    pub(super) fn take_completed_batches(&mut self) -> BTreeSet<FiltersBatch> {
        std::mem::take(&mut self.completed_batches)
    }

    /// Initialize the pipeline for a sync range.
    ///
    /// Creates a tracker for every batch in the range; `send_pending` then
    /// declares them to the broker.
    pub(super) fn init(&mut self, start_height: u32, target_height: u32) {
        self.batch_trackers.clear();
        self.batch_stops.clear();
        self.completed_batches.clear();
        self.target_height = target_height;
        self.highest_received = start_height.saturating_sub(1);
        self.filters_received = 0;

        let mut current = start_height;
        while current <= target_height {
            let batch_end = (current + FILTER_BATCH_SIZE - 1).min(target_height);
            self.batch_trackers.insert(current, BatchTracker::new(batch_end));
            current = batch_end + 1;
        }
    }

    /// Extend the target height without resetting pipeline state.
    ///
    /// Adds trackers for the batches from the old target boundary to the new target.
    pub(super) fn extend_target(&mut self, new_target: u32) {
        if new_target <= self.target_height {
            return;
        }

        let old_target = self.target_height;
        self.target_height = new_target;

        let mut current = old_target + 1;
        while current <= new_target {
            let batch_end = (current + FILTER_BATCH_SIZE - 1).min(new_target);
            self.batch_trackers.insert(current, BatchTracker::new(batch_end));
            current = batch_end + 1;
        }
    }

    /// Declare every wanted batch to the network manager.
    ///
    /// Resolves (and caches) each batch's stop hash from storage the first time
    /// it becomes available, then declares all resolved batches to the broker,
    /// which de-duplicates in-flight ones. Batches whose stop header isn't stored
    /// yet are simply skipped this round and retried next tick.
    pub(super) async fn send_pending(
        &mut self,
        network: &Arc<dyn NetworkManager>,
        storage: &impl BlockHeaderStorage,
    ) -> SyncResult<usize> {
        if self.batch_trackers.is_empty() {
            return Ok(0);
        }

        // Resolve stop hashes for any wanted batch we haven't cached yet.
        let uncached: Vec<(u32, u32)> = self
            .batch_trackers
            .iter()
            .filter(|(start, _)| !self.batch_stops.contains_key(start))
            .map(|(&start, tracker)| (start, tracker.end_height()))
            .collect();
        for (start, batch_end) in uncached {
            match storage.get_header(batch_end).await {
                Ok(Some(h)) => {
                    self.batch_stops.insert(start, *h.hash());
                }
                Ok(None) => {
                    tracing::debug!(
                        "Header at height {} not yet available, deferring filter batch {}",
                        batch_end,
                        start
                    );
                }
                Err(e) => {
                    tracing::warn!("Error reading header at height {}: {}", batch_end, e);
                }
            }
        }

        // Declare every wanted batch whose stop hash is known, lowest-first for a
        // deterministic fan-out. The broker de-duplicates, so re-declaring one
        // already in flight is a no-op.
        let mut ready: Vec<(u32, BlockHash)> = self
            .batch_stops
            .iter()
            .filter(|(start, _)| self.batch_trackers.contains_key(start))
            .map(|(&start, &stop)| (start, stop))
            .collect();
        ready.sort_unstable_by_key(|(start, _)| *start);

        let n = ready.len();
        for (start_height, stop_hash) in ready {
            network
                .send(NetworkMessage::GetCFilters(GetCFilters {
                    filter_type: 0u8,
                    start_height,
                    stop_hash,
                }))
                .await;
        }

        Ok(n)
    }

    /// Handle a received CFilter message with filter data.
    ///
    /// Buffers the filter data for batch verification and wallet matching.
    /// Returns `Some(batch_start)` when a batch completes (the `GetCFilters`
    /// request key, so the caller can tell the network manager it was answered),
    /// `None` otherwise.
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
                tracing::trace!(
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

        // Out of the wanted set: drop its tracker and cached stop hash so the next
        // `send_pending` won't re-declare it (the manager also tells the broker it
        // was answered, stopping any in-flight retry).
        self.batch_trackers.remove(&batch_start);
        self.batch_stops.remove(&batch_start);

        tracing::info!(
            "Filter batch {}-{} complete ({} filters)",
            batch_start,
            end_height,
            filters.len()
        );
        let batch = FiltersBatch::new(batch_start, end_height, filters);
        self.completed_batches.insert(batch);

        Some(batch_start)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::block::Header;
    use dashcore_hashes::Hash;
    use key_wallet_manager::FilterMatchKey;

    /// Generate dummy filter data for testing.
    fn dummy_filter_data(height: u32) -> Vec<u8> {
        vec![height as u8, (height >> 8) as u8, 0x01, 0x02]
    }

    #[test]
    fn test_pipeline_new() {
        let pipeline = FiltersPipeline::new();
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
    fn test_pipeline_init() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(100, 500);

        // 100..=500 fits in a single batch.
        assert_eq!(pipeline.batch_trackers.len(), 1);
        assert_eq!(pipeline.target_height, 500);
        assert_eq!(pipeline.highest_received, 99);
        assert_eq!(pipeline.filters_received, 0);
    }

    #[test]
    fn test_pipeline_init_resets_state() {
        let mut pipeline = FiltersPipeline::new();

        pipeline.batch_trackers.insert(0, BatchTracker::new(99));
        pipeline.completed_batches.insert(FiltersBatch::new(100, 199, HashMap::new()));
        pipeline.filters_received = 50;

        pipeline.init(200, 300);

        assert!(pipeline.completed_batches.is_empty());
        assert_eq!(pipeline.filters_received, 0);
        assert_eq!(pipeline.batch_trackers.len(), 1);
        assert_eq!(pipeline.batch_trackers.get(&200).unwrap().end_height(), 300);
        assert_eq!(pipeline.target_height, 300);
    }

    #[test]
    fn test_init_creates_contiguous_batches() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 2500);

        // 0-999, 1000-1999, 2000-2500
        let mut ranges: Vec<(u32, u32)> =
            pipeline.batch_trackers.iter().map(|(&s, t)| (s, t.end_height())).collect();
        ranges.sort_unstable();
        assert_eq!(ranges, vec![(0, 999), (1000, 1999), (2000, 2500)]);
    }

    #[test]
    fn test_extend_target_increases() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 100);
        pipeline.extend_target(200);
        assert_eq!(pipeline.target_height, 200);
    }

    #[test]
    fn test_extend_target_contiguous_batches() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 3500);
        pipeline.extend_target(5000);

        let mut ranges: Vec<(u32, u32)> =
            pipeline.batch_trackers.iter().map(|(&s, t)| (s, t.end_height())).collect();
        ranges.sort_unstable_by_key(|&(s, _)| s);

        for window in ranges.windows(2) {
            assert_eq!(window[0].1 + 1, window[1].0, "gap or overlap between batches");
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

    #[test]
    fn test_receive_single_filter() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 99;
        pipeline.batch_trackers.insert(0, BatchTracker::new(99));

        let height = 50;
        let hash = Header::dummy(height).block_hash();
        let result = pipeline.receive_with_data(height, hash, &dummy_filter_data(height));

        // Batch not complete (1 of 100 filters).
        assert_eq!(result, None);
        assert_eq!(pipeline.filters_received, 1);
        assert_eq!(pipeline.highest_received, 50);
    }

    #[test]
    fn test_receive_unknown_height() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 99;

        let hash = Header::dummy(50).block_hash();
        let result = pipeline.receive_with_data(50, hash, &dummy_filter_data(50));

        assert_eq!(result, None);
        assert_eq!(pipeline.filters_received, 0);
    }

    #[test]
    fn test_receive_batch_completion_returns_batch_start() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 2;
        pipeline.batch_trackers.insert(0, BatchTracker::new(2));

        let mut completed_at = None;
        for h in 0..=2 {
            let hash = Header::dummy(h).block_hash();
            if let Some(start) = pipeline.receive_with_data(h, hash, &dummy_filter_data(h)) {
                completed_at = Some(start);
            }
        }

        // Completing filter returns the batch START (the GetCFilters request key).
        assert_eq!(completed_at, Some(0));
        assert!(pipeline.batch_trackers.is_empty());
        assert!(!pipeline.batch_stops.contains_key(&0));
        assert_eq!(pipeline.completed_batches.len(), 1);

        let completed = pipeline.take_completed_batches();
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

        for h in [3, 1, 4, 0, 2] {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        assert!(pipeline.batch_trackers.is_empty());
        assert_eq!(pipeline.completed_batches.len(), 1);
    }

    #[test]
    fn test_receive_multiple_batches() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.target_height = 9;
        pipeline.batch_trackers.insert(0, BatchTracker::new(4));
        pipeline.batch_trackers.insert(5, BatchTracker::new(9));

        for h in 0..=4 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }
        assert_eq!(pipeline.completed_batches.len(), 1);
        assert_eq!(pipeline.batch_trackers.len(), 1);

        for h in 5..=9 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }
        assert_eq!(pipeline.completed_batches.len(), 2);
        assert!(pipeline.batch_trackers.is_empty());
    }

    #[test]
    fn test_find_batch_for_height() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.batch_trackers.insert(0, BatchTracker::new(999));
        pipeline.batch_trackers.insert(1000, BatchTracker::new(1999));

        assert_eq!(pipeline.find_batch_for_height(500), Some(0));
        assert_eq!(pipeline.find_batch_for_height(1500), Some(1000));
        assert_eq!(pipeline.find_batch_for_height(5000), None);
    }

    #[test]
    fn test_find_batch_for_height_boundary() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.batch_trackers.insert(100, BatchTracker::new(199));

        assert_eq!(pipeline.find_batch_for_height(100), Some(100));
        assert_eq!(pipeline.find_batch_for_height(199), Some(100));
        assert_eq!(pipeline.find_batch_for_height(50), None);
        assert_eq!(pipeline.find_batch_for_height(250), None);
    }

    #[test]
    fn test_take_completed_batches_clears() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.completed_batches.insert(FiltersBatch::new(0, 99, HashMap::new()));
        pipeline.completed_batches.insert(FiltersBatch::new(100, 199, HashMap::new()));

        let taken = pipeline.take_completed_batches();
        assert_eq!(taken.len(), 2);
        assert!(pipeline.completed_batches.is_empty());
    }

    #[test]
    fn test_filters_batch_filters_mut() {
        use dashcore::bip158::BlockFilter;
        let mut batch = FiltersBatch::new(0, 0, HashMap::new());
        batch
            .filters_mut()
            .insert(FilterMatchKey::new(0, BlockHash::all_zeros()), BlockFilter::new(&[0x01]));
        assert_eq!(batch.filters().len(), 1);
    }

    /// `Default` must be the same thing as `new`, since the pipeline is created
    /// through both paths.
    #[test]
    fn test_pipeline_default_trait() {
        let default_pipeline = FiltersPipeline::default();
        let new_pipeline = FiltersPipeline::new();

        assert_eq!(default_pipeline.is_idle(), new_pipeline.is_idle());
        assert_eq!(default_pipeline.target_height, new_pipeline.target_height);
        assert_eq!(default_pipeline.filters_received, new_pipeline.filters_received);
        assert_eq!(default_pipeline.highest_received, new_pipeline.highest_received);
    }

    /// `extend_target` adds trackers for the new range without disturbing the
    /// ones already wanted: an existing batch keeps the `end_height` it was
    /// created with, even when the new target moves far beyond it.
    #[test]
    fn test_extend_target_preserves_existing_batch_end_heights() {
        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 2500);

        // The boundary batch was truncated at the old target.
        assert_eq!(pipeline.batch_trackers.get(&2000).unwrap().end_height(), 2500);

        pipeline.extend_target(4000);

        assert_eq!(
            pipeline.batch_trackers.get(&2000).unwrap().end_height(),
            2500,
            "an already-wanted batch must keep its original end height"
        );
        // ...and the extension picks up from the old boundary.
        assert_eq!(pipeline.batch_trackers.get(&2501).unwrap().end_height(), 3500);
    }

    /// End-to-end over the whole batch: declare it to the broker, feed every
    /// filter in, and take the completed batch out. This is the only coverage
    /// of `send_pending`, which resolves stop hashes from header storage.
    #[tokio::test]
    async fn test_full_batch_lifecycle() {
        use crate::storage::{PersistentBlockHeaderStorage, PersistentStorage};
        use crate::test_utils::MockNetworkManager;
        use tempfile::TempDir;

        let headers = Header::dummy_batch(0..100);
        let tmp_dir = TempDir::new().unwrap();
        let mut storage = PersistentBlockHeaderStorage::open(tmp_dir.path()).await.unwrap();
        storage
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        let mut pipeline = FiltersPipeline::new();
        pipeline.init(0, 99);
        assert!(!pipeline.is_idle());

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        // The single wanted batch is declared to the broker.
        let declared = pipeline.send_pending(&network, &storage).await.unwrap();
        assert_eq!(declared, 1);
        let starts: Vec<u32> = mock
            .sent_messages()
            .iter()
            .filter_map(|m| match m {
                NetworkMessage::GetCFilters(gcf) => Some(gcf.start_height),
                _ => None,
            })
            .collect();
        assert_eq!(starts, vec![0]);

        // Receive all filters
        for h in 0..=99 {
            let hash = Header::dummy(h).block_hash();
            pipeline.receive_with_data(h, hash, &dummy_filter_data(h));
        }

        // Batch complete: nothing wanted, one batch ready to take.
        assert!(pipeline.is_idle());
        assert_eq!(pipeline.completed_batches.len(), 1);
        assert_eq!(pipeline.filters_received, 100);
        assert_eq!(pipeline.highest_received, 99);

        let completed = pipeline.take_completed_batches();
        assert_eq!(completed.len(), 1);
        assert!(pipeline.completed_batches.is_empty());
    }
}
