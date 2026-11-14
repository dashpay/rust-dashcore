//! CFHeaders pipeline implementation.

use std::collections::HashMap;
use std::mem;
use std::sync::Arc;

use dashcore::network::message::NetworkMessage;
use dashcore::network::message_filter::{CFHeaders, GetCFHeaders};
use dashcore::BlockHash;

use crate::error::{StorageError, SyncError, SyncResult};
use crate::network::{NetworkManager, SendRequest};
use crate::storage::BlockHeaderStorage;

/// Batch size for filter header requests.
pub(super) const FILTER_HEADERS_BATCH_SIZE: u32 = 2000;

/// Pipeline for downloading compact block filter headers.
#[derive(Debug)]
pub(super) struct FilterHeadersPipeline {
    /// Wanted batches (stop_hash -> start_height); a batch leaves this map once received.
    batch_starts: HashMap<BlockHash, u32>,
    /// Whether a batch was added since `send_pending` last declared them all.
    undeclared: bool,
    /// Out-of-order response buffer (start_height -> data).
    buffered: HashMap<u32, CFHeaders>,
    /// Next height to process sequentially.
    next_expected: u32,
    /// Target height for sync.
    target_height: u32,
    /// Wanted batches below the stored filter headers (stop_hash -> (start_height, end_height)).
    below_batches: HashMap<BlockHash, (u32, u32)>,
    /// Received batches below (end_height -> (start_height, data)), kept until the stored
    /// filter headers reach down to their end.
    below_buffered: HashMap<u32, (u32, CFHeaders)>,
    /// End height of the next batch to queue below.
    below_end: Option<u32>,
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
            batch_starts: HashMap::new(),
            undeclared: false,
            buffered: HashMap::new(),
            next_expected: 0,
            target_height: 0,
            below_batches: HashMap::new(),
            below_buffered: HashMap::new(),
            below_end: None,
        }
    }

    /// Queue the batches below the stored filter headers, from the one ending at `top`,
    /// or below the ones queued already, down to the one starting at `lowest`.
    pub(super) async fn extend_below(
        &mut self,
        storage: &impl BlockHeaderStorage,
        top: u32,
        lowest: u32,
    ) -> SyncResult<()> {
        let mut end = self.below_end.unwrap_or(top);
        while end > lowest.saturating_sub(1) {
            let start = lowest.max(end.saturating_sub(FILTER_HEADERS_BATCH_SIZE - 1));
            let stop_hash = storage.get_header(end).await?.map(|h| *h.hash()).ok_or_else(|| {
                SyncError::Storage(StorageError::NotFound(format!("Header at height {}", end)))
            })?;
            self.want_below(stop_hash, start, end);
            end = start.saturating_sub(1);
        }
        self.below_end = Some(end);
        Ok(())
    }

    /// Buffer `data` if it answers a wanted batch below. Returns whether it does.
    pub(super) fn receive_below(&mut self, data: &CFHeaders) -> bool {
        let Some((start, end)) = self.below_batches.remove(&data.stop_hash) else {
            return false;
        };
        self.below_buffered.insert(end, (start, data.clone()));
        true
    }

    /// Start height and data of the received batch below that ends at `end`.
    pub(super) fn take_below(&mut self, end: u32) -> Option<(u32, CFHeaders)> {
        self.below_buffered.remove(&end)
    }

    /// Want the batch `start..=end` below the stored filter headers, whose block at `end` is `stop_hash`.
    pub(super) fn want_below(&mut self, stop_hash: BlockHash, start: u32, end: u32) {
        self.below_batches.insert(stop_hash, (start, end));
        self.undeclared = true;
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
            let stop_hash =
                storage.get_header(batch_end).await?.map(|h| *h.hash()).ok_or_else(|| {
                    SyncError::Storage(StorageError::NotFound(format!(
                        "Header at height {}",
                        batch_end
                    )))
                })?;

            self.want(stop_hash, current);
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
        self.batch_starts.is_empty()
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
        self.batch_starts.clear();
        self.buffered.clear();
        self.next_expected = start_height;
        self.target_height = target_height;

        // Build request queue
        let mut current = start_height;
        while current <= target_height {
            let batch_end = (current + FILTER_HEADERS_BATCH_SIZE - 1).min(target_height);

            // Get stop hash for this batch
            let stop_hash =
                storage.get_header(batch_end).await?.map(|h| *h.hash()).ok_or_else(|| {
                    SyncError::Storage(StorageError::NotFound(format!(
                        "Header at height {}",
                        batch_end
                    )))
                })?;

            self.want(stop_hash, current);

            current = batch_end + 1;
        }

        tracing::info!(
            "Built CFHeaders request queue: {} batches for heights {} to {}",
            self.batch_starts.len(),
            start_height,
            target_height
        );

        Ok(())
    }

    /// Declare every wanted CFHeaders batch; the broker de-duplicates, so re-declaring
    /// is safe. Returns the number of batches declared.
    pub(super) async fn send_pending(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<usize> {
        let batches: Vec<(BlockHash, u32)> = self
            .batch_starts
            .iter()
            .map(|(stop_hash, start)| (*stop_hash, *start))
            .chain(self.below_batches.iter().map(|(stop_hash, (start, _))| (*stop_hash, *start)))
            .collect();
        if batches.is_empty() {
            return Ok(0);
        }

        for (stop_hash, start_height) in &batches {
            network
                .send(GetCFHeaders {
                    filter_type: 0u8,
                    start_height: *start_height,
                    stop_hash: *stop_hash,
                })
                .await;
        }

        if mem::take(&mut self.undeclared) {
            tracing::debug!("Declared {} wanted CFHeaders batch(es) to the broker", batches.len());
        }

        Ok(batches.len())
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
        let start_height = *self.batch_starts.get(&cfheaders.stop_hash)?;
        Some((start_height, cfheaders.clone()))
    }

    /// Handle a received response.
    ///
    /// Returns `Some(data)` if this response is the next expected and should
    /// be processed immediately. Returns `None` if buffered for later.
    pub(super) fn receive(&mut self, start_height: u32, data: CFHeaders) -> Option<CFHeaders> {
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

    /// Re-request a received batch that was rejected instead of stored.
    ///
    /// Buffered batches above it chain from it, so they are dropped and re-requested
    /// too. `next_expected` is unchanged.
    pub(super) fn requeue_rejected(&mut self, start_height: u32, stop_hash: BlockHash) {
        let dropped: Vec<(u32, BlockHash)> = self
            .buffered
            .extract_if(|&height, _| height > start_height)
            .map(|(height, data)| (height, data.stop_hash))
            .collect();
        for (height, hash) in dropped.into_iter().chain([(start_height, stop_hash)]) {
            self.want(hash, height);
        }
    }

    fn want(&mut self, stop_hash: BlockHash, start_height: u32) {
        self.batch_starts.insert(stop_hash, start_height);
        self.undeclared = true;
    }
}

#[cfg(test)]
mod tests {
    use dashcore::hash_types::{FilterHash, FilterHeader};

    use super::*;
    use crate::test_utils::MockNetworkManager;

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
        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 100;

        let stop_hash = BlockHash::all_zeros();

        // Mark batch as wanted (by stop_hash)
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
        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 1;
        pipeline.target_height = 4000;

        let stop_hash = BlockHash::all_zeros();

        // Mark batch as wanted (by stop_hash)
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

    /// A rejected batch is requested again with its start height, along with every
    /// buffered batch above it; batches below it are not touched.
    #[tokio::test]
    async fn test_requeue_rejected_reissues_batch_and_drops_buffered_above() {
        let mut pipeline = FilterHeadersPipeline::new();
        pipeline.next_expected = 2001;
        pipeline.target_height = 8000;

        let rejected = BlockHash::from_byte_array([0x02; 32]);
        for (height, byte) in [(6001, 0x04), (4001, 0x03)] {
            pipeline.buffered.insert(
                height,
                CFHeaders {
                    filter_type: 0,
                    stop_hash: BlockHash::from_byte_array([byte; 32]),
                    previous_filter_header: FilterHeader::all_zeros(),
                    filter_hashes: vec![FilterHash::all_zeros()],
                },
            );
        }

        pipeline.requeue_rejected(2001, rejected);
        assert!(pipeline.buffered.is_empty());
        assert_eq!(pipeline.next_expected(), 2001);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        assert_eq!(pipeline.send_pending(&network).await.unwrap(), 3);
        let mut reissued: Vec<(u32, BlockHash)> = mock
            .sent_messages()
            .await
            .into_iter()
            .filter_map(|msg| match msg {
                NetworkMessage::GetCFHeaders(get) => Some((get.start_height, get.stop_hash)),
                _ => None,
            })
            .collect();
        reissued.sort();
        assert_eq!(
            reissued,
            vec![
                (2001, rejected),
                (4001, BlockHash::from_byte_array([0x03; 32])),
                (6001, BlockHash::from_byte_array([0x04; 32])),
            ]
        );
    }
}
