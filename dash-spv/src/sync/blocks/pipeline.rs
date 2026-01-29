//! Blocks pipeline implementation.
//!
//! Handles concurrent block downloads with timeout and retry logic.
//! Uses the generic DownloadCoordinator for core mechanics.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::sync::download_coordinator::{DownloadConfig, DownloadCoordinator};
use dashcore::blockdata::block::Block;
use dashcore::BlockHash;
use key_wallet_manager::wallet_manager::FilterMatchKey;

/// Maximum number of concurrent block downloads.
const MAX_CONCURRENT_BLOCK_DOWNLOADS: usize = 20;

/// Timeout for block downloads before retry.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of retries for block downloads.
const BLOCK_MAX_RETRIES: u32 = 3;

/// Maximum blocks per GetData request, kept a bit lower for better download distribution to multiple peers
const BLOCKS_PER_REQUEST: usize = 8;

/// Pipeline for downloading blocks with height-ordered processing.
///
/// Uses DownloadCoordinator<BlockHash> for core download mechanics.
/// This is a thin wrapper that handles building GetData inventory messages.
/// Tracks block heights to enable ordered processing and buffers downloaded blocks.
pub(super) struct BlocksPipeline {
    /// Core download coordinator (handles pending, in-flight, timeouts).
    coordinator: DownloadCoordinator<BlockHash>,
    /// Number of completed block downloads.
    completed_count: u32,
    /// Heights queued or in-flight (waiting for download).
    pending_heights: BTreeSet<u32>,
    /// Downloaded blocks ready to process (height -> Block).
    downloaded: BTreeMap<u32, Block>,
    /// Map hash -> height for looking up height when block arrives.
    hash_to_height: HashMap<BlockHash, u32>,
}

impl std::fmt::Debug for BlocksPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlocksPipeline")
            .field("coordinator", &self.coordinator)
            .field("completed_count", &self.completed_count)
            .field("pending_heights", &self.pending_heights.len())
            .field("downloaded", &self.downloaded.len())
            .finish()
    }
}

impl Default for BlocksPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl BlocksPipeline {
    /// Create a new blocks pipeline.
    pub(super) fn new() -> Self {
        Self {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(MAX_CONCURRENT_BLOCK_DOWNLOADS)
                    .with_timeout(BLOCK_TIMEOUT)
                    .with_max_retries(BLOCK_MAX_RETRIES),
            ),
            completed_count: 0,
            pending_heights: BTreeSet::new(),
            downloaded: BTreeMap::new(),
            hash_to_height: HashMap::new(),
        }
    }

    /// Queue blocks with their heights for download.
    ///
    /// This is the preferred method as it enables height-ordered processing.
    pub(super) fn queue(&mut self, blocks: impl IntoIterator<Item = FilterMatchKey>) {
        for key in blocks {
            self.coordinator.enqueue([*key.hash()]);
            self.pending_heights.insert(key.height());
            self.hash_to_height.insert(*key.hash(), key.height());
        }
    }

    /// Check if the pipeline has completed all work.
    ///
    /// Returns true when no blocks are pending, downloading, or waiting to be processed.
    pub(super) fn is_complete(&self) -> bool {
        self.coordinator.is_empty() && self.downloaded.is_empty() && self.pending_heights.is_empty()
    }

    /// Check if there are pending requests to make.
    pub(super) fn has_pending_requests(&self) -> bool {
        self.coordinator.available_to_send() > 0
    }

    /// Send pending block requests up to the concurrency limit.
    ///
    /// Sends multiple smaller GetData messages to distribute requests across peers.
    /// Returns the number of blocks requested.
    pub(super) async fn send_pending(&mut self, requests: &RequestSender) -> SyncResult<usize> {
        let mut total_sent = 0;

        while self.coordinator.available_to_send() > 0 {
            // Take a batch of up to BLOCKS_PER_REQUEST
            let count = self.coordinator.available_to_send().min(BLOCKS_PER_REQUEST);
            let hashes = self.coordinator.take_pending(count);
            if hashes.is_empty() {
                break;
            }

            requests.request_blocks(hashes.clone())?;
            self.coordinator.mark_sent(&hashes);
            total_sent += hashes.len();

            tracing::debug!(
                "Requested {} blocks ({} downloading, {} pending)",
                hashes.len(),
                self.coordinator.active_count(),
                self.coordinator.pending_count()
            );
        }

        Ok(total_sent)
    }

    /// Handle a received block using internal height mapping.
    ///
    /// Looks up the height from the internal hash_to_height map and stores
    /// the block in the downloaded buffer for height-ordered processing.
    /// Returns `true` if this was a tracked block, `false` if unrequested.
    pub(super) fn receive_block(&mut self, block: &Block) -> bool {
        let hash = block.block_hash();
        if !self.coordinator.receive(&hash) {
            tracing::debug!("Ignoring unrequested block: {}", hash);
            return false;
        }

        if let Some(height) = self.hash_to_height.remove(&hash) {
            self.pending_heights.remove(&height);
            self.downloaded.insert(height, block.clone());
            self.completed_count += 1;
            true
        } else {
            // Block was tracked by coordinator but not by height mapping.
            // This can happen if queue() was used instead of queue_with_heights().
            self.completed_count += 1;
            true
        }
    }

    /// Take the next block that's safe to process in height order.
    ///
    /// Returns None if:
    /// - No downloaded blocks available, or
    /// - Waiting for a lower-height block still pending
    pub(super) fn take_next_ordered_block(&mut self) -> Option<(Block, u32)> {
        let lowest_downloaded = *self.downloaded.keys().next()?;

        // Check if any pending blocks have lower heights
        if let Some(&min_pending) = self.pending_heights.first() {
            if min_pending < lowest_downloaded {
                return None; // Wait for lower block
            }
        }

        // Safe to return this block
        let block = self.downloaded.remove(&lowest_downloaded).unwrap();
        Some((block, lowest_downloaded))
    }

    /// Add a block that was loaded from storage (skip download).
    ///
    /// Used when blocks are already persisted from a previous sync.
    pub(super) fn add_from_storage(&mut self, block: Block, height: u32) {
        self.downloaded.insert(height, block);
    }

    /// Check for timed out downloads and re-queue them.
    ///
    /// Returns the list of timed out block hashes.
    pub(super) fn handle_timeouts(&mut self) -> Vec<BlockHash> {
        let timed_out = self.coordinator.check_and_retry_timeouts();

        if !timed_out.is_empty() {
            tracing::debug!("Re-queued {} timed out block downloads", timed_out.len());
        }

        timed_out
    }
}

#[cfg(test)]
mod tests {
    use dashcore_hashes::Hash;

    use super::*;

    fn test_hash(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    fn make_test_block(n: u8) -> Block {
        use dashcore::blockdata::block::Header;
        let header = Header {
            version: dashcore::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([n; 32]),
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: n as u32,
            bits: dashcore::CompactTarget::from_consensus(0),
            nonce: n as u32,
        };
        Block {
            header,
            txdata: vec![],
        }
    }

    #[test]
    fn test_blocks_pipeline_new() {
        let pipeline = BlocksPipeline::new();
        assert_eq!(pipeline.coordinator.pending_count(), 0);
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.completed_count, 0);
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_queue_block() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        pipeline.queue([FilterMatchKey::new(100, block.block_hash())]);

        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert!(!pipeline.is_complete());
        assert!(pipeline.has_pending_requests());
    }

    #[test]
    fn test_queue_multiple() {
        let mut pipeline = BlocksPipeline::new();
        let block1 = make_test_block(1);
        let block2 = make_test_block(2);
        let block3 = make_test_block(3);
        pipeline.queue([
            FilterMatchKey::new(100, block1.block_hash()),
            FilterMatchKey::new(101, block2.block_hash()),
            FilterMatchKey::new(102, block3.block_hash()),
        ]);

        assert_eq!(pipeline.coordinator.pending_count(), 3);
        assert_eq!(pipeline.pending_heights.len(), 3);
        assert!(pipeline.pending_heights.contains(&100));
        assert!(pipeline.pending_heights.contains(&101));
        assert!(pipeline.pending_heights.contains(&102));
    }

    #[test]
    fn test_receive_block_with_height() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();

        // Queue with height tracking
        pipeline.queue([FilterMatchKey::new(100, block.block_hash())]);

        // Simulate sending via coordinator
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);
        assert_eq!(pipeline.coordinator.active_count(), 1);

        // Receive block
        assert!(pipeline.receive_block(&block));
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.completed_count, 1);
        assert_eq!(pipeline.downloaded.len(), 1);
        assert!(pipeline.pending_heights.is_empty());
        assert_eq!(pipeline.downloaded.get(&100).unwrap().block_hash(), hash);
    }

    #[test]
    fn test_receive_block_unrequested() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);

        assert!(!pipeline.receive_block(&block));
        assert_eq!(pipeline.completed_count, 0);
        assert!(pipeline.downloaded.is_empty());
    }

    #[test]
    fn test_max_concurrent() {
        let mut pipeline = BlocksPipeline::new();

        // Queue more blocks than max concurrent
        for i in 0..=MAX_CONCURRENT_BLOCK_DOWNLOADS {
            let block = make_test_block(i as u8);
            pipeline.queue([FilterMatchKey::new(i as u32, block.block_hash())]);
        }

        // Take and mark as downloading up to limit
        let to_send = pipeline.coordinator.available_to_send();
        let hashes = pipeline.coordinator.take_pending(to_send);
        pipeline.coordinator.mark_sent(&hashes);

        assert_eq!(pipeline.coordinator.active_count(), MAX_CONCURRENT_BLOCK_DOWNLOADS);
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert!(!pipeline.has_pending_requests());
    }

    #[test]
    fn test_timeout_requeues() {
        // Create pipeline with very short timeout for testing
        let mut pipeline = BlocksPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(MAX_CONCURRENT_BLOCK_DOWNLOADS)
                    .with_timeout(Duration::from_millis(10)),
            ),
            completed_count: 0,
            pending_heights: BTreeSet::new(),
            downloaded: BTreeMap::new(),
            hash_to_height: HashMap::new(),
        };

        // Use coordinator directly to set up in-flight state
        let hash = test_hash(1);
        pipeline.coordinator.enqueue([hash]);
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        let timed_out = pipeline.handle_timeouts();

        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], hash);
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.coordinator.pending_count(), 1);
    }

    #[test]
    fn test_take_next_ordered_block_in_order() {
        let mut pipeline = BlocksPipeline::new();
        let block1 = make_test_block(1);
        let block2 = make_test_block(2);
        let hash1 = block1.block_hash();
        let hash2 = block2.block_hash();

        // Use add_from_storage to test ordering logic without network
        // Add block 2 first (out of order)
        pipeline.add_from_storage(block2.clone(), 101);
        // Also track height 100 as pending to simulate waiting
        pipeline.pending_heights.insert(100);

        // Cannot take block 2 yet - waiting for block at height 100
        assert!(pipeline.take_next_ordered_block().is_none());

        // Add block 1
        pipeline.pending_heights.remove(&100);
        pipeline.add_from_storage(block1.clone(), 100);

        // Now block 1 is ready (lowest height)
        let (block, height) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 100);
        assert_eq!(block.block_hash(), hash1);

        // Block 2 is now ready
        let (block, height) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 101);
        assert_eq!(block.block_hash(), hash2);

        // No more blocks
        assert!(pipeline.take_next_ordered_block().is_none());
    }

    #[test]
    fn test_take_next_ordered_block_waits_for_pending() {
        let mut pipeline = BlocksPipeline::new();
        let block2 = make_test_block(2);

        // Add block at height 101, but height 100 is still pending
        pipeline.pending_heights.insert(100);
        pipeline.add_from_storage(block2.clone(), 101);

        // Cannot take block 2 - block at height 100 is still pending
        assert!(pipeline.take_next_ordered_block().is_none());

        // Clear the pending height
        pipeline.pending_heights.remove(&100);

        // Now block 2 is ready
        let (_, height) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 101);
    }

    #[test]
    fn test_add_from_storage() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();

        pipeline.add_from_storage(block.clone(), 100);

        assert_eq!(pipeline.downloaded.len(), 1);

        let (taken_block, height) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 100);
        assert_eq!(taken_block.block_hash(), hash);
    }

    #[test]
    fn test_is_complete() {
        let mut pipeline = BlocksPipeline::new();
        assert!(pipeline.is_complete());

        // Adding to downloaded makes it incomplete
        let block = make_test_block(1);
        pipeline.add_from_storage(block, 100);
        assert!(!pipeline.is_complete());

        // Take the block
        pipeline.take_next_ordered_block();
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_is_complete_with_pending_heights() {
        let mut pipeline = BlocksPipeline::new();
        assert!(pipeline.is_complete());

        // Pending heights make it incomplete
        pipeline.pending_heights.insert(100);
        assert!(!pipeline.is_complete());

        pipeline.pending_heights.remove(&100);
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_handle_timeouts_with_multiple_retries() {
        let mut pipeline = BlocksPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(MAX_CONCURRENT_BLOCK_DOWNLOADS)
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(2),
            ),
            completed_count: 0,
            pending_heights: BTreeSet::new(),
            downloaded: BTreeMap::new(),
            hash_to_height: HashMap::new(),
        };

        // Use coordinator to set up in-flight state
        let hash = test_hash(1);
        pipeline.coordinator.enqueue([hash]);
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);

        // First timeout - returns item (it's re-queued)
        std::thread::sleep(Duration::from_millis(5));
        let timed_out = pipeline.handle_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(pipeline.coordinator.pending_count(), 1);

        // Re-send the retry
        let items = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&items);

        // Second timeout - still re-queued
        std::thread::sleep(Duration::from_millis(5));
        let timed_out = pipeline.handle_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(pipeline.coordinator.pending_count(), 1);

        // Re-send
        let items = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&items);

        // Third timeout - exceeds max retries, NOT re-queued
        std::thread::sleep(Duration::from_millis(5));
        let timed_out = pipeline.handle_timeouts();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(pipeline.coordinator.pending_count(), 0);
    }

    #[test]
    fn test_receive_block_duplicate() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);

        // Queue and mark as sent via coordinator
        pipeline.queue([FilterMatchKey::new(100, block.block_hash())]);
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);

        // First receive
        let result = pipeline.receive_block(&block);
        assert!(result);
        assert_eq!(pipeline.completed_count, 1);
        assert_eq!(pipeline.downloaded.len(), 1);

        // Duplicate receive (not tracked anymore since already completed)
        let result = pipeline.receive_block(&block);
        assert!(!result);
        assert_eq!(pipeline.completed_count, 1);
        assert_eq!(pipeline.downloaded.len(), 1);
    }
}
