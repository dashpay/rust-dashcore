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
use key_wallet_manager::{FilterMatchKey, WalletId};

/// Maximum number of concurrent block downloads.
const MAX_CONCURRENT_BLOCK_DOWNLOADS: usize = 20;

/// Timeout for block downloads before retry.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Heights queued or in-flight (waiting for download).
    pending_heights: BTreeSet<u32>,
    /// Downloaded blocks ready to process (height -> Block).
    downloaded: BTreeMap<u32, Block>,
    /// Map hash -> height for looking up height when block arrives.
    hash_to_height: HashMap<BlockHash, u32>,
    /// Per-block interested wallets, populated when the block is queued.
    /// Only those wallets get the block processed.
    hash_to_wallets: HashMap<BlockHash, BTreeSet<WalletId>>,
}

impl std::fmt::Debug for BlocksPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlocksPipeline")
            .field("coordinator", &self.coordinator)
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
                    .with_timeout(BLOCK_TIMEOUT),
            ),
            pending_heights: BTreeSet::new(),
            downloaded: BTreeMap::new(),
            hash_to_height: HashMap::new(),
            hash_to_wallets: HashMap::new(),
        }
    }

    /// Queue blocks with their heights and per-block interested wallet sets.
    pub(super) fn queue(
        &mut self,
        blocks: impl IntoIterator<Item = (FilterMatchKey, BTreeSet<WalletId>)>,
    ) {
        for (key, wallets) in blocks {
            let hash = *key.hash();
            let already_tracked =
                self.hash_to_height.contains_key(&hash) || self.hash_to_wallets.contains_key(&hash);
            if !already_tracked {
                self.coordinator.enqueue([hash]);
                self.pending_heights.insert(key.height());
                self.hash_to_height.insert(hash, key.height());
            }
            self.hash_to_wallets.entry(hash).or_default().extend(wallets);
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
        }
        true
    }

    /// Take the next block that's safe to process in height order, along with
    /// the wallet set whose filters matched this block.
    ///
    /// Returns None if:
    /// - No downloaded blocks available, or
    /// - Waiting for a lower-height block still pending
    pub(super) fn take_next_ordered_block(&mut self) -> Option<(Block, u32, BTreeSet<WalletId>)> {
        let lowest_downloaded = *self.downloaded.keys().next()?;

        // Check if any pending blocks have lower heights
        if let Some(&min_pending) = self.pending_heights.first() {
            if min_pending < lowest_downloaded {
                return None; // Wait for lower block
            }
        }

        let block = self.downloaded.remove(&lowest_downloaded).unwrap();
        let wallets = self.hash_to_wallets.remove(&block.block_hash()).unwrap_or_default();
        Some((block, lowest_downloaded, wallets))
    }

    /// Add a block that was loaded from storage (skip download).
    ///
    /// Used when blocks are already persisted from a previous sync.
    pub(super) fn add_from_storage(
        &mut self,
        block: Block,
        height: u32,
        wallets: BTreeSet<WalletId>,
    ) {
        let hash = block.block_hash();
        self.hash_to_wallets.entry(hash).or_default().extend(wallets);
        self.downloaded.insert(height, block);
    }

    /// Check for timed out downloads and re-queue them.
    pub(super) fn handle_timeouts(&mut self) {
        self.coordinator.check_and_retry_timeouts();
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
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_queue_block() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        pipeline.queue([(FilterMatchKey::new(100, block.block_hash()), BTreeSet::new())]);

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
            (FilterMatchKey::new(100, block1.block_hash()), BTreeSet::new()),
            (FilterMatchKey::new(101, block2.block_hash()), BTreeSet::new()),
            (FilterMatchKey::new(102, block3.block_hash()), BTreeSet::new()),
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
        pipeline.queue([(FilterMatchKey::new(100, block.block_hash()), BTreeSet::new())]);

        // Simulate sending via coordinator
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);
        assert_eq!(pipeline.coordinator.active_count(), 1);

        // Receive block
        assert!(pipeline.receive_block(&block));
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.downloaded.len(), 1);
        assert!(pipeline.pending_heights.is_empty());
        assert_eq!(pipeline.downloaded.get(&100).unwrap().block_hash(), hash);
    }

    #[test]
    fn test_receive_block_unrequested() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);

        assert!(!pipeline.receive_block(&block));
        assert!(pipeline.downloaded.is_empty());
    }

    #[test]
    fn test_max_concurrent() {
        let mut pipeline = BlocksPipeline::new();

        // Queue more blocks than max concurrent
        for i in 0..=MAX_CONCURRENT_BLOCK_DOWNLOADS {
            let block = make_test_block(i as u8);
            pipeline.queue([(FilterMatchKey::new(i as u32, block.block_hash()), BTreeSet::new())]);
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
            pending_heights: BTreeSet::new(),
            downloaded: BTreeMap::new(),
            hash_to_height: HashMap::new(),
            hash_to_wallets: HashMap::new(),
        };

        // Use coordinator directly to set up in-flight state
        let hash = test_hash(1);
        pipeline.coordinator.enqueue([hash]);
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        pipeline.handle_timeouts();

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
        pipeline.add_from_storage(block2.clone(), 101, BTreeSet::new());
        // Also track height 100 as pending to simulate waiting
        pipeline.pending_heights.insert(100);

        // Cannot take block 2 yet - waiting for block at height 100
        assert!(pipeline.take_next_ordered_block().is_none());

        // Add block 1
        pipeline.pending_heights.remove(&100);
        pipeline.add_from_storage(block1.clone(), 100, BTreeSet::new());

        // Now block 1 is ready (lowest height)
        let (block, height, _) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 100);
        assert_eq!(block.block_hash(), hash1);

        // Block 2 is now ready
        let (block, height, _) = pipeline.take_next_ordered_block().unwrap();
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
        pipeline.add_from_storage(block2.clone(), 101, BTreeSet::new());

        // Cannot take block 2 - block at height 100 is still pending
        assert!(pipeline.take_next_ordered_block().is_none());

        // Clear the pending height
        pipeline.pending_heights.remove(&100);

        // Now block 2 is ready
        let (_, height, _) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 101);
    }

    #[test]
    fn test_add_from_storage() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();

        pipeline.add_from_storage(block.clone(), 100, BTreeSet::new());

        assert_eq!(pipeline.downloaded.len(), 1);

        let (taken_block, height, _) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(height, 100);
        assert_eq!(taken_block.block_hash(), hash);
    }

    #[test]
    fn test_is_complete() {
        let mut pipeline = BlocksPipeline::new();
        assert!(pipeline.is_complete());

        // Adding to downloaded makes it incomplete
        let block = make_test_block(1);
        pipeline.add_from_storage(block, 100, BTreeSet::new());
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
    fn test_queue_propagates_wallet_set_through_take_next() {
        // A block queued with a non-empty wallet set must yield that exact
        // wallet set when taken in height order via `take_next_ordered_block`.
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();
        let wallets: BTreeSet<WalletId> = BTreeSet::from([[1u8; 32], [2u8; 32]]);

        pipeline.queue([(FilterMatchKey::new(100, hash), wallets.clone())]);

        // Drive the block through receive_block to land it in `downloaded`.
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);
        assert!(pipeline.receive_block(&block));

        let (taken_block, height, taken_wallets) = pipeline.take_next_ordered_block().unwrap();
        assert_eq!(taken_block.block_hash(), hash);
        assert_eq!(height, 100);
        assert_eq!(taken_wallets, wallets);
    }

    #[test]
    fn test_queue_merges_wallet_sets_for_repeat_hashes() {
        // Queueing the same block hash twice with different wallet sets must
        // produce the union when the block is later taken from the pipeline,
        // and must not double-count it in the coordinator's pending state.
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();
        let wallets_a: BTreeSet<WalletId> = BTreeSet::from([[1u8; 32]]);
        let wallets_b: BTreeSet<WalletId> = BTreeSet::from([[2u8; 32], [3u8; 32]]);

        pipeline.queue([(FilterMatchKey::new(100, hash), wallets_a.clone())]);
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        pipeline.queue([(FilterMatchKey::new(100, hash), wallets_b.clone())]);
        // Re-queueing must not double the coordinator's pending count.
        assert_eq!(pipeline.coordinator.pending_count(), 1);

        // Land the block in `downloaded` to retrieve it.
        let hashes = pipeline.coordinator.take_pending(1);
        assert_eq!(hashes.len(), 1);
        pipeline.coordinator.mark_sent(&hashes);
        assert!(pipeline.receive_block(&block));

        let (_, _, taken_wallets) = pipeline.take_next_ordered_block().unwrap();
        let mut expected = wallets_a;
        expected.extend(wallets_b);
        assert_eq!(taken_wallets, expected);
    }

    #[test]
    fn test_queue_does_not_re_enqueue_in_flight_hash() {
        // A late-arriving wallet match for a block already in flight must
        // merge the wallet id without re-enqueueing the hash. Re-enqueueing
        // would cause a duplicate request and corrupt the coordinator's
        // pending/in-flight state.
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();
        let wallets_a: BTreeSet<WalletId> = BTreeSet::from([[1u8; 32]]);
        let wallets_b: BTreeSet<WalletId> = BTreeSet::from([[2u8; 32]]);

        pipeline.queue([(FilterMatchKey::new(100, hash), wallets_a.clone())]);
        // Move the hash to in-flight.
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);
        assert_eq!(pipeline.coordinator.pending_count(), 0);
        assert_eq!(pipeline.coordinator.active_count(), 1);

        // A second queue call for the same hash must not push it back to
        // pending while it is in flight.
        pipeline.queue([(FilterMatchKey::new(100, hash), wallets_b.clone())]);
        assert_eq!(pipeline.coordinator.pending_count(), 0);
        assert_eq!(pipeline.coordinator.active_count(), 1);

        // Late wallet ids are still merged for when the block arrives.
        assert!(pipeline.receive_block(&block));
        let (_, _, taken_wallets) = pipeline.take_next_ordered_block().unwrap();
        let mut expected = wallets_a;
        expected.extend(wallets_b);
        assert_eq!(taken_wallets, expected);
    }

    #[test]
    fn test_queue_does_not_re_enqueue_downloaded_hash() {
        // A late-arriving wallet match for a block already received and sitting
        // in `downloaded` (but not yet consumed by `take_next_ordered_block`)
        // must merge the wallet id without re-enqueueing the hash.
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let hash = block.block_hash();
        let wallets_a: BTreeSet<WalletId> = BTreeSet::from([[1u8; 32]]);
        let wallets_b: BTreeSet<WalletId> = BTreeSet::from([[2u8; 32]]);

        pipeline.queue([(FilterMatchKey::new(100, hash), wallets_a.clone())]);
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);
        assert!(pipeline.receive_block(&block));
        assert_eq!(pipeline.downloaded.len(), 1);
        assert_eq!(pipeline.coordinator.pending_count(), 0);
        assert_eq!(pipeline.coordinator.active_count(), 0);

        // Late-arriving match for the same hash must not re-enqueue.
        pipeline.queue([(FilterMatchKey::new(100, hash), wallets_b.clone())]);
        assert_eq!(pipeline.coordinator.pending_count(), 0);
        assert_eq!(pipeline.coordinator.active_count(), 0);
        assert_eq!(pipeline.downloaded.len(), 1);

        // Late wallet ids are still merged for when the block is taken.
        let (_, _, taken_wallets) = pipeline.take_next_ordered_block().unwrap();
        let mut expected = wallets_a;
        expected.extend(wallets_b);
        assert_eq!(taken_wallets, expected);
    }

    #[test]
    fn test_add_from_storage_merges_wallet_sets() {
        // The `add_from_storage` path must merge wallet sets for repeat
        // additions of the same block hash, matching `queue`'s semantics.
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);
        let wallets_a: BTreeSet<WalletId> = BTreeSet::from([[1u8; 32]]);
        let wallets_b: BTreeSet<WalletId> = BTreeSet::from([[2u8; 32]]);

        pipeline.add_from_storage(block.clone(), 100, wallets_a.clone());
        pipeline.add_from_storage(block.clone(), 100, wallets_b.clone());

        let (_, _, taken_wallets) = pipeline.take_next_ordered_block().unwrap();
        let mut expected = wallets_a;
        expected.extend(wallets_b);
        assert_eq!(taken_wallets, expected);
    }

    #[test]
    fn test_receive_block_duplicate() {
        let mut pipeline = BlocksPipeline::new();
        let block = make_test_block(1);

        // Queue and mark as sent via coordinator
        pipeline.queue([(FilterMatchKey::new(100, block.block_hash()), BTreeSet::new())]);
        let hashes = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&hashes);

        // First receive
        let result = pipeline.receive_block(&block);
        assert!(result);
        assert_eq!(pipeline.downloaded.len(), 1);

        // Duplicate receive (not tracked anymore since already completed)
        let result = pipeline.receive_block(&block);
        assert!(!result);
        assert_eq!(pipeline.downloaded.len(), 1);
    }
}
