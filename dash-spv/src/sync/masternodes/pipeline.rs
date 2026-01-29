//! MnListDiff pipeline implementation.
//!
//! Handles pipelined download of MnListDiff messages for quorum validation.
//! Uses DownloadCoordinator for request tracking with timeout and retry logic.

use std::collections::HashMap;
use std::time::Duration;

use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::sync::download_coordinator::{DownloadConfig, DownloadCoordinator};
use dashcore::network::message_sml::MnListDiff;
use dashcore::BlockHash;

/// Maximum concurrent MnListDiff requests.
const MAX_CONCURRENT_MNLISTDIFF: usize = 20;

/// Timeout for MnListDiff requests.
const MNLISTDIFF_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum number of retries for MnListDiff requests.
const MNLISTDIFF_MAX_RETRIES: u32 = 3;

/// Pipeline for downloading MnListDiff messages for quorum validation.
///
/// Uses `DownloadCoordinator<BlockHash>` for request tracking (keyed by target block_hash),
/// with a HashMap to store the base hash for each request.
#[derive(Debug)]
pub(super) struct MnListDiffPipeline {
    /// Core coordinator tracks requests by target block_hash.
    coordinator: DownloadCoordinator<BlockHash>,
    /// Maps target_hash -> base_hash for each request.
    base_hashes: HashMap<BlockHash, BlockHash>,
}

impl Default for MnListDiffPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl MnListDiffPipeline {
    /// Create a new MnListDiff pipeline.
    pub(super) fn new() -> Self {
        Self {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(MAX_CONCURRENT_MNLISTDIFF)
                    .with_timeout(MNLISTDIFF_TIMEOUT)
                    .with_max_retries(MNLISTDIFF_MAX_RETRIES),
            ),
            base_hashes: HashMap::new(),
        }
    }

    /// Clear all state.
    pub(super) fn clear(&mut self) {
        self.coordinator.clear();
        self.base_hashes.clear();
    }

    /// Queue MnListDiff requests.
    ///
    /// Each request is a (base_hash, target_hash) pair.
    pub(super) fn queue_requests(&mut self, requests: Vec<(BlockHash, BlockHash)>) {
        for (base_hash, target_hash) in requests {
            self.coordinator.enqueue([target_hash]);
            self.base_hashes.insert(target_hash, base_hash);
        }

        if !self.base_hashes.is_empty() {
            tracing::info!("Queued {} MnListDiff requests", self.base_hashes.len());
        }
    }

    /// Send pending requests.
    ///
    /// Returns the number of requests sent.
    pub(super) fn send_pending(&mut self, requests: &RequestSender) -> SyncResult<()> {
        let count = self.coordinator.available_to_send();
        if count == 0 {
            return Ok(());
        }

        let target_hashes = self.coordinator.take_pending(count);

        for target_hash in target_hashes {
            let Some(&base_hash) = self.base_hashes.get(&target_hash) else {
                tracing::warn!("Missing base hash for target {}, skipping", target_hash);
                continue;
            };

            requests.request_mnlist_diff(base_hash, target_hash)?;
            self.coordinator.mark_sent(&[target_hash]);

            tracing::debug!(
                "Sent GetMnListDiff: base={}, target={} ({} active, {} pending)",
                base_hash,
                target_hash,
                self.coordinator.active_count(),
                self.coordinator.pending_count()
            );
        }

        Ok(())
    }

    /// Check if response matches an in-flight request.
    pub(super) fn match_response(&self, diff: &MnListDiff) -> bool {
        self.coordinator.is_in_flight(&diff.block_hash)
    }

    /// Receive a MnListDiff response.
    ///
    /// Returns true if the diff was expected, false if unexpected.
    pub(super) fn receive(&mut self, diff: &MnListDiff) -> bool {
        let target_hash = diff.block_hash;

        if !self.coordinator.receive(&target_hash) {
            return false;
        }

        self.base_hashes.remove(&target_hash);

        tracing::debug!(
            "Received MnListDiff for {} ({} remaining)",
            target_hash,
            self.coordinator.remaining()
        );

        true
    }

    /// Handle timeouts, re-queuing failed requests.
    ///
    /// Returns hashes that exceeded max retries and were dropped.
    pub(super) fn handle_timeouts(&mut self) {
        for target_hash in self.coordinator.check_timeouts() {
            if !self.coordinator.enqueue_retry(target_hash) {
                tracing::warn!(
                    "MnListDiff request for {} exceeded max retries, dropping",
                    target_hash
                );
                self.base_hashes.remove(&target_hash);
            }
        }
    }

    /// Check if pipeline has no pending work.
    pub(super) fn is_complete(&self) -> bool {
        self.coordinator.is_empty()
    }

    /// Get the number of in-flight requests.
    pub(super) fn active_count(&self) -> usize {
        self.coordinator.active_count()
    }
}

#[cfg(test)]
mod tests {
    use dashcore::transaction::{OutPoint, Transaction};
    use dashcore::{ScriptBuf, TxIn, TxOut, Witness};
    use dashcore_hashes::Hash;

    use super::*;

    /// Create a minimal MnListDiff for testing.
    fn create_test_diff(base_hash: BlockHash, target_hash: BlockHash) -> MnListDiff {
        // Create a minimal coinbase transaction
        let coinbase_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: 0,
                script_pubkey: ScriptBuf::new(),
            }],
            special_transaction_payload: None,
        };

        MnListDiff {
            version: 1,
            base_block_hash: base_hash,
            block_hash: target_hash,
            total_transactions: 1,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx,
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            quorums_chainlock_signatures: vec![],
        }
    }

    #[test]
    fn test_pipeline_new() {
        let pipeline = MnListDiffPipeline::new();
        assert!(pipeline.is_complete());
        assert_eq!(pipeline.active_count(), 0);
    }

    #[test]
    fn test_queue_requests() {
        let mut pipeline = MnListDiffPipeline::new();

        let base1 = BlockHash::from_byte_array([0x01; 32]);
        let target1 = BlockHash::from_byte_array([0x02; 32]);
        let base2 = BlockHash::from_byte_array([0x03; 32]);
        let target2 = BlockHash::from_byte_array([0x04; 32]);

        pipeline.queue_requests(vec![(base1, target1), (base2, target2)]);

        assert!(!pipeline.is_complete());
        assert_eq!(pipeline.coordinator.pending_count(), 2);
        assert_eq!(pipeline.base_hashes.len(), 2);
        assert_eq!(pipeline.base_hashes.get(&target1), Some(&base1));
        assert_eq!(pipeline.base_hashes.get(&target2), Some(&base2));
    }

    #[test]
    fn test_match_response() {
        let mut pipeline = MnListDiffPipeline::new();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);

        // Take and mark as sent
        let items = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&items);

        // Create a test diff
        let diff = create_test_diff(base, target);
        assert!(pipeline.match_response(&diff));

        // Unknown hash should not match
        let unknown_diff = create_test_diff(base, BlockHash::from_byte_array([0xFF; 32]));
        assert!(!pipeline.match_response(&unknown_diff));
    }

    #[test]
    fn test_receive() {
        let mut pipeline = MnListDiffPipeline::new();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);

        // Take and mark as sent
        let items = pipeline.coordinator.take_pending(1);
        pipeline.coordinator.mark_sent(&items);

        let diff = create_test_diff(base, target);
        assert!(pipeline.receive(&diff));
        assert!(pipeline.is_complete());
        assert!(pipeline.base_hashes.is_empty());
    }

    #[test]
    fn test_receive_unexpected() {
        let mut pipeline = MnListDiffPipeline::new();

        let diff = create_test_diff(
            BlockHash::from_byte_array([0x01; 32]),
            BlockHash::from_byte_array([0x02; 32]),
        );

        // Receiving unexpected diff should return false
        assert!(!pipeline.receive(&diff));
    }

    #[test]
    fn test_clear() {
        let mut pipeline = MnListDiffPipeline::new();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);
        pipeline.clear();

        assert!(pipeline.is_complete());
        assert!(pipeline.base_hashes.is_empty());
    }

    #[test]
    fn test_handle_timeouts() {
        use std::time::Duration;

        let mut pipeline = MnListDiffPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(0),
            ),
            base_hashes: HashMap::new(),
        };

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.base_hashes.insert(target, base);
        pipeline.coordinator.mark_sent(&[target]);

        std::thread::sleep(Duration::from_millis(5));

        pipeline.handle_timeouts();
        assert!(pipeline.base_hashes.is_empty());
    }

    #[test]
    fn test_handle_timeouts_with_retry() {
        use std::time::Duration;

        let mut pipeline = MnListDiffPipeline {
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_timeout(Duration::from_millis(1))
                    .with_max_retries(3),
            ),
            base_hashes: HashMap::new(),
        };

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.base_hashes.insert(target, base);
        pipeline.coordinator.mark_sent(&[target]);

        std::thread::sleep(Duration::from_millis(5));

        // First timeout should retry, not fail
        pipeline.handle_timeouts();
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert!(pipeline.base_hashes.contains_key(&target));
    }
}
