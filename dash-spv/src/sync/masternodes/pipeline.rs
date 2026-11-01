//! MnListDiff pipeline implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// tokio's `Instant`, so tests can pause and advance the clock.
use tokio::time::Instant;

use crate::error::SyncResult;
use crate::network::{NetworkManager, SendRequest};
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_sml::{GetMnListDiff, MnListDiff};
use dashcore::BlockHash;

/// Pipeline for downloading MnListDiff messages for quorum validation.
#[derive(Debug, Default)]
pub(super) struct MnListDiffPipeline {
    /// Wanted requests: target_hash -> base_hash.
    base_hashes: HashMap<BlockHash, BlockHash>,
    /// Wanted targets that are work-block list requests, and when each was first queued.
    work_block_queued: HashMap<BlockHash, Instant>,
}

impl MnListDiffPipeline {
    /// Clear all state.
    pub(super) fn clear(&mut self) {
        self.base_hashes.clear();
        self.work_block_queued.clear();
    }

    /// Queue MnListDiff requests.
    ///
    /// Each request is a (base_hash, target_hash) pair.
    pub(super) fn queue_requests(&mut self, requests: Vec<(BlockHash, BlockHash)>) {
        for (base_hash, target_hash) in requests {
            self.base_hashes.insert(target_hash, base_hash);
        }

        if !self.base_hashes.is_empty() {
            tracing::info!("Queued {} MnListDiff requests", self.base_hashes.len());
        }
    }

    /// Like [`Self::queue_requests`], but the targets expire in [`Self::expire_work_block_requests`].
    pub(super) fn queue_work_block_requests(&mut self, requests: Vec<(BlockHash, BlockHash)>) {
        let now = Instant::now();
        for (_, target_hash) in &requests {
            self.work_block_queued.entry(*target_hash).or_insert(now);
        }
        self.queue_requests(requests);
    }

    /// Drop the work-block requests queued longer than `deadline` ago and return their targets.
    pub(super) fn expire_work_block_requests(&mut self, deadline: Duration) -> Vec<BlockHash> {
        let expired: Vec<BlockHash> = self
            .work_block_queued
            .extract_if(|_, queued| queued.elapsed() > deadline)
            .map(|(target, _)| target)
            .collect();
        for target in &expired {
            self.base_hashes.remove(target);
        }
        expired
    }

    /// Declare every wanted MnListDiff; the broker de-duplicates, so re-declaring is safe.
    pub(super) async fn send_pending(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<()> {
        if self.base_hashes.is_empty() {
            return Ok(());
        }

        let requests: Vec<(BlockHash, BlockHash)> =
            self.base_hashes.iter().map(|(target, base)| (*base, *target)).collect();

        for (base_block_hash, block_hash) in requests {
            network
                .send(NetworkMessage::GetMnListD(GetMnListDiff {
                    base_block_hash,
                    block_hash,
                }))
                .await;
            tracing::trace!(
                "Declared GetMnListDiff: base={}, target={}",
                base_block_hash,
                block_hash
            );
        }

        Ok(())
    }

    /// Check if response matches a wanted request.
    pub(super) fn match_response(&self, diff: &MnListDiff) -> bool {
        self.base_hashes.contains_key(&diff.block_hash)
    }

    /// Receive a MnListDiff response.
    ///
    /// Returns true if the diff was expected, false if unexpected.
    pub(super) fn receive(&mut self, diff: &MnListDiff) -> bool {
        let target_hash = diff.block_hash;

        if self.base_hashes.remove(&target_hash).is_none() {
            return false;
        }
        self.work_block_queued.remove(&target_hash);

        tracing::debug!(
            "Received MnListDiff for {} ({} remaining)",
            target_hash,
            self.base_hashes.len()
        );

        true
    }

    /// Check if pipeline has no pending work.
    pub(super) fn is_complete(&self) -> bool {
        self.base_hashes.is_empty()
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
        let pipeline = MnListDiffPipeline::default();
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_queue_requests() {
        let mut pipeline = MnListDiffPipeline::default();

        let base1 = BlockHash::from_byte_array([0x01; 32]);
        let target1 = BlockHash::from_byte_array([0x02; 32]);
        let base2 = BlockHash::from_byte_array([0x03; 32]);
        let target2 = BlockHash::from_byte_array([0x04; 32]);

        pipeline.queue_requests(vec![(base1, target1), (base2, target2)]);

        assert!(!pipeline.is_complete());
        assert_eq!(pipeline.base_hashes.len(), 2);
        assert_eq!(pipeline.base_hashes.get(&target1), Some(&base1));
        assert_eq!(pipeline.base_hashes.get(&target2), Some(&base2));
    }

    #[test]
    fn test_match_response() {
        let mut pipeline = MnListDiffPipeline::default();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);

        let diff = create_test_diff(base, target);
        assert!(pipeline.match_response(&diff));

        // Unknown hash should not match
        let unknown_diff = create_test_diff(base, BlockHash::from_byte_array([0xFF; 32]));
        assert!(!pipeline.match_response(&unknown_diff));
    }

    #[test]
    fn test_receive() {
        let mut pipeline = MnListDiffPipeline::default();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);

        let diff = create_test_diff(base, target);
        assert!(pipeline.receive(&diff));
        assert!(pipeline.is_complete());
        assert!(pipeline.base_hashes.is_empty());
    }

    #[test]
    fn test_receive_unexpected() {
        let mut pipeline = MnListDiffPipeline::default();

        let diff = create_test_diff(
            BlockHash::from_byte_array([0x01; 32]),
            BlockHash::from_byte_array([0x02; 32]),
        );

        // Receiving unexpected diff should return false
        assert!(!pipeline.receive(&diff));
    }

    #[test]
    fn test_receive_duplicate() {
        let mut pipeline = MnListDiffPipeline::default();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);
        let diff = create_test_diff(base, target);

        assert!(pipeline.receive(&diff));
        assert!(!pipeline.receive(&diff));
        assert!(pipeline.is_complete());
    }

    #[test]
    fn test_clear() {
        let mut pipeline = MnListDiffPipeline::default();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(vec![(base, target)]);
        pipeline.clear();

        assert!(pipeline.is_complete());
        assert!(pipeline.base_hashes.is_empty());
    }

    /// Only work-block requests expire; a tip-update request queued at the same time stays wanted.
    #[tokio::test]
    async fn only_work_block_requests_expire() {
        tokio::time::pause();
        let base = BlockHash::from_byte_array([1; 32]);
        let tip = BlockHash::from_byte_array([2; 32]);
        let work_block = BlockHash::from_byte_array([3; 32]);
        let mut pipeline = MnListDiffPipeline::default();
        pipeline.queue_requests(vec![(base, tip)]);
        pipeline.queue_work_block_requests(vec![(base, work_block)]);

        let deadline = Duration::from_secs(100);
        tokio::time::advance(deadline).await;
        assert!(pipeline.expire_work_block_requests(deadline).is_empty());

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(pipeline.expire_work_block_requests(deadline), vec![work_block]);
        assert!(!pipeline.is_complete());
        assert!(pipeline.receive(&create_test_diff(base, tip)));
        assert!(pipeline.is_complete());
    }
}
