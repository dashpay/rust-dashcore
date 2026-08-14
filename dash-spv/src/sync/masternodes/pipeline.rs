//! MnListDiff pipeline implementation.
//!
//! Declares wanted MnListDiff requests (keyed by target block hash) to the
//! network manager (the broker). The broker owns pacing, de-duplication,
//! timeouts and retries — this pipeline keeps no in-flight queue of its own and
//! simply tracks which `(base, target)` diffs are still wanted.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::SyncResult;
use crate::network::NetworkManager;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_sml::{GetMnListDiff, MnListDiff};
use dashcore::BlockHash;

/// Pipeline for downloading MnListDiff messages for quorum validation.
///
/// Holds no request queue of its own: the `base_hashes` map (target -> base) is
/// the "wanted" set. A diff is wanted for exactly as long as it sits in this map;
/// `receive` removes it. The broker de-duplicates, paces, times out and retries.
#[derive(Debug, Default)]
pub(super) struct MnListDiffPipeline {
    /// Wanted requests: target_hash -> base_hash. Doubles as the "is this diff
    /// wanted?" set for validating arrivals.
    base_hashes: HashMap<BlockHash, BlockHash>,
}

impl MnListDiffPipeline {
    /// Clear all state.
    pub(super) fn clear(&mut self) {
        self.base_hashes.clear();
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

    /// Declare every wanted MnListDiff to the network manager.
    ///
    /// Fired freely (on queue, on tick): the broker de-duplicates, so re-declaring
    /// a diff already queued or on the wire is a no-op, and it owns pacing and
    /// retry. Re-declaring each tick is the safety net if a peer drops.
    pub(super) async fn send_pending(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<()> {
        if self.base_hashes.is_empty() {
            return Ok(());
        }

        // Collect first so no borrow of `self` is held across the awaits.
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

    /// Check if response matches a still-wanted request.
    pub(super) fn match_response(&self, diff: &MnListDiff) -> bool {
        self.base_hashes.contains_key(&diff.block_hash)
    }

    /// Receive a MnListDiff response, removing it from the wanted set.
    ///
    /// Returns true if the diff was expected, false if unexpected.
    pub(super) fn receive(&mut self, diff: &MnListDiff) -> bool {
        let target_hash = diff.block_hash;

        if self.base_hashes.remove(&target_hash).is_none() {
            return false;
        }

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

        // A queued (wanted) diff matches.
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

        // First receive removes it from the wanted set.
        assert!(pipeline.receive(&diff));
        // Duplicate receive: no longer wanted.
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
}
