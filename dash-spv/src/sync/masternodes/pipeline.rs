//! MnListDiff pipeline implementation.

use std::collections::HashMap;
use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::SyncResult;
use crate::network::{NetworkManager, RequestKey, SendRequest};
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_sml::{GetMnListDiff, MnListDiff};
use dashcore::BlockHash;

/// How long a diff may stay wanted before it is given up. The broker retries a request
/// forever, so a diff no peer can answer would otherwise block every later tip update and
/// QRInfo.
pub(super) const MNLISTDIFF_DEADLINE: Duration = Duration::from_secs(60);

/// What a wanted diff is for, recorded when it is queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiffKind {
    /// Moves the newest list to the header tip.
    TipUpdate,
    /// Fetches the list at a quorum's work block, needed to validate that quorum.
    WorkBlockList,
}

#[derive(Debug)]
struct WantedDiff {
    base: BlockHash,
    kind: DiffKind,
    queued_at: Instant,
}

/// Pipeline for downloading MnListDiff messages for quorum validation.
#[derive(Debug, Default)]
pub(super) struct MnListDiffPipeline {
    /// Keyed by target, which is also the request's key at the broker.
    wanted: HashMap<BlockHash, WantedDiff>,
}

impl MnListDiffPipeline {
    /// Drops every wanted diff and releases it from the broker. Otherwise the broker keeps
    /// retrying it, and kicks peers as stalled when we ignore their answers.
    pub(super) async fn clear(&mut self, network: &Arc<dyn NetworkManager>) {
        for target in mem::take(&mut self.wanted).into_keys() {
            network.release_request(RequestKey::MnListDiff(target)).await;
        }
    }

    /// Queues `(base, target)` requests of one kind. A target already wanted from a different
    /// base is released from the broker. The broker keys requests by target only, so it would
    /// keep sending the old request, whose answers no longer match.
    pub(super) async fn queue_requests(
        &mut self,
        kind: DiffKind,
        requests: Vec<(BlockHash, BlockHash)>,
        network: &Arc<dyn NetworkManager>,
    ) {
        let queued_at = Instant::now();
        for (base, target) in requests {
            let replaced = self.wanted.insert(
                target,
                WantedDiff {
                    base,
                    kind,
                    queued_at,
                },
            );
            if replaced.is_some_and(|replaced| replaced.base != base) {
                network.release_request(RequestKey::MnListDiff(target)).await;
            }
        }

        if !self.wanted.is_empty() {
            tracing::info!("Queued {} MnListDiff requests", self.wanted.len());
        }
    }

    /// Declare every wanted MnListDiff; the broker de-duplicates, so re-declaring is safe.
    pub(super) async fn send_pending(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<()> {
        let requests: Vec<(BlockHash, BlockHash)> =
            self.wanted.iter().map(|(target, wanted)| (wanted.base, *target)).collect();

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

    /// Returns the kind of the wanted request that `diff` answers, if any. Core echoes the
    /// requested base, so a diff with a different base answers nothing.
    pub(super) fn match_response(&self, diff: &MnListDiff) -> Option<DiffKind> {
        self.wanted
            .get(&diff.block_hash)
            .filter(|wanted| wanted.base == diff.base_block_hash)
            .map(|wanted| wanted.kind)
    }

    /// Stop wanting `target` and release it from the broker. Returns its kind,
    /// or `None` when it was not wanted.
    pub(super) async fn release(
        &mut self,
        target: BlockHash,
        network: &Arc<dyn NetworkManager>,
    ) -> Option<DiffKind> {
        let wanted = self.wanted.remove(&target)?;
        network.release_request(RequestKey::MnListDiff(target)).await;
        tracing::debug!("Settled MnListDiff for {} ({} remaining)", target, self.wanted.len());
        Some(wanted.kind)
    }

    /// The targets wanted for longer than [`MNLISTDIFF_DEADLINE`] at `now`.
    pub(super) fn expired(&self, now: Instant) -> Vec<BlockHash> {
        self.wanted
            .iter()
            .filter(|(_, wanted)| {
                now.saturating_duration_since(wanted.queued_at) > MNLISTDIFF_DEADLINE
            })
            .map(|(target, _)| *target)
            .collect()
    }

    /// Check if pipeline has no pending work.
    pub(super) fn is_complete(&self) -> bool {
        self.wanted.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use dashcore::transaction::{OutPoint, Transaction};
    use dashcore::{ScriptBuf, TxIn, TxOut, Witness};
    use dashcore_hashes::Hash;

    use super::*;
    use crate::test_utils::MockNetworkManager;

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

    fn test_network() -> (Arc<dyn NetworkManager>, Arc<MockNetworkManager>) {
        let mock = Arc::new(MockNetworkManager::new());
        (mock.clone(), mock)
    }

    #[test]
    fn test_pipeline_new() {
        let pipeline = MnListDiffPipeline::default();
        assert!(pipeline.is_complete());
    }

    #[tokio::test]
    async fn test_queue_requests() {
        let mut pipeline = MnListDiffPipeline::default();
        let (network, mock) = test_network();

        let base1 = BlockHash::from_byte_array([0x01; 32]);
        let target1 = BlockHash::from_byte_array([0x02; 32]);
        let base2 = BlockHash::from_byte_array([0x03; 32]);
        let target2 = BlockHash::from_byte_array([0x04; 32]);

        pipeline
            .queue_requests(
                DiffKind::WorkBlockList,
                vec![(base1, target1), (base2, target2)],
                &network,
            )
            .await;

        assert!(!pipeline.is_complete());
        assert_eq!(pipeline.wanted.len(), 2);
        assert_eq!(pipeline.wanted[&target1].base, base1);
        assert_eq!(pipeline.wanted[&target2].base, base2);

        // Re-queued from the same base, a target stays at the broker. From a different base
        // it is released, so the new request goes out.
        pipeline.send_pending(&network).await.unwrap();
        mock.clear_sent().await;
        pipeline.queue_requests(DiffKind::WorkBlockList, vec![(base1, target1)], &network).await;
        pipeline.queue_requests(DiffKind::WorkBlockList, vec![(base1, target2)], &network).await;
        assert_eq!(mock.released_keys().await, vec![RequestKey::MnListDiff(target2)]);
        pipeline.send_pending(&network).await.unwrap();
        let sent: Vec<_> = mock
            .sent_messages()
            .await
            .into_iter()
            .filter_map(|msg| match msg {
                NetworkMessage::GetMnListD(get) => Some((get.base_block_hash, get.block_hash)),
                _ => None,
            })
            .collect();
        assert_eq!(sent, vec![(base1, target2)]);
    }

    #[tokio::test]
    async fn test_match_response() {
        let mut pipeline = MnListDiffPipeline::default();
        let (network, _mock) = test_network();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);
        let work_target = BlockHash::from_byte_array([0x03; 32]);

        pipeline.queue_requests(DiffKind::TipUpdate, vec![(base, target)], &network).await;
        pipeline.queue_requests(DiffKind::WorkBlockList, vec![(base, work_target)], &network).await;

        assert_eq!(
            pipeline.match_response(&create_test_diff(base, target)),
            Some(DiffKind::TipUpdate)
        );
        assert_eq!(
            pipeline.match_response(&create_test_diff(base, work_target)),
            Some(DiffKind::WorkBlockList)
        );

        // Unknown hash should not match
        let unknown_diff = create_test_diff(base, BlockHash::from_byte_array([0xFF; 32]));
        assert_eq!(pipeline.match_response(&unknown_diff), None);

        // A wanted target with a different base does not match either, since it would build
        // a different list.
        let other_base = create_test_diff(BlockHash::from_byte_array([0xEE; 32]), target);
        assert_eq!(pipeline.match_response(&other_base), None);
    }

    #[tokio::test]
    async fn test_release() {
        let mut pipeline = MnListDiffPipeline::default();
        let (network, mock) = test_network();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(DiffKind::TipUpdate, vec![(base, target)], &network).await;
        pipeline.send_pending(&network).await.unwrap();

        assert_eq!(pipeline.release(target, &network).await, Some(DiffKind::TipUpdate));
        assert!(pipeline.is_complete());
        assert_eq!(mock.released_keys().await, vec![RequestKey::MnListDiff(target)]);

        // Releasing it again, or one never wanted, releases nothing.
        assert_eq!(pipeline.release(target, &network).await, None);
        assert_eq!(pipeline.release(base, &network).await, None);
        assert_eq!(mock.released_keys().await.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let mut pipeline = MnListDiffPipeline::default();
        let (network, mock) = test_network();

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.queue_requests(DiffKind::WorkBlockList, vec![(base, target)], &network).await;
        pipeline.send_pending(&network).await.unwrap();
        pipeline.clear(&network).await;

        assert!(pipeline.is_complete());
        assert_eq!(
            mock.released_keys().await,
            vec![RequestKey::MnListDiff(target)],
            "a dropped request must be released, or the broker retries it forever"
        );
    }
}
