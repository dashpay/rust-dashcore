//! MnListDiff pipeline implementation.
//!
//! Handles pipelined download of MnListDiff messages for quorum validation.
//! Uses DownloadCoordinator for request tracking with timeout and retry logic.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::sync::download_coordinator::{DownloadConfig, DownloadCoordinator};
use dashcore::network::message_sml::MnListDiff;
use dashcore::BlockHash;

/// Maximum concurrent MnListDiff requests.
const MAX_CONCURRENT_MNLISTDIFF: usize = 20;

/// Timeout for MnListDiff requests.
const MNLISTDIFF_TIMEOUT: Duration = Duration::from_secs(15);

/// Attempts a target gets before it is given up. One is spent by a timeout,
/// by a block the header chain cannot place, or by a response the engine
/// refuses from a peer that had not sent a refused one for it.
pub(super) const MAX_MNLISTDIFF_ATTEMPTS: u32 = 3;

/// How long after its first send a target is given up, whatever attempts it
/// has left: as long as its attempts take when each one times out, and one
/// timeout more for the retries, which go out a tick after the timeout. A
/// send cut short by a peer disconnect spends no attempt, so without this,
/// peers dropping one after another would keep a target in flight forever.
const MNLISTDIFF_LIFETIME: Duration =
    MNLISTDIFF_TIMEOUT.saturating_mul(MAX_MNLISTDIFF_ATTEMPTS + 1);

/// What became of a target whose attempt failed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Attempt {
    /// Queued again.
    Retried,
    /// Out of attempts and dropped from the pipeline.
    GivenUp,
}

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
    /// Peers whose response for a target the engine refused. A later response
    /// from one of them is ignored.
    refusers: HashMap<BlockHash, Vec<SocketAddr>>,
    /// When each target was first sent, see [`MNLISTDIFF_LIFETIME`].
    first_sent: HashMap<BlockHash, Instant>,
    /// How long after its first send a target is given up.
    lifetime: Duration,
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
                    .with_timeout(MNLISTDIFF_TIMEOUT),
            ),
            base_hashes: HashMap::new(),
            refusers: HashMap::new(),
            first_sent: HashMap::new(),
            lifetime: MNLISTDIFF_LIFETIME,
        }
    }

    /// Clear all state.
    pub(super) fn clear(&mut self) {
        self.coordinator.clear();
        self.base_hashes.clear();
        self.refusers.clear();
        self.first_sent.clear();
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
            self.first_sent.entry(target_hash).or_insert_with(Instant::now);

            tracing::trace!(
                "Sent GetMnListDiff: base={}, target={} ({} active, {} pending)",
                base_hash,
                target_hash,
                self.coordinator.active_count(),
                self.coordinator.pending_count()
            );
        }

        Ok(())
    }

    /// Check if response matches an in-flight request, base included.
    pub(super) fn match_response(&self, diff: &MnListDiff) -> bool {
        self.coordinator.is_in_flight(&diff.block_hash)
            && self.base_hashes.get(&diff.block_hash) == Some(&diff.base_block_hash)
    }

    /// Whether `peer` already sent a response for `target` that the engine
    /// refused.
    pub(super) fn has_refused(&self, target: BlockHash, peer: SocketAddr) -> bool {
        self.refusers.get(&target).is_some_and(|peers| peers.contains(&peer))
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
        self.refusers.remove(&target_hash);
        self.first_sent.remove(&target_hash);

        tracing::debug!(
            "Received MnListDiff for {} ({} remaining)",
            target_hash,
            self.coordinator.remaining()
        );

        true
    }

    /// Spends an attempt of the in-flight `target`, whose response could not
    /// be used, and queues it again or gives it up. `refused_by` is the peer
    /// whose response the engine refused, `None` when the fault is ours.
    pub(super) fn retry_or_give_up(
        &mut self,
        target: BlockHash,
        refused_by: Option<SocketAddr>,
    ) -> Attempt {
        self.coordinator.release(&target);
        if let Some(peer) = refused_by {
            self.refusers.entry(target).or_default().push(peer);
        }
        self.spend_attempt(target)
    }

    fn spend_attempt(&mut self, target: BlockHash) -> Attempt {
        if self.coordinator.retry_count(&target) + 1 < MAX_MNLISTDIFF_ATTEMPTS {
            self.coordinator.enqueue_retry(target);
            return Attempt::Retried;
        }
        self.give_up(target);
        Attempt::GivenUp
    }

    /// Drops `target` from the pipeline, whether in flight or pending.
    fn give_up(&mut self, target: BlockHash) {
        self.coordinator.release(&target);
        self.coordinator.cancel_pending(&target);
        self.base_hashes.remove(&target);
        self.refusers.remove(&target);
        self.first_sent.remove(&target);
    }

    /// Forgets the attempts spent, the time used and the refusing peers, for a
    /// new set of peers.
    pub(super) fn forget_attempts(&mut self) {
        self.coordinator.clear_retry_counts();
        self.refusers.clear();
        self.first_sent.clear();
    }

    /// Move in-flight `getmnlistd` requests back to pending after a peer
    /// disconnect so the next `send_pending` reissues them. They keep the
    /// attempts and the lifetime they have left.
    ///
    /// `base_hashes` must survive, since `send_pending` drops a pending target
    /// hash that has no base hash to pair it with.
    pub(super) fn requeue_in_flight(&mut self) {
        self.coordinator.requeue_in_flight();
    }

    /// Spends an attempt of every timed-out request, queuing it again or
    /// giving it up, and gives up every target past its lifetime. Returns the
    /// `(base, target)` pairs given up.
    pub(super) fn handle_timeouts(&mut self) -> Vec<(BlockHash, BlockHash)> {
        let mut given_up = Vec::new();
        for target_hash in self.coordinator.check_timeouts() {
            let base_hash = self.base_hashes.get(&target_hash).copied();
            if self.spend_attempt(target_hash) == Attempt::GivenUp {
                given_up.extend(base_hash.map(|base_hash| (base_hash, target_hash)));
            }
        }
        let expired: Vec<BlockHash> = self
            .first_sent
            .iter()
            .filter(|(_, first_sent)| first_sent.elapsed() >= self.lifetime)
            .map(|(target_hash, _)| *target_hash)
            .collect();
        for target_hash in expired {
            let base_hash = self.base_hashes.get(&target_hash).copied();
            self.give_up(target_hash);
            given_up.extend(base_hash.map(|base_hash| (base_hash, target_hash)));
        }
        given_up
    }

    /// Check if pipeline has no pending work.
    pub(super) fn is_complete(&self) -> bool {
        self.coordinator.is_empty()
    }

    #[cfg(test)]
    pub(super) fn set_timeout(&mut self, timeout: Duration) {
        self.coordinator.set_timeout(timeout);
    }

    #[cfg(test)]
    pub(super) fn set_lifetime(&mut self, lifetime: Duration) {
        self.lifetime = lifetime;
    }

    /// Has every target sent been sent first `by` earlier.
    #[cfg(test)]
    pub(super) fn age_first_sends(&mut self, by: Duration) {
        for first_sent in self.first_sent.values_mut() {
            *first_sent = first_sent.checked_sub(by).expect("the clock reaches back that far");
        }
    }

    /// Get the number of in-flight requests.
    #[cfg(test)]
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
    use crate::network::NetworkRequest;
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_sml::GetMnListDiff;
    use tokio::sync::mpsc::unbounded_channel;

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
                DownloadConfig::default().with_timeout(Duration::from_millis(1)),
            ),
            ..MnListDiffPipeline::new()
        };

        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);

        pipeline.base_hashes.insert(target, base);
        pipeline.coordinator.mark_sent(&[target]);

        std::thread::sleep(Duration::from_millis(5));

        // Timeout re-queues the request, base_hashes preserved
        pipeline.handle_timeouts();
        assert_eq!(pipeline.coordinator.pending_count(), 1);
        assert!(pipeline.base_hashes.contains_key(&target));
    }

    /// A request no peer answers is given up after three attempts. Core sends
    /// nothing for a base outside its active chain, and retrying it forever
    /// would keep the pipeline, and every tip update queued behind it, busy.
    #[test]
    fn test_unanswered_request_is_given_up_after_three_attempts() {
        use std::time::Duration;

        let mut pipeline = MnListDiffPipeline::new();
        pipeline.set_timeout(Duration::from_millis(1));
        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);
        pipeline.queue_requests(vec![(base, target)]);
        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        for attempt in 1..=3 {
            pipeline.send_pending(&requests).expect("the request is queued");
            std::thread::sleep(Duration::from_millis(5));
            let given_up = pipeline.handle_timeouts();
            let last = attempt == 3;
            assert_eq!(
                given_up,
                if last {
                    vec![(base, target)]
                } else {
                    vec![]
                }
            );
            assert_eq!(pipeline.is_complete(), last, "attempt {attempt}");
        }
    }

    /// A target's lifetime outlasts its attempts when each one times out,
    /// with time to spare for retries that go out a tick late, so it only
    /// ever cuts short sends that a peer disconnect restarted.
    #[test]
    fn a_target_s_lifetime_outlasts_its_attempts() {
        let late_retries = Duration::from_secs(1);
        assert!(
            MNLISTDIFF_LIFETIME
                >= (MNLISTDIFF_TIMEOUT + late_retries).saturating_mul(MAX_MNLISTDIFF_ATTEMPTS)
        );
    }

    /// The time a target used up goes with the peers it was sent to: after a
    /// full disconnect, the new peers give it a whole lifetime again.
    #[test]
    fn a_target_gets_a_new_lifetime_from_the_peers_after_a_full_disconnect() {
        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);
        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);
        let sent_a_lifetime_ago = |full_disconnect: bool| {
            let mut pipeline = MnListDiffPipeline::new();
            pipeline.queue_requests(vec![(base, target)]);
            pipeline.send_pending(&requests).unwrap();
            pipeline.age_first_sends(MNLISTDIFF_LIFETIME);
            pipeline.requeue_in_flight();
            if full_disconnect {
                pipeline.forget_attempts();
            }
            pipeline.send_pending(&requests).unwrap();
            pipeline.handle_timeouts()
        };

        assert_eq!(sent_a_lifetime_ago(false), vec![(base, target)], "a peer drop keeps it");
        assert_eq!(sent_a_lifetime_ago(true), vec![], "the new peers get a new lifetime");
    }

    /// A refused response puts its target back in pending with its base, and
    /// the retry asks for it from that base. The attempt it spent still counts
    /// after a peer disconnect requeues the retry.
    #[test]
    fn test_refused_target_is_retried_from_its_base() {
        let mut pipeline = MnListDiffPipeline::new();
        let base = BlockHash::from_byte_array([0x01; 32]);
        let target = BlockHash::from_byte_array([0x02; 32]);
        let refusing: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);
        pipeline.queue_requests(vec![(base, target)]);
        pipeline.send_pending(&requests).unwrap();
        while rx.try_recv().is_ok() {}

        assert_eq!(pipeline.retry_or_give_up(target, Some(refusing)), Attempt::Retried);
        assert!(!pipeline.is_complete());
        assert!(pipeline.has_refused(target, refusing));

        pipeline.send_pending(&requests).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Ok(NetworkRequest::SendMessage(NetworkMessage::GetMnListD(request)))
                if request.base_block_hash == base && request.block_hash == target
        ));

        pipeline.requeue_in_flight();
        pipeline.send_pending(&requests).unwrap();
        assert_eq!(pipeline.retry_or_give_up(target, None), Attempt::Retried);
        pipeline.send_pending(&requests).unwrap();
        assert_eq!(pipeline.retry_or_give_up(target, None), Attempt::GivenUp);
        assert!(pipeline.is_complete());
        assert!(pipeline.base_hashes.is_empty());
    }

    /// A peer disconnect requeues every in-flight request, and each one must be
    /// reissued with the base hash it was originally paired with.
    #[test]
    fn test_requeue_in_flight_reissues_with_base_hashes() {
        let mut pipeline = MnListDiffPipeline::new();

        let base1 = BlockHash::from_byte_array([0x01; 32]);
        let target1 = BlockHash::from_byte_array([0x02; 32]);
        let base2 = BlockHash::from_byte_array([0x03; 32]);
        let target2 = BlockHash::from_byte_array([0x04; 32]);

        pipeline.queue_requests(vec![(base1, target1), (base2, target2)]);

        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);
        pipeline.send_pending(&requests).unwrap();
        assert_eq!(pipeline.active_count(), 2);
        while rx.try_recv().is_ok() {}

        pipeline.requeue_in_flight();
        assert_eq!(pipeline.active_count(), 0);
        assert_eq!(pipeline.coordinator.pending_count(), 2);

        pipeline.send_pending(&requests).unwrap();
        assert_eq!(pipeline.active_count(), 2);

        let mut reissued = Vec::new();
        while let Ok(request) = rx.try_recv() {
            match request {
                NetworkRequest::SendMessage(NetworkMessage::GetMnListD(GetMnListDiff {
                    base_block_hash,
                    block_hash,
                })) => reissued.push((base_block_hash, block_hash)),
                other => panic!("Expected GetMnListD, got {:?}", other),
            }
        }
        reissued.sort();
        let mut expected = vec![(base1, target1), (base2, target2)];
        expected.sort();
        assert_eq!(reissued, expected);
    }
}
