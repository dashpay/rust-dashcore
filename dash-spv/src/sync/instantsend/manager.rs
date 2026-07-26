//! InstantSend manager.
//!
//! Handles InstantSendLock messages (islock) from the network. Validates locks
//! when masternode data is available, queues them when not.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::Txid;
use tokio::sync::RwLock;

use crate::error::SyncResult;
use crate::sync::{InstantSendProgress, SyncEvent, SyncState};

/// Maximum number of pending InstantLocks awaiting validation.
const MAX_PENDING_INSTANTLOCKS: usize = 500;

/// Maximum number of InstantLocks to cache.
const MAX_CACHE_SIZE: usize = 5000;

/// TTL for cached InstantLocks (1 hour).
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// How long a pending InstantLock is retained while awaiting the quorum data
/// needed to verify it. Locks that stay unverifiable for longer than this are
/// dropped. Expiry is time-based (not attempt-based) because re-validation can
/// now be driven from `tick` as the engine advances, so an attempt counter
/// would overrun long before an hour elapsed during a fresh sync.
const PENDING_TTL: Duration = Duration::from_secs(3600);

/// Entry in the InstantLock cache.
#[derive(Debug, Clone)]
pub struct InstantLockEntry {
    /// The InstantLock data.
    pub instant_lock: InstantLock,
    /// When the InstantLock was received.
    pub received_at: SystemTime,
    /// Whether the BLS signature was validated.
    pub validated: bool,
}

/// Pending InstantLock awaiting the quorum data required to verify it.
#[derive(Debug, Clone)]
pub(super) struct PendingInstantLock {
    /// The InstantLock data.
    instant_lock: InstantLock,
    /// When the lock was first received, used to expire locks that never
    /// become verifiable. Uses a monotonic `Instant` so the elapsed-time TTL
    /// check is unaffected by wall-clock adjustments.
    first_seen: Instant,
}

/// InstantSend manager.
///
/// This manager:
/// - Subscribes to ISLock messages from the network
/// - Validates InstantLocks when masternode engine is available
/// - Queues InstantLocks for later validation when engine not ready
/// - Emits InstantLockReceived events
pub struct InstantSendManager {
    /// Current progress of the manager.
    pub(super) progress: InstantSendProgress,
    /// Shared Masternode list engine.
    engine: Arc<RwLock<MasternodeListEngine>>,
    /// InstantLocks indexed by txid.
    instantlocks: HashMap<Txid, InstantLockEntry>,
    /// Pending InstantLocks awaiting the quorum data required to verify them.
    pub(super) pending_instantlocks: Vec<PendingInstantLock>,
    /// Highest masternode-list height at which every pending InstantLock has
    /// already been (re)validated.
    ///
    /// `tick` uses this to re-run validation only once the engine has advanced
    /// past this height, so a lock received before quorum sync completed is
    /// re-checked as soon as new quorum data lands — instead of waiting for the
    /// next `MasternodeStateUpdated` event, which for a freshly broadcast
    /// transaction may not arrive until the block that mines it.
    pub(super) last_validated_engine_height: Option<u32>,
}

impl InstantSendManager {
    /// Create a new InstantSend manager.
    pub fn new(engine: Arc<RwLock<MasternodeListEngine>>) -> Self {
        Self {
            progress: InstantSendProgress::default(),
            engine,
            instantlocks: HashMap::new(),
            pending_instantlocks: Vec::new(),
            last_validated_engine_height: None,
        }
    }

    /// Process an incoming InstantLock message.
    pub(super) async fn process_instantlock(
        &mut self,
        instantlock: &InstantLock,
    ) -> SyncResult<Vec<SyncEvent>> {
        let txid = instantlock.txid;

        tracing::info!("Processing InstantLock for txid {}", txid);

        // Check for duplicates
        if self.instantlocks.contains_key(&txid) {
            tracing::debug!("Already have InstantLock for txid {}", txid);
            return Ok(vec![]);
        }

        // Structural validation
        if !self.validate_structure(instantlock) {
            tracing::warn!("Invalid InstantLock structure for txid {}", txid);
            self.progress.add_invalid(1);
            return Ok(vec![]);
        }

        // Try to validate with masternode engine
        let validated = self.validate_signature(instantlock).await;

        if validated {
            self.progress.add_valid(1);
        } else {
            self.queue_pending(PendingInstantLock {
                instant_lock: instantlock.clone(),
                first_seen: Instant::now(),
            });
            self.progress.update_pending(self.pending_instantlocks.len());
        }

        // Store in cache
        let entry = InstantLockEntry {
            instant_lock: instantlock.clone(),
            received_at: SystemTime::now(),
            validated,
        };
        self.store_instantlock(txid, entry);

        Ok(vec![SyncEvent::InstantLockReceived {
            instant_lock: instantlock.clone(),
            validated,
        }])
    }

    /// Validate the structural integrity of an InstantLock.
    fn validate_structure(&self, instantlock: &InstantLock) -> bool {
        // Must have at least one input
        if instantlock.inputs.is_empty() {
            return false;
        }

        // Txid must not be null
        if instantlock.txid == Txid::all_zeros() {
            return false;
        }

        // Signature must not be zeroed
        if instantlock.signature.is_zeroed() {
            return false;
        }

        true
    }

    /// Validate the InstantLock BLS signature using the masternode engine.
    async fn validate_signature(&self, instantlock: &InstantLock) -> bool {
        let engine = self.engine.read().await;

        match engine.verify_is_lock(instantlock) {
            Ok(()) => {
                tracing::info!(
                    "InstantLock signature verified for txid {} (cyclehash={})",
                    instantlock.txid,
                    instantlock.cyclehash
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    "InstantLock signature verification failed for txid {} (cyclehash={}, inputs={}): {}",
                    instantlock.txid,
                    instantlock.cyclehash,
                    instantlock.inputs.len(),
                    e
                );
                false
            }
        }
    }

    /// Queue an InstantLock for later validation.
    fn queue_pending(&mut self, pending: PendingInstantLock) {
        // Remove oldest if at capacity
        if self.pending_instantlocks.len() >= MAX_PENDING_INSTANTLOCKS {
            let dropped = self.pending_instantlocks.remove(0);
            tracing::warn!(
                "Pending InstantLocks queue at capacity ({}), dropping oldest for txid {}",
                MAX_PENDING_INSTANTLOCKS,
                dropped.instant_lock.txid
            );
            self.progress.add_invalid(1);
        }
        self.pending_instantlocks.push(pending);
    }

    /// Store an InstantLock in the cache.
    fn store_instantlock(&mut self, txid: Txid, entry: InstantLockEntry) {
        self.instantlocks.insert(txid, entry);

        // Enforce cache limit by removing oldest
        if self.instantlocks.len() > MAX_CACHE_SIZE {
            let oldest =
                self.instantlocks.iter().min_by_key(|(_, e)| e.received_at).map(|(k, _)| *k);
            if let Some(key) = oldest {
                self.instantlocks.remove(&key);
            }
        }
    }

    /// Latest masternode-list height known to the shared engine, if any.
    pub(super) async fn engine_height(&self) -> Option<u32> {
        self.engine.read().await.masternode_lists.keys().next_back().copied()
    }

    /// Re-validate every pending InstantLock against the current engine state.
    ///
    /// Called both when a `MasternodeStateUpdated` event arrives and from `tick`
    /// once the engine has advanced. Locks that verify are emitted as validated
    /// `InstantLockReceived` events; locks that still can't be verified are
    /// re-queued until they either become verifiable or exceed [`PENDING_TTL`].
    pub(super) async fn validate_pending(&mut self) -> SyncResult<Vec<SyncEvent>> {
        // Snapshot the height we are validating against before doing the work so
        // `tick` knows not to re-run until the engine advances past it.
        let engine_height = self.engine_height().await;

        let pending = std::mem::take(&mut self.pending_instantlocks);
        let mut events = Vec::new();

        for pending_lock in pending {
            let txid = pending_lock.instant_lock.txid;

            // Drop locks that have been awaiting quorum data for too long.
            let expired = pending_lock.first_seen.elapsed() > PENDING_TTL;
            if expired {
                tracing::warn!(
                    "Dropping InstantLock for txid {} after awaiting quorum data for over {}s",
                    txid,
                    PENDING_TTL.as_secs()
                );
                self.progress.add_invalid(1);
                continue;
            }

            let validated = self.validate_signature(&pending_lock.instant_lock).await;

            if validated {
                self.progress.add_valid(1);
                // Update the cached entry
                if let Some(entry) = self.instantlocks.get_mut(&txid) {
                    entry.validated = true;
                }
                events.push(SyncEvent::InstantLockReceived {
                    instant_lock: pending_lock.instant_lock.clone(),
                    validated: true,
                });
            } else {
                // Still can't validate, re-queue
                self.queue_pending(pending_lock);
            }
        }

        self.last_validated_engine_height = engine_height;
        self.progress.update_pending(self.pending_instantlocks.len());
        Ok(events)
    }

    /// Prune old entries from the cache.
    pub(super) fn prune_old_entries(&mut self) {
        let now = SystemTime::now();
        self.instantlocks.retain(|_, entry| {
            now.duration_since(entry.received_at).map(|d| d < CACHE_TTL).unwrap_or(true)
        });
    }

    /// Drop cached InstantLock entries that were never BLS-validated, and clear
    /// the queued locks that fed them.
    ///
    /// Called on disconnect. The `instantlocks` cache is what
    /// [`process_instantlock`](Self::process_instantlock) dedupes against, so if
    /// an unvalidated entry survived a disconnect the same lock re-announced
    /// after reconnect would be treated as a duplicate and never re-queued or
    /// re-validated. Validated entries are kept — their locks are already final.
    pub(super) fn clear_unvalidated_on_disconnect(&mut self) {
        self.pending_instantlocks.clear();
        self.instantlocks.retain(|_, entry| entry.validated);
        self.progress.update_pending(0);
    }

    /// Drop pending locks that have outlived [`PENDING_TTL`] without running BLS
    /// verification.
    ///
    /// This is the cheap, advancement-independent half of expiry: `tick` calls
    /// it on every tick so a lock that never becomes verifiable is dropped after
    /// an hour even when the masternode engine height is static. Full
    /// re-validation (which does run BLS) stays in
    /// [`validate_pending`](Self::validate_pending) and only runs when the engine
    /// advances. Returns the number of locks expired.
    pub(super) fn expire_pending(&mut self) -> usize {
        let before = self.pending_instantlocks.len();
        self.pending_instantlocks.retain(|pending| {
            let expired = pending.first_seen.elapsed() > PENDING_TTL;
            if expired {
                tracing::warn!(
                    "Dropping InstantLock for txid {} after awaiting quorum data for over {}s",
                    pending.instant_lock.txid,
                    PENDING_TTL.as_secs()
                );
            }
            !expired
        });
        let expired = before - self.pending_instantlocks.len();
        if expired > 0 {
            self.progress.add_invalid(expired as u32);
            self.progress.update_pending(self.pending_instantlocks.len());
        }
        expired
    }

    /// Transition to [`SyncState::Synced`] once no pending validations remain.
    ///
    /// Shared by the event-driven (`handle_sync_event`) and tick-driven
    /// revalidation paths so both resolve the manager's state the same way when
    /// the last pending lock is validated or expired. No-op unless the manager
    /// is currently `Syncing` or `WaitForEvents`.
    pub(super) fn transition_synced_if_idle(&mut self) {
        if self.pending_instantlocks.is_empty()
            && matches!(self.progress.state(), SyncState::Syncing | SyncState::WaitForEvents)
        {
            self.progress.set_state(SyncState::Synced);
            tracing::info!("InstantSend manager synced (no pending validations)");
        }
    }

    /// Get an InstantLock by transaction ID.
    pub fn get_instantlock(&self, txid: &Txid) -> Option<&InstantLockEntry> {
        self.instantlocks.get(txid)
    }

    /// Check if a transaction has a validated InstantLock.
    pub fn is_transaction_locked(&self, txid: &Txid) -> bool {
        self.instantlocks.get(txid).map(|e| e.validated).unwrap_or(false)
    }

    /// Get the number of pending InstantLocks awaiting validation.
    pub fn pending_count(&self) -> usize {
        self.pending_instantlocks.len()
    }

    /// Get the number of cached InstantLocks.
    pub fn cached_count(&self) -> usize {
        self.instantlocks.len()
    }
}

impl std::fmt::Debug for InstantSendManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstantSendManager")
            .field("progress", &self.progress)
            .field("cached", &self.instantlocks.len())
            .field("pending", &self.pending_instantlocks.len())
            .finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{MessageType, RequestSender};
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress, SyncState};
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hash_types::CycleHash;
    use dashcore::hashes::Hash;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::{BlockHash, OutPoint};
    use tokio::sync::mpsc::unbounded_channel;

    /// Insert an empty masternode list at `height` so the shared engine reports a
    /// new tip height. Empty lists carry no rotated quorums, so InstantLock
    /// verification still fails — which is exactly what we want when exercising
    /// the "engine advanced but the needed quorum is still absent" path.
    async fn advance_engine_height(manager: &InstantSendManager, height: u32) {
        let mut engine = manager.engine.write().await;
        engine.masternode_lists.insert(
            height,
            MasternodeList::empty(BlockHash::from_byte_array([height as u8; 32]), height),
        );
    }

    fn no_op_requests() -> RequestSender {
        let (tx, _rx) = unbounded_channel();
        RequestSender::new(tx)
    }

    fn expired_pending(txid: Txid) -> PendingInstantLock {
        PendingInstantLock {
            instant_lock: create_test_instantlock(txid),
            first_seen: Instant::now() - Duration::from_secs(PENDING_TTL.as_secs() + 60),
        }
    }

    fn fresh_pending(txid: Txid) -> PendingInstantLock {
        PendingInstantLock {
            instant_lock: create_test_instantlock(txid),
            first_seen: Instant::now(),
        }
    }

    fn create_test_instantlock(txid: Txid) -> InstantLock {
        InstantLock {
            version: 1,
            inputs: vec![OutPoint::default()],
            txid,
            cyclehash: CycleHash::all_zeros(),
            signature: BLSSignature::from([1u8; 96]), // Non-zero signature
        }
    }

    fn create_test_manager() -> InstantSendManager {
        let engine = Arc::new(RwLock::new(MasternodeListEngine::default_for_network(
            dashcore::Network::Testnet,
        )));
        InstantSendManager::new(engine)
    }

    #[tokio::test]
    async fn test_instantsend_manager_new() {
        let manager = create_test_manager();
        assert_eq!(manager.identifier(), ManagerIdentifier::InstantSend);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::ISLock, MessageType::Inv]);
    }

    /// Buffered `MasternodeStateUpdated` events delivered during
    /// `WaitingForConnections` must not run validation or transition state.
    /// `pending_instantlocks` is cleared on disconnect and
    /// `MasternodesManager` re-emits the event after reconnect.
    #[tokio::test]
    async fn test_handle_sync_event_drops_masternode_state_updated_in_waiting_for_connections() {
        use crate::network::RequestSender;
        use crate::sync::SyncEvent;
        use tokio::sync::mpsc::unbounded_channel;

        let mut manager = create_test_manager();
        manager.set_state(SyncState::WaitingForConnections);

        let event = SyncEvent::MasternodeStateUpdated {
            height: 100,
            qr_info_result: None,
        };
        let (tx, _rx) = unbounded_channel();
        let events = manager.handle_sync_event(&event, &RequestSender::new(tx)).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
    }

    #[tokio::test]
    async fn test_instantsend_duplicate_handling() {
        let mut manager = create_test_manager();

        let txid = Txid::from_byte_array([1u8; 32]);
        let islock1 = create_test_instantlock(txid);
        let islock2 = create_test_instantlock(txid);

        // First should process
        let events1 = manager.process_instantlock(&islock1).await.unwrap();
        assert_eq!(events1.len(), 1);

        // Second should be ignored as duplicate
        let events2 = manager.process_instantlock(&islock2).await.unwrap();
        assert_eq!(events2.len(), 0);
    }

    #[tokio::test]
    async fn test_instantsend_pending_queue() {
        let mut manager = create_test_manager();

        // Without masternode engine, InstantLocks should be queued
        let txid = Txid::from_byte_array([1u8; 32]);
        let islock = create_test_instantlock(txid);
        let _ = manager.process_instantlock(&islock).await.unwrap();

        assert_eq!(manager.pending_count(), 1);
    }

    #[tokio::test]
    async fn test_instantsend_structural_validation() {
        let manager = create_test_manager();

        // Valid structure
        let txid = Txid::from_byte_array([1u8; 32]);
        let valid = create_test_instantlock(txid);
        assert!(manager.validate_structure(&valid));

        // Empty inputs
        let mut invalid = create_test_instantlock(txid);
        invalid.inputs = vec![];
        assert!(!manager.validate_structure(&invalid));

        // Null txid
        let invalid_txid = InstantLock {
            version: 1,
            inputs: vec![OutPoint::default()],
            txid: Txid::all_zeros(),
            cyclehash: CycleHash::all_zeros(),
            signature: BLSSignature::from([1u8; 96]),
        };
        assert!(!manager.validate_structure(&invalid_txid));

        // Zeroed signature
        let invalid_sig = InstantLock {
            version: 1,
            inputs: vec![OutPoint::default()],
            txid: Txid::from_byte_array([1u8; 32]),
            cyclehash: CycleHash::all_zeros(),
            signature: BLSSignature::from([0u8; 96]),
        };
        assert!(!manager.validate_structure(&invalid_sig));
    }

    #[tokio::test]
    async fn test_instantsend_progress() {
        let mut manager = create_test_manager();
        manager.set_state(SyncState::Syncing);
        manager.progress.update_pending(2);
        manager.progress.add_valid(8);
        manager.progress.add_invalid(2);

        let progress = manager.progress();
        if let SyncManagerProgress::InstantSend(progress) = progress {
            assert_eq!(progress.state(), SyncState::Syncing);
            assert_eq!(progress.valid(), 8);
            assert_eq!(progress.invalid(), 2);
            assert_eq!(progress.pending(), 2);
            assert!(progress.last_activity().elapsed().as_secs() < 1);
        } else {
            panic!("Expected SyncManagerProgress::InstantSend");
        }
    }

    #[tokio::test]
    async fn test_instantsend_accessors() {
        let mut manager = create_test_manager();

        let txid = Txid::from_byte_array([1u8; 32]);
        let islock = create_test_instantlock(txid);
        let _ = manager.process_instantlock(&islock).await.unwrap();

        // Should be retrievable by txid
        assert!(manager.get_instantlock(&txid).is_some());

        // Unknown txid
        let unknown = Txid::from_byte_array([2u8; 32]);
        assert!(manager.get_instantlock(&unknown).is_none());
    }

    #[tokio::test]
    async fn test_instantsend_cache_limit() {
        let mut manager = create_test_manager();

        // Add more than MAX_CACHE_SIZE instantlocks
        for i in 0..MAX_CACHE_SIZE + 10 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            let txid = Txid::from_byte_array(bytes);
            let islock = create_test_instantlock(txid);
            let _ = manager.process_instantlock(&islock).await.unwrap();
        }

        // Should be capped at MAX_CACHE_SIZE
        assert!(manager.cached_count() <= MAX_CACHE_SIZE);
    }

    /// A queued InstantLock must be re-validated by `tick` as soon as the
    /// masternode engine advances — not only when a `MasternodeStateUpdated`
    /// event happens to arrive. This is the regression behind the on-device
    /// incident: an islock received right after a fresh SPV start stayed pending
    /// until the transaction was mined because nothing re-checked it.
    #[tokio::test]
    async fn test_tick_revalidates_pending_when_engine_advances() {
        let mut manager = create_test_manager();
        let requests = no_op_requests();

        // A lock arrives before quorum sync: the empty engine can't verify it,
        // so it is queued.
        let txid = Txid::from_byte_array([3u8; 32]);
        let _ = manager.process_instantlock(&create_test_instantlock(txid)).await.unwrap();
        assert_eq!(manager.pending_count(), 1);
        assert_eq!(manager.last_validated_engine_height, None);

        // Engine has not advanced yet (still empty): tick must not re-validate,
        // and the pending-validation marker stays untouched.
        let events = manager.tick(&requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.pending_count(), 1);
        assert_eq!(manager.last_validated_engine_height, None);

        // The engine gains a new masternode-list height: tick now re-validates.
        // The needed rotated quorum is still absent, so the lock is re-queued,
        // but the marker records the height we validated against.
        advance_engine_height(&manager, 200).await;
        let events = manager.tick(&requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.pending_count(), 1);
        assert_eq!(manager.last_validated_engine_height, Some(200));

        // No further advance: tick must not spend work re-validating again.
        let events = manager.tick(&requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.last_validated_engine_height, Some(200));

        // Another advance re-arms re-validation.
        advance_engine_height(&manager, 201).await;
        let _ = manager.tick(&requests).await.unwrap();
        assert_eq!(manager.last_validated_engine_height, Some(201));
    }

    /// Without an engine advance, `tick` must not run (potentially expensive) BLS
    /// re-validation. A *fresh* pending lock (well within its TTL) must survive
    /// the tick untouched: the advancement-independent expiry pass leaves it in
    /// place and validation never runs.
    #[tokio::test]
    async fn test_tick_skips_revalidation_without_engine_advance() {
        let mut manager = create_test_manager();
        let requests = no_op_requests();

        // Engine at height 100, but the marker is deliberately set ABOVE it so
        // the advancement gate (current > last) stays closed. If `validate_pending`
        // ran it would overwrite the marker down to 100 — so an unchanged marker
        // proves it did not run.
        advance_engine_height(&manager, 100).await;
        manager.last_validated_engine_height = Some(150);

        manager.pending_instantlocks.push(fresh_pending(Txid::from_byte_array([7u8; 32])));

        let events = manager.tick(&requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.pending_count(), 1);
        assert_eq!(manager.last_validated_engine_height, Some(150));
        if let SyncManagerProgress::InstantSend(progress) = manager.progress() {
            assert_eq!(progress.invalid(), 0);
        } else {
            panic!("Expected SyncManagerProgress::InstantSend");
        }
    }

    /// TTL expiry must be independent of engine advancement (finding: expire
    /// pending locks even when the engine height is static). A lock past its TTL
    /// is dropped by `tick` without the engine ever advancing and without running
    /// BLS re-validation.
    #[tokio::test]
    async fn test_tick_expires_pending_without_engine_advance() {
        let mut manager = create_test_manager();
        let requests = no_op_requests();

        // Close the advancement gate: engine at 100, already validated at 100.
        // `validate_pending` therefore cannot run this tick.
        advance_engine_height(&manager, 100).await;
        manager.last_validated_engine_height = Some(100);

        manager.pending_instantlocks.push(expired_pending(Txid::from_byte_array([8u8; 32])));

        let events = manager.tick(&requests).await.unwrap();

        assert!(events.is_empty());
        // Expired purely by the advancement-independent pass.
        assert_eq!(manager.pending_count(), 0);
        // Marker untouched: only cheap expiry ran, not validation.
        assert_eq!(manager.last_validated_engine_height, Some(100));
        if let SyncManagerProgress::InstantSend(progress) = manager.progress() {
            assert_eq!(progress.invalid(), 1);
        } else {
            panic!("Expected SyncManagerProgress::InstantSend");
        }
    }

    /// When `tick` resolves the final pending lock — here by expiring it under a
    /// static engine height — the manager must leave `Syncing`, exactly as it
    /// would had the resolution come from a `MasternodeStateUpdated` event via
    /// `handle_sync_event`. Otherwise it stays stuck in `Syncing` indefinitely.
    #[tokio::test]
    async fn test_tick_transitions_synced_when_last_pending_resolved() {
        let mut manager = create_test_manager();
        let requests = no_op_requests();

        manager.set_state(SyncState::Syncing);
        manager.pending_instantlocks.push(expired_pending(Txid::from_byte_array([4u8; 32])));

        let events = manager.tick(&requests).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.pending_count(), 0);
        assert_eq!(manager.state(), SyncState::Synced);
    }

    /// A lock re-announced with the same txid after a disconnect must be
    /// processed fresh, not silently dropped as a duplicate. `on_disconnect` has
    /// to evict the unvalidated cache entry that `process_instantlock` dedupes
    /// against, otherwise the re-announced lock is never re-queued/re-validated.
    #[tokio::test]
    async fn test_reannounce_after_disconnect_is_not_duplicate() {
        let mut manager = create_test_manager();

        let txid = Txid::from_byte_array([5u8; 32]);

        // First announcement: the empty engine can't verify it, so it is queued
        // and cached as an unvalidated entry.
        let events = manager.process_instantlock(&create_test_instantlock(txid)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(manager.pending_count(), 1);
        assert!(manager.get_instantlock(&txid).is_some());

        // Disconnect must clear the queue AND the unvalidated cache entry.
        manager.on_disconnect();
        assert_eq!(manager.pending_count(), 0);
        assert!(manager.get_instantlock(&txid).is_none());

        // Re-announcement of the same txid is processed fresh, not deduped away.
        let events = manager.process_instantlock(&create_test_instantlock(txid)).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(manager.pending_count(), 1);
    }

    /// A pending lock past its [`PENDING_TTL`] is dropped and counted invalid,
    /// even when the engine has also advanced. Expiry is handled by the cheap
    /// advancement-independent pass, which drains the queue before the
    /// validation gate — so `validate_pending` never runs and the marker is left
    /// untouched (it is meaningless with no pending locks anyway).
    #[tokio::test]
    async fn test_pending_expires_after_ttl_on_revalidation() {
        let mut manager = create_test_manager();
        let requests = no_op_requests();

        manager.pending_instantlocks.push(expired_pending(Txid::from_byte_array([9u8; 32])));

        // The lock is past its TTL and still unverifiable, so it is dropped and
        // counted invalid regardless of the engine advancing to height 300.
        advance_engine_height(&manager, 300).await;
        let events = manager.tick(&requests).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.pending_count(), 0);
        // Expiry drained the queue before the validation gate, so the marker was
        // never set by a validation pass.
        assert_eq!(manager.last_validated_engine_height, None);
        if let SyncManagerProgress::InstantSend(progress) = manager.progress() {
            assert_eq!(progress.invalid(), 1);
        } else {
            panic!("Expected SyncManagerProgress::InstantSend");
        }
    }

    /// `on_disconnect` clears queued locks and resets the re-validation marker so
    /// a lock re-received after reconnect is validated fresh.
    #[tokio::test]
    async fn test_on_disconnect_resets_validation_marker() {
        let mut manager = create_test_manager();

        advance_engine_height(&manager, 100).await;
        manager.last_validated_engine_height = Some(100);
        manager.pending_instantlocks.push(expired_pending(Txid::from_byte_array([1u8; 32])));

        manager.on_disconnect();

        assert_eq!(manager.pending_count(), 0);
        assert_eq!(manager.last_validated_engine_height, None);
    }
}
