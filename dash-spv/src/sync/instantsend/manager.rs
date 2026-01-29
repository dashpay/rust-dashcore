//! InstantSend manager.
//!
//! Handles InstantSendLock messages (islock) from the network. Validates locks
//! when masternode data is available, queues them when not.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::Txid;
use tokio::sync::RwLock;

use crate::error::SyncResult;
use crate::sync::{InstantSendProgress, SyncEvent};

/// Maximum number of pending InstantLocks awaiting validation.
const MAX_PENDING_INSTANTLOCKS: usize = 500;

/// Maximum number of InstantLocks to cache.
const MAX_CACHE_SIZE: usize = 5000;

/// TTL for cached InstantLocks (1 hour).
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Maximum retry attempts before dropping a pending InstantLock (~1 hour at 2.5min blocks).
const MAX_RETRIES: u32 = 24;

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

/// Pending InstantLock awaiting validation with retry tracking.
#[derive(Debug, Clone)]
struct PendingInstantLock {
    /// The InstantLock data.
    instant_lock: InstantLock,
    /// Number of validation retry attempts.
    retry_count: u32,
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
    /// Pending InstantLocks awaiting validation with retry tracking.
    pending_instantlocks: Vec<PendingInstantLock>,
}

impl InstantSendManager {
    /// Create a new InstantSend manager.
    pub fn new(engine: Arc<RwLock<MasternodeListEngine>>) -> Self {
        Self {
            progress: InstantSendProgress::default(),
            engine,
            instantlocks: HashMap::new(),
            pending_instantlocks: Vec::new(),
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
            return Ok(vec![]);
        }

        // Try to validate with masternode engine
        let validated = self.validate_signature(instantlock).await;

        if validated {
            self.progress.add_valid(1);
        } else {
            self.queue_pending(PendingInstantLock {
                instant_lock: instantlock.clone(),
                retry_count: 0,
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
            txid,
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
                tracing::info!("InstantLock signature verified for txid {}", instantlock.txid);
                true
            }
            Err(e) => {
                tracing::warn!(
                    "InstantLock signature verification failed for txid {}: {}",
                    instantlock.txid,
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

    /// Validate pending InstantLocks after masternode engine becomes available.
    pub(super) async fn validate_pending(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let pending = std::mem::take(&mut self.pending_instantlocks);
        let mut events = Vec::new();

        for mut pending_lock in pending {
            pending_lock.retry_count += 1;
            let txid = pending_lock.instant_lock.txid;

            // Check if max retries exceeded
            if pending_lock.retry_count > MAX_RETRIES {
                tracing::warn!(
                    "Dropping InstantLock for txid {} after {} retries",
                    txid,
                    pending_lock.retry_count
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
                    txid,
                    validated: true,
                });
            } else {
                // Still can't validate, re-queue
                self.queue_pending(pending_lock);
            }
        }

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
    use crate::network::MessageType;
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress, SyncState};
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hash_types::CycleHash;
    use dashcore::hashes::Hash;
    use dashcore::OutPoint;

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
        assert_eq!(manager.state(), SyncState::Initializing);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::ISLock, MessageType::Inv]);
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
}
