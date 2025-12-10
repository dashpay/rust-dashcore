//! ChainLock manager for parallel sync.
//!
//! Handles ChainLock messages (clsig) from the network. Validates ChainLocks
//! when masternode data is available, queues them when not.

use std::sync::Arc;
use std::time::SystemTime;

use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hash_types::ChainLockHash;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::BlockHash;
use indexmap::IndexMap;
use std::collections::HashSet;
use tokio::sync::RwLock;

use crate::error::SyncResult;
use crate::storage::BlockHeaderStorage;
use crate::sync::{ChainLockProgress, SyncEvent};

/// Maximum number of pending ChainLocks awaiting validation.
const MAX_PENDING_CHAINLOCKS: usize = 100;

/// Maximum number of ChainLocks to cache.
const MAX_CACHE_SIZE: usize = 1000;

/// Entry in the ChainLock cache.
#[derive(Debug, Clone)]
pub struct ChainLockEntry {
    /// The ChainLock data.
    pub chain_lock: ChainLock,
    /// When the ChainLock was received.
    pub received_at: SystemTime,
    /// Whether the BLS signature was validated.
    pub validated: bool,
}

/// ChainLock manager for the parallel sync coordinator.
///
/// This manager:
/// - Subscribes to CLSig messages from the network
/// - Validates ChainLocks when masternode engine is available
/// - Queues ChainLocks for later validation when engine not ready
/// - Emits ChainLockReceived events
pub struct ChainLockManager<H: BlockHeaderStorage> {
    /// Current progress of the manager.
    pub(super) progress: ChainLockProgress,
    /// Block header storage for hash verification.
    header_storage: Arc<RwLock<H>>,
    /// Masternode engine for BLS signature validation.
    masternode_engine: Arc<RwLock<MasternodeListEngine>>,
    /// ChainLocks indexed by height.
    chainlocks_by_height: IndexMap<u32, ChainLockEntry>,
    /// ChainLocks indexed by block hash.
    chainlocks_by_hash: IndexMap<BlockHash, ChainLockEntry>,
    /// Pending ChainLocks awaiting validation.
    pub(super) pending_chainlocks: Vec<ChainLock>,
    /// ChainLock hashes that have been requested (to avoid duplicate requests).
    pub(super) requested_chainlocks: HashSet<ChainLockHash>,
}

impl<H: BlockHeaderStorage> ChainLockManager<H> {
    /// Create a new ChainLock manager.
    pub fn new(
        header_storage: Arc<RwLock<H>>,
        masternode_engine: Arc<RwLock<MasternodeListEngine>>,
    ) -> Self {
        Self {
            progress: ChainLockProgress::default(),
            header_storage,
            masternode_engine,
            chainlocks_by_height: IndexMap::new(),
            chainlocks_by_hash: IndexMap::new(),
            pending_chainlocks: Vec::new(),
            requested_chainlocks: HashSet::new(),
        }
    }

    /// Process an incoming ChainLock message.
    pub(super) async fn process_chainlock(
        &mut self,
        chainlock: &ChainLock,
    ) -> SyncResult<Vec<SyncEvent>> {
        let height = chainlock.block_height;
        let block_hash = chainlock.block_hash;

        tracing::info!("Processing ChainLock for height {} hash {}", height, block_hash);

        // Check for duplicates and conflicts
        if let Some(existing) = self.chainlocks_by_height.get(&height) {
            if existing.chain_lock.block_hash != block_hash {
                tracing::warn!(
                    "Conflicting ChainLock at height {}: stored {} vs received {}",
                    height,
                    existing.chain_lock.block_hash,
                    block_hash
                );
            } else {
                tracing::debug!("Duplicate ChainLock at height {}", height);
            }
            return Ok(vec![]);
        }

        // Verify block hash matches our chain (if we have the header)
        if !self.verify_block_hash(chainlock).await {
            tracing::warn!("ChainLock hash mismatch at height {}, rejecting", height);
            return Ok(vec![]);
        }

        // Try to validate with masternode engine
        let validated = self.validate_signature(chainlock).await;

        if !validated {
            self.queue_pending(chainlock.clone());
        }

        // Store in cache
        let entry = ChainLockEntry {
            chain_lock: chainlock.clone(),
            received_at: SystemTime::now(),
            validated,
        };
        self.store_chainlock(entry.clone());

        self.progress.add_processed(1);

        if validated && height > self.progress.best_validated_height() {
            self.progress.update_best_validated_height(height);
        }

        Ok(vec![SyncEvent::ChainLockReceived {
            height,
            block_hash,
            validated,
        }])
    }

    /// Verify that the ChainLock block hash matches our stored header.
    /// Returns true if the hash matches or we don't have the header yet.
    /// Returns false if we have the header and the hash doesn't match.
    async fn verify_block_hash(&self, chainlock: &ChainLock) -> bool {
        let storage = self.header_storage.read().await;
        match storage.get_header(chainlock.block_height).await {
            Ok(Some(header)) => header.block_hash() == chainlock.block_hash,
            Ok(None) => {
                // Don't reject if we don't have the header yet
                true
            }
            Err(e) => {
                tracing::warn!(
                    "Storage error checking ChainLock header at height {}: {}",
                    chainlock.block_height,
                    e
                );
                // Accept since we can't verify - will validate when header arrives
                true
            }
        }
    }

    /// Validate the ChainLock BLS signature using the masternode engine.
    async fn validate_signature(&self, chainlock: &ChainLock) -> bool {
        let engine = self.masternode_engine.read().await;

        match engine.verify_chain_lock(chainlock) {
            Ok(()) => {
                tracing::info!(
                    "ChainLock signature verified for height {}",
                    chainlock.block_height
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    "ChainLock signature verification failed for height {}: {}",
                    chainlock.block_height,
                    e
                );
                false
            }
        }
    }

    /// Queue a ChainLock for later validation.
    fn queue_pending(&mut self, chainlock: ChainLock) {
        // Remove oldest if at capacity
        if self.pending_chainlocks.len() >= MAX_PENDING_CHAINLOCKS {
            let dropped = self.pending_chainlocks.remove(0);
            tracing::warn!(
                "Pending ChainLocks queue at capacity ({}), dropping oldest at height {}",
                MAX_PENDING_CHAINLOCKS,
                dropped.block_height
            );
        }
        self.pending_chainlocks.push(chainlock);
    }

    /// Store a ChainLock in the cache.
    fn store_chainlock(&mut self, entry: ChainLockEntry) {
        let height = entry.chain_lock.block_height;
        let hash = entry.chain_lock.block_hash;

        self.chainlocks_by_height.insert(height, entry.clone());
        self.chainlocks_by_hash.insert(hash, entry);

        // Enforce cache limit by removing oldest
        while self.chainlocks_by_height.len() > MAX_CACHE_SIZE {
            if let Some((_, removed)) = self.chainlocks_by_height.shift_remove_index(0) {
                self.chainlocks_by_hash.shift_remove(&removed.chain_lock.block_hash);
            }
        }
    }

    /// Validate pending ChainLocks after masternode engine becomes available.
    pub(super) async fn validate_pending(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let pending = std::mem::take(&mut self.pending_chainlocks);
        let mut events = Vec::new();

        for chainlock in pending {
            let validated = self.validate_signature(&chainlock).await;
            let height = chainlock.block_height;
            let block_hash = chainlock.block_hash;

            if validated {
                // Update the cached entry
                if let Some(entry) = self.chainlocks_by_height.get_mut(&height) {
                    entry.validated = true;
                }
                if let Some(entry) = self.chainlocks_by_hash.get_mut(&block_hash) {
                    entry.validated = true;
                }
                if height > self.progress.best_validated_height() {
                    self.progress.update_best_validated_height(height);
                }
                events.push(SyncEvent::ChainLockReceived {
                    height,
                    block_hash,
                    validated: true,
                });
            } else {
                // Still can't validate, re-queue
                self.queue_pending(chainlock);
            }
        }

        Ok(events)
    }

    /// Get a ChainLock by block height.
    pub fn get_chainlock_by_height(&self, height: u32) -> Option<&ChainLockEntry> {
        self.chainlocks_by_height.get(&height)
    }

    /// Get a ChainLock by block hash.
    pub fn get_chainlock_by_hash(&self, hash: &BlockHash) -> Option<&ChainLockEntry> {
        self.chainlocks_by_hash.get(hash)
    }

    /// Check if a block at the given height has a validated ChainLock.
    pub fn is_block_chainlocked(&self, height: u32) -> bool {
        self.chainlocks_by_height.get(&height).map(|e| e.validated).unwrap_or(false)
    }

    /// Get the number of pending ChainLocks awaiting validation.
    pub fn pending_count(&self) -> usize {
        self.pending_chainlocks.len()
    }
}

impl<H: BlockHeaderStorage> std::fmt::Debug for ChainLockManager<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLockManager")
            .field("progress", &self.progress)
            .field("cached", &self.chainlocks_by_height.len())
            .field("pending", &self.pending_chainlocks.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MessageType;
    use crate::storage::{DiskStorageManager, PersistentBlockHeaderStorage};
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress, SyncState};
    use crate::ClientConfig;
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hashes::Hash;

    type TestChainLockManager = ChainLockManager<PersistentBlockHeaderStorage>;

    async fn create_test_manager() -> TestChainLockManager {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = ClientConfig::testnet().with_storage_path(temp_dir.path());
        let storage = DiskStorageManager::new(&config).await.unwrap();
        let engine =
            Arc::new(RwLock::new(MasternodeListEngine::default_for_network(config.network)));
        ChainLockManager::new(storage.header_storage(), engine)
    }

    fn create_test_chainlock(height: u32) -> ChainLock {
        ChainLock {
            block_height: height,
            block_hash: BlockHash::all_zeros(),
            signature: BLSSignature::from([0u8; 96]),
        }
    }

    #[tokio::test]
    async fn test_chainlock_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::ChainLock);
        assert_eq!(manager.state(), SyncState::Initializing);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::CLSig, MessageType::Inv]);
    }

    #[tokio::test]
    async fn test_chainlock_duplicate_handling() {
        let mut manager = create_test_manager().await;

        let chainlock1 = create_test_chainlock(100);
        let chainlock2 = create_test_chainlock(100);

        // First should process
        let events1 = manager.process_chainlock(&chainlock1).await.unwrap();
        assert_eq!(events1.len(), 1);

        // Second should be ignored as duplicate
        let events2 = manager.process_chainlock(&chainlock2).await.unwrap();
        assert_eq!(events2.len(), 0);
    }

    #[tokio::test]
    async fn test_chainlock_pending_queue() {
        let mut manager = create_test_manager().await;

        // Without masternode engine, ChainLocks should be queued
        let chainlock = create_test_chainlock(100);
        let _ = manager.process_chainlock(&chainlock).await.unwrap();

        assert_eq!(manager.pending_count(), 1);
    }

    #[tokio::test]
    async fn test_chainlock_cache_limit() {
        let mut manager = create_test_manager().await;

        // Add more than MAX_CACHE_SIZE chainlocks
        for i in 0..MAX_CACHE_SIZE + 10 {
            let chainlock = create_test_chainlock(i as u32);
            let _ = manager.process_chainlock(&chainlock).await.unwrap();
        }

        // Should be capped at MAX_CACHE_SIZE
        assert!(manager.chainlocks_by_height.len() <= MAX_CACHE_SIZE);
    }

    #[tokio::test]
    async fn test_chainlock_progress() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);
        manager.progress.update_best_validated_height(500);
        manager.progress.update_pending(2);
        manager.progress.add_processed(10);

        let progress = manager.progress();
        if let SyncManagerProgress::ChainLock(cp) = progress {
            assert_eq!(cp.state(), SyncState::Syncing);
            assert_eq!(cp.best_validated_height(), 500);
            assert_eq!(cp.pending(), 2);
            assert_eq!(cp.processed(), 10);
        } else {
            panic!("Expected SyncManagerProgress::ChainLock");
        }
    }

    #[tokio::test]
    async fn test_chainlock_accessors() {
        let mut manager = create_test_manager().await;

        let chainlock = create_test_chainlock(100);
        let _ = manager.process_chainlock(&chainlock.clone()).await.unwrap();

        // Should be retrievable by height
        assert!(manager.get_chainlock_by_height(100).is_some());
        assert!(manager.get_chainlock_by_height(101).is_none());

        // Should be retrievable by hash
        assert!(manager.get_chainlock_by_hash(&chainlock.block_hash).is_some());
    }
}
