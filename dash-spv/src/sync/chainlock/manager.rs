//! ChainLock manager for parallel sync.
//!
//! Handles ChainLock messages (clsig) from the network. Validates ChainLocks
//! only after masternode data is available. Since ChainLocks are cumulative
//! (all blocks below the best ChainLock are implicitly locked), we only track
//! the best validated ChainLock.

use std::sync::Arc;

use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hash_types::ChainLockHash;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use std::collections::HashSet;
use tokio::sync::RwLock;

use crate::error::SyncResult;
use crate::storage::{BlockHeaderStorage, MetadataStorage};
use crate::sync::{ChainLockProgress, SyncEvent};

/// Metadata key for persisting the best validated ChainLock.
const BEST_CHAINLOCK_KEY: &str = "best_chainlock";

/// ChainLock manager for the parallel sync coordinator.
///
/// This manager:
/// - Subscribes to CLSig messages from the network
/// - Validates ChainLocks only after masternode sync is complete
/// - Tracks only the best (highest) validated ChainLock
/// - Emits ChainLockReceived events
pub struct ChainLockManager<H: BlockHeaderStorage, M: MetadataStorage> {
    /// Current progress of the manager.
    pub(super) progress: ChainLockProgress,
    /// Block header storage for hash verification.
    header_storage: Arc<RwLock<H>>,
    /// Metadata storage for persisting the best chainlock.
    metadata_storage: Arc<RwLock<M>>,
    /// Masternode engine for BLS signature validation.
    masternode_engine: Arc<RwLock<MasternodeListEngine>>,
    /// The best (highest height) validated ChainLock.
    best_chainlock: Option<ChainLock>,
    /// ChainLock hashes that have been requested (to avoid duplicate requests).
    pub(super) requested_chainlocks: HashSet<ChainLockHash>,
    /// Whether masternode sync is complete and we can validate signatures.
    masternode_ready: bool,
}

impl<H: BlockHeaderStorage, M: MetadataStorage> ChainLockManager<H, M> {
    /// Create a new ChainLock manager.
    pub async fn new(
        header_storage: Arc<RwLock<H>>,
        metadata_storage: Arc<RwLock<M>>,
        masternode_engine: Arc<RwLock<MasternodeListEngine>>,
    ) -> Self {
        let mut manager = Self {
            progress: ChainLockProgress::default(),
            header_storage,
            metadata_storage,
            masternode_engine,
            best_chainlock: None,
            requested_chainlocks: HashSet::new(),
            masternode_ready: false,
        };

        // TODO: Move load_best_chainlock() and save_best_chainlock() to MetadataStorage trait.
        manager.load_best_chainlock().await;

        manager
    }

    /// Notify the manager that masternode sync is complete.
    pub(super) fn set_masternode_ready(&mut self) {
        self.masternode_ready = true;
    }

    /// Process an incoming ChainLock message.
    pub(super) async fn process_chainlock(
        &mut self,
        chainlock: &ChainLock,
    ) -> SyncResult<Vec<SyncEvent>> {
        let height = chainlock.block_height;
        let block_hash = chainlock.block_hash;

        tracing::info!("Processing ChainLock for height {} hash {}", height, block_hash);

        // Skip if we already have a better or equal ChainLock
        if let Some(best) = &self.best_chainlock {
            if height <= best.block_height {
                tracing::debug!(
                    "Ignoring ChainLock at height {} (best is {})",
                    height,
                    best.block_height
                );
                return Ok(vec![]);
            }
        }

        // Verify block hash matches our chain (if we have the header)
        if !self.verify_block_hash(chainlock).await {
            tracing::warn!("ChainLock hash mismatch at height {}, rejecting", height);
            return Ok(vec![]);
        }

        // Only validate if masternode sync is complete
        if !self.masternode_ready {
            tracing::debug!(
                "Skipping ChainLock validation at height {} (masternode sync not complete)",
                height
            );
            return Ok(vec![SyncEvent::ChainLockReceived {
                chain_lock: chainlock.clone(),
                validated: false,
            }]);
        }

        // Validate with masternode engine
        let validated = self.validate_signature(chainlock).await;

        if validated {
            self.progress.add_valid(1);
            self.progress.update_best_validated_height(height);

            // Update best ChainLock and persist to storage
            self.best_chainlock = Some(chainlock.clone());
            self.save_best_chainlock().await;
        } else {
            self.progress.add_invalid(1);
        }

        Ok(vec![SyncEvent::ChainLockReceived {
            chain_lock: chainlock.clone(),
            validated,
        }])
    }

    /// Persist the best chainlock to metadata storage.
    async fn save_best_chainlock(&self) {
        let Some(chainlock) = &self.best_chainlock else {
            return;
        };
        match serde_json::to_vec(chainlock) {
            Ok(bytes) => {
                let mut storage = self.metadata_storage.write().await;
                if let Err(e) = storage.store_metadata(BEST_CHAINLOCK_KEY, &bytes).await {
                    tracing::warn!("Failed to persist best chainlock: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize best chainlock: {}", e);
            }
        }
    }

    /// Load the best chainlock from metadata storage and restore progress.
    pub(super) async fn load_best_chainlock(&mut self) {
        let storage = self.metadata_storage.read().await;
        match storage.load_metadata(BEST_CHAINLOCK_KEY).await {
            Ok(Some(bytes)) => match serde_json::from_slice::<ChainLock>(&bytes) {
                Ok(chainlock) => {
                    let height = chainlock.block_height;
                    tracing::info!("Restored persisted ChainLock at height {}", height);
                    self.progress.update_best_validated_height(height);
                    self.best_chainlock = Some(chainlock);
                }
                Err(e) => {
                    tracing::warn!("Failed to deserialize persisted chainlock: {}", e);
                }
            },
            Ok(None) => {
                tracing::debug!("No persisted chainlock found (fresh start)");
            }
            Err(e) => {
                tracing::warn!("Failed to load persisted chainlock: {}", e);
            }
        }
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

    /// Get the best validated ChainLock.
    pub fn best_chainlock(&self) -> Option<&ChainLock> {
        self.best_chainlock.as_ref()
    }

    /// Check if a block at the given height is chainlocked.
    /// All blocks at or below the best validated ChainLock height are considered locked.
    pub fn is_block_chainlocked(&self, height: u32) -> bool {
        self.best_chainlock.as_ref().map(|cl| height <= cl.block_height).unwrap_or(false)
    }
}

impl<H: BlockHeaderStorage, M: MetadataStorage> std::fmt::Debug for ChainLockManager<H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLockManager")
            .field("progress", &self.progress)
            .field("best_height", &self.best_chainlock.as_ref().map(|cl| cl.block_height))
            .field("masternode_ready", &self.masternode_ready)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MessageType;
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentMetadataStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress, SyncState};
    use crate::Network;
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hashes::Hash;
    use dashcore::BlockHash;

    type TestChainLockManager =
        ChainLockManager<PersistentBlockHeaderStorage, PersistentMetadataStorage>;

    async fn create_test_manager() -> TestChainLockManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let engine =
            Arc::new(RwLock::new(MasternodeListEngine::default_for_network(Network::Testnet)));
        ChainLockManager::new(storage.block_headers(), storage.metadata(), engine).await
    }

    async fn create_test_manager_with_storage(
        storage: &DiskStorageManager,
    ) -> TestChainLockManager {
        let engine =
            Arc::new(RwLock::new(MasternodeListEngine::default_for_network(Network::Testnet)));
        ChainLockManager::new(storage.block_headers(), storage.metadata(), engine).await
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
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::CLSig, MessageType::Inv]);
    }

    #[tokio::test]
    async fn test_chainlock_skips_validation_before_masternode_ready() {
        let mut manager = create_test_manager().await;

        // Before masternode sync, ChainLocks should not be validated
        let chainlock = create_test_chainlock(100);
        let events = manager.process_chainlock(&chainlock).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(manager.progress.valid(), 0);
        assert_eq!(manager.progress.invalid(), 0);
        assert!(manager.best_chainlock().is_none());
    }

    #[tokio::test]
    async fn test_chainlock_validates_after_masternode_ready() {
        let mut manager = create_test_manager().await;
        manager.set_masternode_ready();

        // After masternode sync, ChainLocks should be validated (will fail with empty engine)
        let chainlock = create_test_chainlock(100);
        let _ = manager.process_chainlock(&chainlock).await.unwrap();

        assert_eq!(manager.progress.invalid(), 1);
        assert_eq!(manager.progress.valid(), 0);
    }

    #[tokio::test]
    async fn test_chainlock_keeps_only_best() {
        let mut manager = create_test_manager().await;

        // Manually set a best chainlock
        manager.best_chainlock = Some(create_test_chainlock(200));

        // Lower height should be ignored
        let chainlock_lower = create_test_chainlock(150);
        let events = manager.process_chainlock(&chainlock_lower).await.unwrap();
        assert_eq!(events.len(), 0);

        // Equal height should also be ignored
        let chainlock_equal = create_test_chainlock(200);
        let events = manager.process_chainlock(&chainlock_equal).await.unwrap();
        assert_eq!(events.len(), 0);

        // Higher height should be processed
        let chainlock_higher = create_test_chainlock(300);
        let events = manager.process_chainlock(&chainlock_higher).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_chainlock_progress() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);
        manager.progress.update_best_validated_height(500);
        manager.progress.add_valid(8);
        manager.progress.add_invalid(2);

        let progress = manager.progress();
        if let SyncManagerProgress::ChainLock(cp) = progress {
            assert_eq!(cp.state(), SyncState::Syncing);
            assert_eq!(cp.best_validated_height(), 500);
            assert_eq!(cp.valid(), 8);
            assert_eq!(cp.invalid(), 2);
        } else {
            panic!("Expected SyncManagerProgress::ChainLock");
        }
    }

    #[tokio::test]
    async fn test_is_block_chainlocked() {
        let mut manager = create_test_manager().await;

        // No ChainLock yet
        assert!(!manager.is_block_chainlocked(100));

        // Manually set best chainlock for testing
        manager.best_chainlock = Some(create_test_chainlock(500));

        // All blocks at or below 500 should be chainlocked
        assert!(manager.is_block_chainlocked(1));
        assert!(manager.is_block_chainlocked(500));
        assert!(!manager.is_block_chainlocked(501));
    }

    #[tokio::test]
    async fn test_load_from_empty_storage_returns_none() {
        let mut manager = create_test_manager().await;

        manager.load_best_chainlock().await;

        assert!(manager.best_chainlock().is_none());
        assert_eq!(manager.progress.best_validated_height(), 0);
    }

    #[tokio::test]
    async fn test_save_and_load_chainlock_round_trip() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let chainlock = create_test_chainlock(42000);

        // Save a chainlock via the first manager
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.best_chainlock = Some(chainlock.clone());
            manager.save_best_chainlock().await;
        }

        // Fresh manager sharing the same storage should load the chainlock automatically
        {
            let manager = create_test_manager_with_storage(&storage).await;

            let restored = manager.best_chainlock().expect("chainlock should be restored");
            assert_eq!(restored.block_height, 42000);
            assert_eq!(restored.block_hash, chainlock.block_hash);
            assert_eq!(restored.signature, chainlock.signature);
            assert_eq!(manager.progress.best_validated_height(), 42000);
        }
    }

    #[tokio::test]
    async fn test_initialize_restores_persisted_chainlock() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let chainlock = create_test_chainlock(99999);

        // Persist a chainlock directly via metadata storage
        {
            let bytes = serde_json::to_vec(&chainlock).unwrap();
            let meta_storage = storage.metadata();
            let mut meta = meta_storage.write().await;
            meta.store_metadata(BEST_CHAINLOCK_KEY, &bytes).await.unwrap();
        }

        // Create a new manager and call initialize (the SyncManager trait method)
        let manager = create_test_manager_with_storage(&storage).await;

        let restored =
            manager.best_chainlock().expect("chainlock should be restored after initialize");
        assert_eq!(restored.block_height, 99999);
        assert_eq!(manager.progress.best_validated_height(), 99999);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
    }

    #[tokio::test]
    async fn test_process_chainlock_persists_on_validation() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut manager = create_test_manager_with_storage(&storage).await;

        // Without masternode ready, chainlocks are not validated and not persisted
        let chainlock = create_test_chainlock(500);
        manager.process_chainlock(&chainlock).await.unwrap();
        assert!(manager.best_chainlock().is_none());

        // Verify nothing was persisted
        {
            let meta_storage = storage.metadata();
            let meta = meta_storage.read().await;
            let loaded = meta.load_metadata(BEST_CHAINLOCK_KEY).await.unwrap();
            assert!(loaded.is_none());
        }
    }

    #[tokio::test]
    async fn test_save_overwrites_previous_chainlock() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();

        // Save first chainlock
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.best_chainlock = Some(create_test_chainlock(100));
            manager.save_best_chainlock().await;
        }

        // Save a higher chainlock
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.best_chainlock = Some(create_test_chainlock(200));
            manager.save_best_chainlock().await;
        }

        // Load and verify only the latest is stored
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.load_best_chainlock().await;

            let restored = manager.best_chainlock().expect("chainlock should be restored");
            assert_eq!(restored.block_height, 200);
        }
    }

    #[tokio::test]
    async fn test_lower_chainlock_rejected_after_load() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();

        // Save chainlock at height 200
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.best_chainlock = Some(create_test_chainlock(200));
            manager.save_best_chainlock().await;
        }

        // Load and try to process a lower chainlock
        {
            let mut manager = create_test_manager_with_storage(&storage).await;
            manager.load_best_chainlock().await;

            // Try to process a lower chainlock
            let lower_chainlock = create_test_chainlock(100);
            let events = manager.process_chainlock(&lower_chainlock).await.unwrap();

            // Should be rejected (no events)
            assert_eq!(events.len(), 0);

            // Best should still be 200
            let best = manager.best_chainlock().expect("should have best chainlock");
            assert_eq!(best.block_height, 200);
        }
    }
}
