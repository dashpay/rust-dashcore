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
use crate::storage::BlockHeaderStorage;
use crate::sync::{ChainLockProgress, SyncEvent};

/// ChainLock manager for the parallel sync coordinator.
///
/// This manager:
/// - Subscribes to CLSig messages from the network
/// - Validates ChainLocks only after masternode sync is complete
/// - Tracks only the best (highest) validated ChainLock
/// - Emits ChainLockReceived events
pub struct ChainLockManager<H: BlockHeaderStorage> {
    /// Current progress of the manager.
    pub(super) progress: ChainLockProgress,
    /// Block header storage for hash verification.
    header_storage: Arc<RwLock<H>>,
    /// Masternode engine for BLS signature validation.
    masternode_engine: Arc<RwLock<MasternodeListEngine>>,
    /// The best (highest height) validated ChainLock.
    best_chainlock: Option<ChainLock>,
    /// ChainLock hashes that have been requested (to avoid duplicate requests).
    pub(super) requested_chainlocks: HashSet<ChainLockHash>,
    /// Whether masternode sync is complete and we can validate signatures.
    masternode_ready: bool,
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
            best_chainlock: None,
            requested_chainlocks: HashSet::new(),
            masternode_ready: false,
        }
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
                height,
                block_hash,
                validated: false,
            }]);
        }

        // Validate with masternode engine
        let validated = self.validate_signature(chainlock).await;

        if validated {
            self.progress.add_valid(1);
            self.progress.update_best_validated_height(height);

            // Update best ChainLock
            self.best_chainlock = Some(chainlock.clone());
        } else {
            self.progress.add_invalid(1);
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

impl<H: BlockHeaderStorage> std::fmt::Debug for ChainLockManager<H> {
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
    use crate::storage::{DiskStorageManager, PersistentBlockHeaderStorage};
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress, SyncState};
    use crate::Network;
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hashes::Hash;
    use dashcore::BlockHash;

    type TestChainLockManager = ChainLockManager<PersistentBlockHeaderStorage>;

    async fn create_test_manager() -> TestChainLockManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let engine =
            Arc::new(RwLock::new(MasternodeListEngine::default_for_network(Network::Testnet)));
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
}
