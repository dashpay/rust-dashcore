//! ChainLock manager for DIP8 implementation
//!
//! This module implements ChainLock validation and management according to DIP8,
//! providing protection against 51% attacks and securing InstantSend transactions.

use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::{BlockHash, ChainLock};
use indexmap::IndexMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult, ValidationError, ValidationResult};
use crate::storage::StorageManager;
use crate::types::ChainState;

/// Maximum number of pending ChainLocks to queue
const MAX_PENDING_CHAINLOCKS: usize = 100;

/// ChainLock storage entry
#[derive(Debug, Clone)]
pub struct ChainLockEntry {
    /// The chain lock message
    pub chain_lock: ChainLock,
    /// When this chain lock was received
    pub received_at: std::time::SystemTime,
    /// Whether this chain lock has been validated
    pub validated: bool,
}

/// Manages ChainLocks according to DIP8
pub struct ChainLockManager {
    /// In-memory cache of chain locks by height (maintains insertion order)
    chain_locks_by_height: Arc<RwLock<IndexMap<u32, ChainLockEntry>>>,
    /// In-memory cache of chain locks by block hash
    chain_locks_by_hash: Arc<RwLock<IndexMap<BlockHash, ChainLockEntry>>>,
    /// Maximum number of chain locks to keep in memory
    max_cache_size: usize,
    /// Whether to enforce chain locks (can be disabled for testing)
    enforce_chain_locks: bool,
    /// Optional reference to masternode engine for full validation
    masternode_engine: Arc<RwLock<Option<Arc<MasternodeListEngine>>>>,
    /// Queue for ChainLocks pending validation (received before masternode sync)
    pending_chainlocks: Arc<RwLock<Vec<ChainLock>>>,
}

impl ChainLockManager {
    /// Create a new ChainLockManager
    pub fn new(enforce_chain_locks: bool) -> Self {
        Self {
            chain_locks_by_height: Arc::new(RwLock::new(IndexMap::new())),
            chain_locks_by_hash: Arc::new(RwLock::new(IndexMap::new())),
            max_cache_size: 1000,
            enforce_chain_locks,
            masternode_engine: Arc::new(RwLock::new(None)),
            pending_chainlocks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Set the masternode engine for validation
    pub async fn set_masternode_engine(&self, engine: Arc<MasternodeListEngine>) {
        let mut guard = self.masternode_engine.write().await;
        *guard = Some(engine);
        info!("Masternode engine set for ChainLock validation");
    }

    /// Queue a ChainLock for validation when masternode data is available
    pub async fn queue_pending_chainlock(&self, chain_lock: ChainLock) -> StorageResult<()> {
        let mut pending = self.pending_chainlocks.write().await;
        // If at capacity, drop the oldest ChainLock
        if pending.len() >= MAX_PENDING_CHAINLOCKS {
            let dropped = pending.remove(0);
            warn!(
                "Pending ChainLocks queue at capacity ({}), dropping oldest ChainLock at height {}",
                MAX_PENDING_CHAINLOCKS, dropped.block_height
            );
        }

        pending.push(chain_lock);
        debug!("Queued ChainLock for pending validation, total pending: {}", pending.len());
        Ok(())
    }

    /// Validate all pending ChainLocks after masternode sync
    pub async fn validate_pending_chainlocks(
        &self,
        chain_state: &ChainState,
        storage: &mut dyn StorageManager,
    ) -> ValidationResult<()> {
        let pending = {
            let mut pending_guard = self.pending_chainlocks.write().await;
            std::mem::take(&mut *pending_guard)
        };

        info!("Validating {} pending ChainLocks", pending.len());

        let mut validated_count = 0;
        let mut failed_count = 0;

        for chain_lock in pending {
            match self.process_chain_lock(chain_lock.clone(), chain_state, storage).await {
                Ok(_) => {
                    validated_count += 1;
                    debug!(
                        "Successfully validated pending ChainLock at height {}",
                        chain_lock.block_height
                    );
                }
                Err(e) => {
                    failed_count += 1;
                    error!(
                        "Failed to validate pending ChainLock at height {}: {}",
                        chain_lock.block_height, e
                    );
                }
            }
        }

        info!(
            "Pending ChainLock validation complete: {} validated, {} failed",
            validated_count, failed_count
        );

        Ok(())
    }

    /// Process a new chain lock
    pub async fn process_chain_lock(
        &self,
        chain_lock: ChainLock,
        chain_state: &ChainState,
        storage: &mut dyn StorageManager,
    ) -> ValidationResult<()> {
        info!(
            "Processing ChainLock for height {} hash {}",
            chain_lock.block_height, chain_lock.block_hash
        );

        // Check if we already have this chain lock
        if self.has_chain_lock_at_height(chain_lock.block_height).await {
            let existing = self.get_chain_lock_by_height(chain_lock.block_height).await;
            if let Some(existing_entry) = existing {
                if existing_entry.chain_lock.block_hash != chain_lock.block_hash {
                    error!(
                        "Conflicting ChainLock at height {}: existing {} vs new {}",
                        chain_lock.block_height,
                        existing_entry.chain_lock.block_hash,
                        chain_lock.block_hash
                    );
                    return Err(ValidationError::InvalidChainLock(format!(
                        "Conflicting ChainLock at height {}",
                        chain_lock.block_height
                    )));
                }
                debug!("Already have ChainLock for height {}", chain_lock.block_height);
                return Ok(());
            }
        }

        // Verify the block exists in our chain
        if let Some(header) = chain_state.header_at_height(chain_lock.block_height) {
            let header_hash = header.block_hash();
            if header_hash != chain_lock.block_hash {
                return Err(ValidationError::InvalidChainLock(format!(
                    "ChainLock block hash {} does not match our chain at height {} (expected {})",
                    chain_lock.block_hash, chain_lock.block_height, header_hash
                )));
            }
        } else {
            // We don't have this block yet, store the chain lock for future validation
            warn!("Received ChainLock for future block at height {}", chain_lock.block_height);
        }

        // Full validation with masternode engine if available
        let engine_guard = self.masternode_engine.read().await;
        let mut validated = false;

        if let Some(engine) = engine_guard.as_ref() {
            // Use the masternode engine's verify_chain_lock method
            match engine.verify_chain_lock(&chain_lock) {
                Ok(()) => {
                    info!(
                        "✅ ChainLock validated with masternode engine for height {}",
                        chain_lock.block_height
                    );
                    validated = true;
                }
                Err(e) => {
                    // Check if the error is due to missing masternode lists
                    let error_string = e.to_string();
                    if error_string.contains("No masternode lists in engine") {
                        // ChainLock validation requires masternode list at (block_height - 8)
                        let required_height = chain_lock.block_height.saturating_sub(8);
                        warn!("⚠️ Masternode engine exists but lacks required masternode lists for height {} (needs list at height {} for ChainLock validation), queueing ChainLock for later validation", 
                            chain_lock.block_height, required_height);
                        drop(engine_guard); // Release the read lock before acquiring write lock
                        self.queue_pending_chainlock(chain_lock.clone()).await.map_err(|e| {
                            ValidationError::InvalidChainLock(format!(
                                "Failed to queue pending ChainLock: {}",
                                e
                            ))
                        })?;
                    } else {
                        return Err(ValidationError::InvalidChainLock(format!(
                            "MasternodeListEngine validation failed: {:?}",
                            e
                        )));
                    }
                }
            }
        } else {
            // Queue for later validation when engine becomes available
            warn!("⚠️ Masternode engine not available, queueing ChainLock for later validation");
            drop(engine_guard); // Release the read lock before acquiring write lock
            self.queue_pending_chainlock(chain_lock.clone()).await.map_err(|e| {
                ValidationError::InvalidChainLock(format!(
                    "Failed to queue pending ChainLock: {}",
                    e
                ))
            })?;
        }

        // Store the chain lock with appropriate validation status
        self.store_chain_lock_with_validation(chain_lock.clone(), storage, validated).await?;

        // Update chain state
        self.update_chain_state_with_lock(&chain_lock, chain_state);

        if validated {
            info!(
                "Successfully processed and validated ChainLock for height {}",
                chain_lock.block_height
            );
        } else {
            info!(
                "Processed ChainLock for height {} (pending full validation)",
                chain_lock.block_height
            );
        }

        Ok(())
    }

    /// Store a chain lock with validation status
    async fn store_chain_lock_with_validation(
        &self,
        chain_lock: ChainLock,
        storage: &mut dyn StorageManager,
        validated: bool,
    ) -> StorageResult<()> {
        let entry = ChainLockEntry {
            chain_lock: chain_lock.clone(),
            received_at: std::time::SystemTime::now(),
            validated,
        };

        self.store_chain_lock_internal(chain_lock, entry, storage).await
    }

    /// Store a chain lock (deprecated, use store_chain_lock_with_validation)
    async fn store_chain_lock(
        &self,
        chain_lock: ChainLock,
        storage: &mut dyn StorageManager,
    ) -> StorageResult<()> {
        self.store_chain_lock_with_validation(chain_lock, storage, true).await
    }

    /// Internal method to store a chain lock entry
    async fn store_chain_lock_internal(
        &self,
        chain_lock: ChainLock,
        entry: ChainLockEntry,
        storage: &mut dyn StorageManager,
    ) -> StorageResult<()> {
        // Store in memory caches
        {
            let mut by_height = self.chain_locks_by_height.write().await;
            let mut by_hash = self.chain_locks_by_hash.write().await;

            by_height.insert(chain_lock.block_height, entry.clone());
            by_hash.insert(chain_lock.block_hash, entry.clone());

            // Enforce cache size limit
            if by_height.len() > self.max_cache_size {
                // Calculate how many entries to remove
                let entries_to_remove = by_height.len() - self.max_cache_size;

                // Collect keys to remove (oldest entries are at the beginning)
                let keys_to_remove: Vec<(u32, BlockHash)> = by_height
                    .iter()
                    .take(entries_to_remove)
                    .map(|(height, entry)| (*height, entry.chain_lock.block_hash))
                    .collect();

                // Batch remove from both maps
                for (height, block_hash) in keys_to_remove {
                    by_height.shift_remove(&height);
                    by_hash.shift_remove(&block_hash);
                }
            }
        }

        // Store persistently
        let key = format!("chainlock:{}", chain_lock.block_height);
        let data = bincode::serialize(&chain_lock)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        storage.store_metadata(&key, &data).await?;

        Ok(())
    }

    /// Check if we have a chain lock at the given height
    pub async fn has_chain_lock_at_height(&self, height: u32) -> bool {
        let locks = self.chain_locks_by_height.read().await;
        locks.contains_key(&height)
    }

    /// Get chain lock by height
    pub async fn get_chain_lock_by_height(&self, height: u32) -> Option<ChainLockEntry> {
        let locks = self.chain_locks_by_height.read().await;
        locks.get(&height).cloned()
    }

    /// Get chain lock by block hash
    pub async fn get_chain_lock_by_hash(&self, hash: &BlockHash) -> Option<ChainLockEntry> {
        let locks = self.chain_locks_by_hash.read().await;
        locks.get(hash).cloned()
    }

    /// Check if a block is chain-locked
    pub async fn is_block_chain_locked(&self, block_hash: &BlockHash, height: u32) -> bool {
        // First check by hash (most specific)
        if let Some(entry) = self.get_chain_lock_by_hash(block_hash).await {
            return entry.validated && entry.chain_lock.block_hash == *block_hash;
        }

        // Then check by height
        if let Some(entry) = self.get_chain_lock_by_height(height).await {
            return entry.validated && entry.chain_lock.block_hash == *block_hash;
        }

        false
    }

    /// Get the highest chain-locked block height
    pub async fn get_highest_chain_locked_height(&self) -> Option<u32> {
        let locks = self.chain_locks_by_height.read().await;
        locks.keys().max().cloned()
    }

    /// Check if a reorganization would violate chain locks
    pub async fn would_violate_chain_lock(
        &self,
        reorg_from_height: u32,
        reorg_to_height: u32,
    ) -> bool {
        if !self.enforce_chain_locks {
            return false;
        }

        let locks = self.chain_locks_by_height.read().await;

        // Check if any chain-locked block would be reorganized
        for height in reorg_from_height..=reorg_to_height {
            if locks.contains_key(&height) {
                debug!("Reorg would violate chain lock at height {}", height);
                return true;
            }
        }

        false
    }

    /// Update chain state with a new chain lock
    fn update_chain_state_with_lock(&self, _chain_lock: &ChainLock, _chain_state: &ChainState) {
        // This is handled by the caller to avoid mutable borrow issues
        // The chain state will be updated with the chain lock information
    }

    /// Load chain locks from storage
    pub async fn load_from_storage(
        &self,
        storage: &dyn StorageManager,
        start_height: u32,
        end_height: u32,
    ) -> StorageResult<Vec<ChainLock>> {
        let mut chain_locks = Vec::new();

        for height in start_height..=end_height {
            let key = format!("chainlock:{}", height);
            if let Some(data) = storage.load_metadata(&key).await? {
                match bincode::deserialize::<ChainLock>(&data) {
                    Ok(chain_lock) => {
                        // Cache it
                        let entry = ChainLockEntry {
                            chain_lock: chain_lock.clone(),
                            received_at: std::time::SystemTime::now(),
                            validated: true,
                        };

                        let mut by_height = self.chain_locks_by_height.write().await;
                        let mut by_hash = self.chain_locks_by_hash.write().await;

                        by_height.insert(chain_lock.block_height, entry.clone());
                        by_hash.insert(chain_lock.block_hash, entry);

                        chain_locks.push(chain_lock);
                    }
                    Err(e) => {
                        error!("Failed to deserialize chain lock at height {}: {}", height, e);
                    }
                }
            }
        }

        Ok(chain_locks)
    }

    /// Get chain lock statistics
    pub async fn get_stats(&self) -> ChainLockStats {
        let by_height = self.chain_locks_by_height.read().await;
        let by_hash = self.chain_locks_by_hash.read().await;

        ChainLockStats {
            total_chain_locks: by_height.len(),
            cached_by_height: by_height.len(),
            cached_by_hash: by_hash.len(),
            highest_locked_height: by_height.keys().max().cloned(),
            lowest_locked_height: by_height.keys().min().cloned(),
            enforce_chain_locks: self.enforce_chain_locks,
        }
    }
}

/// Chain lock statistics
#[derive(Debug, Clone)]
pub struct ChainLockStats {
    pub total_chain_locks: usize,
    pub cached_by_height: usize,
    pub cached_by_hash: usize,
    pub highest_locked_height: Option<u32>,
    pub lowest_locked_height: Option<u32>,
    pub enforce_chain_locks: bool,
}

#[cfg(test)]
#[path = "chainlock_test.rs"]
mod chainlock_test;
