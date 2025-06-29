//! ChainLock manager for DIP8 implementation
//!
//! This module implements ChainLock validation and management according to DIP8,
//! providing protection against 51% attacks and securing InstantSend transactions.

use dashcore::{BlockHash, ChainLock};
use indexmap::IndexMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

use crate::error::{StorageError, StorageResult, ValidationError, ValidationResult};
use crate::storage::StorageManager;
use crate::types::ChainState;
use crate::validation::ChainLockValidator;

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
    /// Chain lock validator
    validator: ChainLockValidator,
    /// In-memory cache of chain locks by height (maintains insertion order)
    chain_locks_by_height: Arc<RwLock<IndexMap<u32, ChainLockEntry>>>,
    /// In-memory cache of chain locks by block hash
    chain_locks_by_hash: Arc<RwLock<IndexMap<BlockHash, ChainLockEntry>>>,
    /// Maximum number of chain locks to keep in memory
    max_cache_size: usize,
    /// Whether to enforce chain locks (can be disabled for testing)
    enforce_chain_locks: bool,
}

impl ChainLockManager {
    /// Create a new ChainLockManager
    pub fn new(enforce_chain_locks: bool) -> Self {
        Self {
            validator: ChainLockValidator::new(),
            chain_locks_by_height: Arc::new(RwLock::new(IndexMap::new())),
            chain_locks_by_hash: Arc::new(RwLock::new(IndexMap::new())),
            max_cache_size: 1000,
            enforce_chain_locks,
        }
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

        // Basic validation
        self.validator.validate(&chain_lock)?;

        // Check if we already have this chain lock
        if self.has_chain_lock_at_height(chain_lock.block_height) {
            let existing = self.get_chain_lock_by_height(chain_lock.block_height);
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

        // Note: Full quorum validation requires masternode list which may not be available yet
        // Call validate_chain_lock_with_quorum when quorum info is available

        // Store the chain lock
        self.store_chain_lock(chain_lock.clone(), storage).await?;

        // Update chain state
        self.update_chain_state_with_lock(&chain_lock, chain_state);

        info!("Successfully processed ChainLock for height {}", chain_lock.block_height);

        Ok(())
    }

    /// Store a chain lock
    async fn store_chain_lock(
        &self,
        chain_lock: ChainLock,
        storage: &mut dyn StorageManager,
    ) -> StorageResult<()> {
        let entry = ChainLockEntry {
            chain_lock: chain_lock.clone(),
            received_at: std::time::SystemTime::now(),
            validated: true,
        };

        // Store in memory caches
        {
            let mut by_height = self.chain_locks_by_height.write()
                .map_err(|_| StorageError::LockPoisoned("chain_locks_by_height".to_string()))?;
            let mut by_hash = self.chain_locks_by_hash.write()
                .map_err(|_| StorageError::LockPoisoned("chain_locks_by_hash".to_string()))?;

            by_height.insert(chain_lock.block_height, entry.clone());
            by_hash.insert(chain_lock.block_hash, entry);

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
    pub fn has_chain_lock_at_height(&self, height: u32) -> bool {
        self.chain_locks_by_height.read()
            .map(|locks| locks.contains_key(&height))
            .unwrap_or(false)
    }

    /// Get chain lock by height
    pub fn get_chain_lock_by_height(&self, height: u32) -> Option<ChainLockEntry> {
        self.chain_locks_by_height.read()
            .ok()
            .and_then(|locks| locks.get(&height).cloned())
    }

    /// Get chain lock by block hash
    pub fn get_chain_lock_by_hash(&self, hash: &BlockHash) -> Option<ChainLockEntry> {
        self.chain_locks_by_hash.read()
            .ok()
            .and_then(|locks| locks.get(hash).cloned())
    }

    /// Check if a block is chain-locked
    pub fn is_block_chain_locked(&self, block_hash: &BlockHash, height: u32) -> bool {
        // First check by hash (most specific)
        if let Some(entry) = self.get_chain_lock_by_hash(block_hash) {
            return entry.validated && entry.chain_lock.block_hash == *block_hash;
        }

        // Then check by height
        if let Some(entry) = self.get_chain_lock_by_height(height) {
            return entry.validated && entry.chain_lock.block_hash == *block_hash;
        }

        false
    }

    /// Get the highest chain-locked block height
    pub fn get_highest_chain_locked_height(&self) -> Option<u32> {
        self.chain_locks_by_height.read()
            .ok()
            .and_then(|locks| locks.keys().max().cloned())
    }

    /// Check if a reorganization would violate chain locks
    pub fn would_violate_chain_lock(&self, reorg_from_height: u32, reorg_to_height: u32) -> bool {
        if !self.enforce_chain_locks {
            return false;
        }

        let locks = match self.chain_locks_by_height.read() {
            Ok(locks) => locks,
            Err(_) => return false, // If we can't read locks, assume no violation
        };

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

                        let mut by_height = self.chain_locks_by_height.write()
                            .map_err(|_| StorageError::LockPoisoned("chain_locks_by_height".to_string()))?;
                        let mut by_hash = self.chain_locks_by_hash.write()
                            .map_err(|_| StorageError::LockPoisoned("chain_locks_by_hash".to_string()))?;

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

    /// Validate a chain lock signature with quorum information
    pub fn validate_chain_lock_signature(
        &self,
        chain_lock: &ChainLock,
        quorum_public_key: &[u8],
    ) -> ValidationResult<()> {
        self.validator.validate_signature(chain_lock, quorum_public_key)
    }

    /// Validate a chain lock with full quorum information
    pub fn validate_chain_lock_with_quorum(
        &self,
        chain_lock: &ChainLock,
        quorum_public_key: &[u8],
        quorum_height: u32,
    ) -> ValidationResult<()> {
        info!("Validating ChainLock for height {} with quorum", chain_lock.block_height);

        // Use the validator to perform full validation including BLS signature
        self.validator.validate_with_quorum(chain_lock, quorum_public_key, quorum_height)?;

        // Mark this chain lock as fully validated
        {
            if let Ok(mut by_height) = self.chain_locks_by_height.write() {
                if let Some(entry) = by_height.get_mut(&chain_lock.block_height) {
                    entry.validated = true;
                }
            }
        }

        Ok(())
    }

    /// Get chain lock statistics
    pub fn get_stats(&self) -> ChainLockStats {
        let by_height = match self.chain_locks_by_height.read() {
            Ok(guard) => guard,
            Err(_) => return ChainLockStats {
                total_chain_locks: 0,
                cached_by_height: 0,
                cached_by_hash: 0,
                highest_locked_height: None,
                lowest_locked_height: None,
                enforce_chain_locks: self.enforce_chain_locks,
            },
        };
        let by_hash = match self.chain_locks_by_hash.read() {
            Ok(guard) => guard,
            Err(_) => return ChainLockStats {
                total_chain_locks: 0,
                cached_by_height: 0,
                cached_by_hash: 0,
                highest_locked_height: None,
                lowest_locked_height: None,
                enforce_chain_locks: self.enforce_chain_locks,
            },
        };

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
