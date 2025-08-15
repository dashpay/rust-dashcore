//! Chain lock validation for enhanced security.
//!
//! This module provides comprehensive validation of chain locks, including
//! historical verification and caching for performance optimization.

use crate::error::{SyncError, SyncResult};
use crate::storage::StorageManager;
use dashcore::{
    bls_sig_utils::{BLSPublicKey, BLSSignature},
    sml::{llmq_type::LLMQType, masternode_list_engine::MasternodeListEngine},
    BlockHash, ChainLock,
};
use dashcore_hashes::Hash;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tracing;

/// Configuration for chain lock validation
#[derive(Debug, Clone)]
pub struct ChainLockValidationConfig {
    /// Enable chain lock validation
    pub enabled: bool,
    /// Maximum number of chain locks to cache
    pub cache_size: usize,
    /// TTL for cached validation results
    pub cache_ttl: Duration,
    /// Validate historical chain locks
    pub validate_historical: bool,
    /// Maximum depth for historical validation
    pub max_historical_depth: u32,
    /// Required LLMQ type for chain lock validation
    pub required_llmq_type: LLMQType,
}

impl Default for ChainLockValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: 1000,
            cache_ttl: Duration::from_secs(3600), // 1 hour
            validate_historical: true,
            max_historical_depth: 1000,
            required_llmq_type: LLMQType::Llmqtype400_60, // ChainLocks quorum type
        }
    }
}

/// Result of chain lock validation
#[derive(Debug, Clone)]
pub struct ChainLockValidationResult {
    /// Whether the chain lock is valid
    pub is_valid: bool,
    /// Height of the chain lock
    pub height: u32,
    /// Quorum hash used for validation
    pub quorum_hash: Option<BlockHash>,
    /// Validation error if any
    pub error: Option<String>,
    /// Time taken for validation
    pub validation_time: Duration,
}

/// Chain lock validator with caching and historical verification
pub struct ChainLockValidator {
    /// Configuration
    config: ChainLockValidationConfig,
    /// Cache of validated chain locks
    validation_cache: HashMap<BlockHash, CachedChainLockResult>,
    /// LRU queue for cache eviction
    cache_lru: VecDeque<BlockHash>,
    /// Statistics
    stats: ChainLockStats,
}

/// Cached chain lock validation result
#[derive(Debug, Clone)]
struct CachedChainLockResult {
    is_valid: bool,
    height: u32,
    timestamp: Instant,
}

/// Chain lock validation statistics
#[derive(Debug, Default)]
struct ChainLockStats {
    total_validations: usize,
    successful_validations: usize,
    failed_validations: usize,
    cache_hits: usize,
    cache_misses: usize,
    historical_validations: usize,
}

impl ChainLockValidator {
    /// Create a new chain lock validator
    pub fn new(config: ChainLockValidationConfig) -> Self {
        Self {
            config,
            validation_cache: HashMap::new(),
            cache_lru: VecDeque::new(),
            stats: ChainLockStats::default(),
        }
    }

    /// Validate a chain lock
    pub async fn validate_chain_lock(
        &mut self,
        chain_lock: &ChainLock,
        engine: &MasternodeListEngine,
        storage: &dyn StorageManager,
    ) -> SyncResult<ChainLockValidationResult> {
        if !self.config.enabled {
            return Ok(ChainLockValidationResult {
                is_valid: true,
                height: chain_lock.block_height,
                quorum_hash: None,
                error: None,
                validation_time: Duration::from_secs(0),
            });
        }

        let start = Instant::now();
        let block_hash = chain_lock.block_hash;

        // Check cache first
        let cached_result = self.get_cached_result(&block_hash).cloned();
        if let Some(cached) = cached_result {
            self.stats.cache_hits += 1;
            return Ok(ChainLockValidationResult {
                is_valid: cached.is_valid,
                height: cached.height,
                quorum_hash: None,
                error: if cached.is_valid {
                    None
                } else {
                    Some("Cached validation failure".to_string())
                },
                validation_time: start.elapsed(),
            });
        }

        self.stats.cache_misses += 1;

        // Perform validation
        let result = self.perform_chain_lock_validation(chain_lock, engine, storage).await?;

        // Cache the result
        self.cache_result(block_hash, result.is_valid, result.height);

        // Update statistics
        self.stats.total_validations += 1;
        if result.is_valid {
            self.stats.successful_validations += 1;
        } else {
            self.stats.failed_validations += 1;
        }

        Ok(result)
    }

    /// Perform actual chain lock validation
    async fn perform_chain_lock_validation(
        &mut self,
        chain_lock: &ChainLock,
        engine: &MasternodeListEngine,
        storage: &dyn StorageManager,
    ) -> SyncResult<ChainLockValidationResult> {
        let start = Instant::now();

        // Get the block header to verify height
        let header = storage
            .get_header(chain_lock.block_height)
            .await
            .map_err(|e| {
                SyncError::Storage(format!(
                    "Failed to get header at height {}: {}",
                    chain_lock.block_height, e
                ))
            })?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "Header not found at height {}",
                    chain_lock.block_height
                ))
            })?;

        // Verify block hash matches
        if header.block_hash() != chain_lock.block_hash {
            return Ok(ChainLockValidationResult {
                is_valid: false,
                height: chain_lock.block_height,
                quorum_hash: None,
                error: Some(format!("Block hash mismatch at height {}", chain_lock.block_height)),
                validation_time: start.elapsed(),
            });
        }

        // Use the engine's built-in chain lock verification
        let is_valid = self.verify_chain_lock_with_engine(chain_lock, engine)?;

        Ok(ChainLockValidationResult {
            is_valid,
            height: chain_lock.block_height,
            quorum_hash: None, // Engine doesn't expose which quorum was used
            error: if is_valid {
                None
            } else {
                Some("Chain lock verification failed".to_string())
            },
            validation_time: start.elapsed(),
        })
    }

    /// Find the appropriate quorum for chain lock validation
    fn find_chain_lock_quorum(
        &self,
        height: u32,
        engine: &MasternodeListEngine,
    ) -> SyncResult<Option<(BlockHash, BLSPublicKey)>> {
        // ChainLocks use the LLMQ at the tip of the chain
        // We need to find the most recent LLMQ of the required type

        // Get the masternode list at or before the height
        let mn_list_height = engine.masternode_lists.range(..=height).rev().next().map(|(h, _)| *h);

        if let Some(list_height) = mn_list_height {
            if let Some(mn_list) = engine.masternode_lists.get(&list_height) {
                // Find the chain lock quorum
                if let Some(quorums) = mn_list.quorums.get(&self.config.required_llmq_type) {
                    // Get the most recent quorum
                    if let Some((quorum_hash, entry)) = quorums.iter().next() {
                        // Get public key from the quorum entry
                        return Ok(Some((*quorum_hash, entry.quorum_entry.quorum_public_key)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Verify chain lock signature using the engine's built-in verification
    fn verify_chain_lock_with_engine(
        &self,
        chain_lock: &ChainLock,
        engine: &MasternodeListEngine,
    ) -> SyncResult<bool> {
        // Use the engine's built-in chain lock verification
        match engine.verify_chain_lock(chain_lock) {
            Ok(()) => {
                tracing::debug!(
                    "Chain lock verified successfully for block {:x} at height {}",
                    chain_lock.block_hash,
                    chain_lock.block_height
                );
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(
                    "Chain lock verification failed for block {:x} at height {}: {}",
                    chain_lock.block_hash,
                    chain_lock.block_height,
                    e
                );
                Ok(false)
            }
        }
    }

    /// Validate historical chain locks
    pub async fn validate_historical_chain_locks(
        &mut self,
        start_height: u32,
        end_height: u32,
        engine: &MasternodeListEngine,
        storage: &dyn StorageManager,
    ) -> SyncResult<Vec<ChainLockValidationResult>> {
        if !self.config.validate_historical {
            return Ok(Vec::new());
        }

        let depth = end_height.saturating_sub(start_height);
        if depth > self.config.max_historical_depth {
            return Err(SyncError::Validation(format!(
                "Historical validation depth {} exceeds maximum {}",
                depth, self.config.max_historical_depth
            )));
        }

        self.stats.historical_validations += 1;
        let mut results = Vec::new();

        tracing::info!(
            "Starting historical chain lock validation from height {} to {}",
            start_height,
            end_height
        );

        for height in start_height..=end_height {
            // Get chain lock at height from storage
            if let Ok(Some(chain_lock)) = storage.load_chain_lock(height).await {
                let result = self.validate_chain_lock(&chain_lock, engine, storage).await?;
                results.push(result);
            }
        }

        tracing::info!("Completed historical validation of {} chain locks", results.len());

        Ok(results)
    }

    /// Get cached validation result
    fn get_cached_result(&self, block_hash: &BlockHash) -> Option<&CachedChainLockResult> {
        self.validation_cache
            .get(block_hash)
            .filter(|cached| cached.timestamp.elapsed() < self.config.cache_ttl)
    }

    /// Cache a validation result
    fn cache_result(&mut self, block_hash: BlockHash, is_valid: bool, height: u32) {
        // Remove oldest entry if cache is full
        if self.validation_cache.len() >= self.config.cache_size {
            if let Some(oldest) = self.cache_lru.pop_front() {
                self.validation_cache.remove(&oldest);
            }
        }

        self.validation_cache.insert(
            block_hash,
            CachedChainLockResult {
                is_valid,
                height,
                timestamp: Instant::now(),
            },
        );

        self.cache_lru.push_back(block_hash);
    }

    /// Clear the validation cache
    pub fn clear_cache(&mut self) {
        self.validation_cache.clear();
        self.cache_lru.clear();
    }

    /// Get validation statistics
    pub fn stats(&self) -> &ChainLockStats {
        &self.stats
    }

    /// Get cache hit rate
    pub fn cache_hit_rate(&self) -> f64 {
        let total_lookups = self.stats.cache_hits + self.stats.cache_misses;
        if total_lookups > 0 {
            self.stats.cache_hits as f64 / total_lookups as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_lock_validator_creation() {
        let config = ChainLockValidationConfig::default();
        let validator = ChainLockValidator::new(config);

        assert_eq!(validator.stats().total_validations, 0);
        assert_eq!(validator.cache_hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_eviction() {
        let mut config = ChainLockValidationConfig::default();
        config.cache_size = 2;

        let mut validator = ChainLockValidator::new(config);

        // Add entries to fill cache
        let hash1 = BlockHash::from([0u8; 32]);
        let hash2 = BlockHash::from([1; 32]);
        let hash3 = BlockHash::from([2; 32]);

        validator.cache_result(hash1, true, 100);
        validator.cache_result(hash2, true, 101);

        assert_eq!(validator.validation_cache.len(), 2);

        // Adding third entry should evict first
        validator.cache_result(hash3, true, 102);

        assert_eq!(validator.validation_cache.len(), 2);
        assert!(!validator.validation_cache.contains_key(&hash1));
        assert!(validator.validation_cache.contains_key(&hash2));
        assert!(validator.validation_cache.contains_key(&hash3));
    }
}
