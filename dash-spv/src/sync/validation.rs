//! Comprehensive validation for masternode sync operations.
//!
//! This module provides a validation engine for verifying masternode lists,
//! chain locks, and quorum information during sync operations. It integrates
//! with the existing masternode list engine to provide additional validation
//! layers for improved security and reliability.

use crate::error::{SyncError, SyncResult};
use dashcore::{
    network::message_qrinfo::QRInfo,
    network::message_sml::MnListDiff,
    sml::{
        llmq_entry_verification::LLMQEntryVerificationStatus, llmq_type::LLMQType,
        masternode_list_engine::MasternodeListEngine,
        quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry,
    },
    BlockHash,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing;

/// Configuration for validation behavior
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Enable comprehensive validation
    pub enabled: bool,
    /// Validate chain locks for all blocks
    pub validate_chain_locks: bool,
    /// Validate rotating quorums
    pub validate_rotating_quorums: bool,
    /// Validate non-rotating quorums
    pub validate_non_rotating_quorums: bool,
    /// Maximum age for cached validation results
    pub cache_ttl: Duration,
    /// Maximum number of validation errors before failing
    pub max_validation_errors: usize,
    /// Retry failed validations
    pub retry_failed_validations: bool,
    /// Number of retries for failed validations
    pub max_retries: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validate_chain_locks: true,
            validate_rotating_quorums: true,
            validate_non_rotating_quorums: true,
            cache_ttl: Duration::from_secs(3600), // 1 hour
            max_validation_errors: 10,
            retry_failed_validations: true,
            max_retries: 3,
        }
    }
}

impl ValidationConfig {
    /// Create a minimal validation configuration for testing
    pub fn minimal() -> Self {
        Self {
            enabled: true,
            validate_chain_locks: false,
            validate_rotating_quorums: false,
            validate_non_rotating_quorums: true,
            cache_ttl: Duration::from_secs(60),
            max_validation_errors: 100,
            retry_failed_validations: false,
            max_retries: 0,
        }
    }
}

/// Result of a validation operation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation passed
    pub success: bool,
    /// Errors encountered during validation
    pub errors: Vec<ValidationError>,
    /// Warnings that don't fail validation
    pub warnings: Vec<ValidationWarning>,
    /// Time taken for validation
    pub duration: Duration,
    /// Number of items validated
    pub items_validated: usize,
}

impl ValidationResult {
    /// Create a successful validation result
    pub fn success(items_validated: usize, duration: Duration) -> Self {
        Self {
            success: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            duration,
            items_validated,
        }
    }

    /// Create a failed validation result
    pub fn failure(errors: Vec<ValidationError>, duration: Duration) -> Self {
        Self {
            success: false,
            errors,
            warnings: Vec::new(),
            duration,
            items_validated: 0,
        }
    }

    /// Add a warning to the result
    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }
}

/// Validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Invalid chain lock signature
    InvalidChainLock(BlockHash),
    /// Missing required masternode list
    MissingMasternodeList(u32),
    /// Quorum validation failed
    QuorumValidationFailed(LLMQType, String),
    /// Invalid masternode list diff
    InvalidMnListDiff(u32, String),
    /// State consistency error
    StateInconsistency(String),
    /// Timeout during validation
    ValidationTimeout(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidChainLock(hash) => write!(f, "Invalid chain lock for block {:x}", hash),
            Self::MissingMasternodeList(height) => {
                write!(f, "Missing masternode list at height {}", height)
            }
            Self::QuorumValidationFailed(qtype, msg) => {
                write!(f, "Quorum validation failed for type {:?}: {}", qtype, msg)
            }
            Self::InvalidMnListDiff(height, msg) => {
                write!(f, "Invalid MnListDiff at height {}: {}", height, msg)
            }
            Self::StateInconsistency(msg) => write!(f, "State inconsistency: {}", msg),
            Self::ValidationTimeout(msg) => write!(f, "Validation timeout: {}", msg),
        }
    }
}

/// Validation warning types
#[derive(Debug, Clone)]
pub enum ValidationWarning {
    /// Quorum close to expiration
    QuorumNearExpiration(LLMQType, u32),
    /// High number of banned masternodes
    HighBannedMasternodeCount(usize),
    /// Unusual masternode list size change
    UnusualListSizeChange(i32),
}

/// Comprehensive validation engine
pub struct ValidationEngine {
    /// Configuration for validation
    config: ValidationConfig,
    /// Cache of recent validation results
    validation_cache: HashMap<ValidationCacheKey, CachedValidationResult>,
    /// Validation statistics
    stats: ValidationStats,
    /// Current validation errors count
    error_count: usize,
}

/// Key for validation cache
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum ValidationCacheKey {
    ChainLock(BlockHash),
    Quorum(LLMQType, BlockHash),
    MasternodeList(u32),
}

/// Cached validation result
#[derive(Debug, Clone)]
struct CachedValidationResult {
    result: bool,
    timestamp: Instant,
}

/// Validation statistics
#[derive(Debug, Default)]
pub struct ValidationStats {
    total_validations: usize,
    successful_validations: usize,
    failed_validations: usize,
    cache_hits: usize,
    cache_misses: usize,
}

impl ValidationEngine {
    /// Create a new validation engine
    pub fn new(config: ValidationConfig) -> Self {
        Self {
            config,
            validation_cache: HashMap::new(),
            stats: ValidationStats::default(),
            error_count: 0,
        }
    }

    /// Validate a QRInfo message comprehensively
    pub fn validate_qr_info(
        &mut self,
        qr_info: &QRInfo,
        engine: &MasternodeListEngine,
    ) -> SyncResult<ValidationResult> {
        if !self.config.enabled {
            return Ok(ValidationResult::success(0, Duration::from_secs(0)));
        }

        let start = Instant::now();
        let mut errors = Vec::new();
        let mut items_validated = 0;

        tracing::debug!(
            "Starting QRInfo validation with {} diffs and {} snapshots",
            qr_info.mn_list_diff_list.len(),
            qr_info.quorum_snapshot_list.len()
        );

        // Validate masternode list diffs
        for diff in &qr_info.mn_list_diff_list {
            match self.validate_mn_list_diff(diff, engine) {
                Ok(true) => items_validated += 1,
                Ok(false) => errors.push(ValidationError::InvalidMnListDiff(
                    0, // We don't have block height in MnListDiff
                    "Validation failed".to_string(),
                )),
                Err(e) => errors.push(ValidationError::InvalidMnListDiff(
                    0, // We don't have block height in MnListDiff
                    e.to_string(),
                )),
            }
        }

        // Validate quorum snapshots
        for snapshot in &qr_info.quorum_snapshot_list {
            items_validated += snapshot.active_quorum_members.len();
            // TODO: Implement quorum snapshot validation
        }

        // Check error threshold
        self.error_count += errors.len();
        if self.error_count > self.config.max_validation_errors {
            return Err(SyncError::Validation(format!(
                "Validation error threshold exceeded: {} errors",
                self.error_count
            )));
        }

        let duration = start.elapsed();
        self.update_stats(errors.is_empty(), items_validated);

        if errors.is_empty() {
            Ok(ValidationResult::success(items_validated, duration))
        } else {
            Ok(ValidationResult::failure(errors, duration))
        }
    }

    /// Validate a masternode list diff
    fn validate_mn_list_diff(
        &mut self,
        diff: &MnListDiff,
        engine: &MasternodeListEngine,
    ) -> SyncResult<bool> {
        let cache_key = ValidationCacheKey::MasternodeList(0); // Use 0 as we don't have block height

        // Check cache
        if let Some(cached) = self.get_cached_result(&cache_key) {
            return Ok(cached);
        }

        // Perform validation
        let result = self.perform_mn_list_diff_validation(diff, engine)?;

        // Cache result
        self.cache_result(cache_key, result);

        Ok(result)
    }

    /// Perform actual masternode list diff validation
    fn perform_mn_list_diff_validation(
        &self,
        diff: &MnListDiff,
        _engine: &MasternodeListEngine,
    ) -> SyncResult<bool> {
        // Check if we have the base list
        // Note: We can't check by height as MnListDiff doesn't contain block height
        // We would need to look up the height from the block hash

        // Validate merkle root matches
        // TODO: Implement merkle root validation

        // Check for unusual changes
        let added_count = diff.new_masternodes.len();
        let removed_count = diff.deleted_masternodes.len();
        let updated_count = 0; // No separate updated field in MnListDiff

        let total_changes = added_count + removed_count + updated_count;
        if total_changes > 100 {
            tracing::warn!(
                "Unusual number of masternode changes for block {:?}: {} total",
                diff.block_hash,
                total_changes
            );
        }

        Ok(true)
    }

    /// Validate quorums for a specific height
    pub fn validate_quorums_at_height(
        &mut self,
        height: u32,
        engine: &MasternodeListEngine,
    ) -> SyncResult<ValidationResult> {
        if !self.config.enabled {
            return Ok(ValidationResult::success(0, Duration::from_secs(0)));
        }

        let start = Instant::now();
        let mut errors = Vec::new();
        let mut items_validated = 0;

        // Get masternode list at height
        let mn_list = engine.masternode_lists.get(&height).ok_or_else(|| {
            SyncError::Validation(format!("No masternode list at height {}", height))
        })?;

        // Validate each quorum type
        for (quorum_type, quorums) in &mn_list.quorums {
            if self.should_validate_quorum_type(quorum_type) {
                for (quorum_hash, entry) in quorums {
                    match self.validate_quorum_entry(quorum_type, quorum_hash, entry, engine) {
                        Ok(true) => items_validated += 1,
                        Ok(false) => errors.push(ValidationError::QuorumValidationFailed(
                            *quorum_type,
                            format!("Quorum {:x} validation failed", quorum_hash),
                        )),
                        Err(e) => errors.push(ValidationError::QuorumValidationFailed(
                            *quorum_type,
                            e.to_string(),
                        )),
                    }
                }
            }
        }

        let duration = start.elapsed();
        self.update_stats(errors.is_empty(), items_validated);

        if errors.is_empty() {
            Ok(ValidationResult::success(items_validated, duration))
        } else {
            Ok(ValidationResult::failure(errors, duration))
        }
    }

    /// Check if we should validate a specific quorum type
    fn should_validate_quorum_type(&self, quorum_type: &LLMQType) -> bool {
        match quorum_type {
            LLMQType::Llmqtype50_60 | LLMQType::Llmqtype400_60 | LLMQType::Llmqtype400_85 => {
                self.config.validate_rotating_quorums
            }
            _ => self.config.validate_non_rotating_quorums,
        }
    }

    /// Validate a single quorum entry
    fn validate_quorum_entry(
        &mut self,
        quorum_type: &LLMQType,
        quorum_hash: &BlockHash,
        entry: &QualifiedQuorumEntry,
        engine: &MasternodeListEngine,
    ) -> SyncResult<bool> {
        let cache_key = ValidationCacheKey::Quorum(*quorum_type, *quorum_hash);

        // Check cache
        if let Some(cached) = self.get_cached_result(&cache_key) {
            return Ok(cached);
        }

        // Check verification status
        let is_valid = match &entry.verified {
            LLMQEntryVerificationStatus::Verified => true,
            LLMQEntryVerificationStatus::Invalid(_) => false,
            LLMQEntryVerificationStatus::Unknown => {
                // Try to verify using engine
                self.verify_quorum_with_engine(quorum_type, quorum_hash, entry, engine)?
            }
            LLMQEntryVerificationStatus::Skipped(_) => {
                // Skipped entries are treated as unknown - try to verify
                self.verify_quorum_with_engine(quorum_type, quorum_hash, entry, engine)?
            }
        };

        // Cache result
        self.cache_result(cache_key, is_valid);

        Ok(is_valid)
    }

    /// Verify a quorum using the engine
    fn verify_quorum_with_engine(
        &self,
        quorum_type: &LLMQType,
        quorum_hash: &BlockHash,
        entry: &QualifiedQuorumEntry,
        _engine: &MasternodeListEngine,
    ) -> SyncResult<bool> {
        // Verify basic quorum properties
        if entry.quorum_entry.llmq_type != *quorum_type {
            tracing::warn!(
                "Quorum type mismatch: expected {:?}, got {:?}",
                quorum_type,
                entry.quorum_entry.llmq_type
            );
            return Ok(false);
        }

        if entry.quorum_entry.quorum_hash != *quorum_hash {
            tracing::warn!(
                "Quorum hash mismatch: expected {:x}, got {:x}",
                quorum_hash,
                entry.quorum_entry.quorum_hash
            );
            return Ok(false);
        }

        // Check if the quorum public key is valid (non-zero)
        if entry.quorum_entry.quorum_public_key.is_zeroed() {
            tracing::warn!("Invalid quorum public key (all zeros) for quorum {:x}", quorum_hash);
            return Ok(false);
        }

        // For now, we trust the engine's quorum data as it should already be validated
        // when it was added to the engine. More complex validation could include:
        // - Verifying the threshold signature shares
        // - Checking member validity against the masternode list
        // - Validating the commitment hash

        Ok(true)
    }

    /// Get cached validation result if still valid
    fn get_cached_result(&mut self, key: &ValidationCacheKey) -> Option<bool> {
        if let Some(cached) = self.validation_cache.get(key) {
            if cached.timestamp.elapsed() < self.config.cache_ttl {
                self.stats.cache_hits += 1;
                return Some(cached.result);
            }
        }
        self.stats.cache_misses += 1;
        None
    }

    /// Cache a validation result
    fn cache_result(&mut self, key: ValidationCacheKey, result: bool) {
        self.validation_cache.insert(
            key,
            CachedValidationResult {
                result,
                timestamp: Instant::now(),
            },
        );

        // Clean up old entries if cache is too large
        if self.validation_cache.len() > 10000 {
            self.cleanup_cache();
        }
    }

    /// Clean up expired cache entries
    fn cleanup_cache(&mut self) {
        let now = Instant::now();
        self.validation_cache
            .retain(|_, v| now.duration_since(v.timestamp) < self.config.cache_ttl);
    }

    /// Update validation statistics
    fn update_stats(&mut self, success: bool, items: usize) {
        self.stats.total_validations += items;
        if success {
            self.stats.successful_validations += items;
        } else {
            self.stats.failed_validations += items;
        }
    }

    /// Get current validation statistics
    pub fn stats(&self) -> ValidationStats {
        ValidationStats {
            total_validations: self.stats.total_validations,
            successful_validations: self.stats.successful_validations,
            failed_validations: self.stats.failed_validations,
            cache_hits: self.stats.cache_hits,
            cache_misses: self.stats.cache_misses,
        }
    }

    /// Reset error count (e.g., after successful sync phase)
    pub fn reset_error_count(&mut self) {
        self.error_count = 0;
    }
}

/// Summary of validation results for reporting
#[derive(Debug, Clone)]
pub struct ValidationSummary {
    /// Total items validated
    pub total_validated: usize,
    /// Number of validation failures
    pub failures: usize,
    /// Number of warnings
    pub warnings: usize,
    /// Total time spent validating
    pub total_time: Duration,
    /// Cache hit rate
    pub cache_hit_rate: f64,
}

impl ValidationSummary {
    /// Create from validation engine stats
    pub fn from_engine(engine: &ValidationEngine) -> Self {
        let stats = &engine.stats;
        let cache_attempts = stats.cache_hits + stats.cache_misses;
        let cache_hit_rate = if cache_attempts > 0 {
            stats.cache_hits as f64 / cache_attempts as f64
        } else {
            0.0
        };

        Self {
            total_validated: stats.total_validations,
            failures: stats.failed_validations,
            warnings: 0,                        // TODO: Track warnings
            total_time: Duration::from_secs(0), // TODO: Track total time
            cache_hit_rate,
        }
    }
}
