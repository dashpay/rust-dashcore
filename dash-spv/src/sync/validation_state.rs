//! Validation state management with snapshot and rollback capabilities.
//!
//! This module provides state management for validation operations, allowing
//! for safe rollback in case of validation failures and maintaining consistency
//! across sync operations.

use crate::error::{SyncError, SyncResult};
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::{sml::llmq_type::LLMQType, BlockHash};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tracing;

/// Maximum number of state snapshots to maintain
const MAX_SNAPSHOTS: usize = 10;

/// Validation state that can be snapshotted and rolled back
#[derive(Debug, Clone)]
pub struct ValidationState {
    /// Current sync height
    pub current_height: u32,
    /// Last validated height
    pub last_validated_height: u32,
    /// Pending validations by height
    pub pending_validations: HashMap<u32, PendingValidation>,
    /// Validation failures by height
    pub validation_failures: HashMap<u32, Vec<ValidationFailure>>,
    /// Active quorum validations
    pub active_quorum_validations: HashMap<(LLMQType, BlockHash), QuorumValidationState>,
    /// Chain lock validation checkpoint
    pub chain_lock_checkpoint: Option<ChainLockCheckpoint>,
    /// State version for consistency checking
    pub version: u64,
    /// Timestamp of last state update
    pub last_update: Instant,
}

/// Pending validation information
#[derive(Debug, Clone)]
pub struct PendingValidation {
    /// Height being validated
    pub height: u32,
    /// Type of validation
    pub validation_type: ValidationType,
    /// Number of retry attempts
    pub retry_count: usize,
    /// Time when validation was queued
    pub queued_at: Instant,
}

/// Types of validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationType {
    MasternodeList,
    ChainLock,
    Quorum(LLMQType),
    QRInfo,
}

/// Validation failure information
#[derive(Debug, Clone)]
pub struct ValidationFailure {
    /// Type of validation that failed
    pub validation_type: ValidationType,
    /// Error message
    pub error: String,
    /// Time of failure
    pub failed_at: Instant,
    /// Whether this failure is recoverable
    pub recoverable: bool,
}

/// State of quorum validation
#[derive(Debug, Clone)]
pub struct QuorumValidationState {
    /// Quorum type
    pub quorum_type: LLMQType,
    /// Quorum hash
    pub quorum_hash: BlockHash,
    /// Validation status
    pub status: QuorumValidationStatus,
    /// Number of members validated
    pub members_validated: usize,
    /// Total members
    pub total_members: usize,
}

/// Quorum validation status
#[derive(Debug, Clone, PartialEq)]
pub enum QuorumValidationStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
}

/// Chain lock validation checkpoint
#[derive(Debug, Clone)]
pub struct ChainLockCheckpoint {
    /// Height of the checkpoint
    pub height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Time when checkpoint was created
    pub created_at: Instant,
}

/// Validation state manager with snapshot and rollback support
pub struct ValidationStateManager {
    /// Current state
    current_state: ValidationState,
    /// State snapshots for rollback
    snapshots: VecDeque<StateSnapshot>,
    /// Maximum age for snapshots
    snapshot_ttl: Duration,
    /// State change listeners
    change_listeners: Vec<Box<dyn Fn(&ValidationState) + Send>>,
}

/// State snapshot for rollback
#[derive(Debug, Clone)]
struct StateSnapshot {
    /// The saved state
    state: ValidationState,
    /// Snapshot ID
    id: u64,
    /// When the snapshot was created
    created_at: Instant,
    /// Description of why snapshot was created
    description: String,
}

impl Default for ValidationState {
    fn default() -> Self {
        Self {
            current_height: 0,
            last_validated_height: 0,
            pending_validations: HashMap::new(),
            validation_failures: HashMap::new(),
            active_quorum_validations: HashMap::new(),
            chain_lock_checkpoint: None,
            version: 0,
            last_update: Instant::now(),
        }
    }
}

impl ValidationStateManager {
    /// Create a new validation state manager
    pub fn new() -> Self {
        Self {
            current_state: ValidationState::default(),
            snapshots: VecDeque::new(),
            snapshot_ttl: Duration::from_secs(3600), // 1 hour
            change_listeners: Vec::new(),
        }
    }

    /// Create a snapshot of the current state
    pub fn create_snapshot(&mut self, description: impl Into<String>) -> u64 {
        let snapshot_id = self.current_state.version;

        let snapshot = StateSnapshot {
            state: self.current_state.clone(),
            id: snapshot_id,
            created_at: Instant::now(),
            description: description.into(),
        };

        self.snapshots.push_back(snapshot);

        // Remove old snapshots
        while self.snapshots.len() > MAX_SNAPSHOTS {
            self.snapshots.pop_front();
        }

        // Clean up expired snapshots
        self.cleanup_expired_snapshots();

        tracing::debug!(
            "Created state snapshot {} with {} pending validations",
            snapshot_id,
            self.current_state.pending_validations.len()
        );

        snapshot_id
    }

    /// Rollback to a specific snapshot
    pub fn rollback_to_snapshot(&mut self, snapshot_id: u64) -> SyncResult<()> {
        let snapshot = self.snapshots.iter().find(|s| s.id == snapshot_id).ok_or_else(|| {
            SyncError::InvalidState(format!("Snapshot {} not found", snapshot_id))
        })?;

        let old_height = self.current_state.current_height;
        self.current_state = snapshot.state.clone();

        tracing::info!(
            "Rolled back state from height {} to {} (snapshot: {})",
            old_height,
            self.current_state.current_height,
            snapshot.description
        );

        // Notify listeners
        self.notify_listeners();

        Ok(())
    }

    /// Rollback to the most recent snapshot
    pub fn rollback_to_latest(&mut self) -> SyncResult<()> {
        let snapshot = self.snapshots.back().ok_or_else(|| {
            SyncError::InvalidState("No snapshots available for rollback".to_string())
        })?;

        let snapshot_id = snapshot.id;
        self.rollback_to_snapshot(snapshot_id)
    }

    /// Update current sync height
    pub fn update_sync_height(&mut self, height: u32) {
        self.current_state.current_height = height;
        self.current_state.version += 1;
        self.current_state.last_update = Instant::now();
        self.notify_listeners();
    }

    /// Add a pending validation
    pub fn add_pending_validation(&mut self, height: u32, validation_type: ValidationType) {
        self.current_state.pending_validations.insert(
            height,
            PendingValidation {
                height,
                validation_type,
                retry_count: 0,
                queued_at: Instant::now(),
            },
        );
        self.current_state.version += 1;
        self.notify_listeners();
    }

    /// Complete a pending validation
    pub fn complete_validation(&mut self, height: u32) -> Option<PendingValidation> {
        let result = self.current_state.pending_validations.remove(&height);
        if result.is_some() {
            self.current_state.last_validated_height =
                self.current_state.last_validated_height.max(height);
            self.current_state.version += 1;
            self.notify_listeners();
        }
        result
    }

    /// Record a validation failure
    pub fn record_validation_failure(
        &mut self,
        height: u32,
        validation_type: ValidationType,
        error: String,
        recoverable: bool,
    ) {
        let failure = ValidationFailure {
            validation_type,
            error,
            failed_at: Instant::now(),
            recoverable,
        };

        self.current_state.validation_failures.entry(height).or_insert_with(Vec::new).push(failure);

        self.current_state.version += 1;
        self.notify_listeners();
    }

    /// Update quorum validation state
    pub fn update_quorum_validation(
        &mut self,
        quorum_type: LLMQType,
        quorum_hash: BlockHash,
        status: QuorumValidationStatus,
    ) {
        let key = (quorum_type, quorum_hash);

        if let Some(state) = self.current_state.active_quorum_validations.get_mut(&key) {
            state.status = status;
        } else {
            self.current_state.active_quorum_validations.insert(
                key,
                QuorumValidationState {
                    quorum_type,
                    quorum_hash,
                    status,
                    members_validated: 0,
                    total_members: 0,
                },
            );
        }

        self.current_state.version += 1;
        self.notify_listeners();
    }

    /// Set chain lock checkpoint
    pub fn set_chain_lock_checkpoint(&mut self, height: u32, block_hash: BlockHash) {
        self.current_state.chain_lock_checkpoint = Some(ChainLockCheckpoint {
            height,
            block_hash,
            created_at: Instant::now(),
        });
        self.current_state.version += 1;
        self.notify_listeners();
    }

    /// Check state consistency
    pub fn validate_consistency(&self) -> SyncResult<()> {
        // Check that last validated height doesn't exceed current height
        if self.current_state.last_validated_height > self.current_state.current_height {
            return Err(SyncError::InvalidState(format!(
                "Last validated height {} exceeds current height {}",
                self.current_state.last_validated_height, self.current_state.current_height
            )));
        }

        // Check that pending validations are within reasonable range
        for (height, _) in &self.current_state.pending_validations {
            if *height > self.current_state.current_height + 1000 {
                return Err(SyncError::InvalidState(format!(
                    "Pending validation at height {} is too far ahead of current height {}",
                    height, self.current_state.current_height
                )));
            }
        }

        // Check chain lock checkpoint consistency
        if let Some(checkpoint) = &self.current_state.chain_lock_checkpoint {
            if checkpoint.height > self.current_state.current_height {
                return Err(SyncError::InvalidState(format!(
                    "Chain lock checkpoint height {} exceeds current height {}",
                    checkpoint.height, self.current_state.current_height
                )));
            }
        }

        // Validate active quorum states
        for (key, state) in &self.current_state.active_quorum_validations {
            if state.members_validated > state.total_members {
                return Err(SyncError::InvalidState(format!(
                    "Quorum {:?} has more validated members ({}) than total members ({})",
                    key, state.members_validated, state.total_members
                )));
            }
        }

        // Check for expired pending validations
        let now = Instant::now();
        let stale_timeout = Duration::from_secs(300); // 5 minutes
        for (height, pending) in &self.current_state.pending_validations {
            if now.duration_since(pending.queued_at) > stale_timeout {
                return Err(SyncError::InvalidState(format!(
                    "Pending validation at height {} has been queued for too long",
                    height
                )));
            }
        }

        Ok(())
    }

    /// Get current state
    pub fn current_state(&self) -> &ValidationState {
        &self.current_state
    }

    /// Get mutable current state
    pub fn current_state_mut(&mut self) -> &mut ValidationState {
        &mut self.current_state
    }

    /// Add a state change listener
    pub fn add_listener<F>(&mut self, listener: F)
    where
        F: Fn(&ValidationState) + Send + 'static,
    {
        self.change_listeners.push(Box::new(listener));
    }

    /// Clean up expired snapshots
    fn cleanup_expired_snapshots(&mut self) {
        let now = Instant::now();
        self.snapshots
            .retain(|snapshot| now.duration_since(snapshot.created_at) < self.snapshot_ttl);
    }

    /// Notify all listeners of state change
    fn notify_listeners(&self) {
        for listener in &self.change_listeners {
            listener(&self.current_state);
        }
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> ValidationStats {
        ValidationStats {
            pending_validations: self.current_state.pending_validations.len(),
            total_failures: self.current_state.validation_failures.values().map(|v| v.len()).sum(),
            active_quorum_validations: self.current_state.active_quorum_validations.len(),
            snapshots_available: self.snapshots.len(),
            state_version: self.current_state.version,
        }
    }
}

/// Validation statistics
#[derive(Debug, Clone)]
pub struct ValidationStats {
    /// Number of pending validations
    pub pending_validations: usize,
    /// Total validation failures
    pub total_failures: usize,
    /// Number of active quorum validations
    pub active_quorum_validations: usize,
    /// Number of snapshots available
    pub snapshots_available: usize,
    /// Current state version
    pub state_version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_and_rollback() {
        let mut manager = ValidationStateManager::new();

        // Update state
        manager.update_sync_height(100);
        manager.add_pending_validation(101, ValidationType::MasternodeList);

        // Create snapshot
        let snapshot_id = manager.create_snapshot("Before validation");

        // Make more changes
        manager.update_sync_height(200);
        manager.record_validation_failure(
            150,
            ValidationType::ChainLock,
            "Test failure".to_string(),
            true,
        );

        assert_eq!(manager.current_state().current_height, 200);
        assert_eq!(manager.current_state().validation_failures.len(), 1);

        // Rollback
        manager.rollback_to_snapshot(snapshot_id).unwrap();

        assert_eq!(manager.current_state().current_height, 100);
        assert_eq!(manager.current_state().validation_failures.len(), 0);
        assert_eq!(manager.current_state().pending_validations.len(), 1);
    }

    #[test]
    fn test_consistency_validation() {
        let mut manager = ValidationStateManager::new();

        manager.update_sync_height(100);
        manager.current_state_mut().last_validated_height = 50;

        // Should pass
        assert!(manager.validate_consistency().is_ok());

        // Set invalid state
        manager.current_state_mut().last_validated_height = 200;

        // Should fail
        assert!(manager.validate_consistency().is_err());
    }
}
