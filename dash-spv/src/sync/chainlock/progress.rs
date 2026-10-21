use crate::sync::SyncState;
use std::fmt;
use std::time::Instant;

/// Progress for ChainLock synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainLockProgress {
    /// Current sync state.
    state: SyncState,
    /// The highest block height of a valid ChainLock.
    best_validated_height: u32,
    /// Number of ChainLocks successfully verified.
    valid: u32,
    /// Number of ChainLocks that failed validation.
    invalid: u32,
    /// The last time a ChainLock was processed or the last manager state change.
    last_activity: Instant,
}

impl Default for ChainLockProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            best_validated_height: 0,
            valid: 0,
            invalid: 0,
            last_activity: Instant::now(),
        }
    }
}

impl ChainLockProgress {
    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state
    }
    /// Get the highest block height of a valid ChainLock.
    pub fn best_validated_height(&self) -> u32 {
        self.best_validated_height
    }
    /// Number of ChainLocks successfully verified.
    pub fn valid(&self) -> u32 {
        self.valid
    }
    /// Number of ChainLocks dropped after max retries.
    pub fn invalid(&self) -> u32 {
        self.invalid
    }
    /// The last time a ChainLock was processed or the last manager state change.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
    /// Update the sync state and bump the last activity time.
    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }
    /// Update the highest block height of a valid ChainLock.
    pub fn update_best_validated_height(&mut self, height: u32) {
        self.best_validated_height = height;
        self.bump_last_activity();
    }
    /// Add a number to the valid counter.
    pub fn add_valid(&mut self, count: u32) {
        self.valid += count;
        self.bump_last_activity();
    }
    /// Add a number to the invalid counter.
    pub fn add_invalid(&mut self, count: u32) {
        self.invalid += count;
        self.bump_last_activity();
    }
    /// Bump the last activity time.
    pub fn bump_last_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Display for ChainLockProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} best_validated_height: {} | valid: {}, invalid: {}, last_activity: {}s",
            self.state,
            self.best_validated_height,
            self.valid,
            self.invalid,
            self.last_activity.elapsed().as_secs()
        )
    }
}
