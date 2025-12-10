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
    /// Number of ChainLocks pending for validation.
    pending: usize,
    /// Number of ChainLocks processed in the current sync session.
    processed: u32,
    /// The last time a ChainLock was processed or the last manager state change.
    last_activity: Instant,
}

impl Default for ChainLockProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            best_validated_height: 0,
            pending: 0,
            processed: 0,
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
    /// Number of ChainLocks pending for validation.
    pub fn pending(&self) -> usize {
        self.pending
    }
    /// Number of ChainLocks processed in the current sync session.
    pub fn processed(&self) -> u32 {
        self.processed
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
    /// Update the number of ChainLocks pending for validation.
    pub fn update_pending(&mut self, count: usize) {
        self.pending = count;
        self.bump_last_activity();
    }
    /// Add a number to the processed counter.
    pub fn add_processed(&mut self, count: u32) {
        self.processed += count;
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
            "{:?} best_validated_height: {} | processed: {}, pending: {}, last_activity: {}s",
            self.state,
            self.best_validated_height,
            self.processed,
            self.pending,
            self.last_activity.elapsed().as_secs()
        )
    }
}
