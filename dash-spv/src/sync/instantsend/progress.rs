use crate::sync::SyncState;
use std::fmt;
use std::time::Instant;

/// Progress for InstantSend synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct InstantSendProgress {
    /// Current sync state.
    state: SyncState,
    /// Number of InstantSend locks pending for validation.
    pending: usize,
    /// Number of InstantSend locks successfully verified.
    valid: u32,
    /// Number of InstantSend locks dropped after max retries (couldn't be validated).
    invalid: u32,
    /// The last time an InstantLock was processed or the last manager state change.
    last_activity: Instant,
}

impl Default for InstantSendProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            pending: 0,
            valid: 0,
            invalid: 0,
            last_activity: Instant::now(),
        }
    }
}

impl InstantSendProgress {
    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state
    }
    /// Number of InstantSend locks pending for validation.
    pub fn pending(&self) -> usize {
        self.pending
    }
    /// Number of InstantSend locks successfully verified.
    pub fn valid(&self) -> u32 {
        self.valid
    }
    /// Number of InstantSend locks dropped after max retries (couldn't be validated).
    pub fn invalid(&self) -> u32 {
        self.invalid
    }
    /// The last time an InstantLock was processed or the last manager state change.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
    /// Update the sync state and bump the last activity time.
    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }
    /// Update the number of pending InstantSend locks.
    pub fn update_pending(&mut self, count: usize) {
        self.pending = count;
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

impl fmt::Display for InstantSendProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} valid: {}, invalid: {}, pending: {}, last_activity: {}s",
            self.state,
            self.valid,
            self.invalid,
            self.pending,
            self.last_activity.elapsed().as_secs()
        )
    }
}
