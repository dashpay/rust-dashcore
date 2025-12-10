use crate::sync::SyncState;
use std::fmt;
use std::time::Instant;

/// Progress for InstantSend synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct InstantSendProgress {
    state: SyncState,
    /// Number of InstantSend locks pending for validation.
    pending: usize,
    /// Number of InstantSend locks processed in the current sync session.
    processed: u32,
    /// The last time an InstantLock was processed or the last manager state change.
    last_activity: Instant,
}

impl Default for InstantSendProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            pending: 0,
            processed: 0,
            last_activity: Instant::now(),
        }
    }
}

impl InstantSendProgress {
    pub fn state(&self) -> SyncState {
        self.state
    }

    pub fn pending(&self) -> usize {
        self.pending
    }

    pub fn processed(&self) -> u32 {
        self.processed
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }

    pub fn update_pending(&mut self, count: usize) {
        self.pending = count;
        self.bump_last_activity();
    }

    pub fn add_processed(&mut self, count: u32) {
        self.processed += count;
        self.bump_last_activity();
    }

    pub fn bump_last_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Display for InstantSendProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} processed: {}, pending: {}, last_activity: {}s",
            self.state,
            self.processed,
            self.pending,
            self.last_activity.elapsed().as_secs()
        )
    }
}
