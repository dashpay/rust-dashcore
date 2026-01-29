use std::fmt;
use std::time::Instant;

use crate::sync::SyncState;

/// Progress for filter-header synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterHeadersProgress {
    /// Current sync state.
    state: SyncState,
    /// The tip height of the filter-header storage.
    current_height: u32,
    /// Target height (peer's best height). Used for progress display.
    target_height: u32,
    /// The tip height of the block-header storage (the download limit for filter headers).
    block_header_tip_height: u32,
    /// Number of filter-headers processed (stored) in the current sync session.
    processed: u32,
    /// The last time a filter-header was stored to disk or the last manager state change.
    last_activity: Instant,
}

impl Default for FilterHeadersProgress {
    fn default() -> Self {
        Self {
            state: SyncState::default(),
            current_height: 0,
            target_height: 0,
            block_header_tip_height: 0,
            processed: 0,
            last_activity: Instant::now(),
        }
    }
}

impl FilterHeadersProgress {
    /// Get completion percentage (0.0 to 1.0).
    /// Uses target_height (peer's best height) for accurate progress display.
    pub fn percentage(&self) -> f64 {
        if self.target_height == 0 {
            return 1.0;
        }
        (self.current_height as f64 / self.target_height as f64).min(1.0)
    }

    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Get the current height (last successfully processed filter-header height).
    pub fn current_height(&self) -> u32 {
        self.current_height
    }

    /// Get the target height (peer's best height, for progress display).
    pub fn target_height(&self) -> u32 {
        self.target_height
    }

    /// Get the block-header tip height (the download limit for filter headers).
    pub fn block_header_tip_height(&self) -> u32 {
        self.block_header_tip_height
    }

    /// Number of filter-headers processed (stored) in the current sync session.
    pub fn processed(&self) -> u32 {
        self.processed
    }

    /// The last time a filter-header was stored to disk or the last manager state change.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Update the sync state and bump the last activity time.
    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }

    /// Update the current height (last successfully processed filter-header height).
    pub fn update_current_height(&mut self, height: u32) {
        self.current_height = height;
        self.bump_last_activity();
    }

    /// Update the target height (peer's best height, for progress display).
    /// Only updates if the new height is greater than the current target (monotonic increase).
    pub fn update_target_height(&mut self, height: u32) {
        if height > self.target_height {
            self.target_height = height;
            self.bump_last_activity();
        }
    }

    /// Update the block-header tip height (called when new block headers are stored).
    pub fn update_block_header_tip_height(&mut self, height: u32) {
        self.block_header_tip_height = height;
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

impl fmt::Display for FilterHeadersProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pct = self.percentage() * 100.0;
        write!(
            f,
            "{:?} {}/{} ({:.1}%) processed: {}, last_activity: {}s",
            self.state,
            self.current_height,
            self.target_height,
            pct,
            self.processed,
            self.last_activity.elapsed().as_secs()
        )
    }
}
