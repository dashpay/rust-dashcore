use crate::sync::progress::ProgressPercentage;
use crate::sync::SyncState;
use std::fmt;
use std::time::Instant;

/// Progress for block-header synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeadersProgress {
    /// Current sync state.
    state: SyncState,
    /// The tip height of the block-header storage.
    tip_height: u32,
    /// Equals to current_height (blockchain tip) when synced and to the best height of connected peers during initial sync.
    target_height: u32,
    /// Number of block-headers processed (stored) in the current sync session.
    processed: u32,
    /// Number of headers currently buffered in the pipeline (waiting to be stored).
    buffered: u32,
    /// The last time a block-header was stored to disk or the last manager state change.
    last_activity: Instant,
}

impl Default for BlockHeadersProgress {
    fn default() -> Self {
        Self {
            state: SyncState::default(),
            tip_height: 0,
            target_height: 0,
            processed: 0,
            buffered: 0,
            last_activity: Instant::now(),
        }
    }
}

impl BlockHeadersProgress {
    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state
    }
    /// Get the current height (last successfully processed height).
    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }
    /// Number of block-headers processed (stored) in the current sync session.
    pub fn processed(&self) -> u32 {
        self.processed
    }
    /// The last time a block-header was stored to disk or the last manager state change.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
    /// Update the sync state and bump the last activity time.
    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }
    /// Update the tip height (last successfully processed height).
    pub fn update_tip_height(&mut self, height: u32) {
        self.tip_height = height;
        self.bump_last_activity();
    }
    /// Update the target height (the best height of the connected peers).
    /// Only updates if the new height is greater than the current target (monotonic increase).
    pub fn update_target_height(&mut self, height: u32) {
        if height > self.target_height {
            self.target_height = height;
            self.bump_last_activity();
        }
    }
    /// Add a number to the processed counter.
    pub fn add_processed(&mut self, count: u32) {
        self.processed += count;
        self.bump_last_activity();
    }
    /// Add a number to the buffered counter.
    pub fn buffered(&self) -> u32 {
        self.buffered
    }
    /// Update the buffered counter.
    pub fn update_buffered(&mut self, count: u32) {
        self.buffered = count;
    }
    /// Bump the last activity time.
    pub fn bump_last_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Display for BlockHeadersProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pct = self.percentage() * 100.0;
        write!(
            f,
            "{:?} {}/{} ({:.1}%) processed: {}, buffered: {}, last_activity: {}s",
            self.state,
            self.current_height(),
            self.target_height,
            pct,
            self.processed,
            self.buffered,
            self.last_activity.elapsed().as_secs()
        )
    }
}

impl ProgressPercentage for BlockHeadersProgress {
    fn target_height(&self) -> u32 {
        self.target_height
    }
    fn current_height(&self) -> u32 {
        // Use the effective height here for the progress to show more realistic values since
        // we download headers in parallel and the tip height is only updated when sequential segments complete.
        self.tip_height + self.buffered
    }
}
