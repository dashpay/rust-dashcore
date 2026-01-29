use crate::sync::SyncState;
use dashcore::prelude::CoreBlockHeight;
use std::fmt;
use std::time::Instant;

/// Progress for masternode list synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct MasternodesProgress {
    /// Current sync state.
    state: SyncState,
    /// The highest block height of a valid masternode list diff.
    current_height: u32,
    /// Target height (peer's best height). Used for progress display.
    target_height: u32,
    /// The tip height of the block header storage (determines when masternode sync can complete).
    block_header_tip_height: u32,
    /// Number of mnlistdiffs processed in the current sync session.
    diffs_processed: u32,
    /// The last time a mnlistdiff was stored/processed or the last manager state change.
    last_activity: Instant,
}

impl Default for MasternodesProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            current_height: 0,
            target_height: 0,
            block_header_tip_height: 0,
            diffs_processed: 0,
            last_activity: Instant::now(),
        }
    }
}

impl MasternodesProgress {
    pub fn state(&self) -> SyncState {
        self.state
    }

    pub fn current_height(&self) -> u32 {
        self.current_height
    }

    /// Get the target height (peer's best height, for progress display).
    pub fn target_height(&self) -> u32 {
        self.target_height
    }

    /// Get the block header tip height (determines when masternode sync can complete).
    pub fn block_header_tip_height(&self) -> u32 {
        self.block_header_tip_height
    }

    /// Number of mnlistdiffs processed in the current sync session.
    pub fn diffs_processed(&self) -> u32 {
        self.diffs_processed
    }

    /// The last time a mnlistdiff was stored/processed or the last manager state change.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Update the sync state and bump the last activity time.
    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }

    /// Update the current height (last successfully processed height).
    pub fn update_current_height(&mut self, height: CoreBlockHeight) {
        self.current_height = height;
        self.bump_last_activity();
    }

    /// Update the target height (peer's best height, for progress display).
    /// Only updates if the new height is greater than the current target (monotonic increase).
    pub fn update_target_height(&mut self, height: CoreBlockHeight) {
        if height > self.target_height {
            self.target_height = height;
            self.bump_last_activity();
        }
    }

    /// Update the block header tip height (called when new block headers are stored).
    pub fn update_block_header_tip_height(&mut self, height: CoreBlockHeight) {
        self.block_header_tip_height = height;
        self.bump_last_activity();
    }

    pub fn add_diffs_processed(&mut self, count: u32) {
        self.diffs_processed += count;
        self.bump_last_activity();
    }

    pub fn bump_last_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Display for MasternodesProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {}/{} | diffs_processed: {}, last_activity: {}s",
            self.state,
            self.current_height,
            self.target_height,
            self.diffs_processed,
            self.last_activity.elapsed().as_secs()
        )
    }
}
