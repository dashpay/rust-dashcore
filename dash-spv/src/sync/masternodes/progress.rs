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
    /// Number of QRInfo requests sent in the current sync session.
    qr_infos_requested: u32,
    /// Number of rotation cycles that completed full fresh validation
    /// (every rotated quorum verified) this session.
    validated_cycles: u32,
    /// Number of distinct rotation cycles the tip has entered this session,
    /// counted on every cycle boundary crossing including the initial one.
    rotation_cycles: u32,
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
            qr_infos_requested: 0,
            validated_cycles: 0,
            rotation_cycles: 0,
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

    /// Number of QRInfo requests sent in the current sync session.
    pub fn qr_infos_requested(&self) -> u32 {
        self.qr_infos_requested
    }

    /// Number of rotation cycles that completed full fresh validation this session.
    pub fn validated_cycles(&self) -> u32 {
        self.validated_cycles
    }

    /// Number of distinct rotation cycles the tip has entered this session.
    pub fn rotation_cycles(&self) -> u32 {
        self.rotation_cycles
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

    pub fn add_qr_infos_requested(&mut self, count: u32) {
        self.qr_infos_requested += count;
        self.bump_last_activity();
    }

    pub fn add_validated_cycles(&mut self, count: u32) {
        self.validated_cycles += count;
        self.bump_last_activity();
    }

    pub fn add_rotation_cycles(&mut self, count: u32) {
        self.rotation_cycles += count;
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
            "{:?} {}/{} | diffs_processed: {}, qr_infos_requested: {}, validated_cycles: {}, rotation_cycles: {}, last_activity: {}s",
            self.state,
            self.current_height,
            self.target_height,
            self.diffs_processed,
            self.qr_infos_requested,
            self.validated_cycles,
            self.rotation_cycles,
            self.last_activity.elapsed().as_secs()
        )
    }
}
