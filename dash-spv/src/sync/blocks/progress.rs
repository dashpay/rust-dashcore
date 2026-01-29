use crate::sync::SyncState;
use dashcore::prelude::CoreBlockHeight;
use std::fmt;
use std::time::Instant;

/// Progress for blocks synchronization.
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksProgress {
    /// Current sync state.
    state: SyncState,
    /// Last processed block height.
    last_processed: CoreBlockHeight,
    /// Total blocks requested from filter matches in the current sync session.
    requested: u32,
    /// Blocks loaded from local storage in the current sync session.
    from_storage: u32,
    /// Blocks downloaded from the network in the current sync session.
    downloaded: u32,
    /// Total blocks processed through wallet in the current sync session.
    processed: u32,
    /// Blocks that contained wallet-relevant transactions in the current sync session.
    relevant: u32,
    /// Number of transactions found in the current sync session.
    transactions: u32,
    /// The last time a block was stored/processed or the last manager state change.
    last_activity: Instant,
}

impl Default for BlocksProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            last_processed: 0,
            requested: 0,
            from_storage: 0,
            downloaded: 0,
            processed: 0,
            relevant: 0,
            transactions: 0,
            last_activity: Instant::now(),
        }
    }
}

impl BlocksProgress {
    pub fn state(&self) -> SyncState {
        self.state
    }

    pub fn last_processed(&self) -> CoreBlockHeight {
        self.last_processed
    }

    pub fn requested(&self) -> u32 {
        self.requested
    }

    pub fn from_storage(&self) -> u32 {
        self.from_storage
    }

    pub fn downloaded(&self) -> u32 {
        self.downloaded
    }

    pub fn processed(&self) -> u32 {
        self.processed
    }

    pub fn relevant(&self) -> u32 {
        self.relevant
    }

    pub fn transactions(&self) -> u32 {
        self.transactions
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }

    pub fn update_last_processed(&mut self, height: CoreBlockHeight) {
        self.last_processed = height;
        self.bump_last_activity();
    }

    pub fn add_requested(&mut self, count: u32) {
        self.requested += count;
        self.bump_last_activity();
    }

    pub fn add_from_storage(&mut self, count: u32) {
        self.from_storage += count;
        self.bump_last_activity();
    }

    pub fn add_downloaded(&mut self, count: u32) {
        self.downloaded += count;
        self.bump_last_activity();
    }

    pub fn add_processed(&mut self, count: u32) {
        self.processed += count;
        self.bump_last_activity();
    }

    pub fn add_relevant(&mut self, count: u32) {
        self.relevant += count;
        self.bump_last_activity();
    }

    pub fn add_transactions(&mut self, count: u32) {
        self.transactions += count;
        self.bump_last_activity();
    }

    pub fn bump_last_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Display for BlocksProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} last_relevant: {} | requested: {}, from_storage: {}, downloaded: {}, processed: {}, relevant: {}, transactions: {}, last_activity: {}s",
            self.state,
            self.last_processed,
            self.requested,
            self.from_storage,
            self.downloaded,
            self.processed,
            self.relevant,
            self.transactions,
            self.last_activity.elapsed().as_secs(),
        )
    }
}
