use crate::error::{SyncError, SyncResult};
use crate::sync::{
    BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
    FiltersProgress, InstantSendProgress, MasternodesProgress,
};
use std::fmt;

/// Overall state of the parallel sync system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncState {
    #[default]
    Initializing,
    WaitingForConnections,
    WaitForEvents,
    Syncing,
    Synced,
    Error,
}

/// Aggregate progress for all managers.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncProgress {
    /// Headers synchronization progress.
    headers: Option<BlockHeadersProgress>,
    /// Filter headers synchronization progress.
    filter_headers: Option<FilterHeadersProgress>,
    /// Filters synchronization progress.
    filters: Option<FiltersProgress>,
    /// Blocks synchronization progress.
    blocks: Option<BlocksProgress>,
    /// Masternodes synchronization progress.
    masternodes: Option<MasternodesProgress>,
    /// ChainLock synchronization progress.
    chainlocks: Option<ChainLockProgress>,
    /// InstantSend synchronization progress.
    instantsend: Option<InstantSendProgress>,
}

impl SyncProgress {
    /// Get the overall sync state.
    ///
    /// Returns the most progressed state among all managers,
    /// or Initializing if no managers have started.
    pub fn state(&self) -> SyncState {
        let states: Vec<SyncState> = [
            self.headers.as_ref().map(|h| h.state()),
            self.filter_headers.as_ref().map(|f| f.state()),
            self.filters.as_ref().map(|f| f.state()),
            self.blocks.as_ref().map(|b| b.state()),
            self.masternodes.as_ref().map(|m| m.state()),
        ]
        .into_iter()
        .flatten()
        .collect();

        if states.is_empty() {
            return SyncState::Initializing;
        }

        // Return the "most progressed" state
        // Priority: Error > Syncing > WaitForEvents > WaitingForConnections > Synced > Initializing
        if states.contains(&SyncState::Error) {
            return SyncState::Error;
        }
        if states.contains(&SyncState::Syncing) {
            return SyncState::Syncing;
        }
        if states.contains(&SyncState::WaitForEvents) {
            return SyncState::WaitForEvents;
        }
        if states.contains(&SyncState::WaitingForConnections) {
            return SyncState::WaitingForConnections;
        }
        if states.iter().all(|s| *s == SyncState::Synced) {
            return SyncState::Synced;
        }
        SyncState::Initializing
    }

    /// Check if all managers are idle (sync complete).
    pub fn is_synced(&self) -> bool {
        let states: Vec<SyncState> = [
            self.headers.as_ref().map(|h| h.state()),
            self.filter_headers.as_ref().map(|f| f.state()),
            self.filters.as_ref().map(|f| f.state()),
            self.blocks.as_ref().map(|b| b.state()),
            self.masternodes.as_ref().map(|m| m.state()),
        ]
        .into_iter()
        .flatten()
        .collect();

        // Not synced if no managers have reported yet
        if states.is_empty() {
            return false;
        }

        states.iter().all(|state| *state == SyncState::Synced)
    }

    /// Get overall completion percentage (0.0 to 1.0).
    pub fn percentage(&self) -> f64 {
        let percentages = [
            self.headers.as_ref().map(|h| h.percentage()).unwrap_or(1.0),
            self.filter_headers.as_ref().map(|f| f.percentage()).unwrap_or(1.0),
            self.filters.as_ref().map(|f| f.percentage()).unwrap_or(1.0),
        ];
        percentages.iter().sum::<f64>() / percentages.len() as f64
    }

    pub fn headers(&self) -> SyncResult<&BlockHeadersProgress> {
        self.headers
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("BlockHeadersManager not started".into()))
    }

    pub fn filter_headers(&self) -> SyncResult<&FilterHeadersProgress> {
        self.filter_headers
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("FilterHeadersManager not started".into()))
    }

    pub fn filters(&self) -> SyncResult<&FiltersProgress> {
        self.filters
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("FiltersManager not started".into()))
    }

    pub fn blocks(&self) -> SyncResult<&BlocksProgress> {
        self.blocks
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("BlocksManager not started".into()))
    }

    pub fn masternodes(&self) -> SyncResult<&MasternodesProgress> {
        self.masternodes
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("MasternodeListManager not started".into()))
    }

    pub fn chainlocks(&self) -> SyncResult<&ChainLockProgress> {
        self.chainlocks
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("ChainLocksManager not started".into()))
    }

    pub fn instantsend(&self) -> SyncResult<&InstantSendProgress> {
        self.instantsend
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("InstantSendManager not started".into()))
    }

    pub fn update_headers(&mut self, progress: BlockHeadersProgress) {
        let updated_headers = Some(progress);
        if self.headers != updated_headers {
            self.headers = updated_headers;
        }
    }

    pub fn update_filter_headers(&mut self, progress: FilterHeadersProgress) {
        let updated_filter_headers = Some(progress);
        if self.filter_headers != updated_filter_headers {
            self.filter_headers = updated_filter_headers;
        }
    }

    /// Update filters progress.
    pub fn update_filters(&mut self, progress: FiltersProgress) {
        let updated_filters = Some(progress);
        if self.filters != updated_filters {
            self.filters = updated_filters;
        }
    }

    /// Update blocks progress.
    pub fn update_blocks(&mut self, progress: BlocksProgress) {
        let updated_blocks = Some(progress);
        if self.blocks != updated_blocks {
            self.blocks = updated_blocks;
        }
    }

    /// Update masternodes progress.
    pub fn update_masternodes(&mut self, progress: MasternodesProgress) {
        let updated_masternodes = Some(progress);
        if self.masternodes != updated_masternodes {
            self.masternodes = updated_masternodes;
        }
    }

    /// Update chainlock progress.
    pub fn update_chainlocks(&mut self, progress: ChainLockProgress) {
        let updated_chainlocks = Some(progress);
        if self.chainlocks != updated_chainlocks {
            self.chainlocks = updated_chainlocks;
        }
    }

    /// Update instantsend progress.
    pub fn update_instantsend(&mut self, progress: InstantSendProgress) {
        let updated_instantsend = Some(progress);
        if self.instantsend != updated_instantsend {
            self.instantsend = updated_instantsend;
        }
    }
}

impl fmt::Display for SyncProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        if let Some(h) = &self.headers {
            writeln!(f, "  Headers:        {}", h)?;
        }
        if let Some(fh) = &self.filter_headers {
            writeln!(f, "  Filter Headers: {}", fh)?;
        }
        if let Some(fl) = &self.filters {
            writeln!(f, "  Filters:        {}", fl)?;
        }
        if let Some(b) = &self.blocks {
            writeln!(f, "  Blocks:         {}", b)?;
        }
        if let Some(m) = &self.masternodes {
            writeln!(f, "  Masternodes:    {}", m)?;
        }
        if let Some(c) = &self.chainlocks {
            writeln!(f, "  ChainLocks:     {}", c)?;
        }
        if let Some(i) = &self.instantsend {
            writeln!(f, "  InstantSend:    {}", i)?;
        }
        Ok(())
    }
}
