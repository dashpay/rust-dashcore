use crate::error::{SyncError, SyncResult};
use crate::sync::{
    BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
    FiltersProgress, InstantSendProgress, MasternodesProgress, MempoolProgress,
};
use dashcore::prelude::CoreBlockHeight;
use std::fmt;

/// Overall state of the parallel sync system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncState {
    #[default]
    WaitForEvents,
    WaitingForConnections,
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
    /// Mempool monitoring progress.
    mempool: Option<MempoolProgress>,
}

impl SyncProgress {
    /// Get the overall sync state.
    ///
    /// Returns the most progressed state among all managers,
    /// or WaitForEvents if no managers have started.
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
            return SyncState::WaitForEvents;
        }

        // Return the "most progressed" state
        // Priority: Error > Syncing > WaitingForConnections > Synced > WaitForEvents
        if states.contains(&SyncState::Error) {
            return SyncState::Error;
        }
        if states.contains(&SyncState::Syncing) {
            return SyncState::Syncing;
        }
        if states.contains(&SyncState::WaitingForConnections) {
            return SyncState::WaitingForConnections;
        }
        if states.iter().all(|s| *s == SyncState::Synced) {
            return SyncState::Synced;
        }
        SyncState::WaitForEvents
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
    ///
    /// Only managers that are active contribute to the average.
    pub fn percentage(&self) -> f64 {
        let percentages: Vec<f64> = [
            self.headers.as_ref().map(|h| h.percentage()),
            self.filter_headers.as_ref().map(|f| f.percentage()),
            self.filters.as_ref().map(|f| f.percentage()),
        ]
        .into_iter()
        .flatten()
        .collect();

        if percentages.is_empty() {
            return 0.0;
        }
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

    pub fn mempool(&self) -> SyncResult<&MempoolProgress> {
        self.mempool
            .as_ref()
            .ok_or_else(|| SyncError::InvalidState("MempoolManager not started".into()))
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

    /// Update mempool progress.
    pub fn update_mempool(&mut self, progress: MempoolProgress) {
        let updated_mempool = Some(progress);
        if self.mempool != updated_mempool {
            self.mempool = updated_mempool;
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
        if let Some(m) = &self.mempool {
            writeln!(f, "  Mempool:        {}", m)?;
        }
        Ok(())
    }
}

/// A trait that provides methods for calculating progress as a percentage from a current height
/// towards a target height.
pub trait ProgressPercentage {
    /// Get the target height used for calculating progress.
    fn target_height(&self) -> CoreBlockHeight;
    /// Get the current height used for calculating progress.
    fn current_height(&self) -> CoreBlockHeight;
    /// Get completion percentage (0.0 to 1.0).
    fn percentage(&self) -> f64 {
        if self.target_height() == 0 {
            return 0.0;
        }
        (self.current_height() as f64 / self.target_height() as f64).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        BlockHeadersProgress, BlocksProgress, FilterHeadersProgress, FiltersProgress,
        MasternodesProgress,
    };

    /// Masternode sync failure should NOT block `is_synced()` for the purpose
    /// of downstream managers (mempool, chainlock, instant-send).
    ///
    /// Production bug: on Dash testnet, MasternodeManager fails with "Required
    /// rotated chain lock sig at h - 0 not present" and never reaches Synced.
    /// Because `is_synced()` includes masternodes, it returns false,
    /// `SyncComplete` is never emitted, and MempoolManager never activates —
    /// the wallet never sees unconfirmed transactions.
    ///
    /// Expected fix: `is_synced()` should return true when all chain-sync
    /// managers (headers, filter_headers, filters, blocks) are Synced, even if
    /// masternodes is still syncing or has failed. Masternode sync is needed
    /// for IS lock validation but should not gate mempool monitoring.
    ///
    /// This test FAILS until the fix is applied.
    #[test]
    #[ignore = "fails until is_synced() decouples masternode sync from chain sync"]
    fn test_is_synced_not_blocked_by_masternode_failure() {
        let mut progress = SyncProgress::default();

        // Set all four chain-sync managers to Synced.
        let mut headers = BlockHeadersProgress::default();
        headers.set_state(SyncState::Synced);
        progress.update_headers(headers);

        let mut filter_headers = FilterHeadersProgress::default();
        filter_headers.set_state(SyncState::Synced);
        progress.update_filter_headers(filter_headers);

        let mut filters = FiltersProgress::default();
        filters.set_state(SyncState::Synced);
        progress.update_filters(filters);

        let mut blocks = BlocksProgress::default();
        blocks.set_state(SyncState::Synced);
        progress.update_blocks(blocks);

        // Masternodes stuck in Syncing (simulates testnet failure).
        let mut mn_failed = MasternodesProgress::default();
        mn_failed.set_state(SyncState::Syncing);
        progress.update_masternodes(mn_failed);

        // EXPECTED: is_synced() returns true — chain sync is complete,
        // masternode sync should not block mempool activation.
        assert!(
            progress.is_synced(),
            "is_synced() should return true when chain sync is complete, \
             even if masternodes are still syncing"
        );
    }
}
