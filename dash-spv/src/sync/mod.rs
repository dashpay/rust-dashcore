//! Synchronization management for the Dash SPV client.
//!
//! This module provides sequential sync strategy:
//! Headers first, then filter headers, then filters on-demand

pub mod chainlock_validation;
pub mod discovery;
pub mod embedded_data;
pub mod filters;
pub mod headers;
pub mod headers2_state;
pub mod headers_with_reorg;
pub mod masternodes;
pub mod sequential;
pub mod state;
pub mod validation;
pub mod validation_state;

#[cfg(test)]
mod validation_test;


pub use filters::FilterSyncManager;
pub use headers::HeaderSyncManager;
pub use headers_with_reorg::{HeaderSyncManagerWithReorg, ReorgConfig};
pub use masternodes::MasternodeSyncManager;
pub use state::SyncState;


/// Sync component types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncComponent {
    Headers,
    FilterHeaders,
    Filters,
    Masternodes,
}
