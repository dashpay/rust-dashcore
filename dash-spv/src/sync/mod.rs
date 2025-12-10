//! Synchronization management for the Dash SPV client.

// Legacy sync modules (moved to legacy/ subdirectory)
pub mod legacy;

mod block_headers;
mod blocks;
mod chainlock;
pub(super) mod download_coordinator;
mod events;
mod filter_headers;
mod filters;
mod identifier;
mod instantsend;
mod masternodes;
mod progress;
mod sync_coordinator;
mod sync_manager;

pub use block_headers::{BlockHeadersManager, BlockHeadersProgress};
pub use blocks::{BlocksManager, BlocksProgress};
pub use chainlock::{ChainLockManager, ChainLockProgress};
pub use filter_headers::{FilterHeadersManager, FilterHeadersProgress};
pub use filters::{FiltersManager, FiltersProgress};
pub use instantsend::{InstantSendManager, InstantSendProgress};
pub use masternodes::{MasternodesManager, MasternodesProgress};

pub use events::SyncEvent;
pub use identifier::ManagerIdentifier;
pub use progress::{SyncProgress, SyncState};
pub use sync_coordinator::{Managers, SyncCoordinator};
pub use sync_manager::{SyncManager, SyncManagerProgress, SyncManagerTaskContext};
