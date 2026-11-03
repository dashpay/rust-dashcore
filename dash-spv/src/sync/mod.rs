//! Synchronization management for the Dash SPV client.

mod block_headers;
mod blocks;
mod chainlock;
mod events;
mod filter_headers;
mod filters;
mod identifier;
mod instantsend;
mod masternodes;
mod mempool;
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
pub(crate) use mempool::MempoolManager;
pub use mempool::{BroadcastConfig, BroadcastHoldout, BroadcastResult, MempoolProgress};

pub use events::SyncEvent;
pub use identifier::ManagerIdentifier;
pub use progress::{ProgressPercentage, SyncProgress, SyncState};
pub use sync_coordinator::{Managers, SyncCoordinator};
pub use sync_manager::{SyncManager, SyncManagerProgress, SyncManagerTaskContext};

/// The legacy best-ChainLock key, written without an anchored signer: it roots
/// no trust, and only keeps forks from going below it while there is no
/// ChainLock anchor.
const BEST_CHAINLOCK_METADATA_STORAGE_KEY: &str = "best_chainlock";
/// The best ChainLock an anchored quorum signed, with the root its trust
/// descends from.
const CHAINLOCK_ANCHOR_METADATA_STORAGE_KEY: &str = "chainlock_anchor";
