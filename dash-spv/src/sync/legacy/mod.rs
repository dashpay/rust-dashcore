//! Legacy synchronization modules for the Dash SPV client.
//!
//! This module contains the original sync implementation with sequential
//! phase-based synchronization.

// Submodules
pub mod filters;
pub mod headers;
pub mod masternodes;

// Sequential sync pipeline modules
pub mod manager;
pub mod message_handlers;
pub mod phase_execution;
pub mod phases;
pub mod post_sync;
pub mod transitions;

// Re-exports
pub use filters::FilterSyncManager;
pub use headers::{HeaderSyncManager, ReorgConfig};
pub use manager::SyncManager;
pub use masternodes::MasternodeSyncManager;
pub use phases::{PhaseTransition, SyncPhase};
pub use transitions::TransitionManager;
