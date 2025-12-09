//! Synchronization management for the Dash SPV client.
//!
//! This module implements a strict sequential sync pipeline where each phase
//! must complete 100% before the next phase begins.
//!
//! # Sequential Sync Benefits:
//! - Simpler state management (one active phase)
//! - Easier error recovery (restart current phase)
//! - Matches dependencies (need headers before filters)
//! - More reliable than concurrent sync
//!
//! # CRITICAL: Lock Ordering
//! To prevent deadlocks, acquire locks in this order:
//! 1. state (via read/write methods)
//! 2. storage (via async methods)
//! 3. network (via send_message)
//!
//! # Module Structure
//! - `manager` - Core SyncManager struct
//! - `phase_execution` - Phase execution, transitions, and timeout handling
//! - `message_handlers` - Handlers for sync phase messages
//! - `post_sync` - Handlers for post-sync messages (after initial sync complete)
//! - `phases` - SyncPhase enum and phase-related types
//! - `transitions` - Phase transition management
//! - `filters` - BIP157 Compact Block Filter synchronization
//! - `headers` - Header synchronization with fork detection
//! - `headers2` - Headers2 compressed header state management
//! - `masternodes` - Masternode synchronization

// Core sync modules
pub mod filters;
pub mod headers;
pub mod headers2;
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
pub use headers2::{Headers2StateManager, Headers2Stats, ProcessError};
pub use manager::SyncManager;
pub use masternodes::{MasternodeSyncManager, SharedMasternodeState};
pub use phases::{PhaseTransition, SyncPhase};
pub use transitions::TransitionManager;
