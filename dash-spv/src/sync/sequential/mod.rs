//! Sequential synchronization manager for dash-spv
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
//! # Tradeoff:
//! Slower total sync time, but significantly simpler code.
//!
//! # CRITICAL: Lock Ordering
//! To prevent deadlocks, acquire locks in this order:
//! 1. state (via read/write methods)
//! 2. storage (via async methods)
//! 3. network (via send_message)
//!
//! # Module Structure
//! This module has been refactored into focused sub-modules:
//! - `manager` - Core struct definition and simple accessors
//! - `lifecycle` - Initialization, startup, and shutdown
//! - `phase_execution` - Phase execution, transitions, and timeout handling
//! - `message_handlers` - Handlers for sync phase messages
//! - `post_sync` - Handlers for post-sync messages (after initial sync complete)
//! - `phases` - SyncPhase enum and phase-related types
//! - `progress` - Progress tracking utilities
//! - `recovery` - Recovery and error handling logic
//! - `transitions` - Phase transition management

// Sub-modules (focused implementations)
pub mod lifecycle;
pub mod manager;
pub mod message_handlers;
pub mod phase_execution;
pub mod post_sync;

// Existing sub-modules
pub mod phases;
pub mod transitions;

// Re-exports
pub use manager::SequentialSyncManager;
pub use phases::{PhaseTransition, SyncPhase};
pub use transitions::TransitionManager;
