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
//! - `legacy` - Original sequential sync implementation
//! - `headers2` - Headers2 compressed header state management

// Legacy sync modules (moved to legacy/ subdirectory)
pub mod legacy;
