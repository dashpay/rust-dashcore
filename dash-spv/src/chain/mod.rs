//! Chain management module with reorganization support
//!
//! This module provides functionality for managing blockchain state including:
//! - Chain reorganization
//! - Multiple chain tip tracking
//! - Chain work calculation
//! - Transaction rollback during reorgs

pub mod chain_tip;
pub mod chain_work;
pub mod chainlock_manager;
pub mod checkpoints;
pub mod orphan_pool;

#[cfg(test)]
mod checkpoint_test;
#[cfg(test)]
mod orphan_pool_test;

pub use chain_tip::{ChainTip, ChainTipManager};
pub use chain_work::ChainWork;
pub use chainlock_manager::{ChainLockEntry, ChainLockManager, ChainLockStats};
pub use checkpoints::{Checkpoint, CheckpointManager};
pub use orphan_pool::{OrphanBlock, OrphanPool, OrphanPoolStats};
