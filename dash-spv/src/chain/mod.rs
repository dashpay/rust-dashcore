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
mod checkpoints;

pub use chain_tip::{ChainTip, ChainTipManager};
pub use chain_work::ChainWork;
pub use chainlock_manager::{ChainLockEntry, ChainLockManager};
pub use checkpoints::CheckpointManager;

pub(crate) use checkpoints::Checkpoint;
