//! Chain management module with reorganization support
//!
//! This module provides functionality for managing blockchain state including:
//! - Chain reorganization
//! - Multiple chain tip tracking
//! - Chain work calculation
//! - Transaction rollback during reorgs

pub mod chain_tip;
pub mod chain_work;
pub mod checkpoints;

#[cfg(test)]
mod checkpoint_test;

pub use chain_tip::{ChainTip, ChainTipManager};
pub use chain_work::ChainWork;
pub use checkpoints::{Checkpoint, CheckpointManager};
