//! Chain management module with reorganization support
//!
//! This module provides functionality for managing blockchain state including:
//! - Chain reorganization
//! - Multiple chain tip tracking
//! - Chain work calculation
//! - Transaction rollback during reorgs

pub mod chain_tip;
pub mod chain_work;
mod checkpoints;

pub use chain_tip::{ChainTip, ChainTipManager};
pub use chain_work::ChainWork;
pub(crate) use checkpoints::{Checkpoint, CheckpointManager};
