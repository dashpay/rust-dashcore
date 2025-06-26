//! Chain management module with reorganization support
//!
//! This module provides functionality for managing blockchain state including:
//! - Fork detection and handling
//! - Chain reorganization
//! - Multiple chain tip tracking
//! - Chain work calculation
//! - Transaction rollback during reorgs

pub mod fork_detector;
pub mod reorg;
pub mod chain_work;
pub mod chain_tip;
pub mod checkpoints;
pub mod chainlock_manager;
pub mod orphan_pool;

#[cfg(test)]
mod reorg_test;

pub use fork_detector::{ForkDetector, ForkDetectionResult};
pub use reorg::{ReorgManager, ReorgEvent};
pub use chain_work::ChainWork;
pub use chain_tip::{ChainTip, ChainTipManager};
pub use checkpoints::{Checkpoint, CheckpointManager};
pub use chainlock_manager::{ChainLockManager, ChainLockEntry, ChainLockStats};
pub use orphan_pool::{OrphanPool, OrphanBlock, OrphanPoolStats};

use dashcore::{BlockHash, Header as BlockHeader};

/// Represents a potential chain fork
#[derive(Debug, Clone)]
pub struct Fork {
    /// The block hash where the fork diverges from the main chain
    pub fork_point: BlockHash,
    /// The height of the fork point
    pub fork_height: u32,
    /// The tip of the forked chain
    pub tip_hash: BlockHash,
    /// The height of the fork tip
    pub tip_height: u32,
    /// Headers in the fork (from fork point to tip)
    pub headers: Vec<BlockHeader>,
    /// Cumulative chain work of this fork
    pub chain_work: ChainWork,
}

