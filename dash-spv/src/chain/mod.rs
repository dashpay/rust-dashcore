//! Chain primitives: cumulative work, checkpoints, DGW v3 difficulty, and the fork-candidate carrier.

pub(crate) mod chain_tip;
pub(crate) mod chain_work;
pub mod checkpoints;
pub(crate) mod difficulty;

#[cfg(test)]
mod checkpoint_test;

pub(crate) use chain_tip::ForkCandidate;
pub use chain_work::ChainWork;
pub use checkpoints::{Checkpoint, CheckpointManager};
