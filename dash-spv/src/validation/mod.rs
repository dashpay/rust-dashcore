//! Validation functionality for the Dash SPV client.

pub mod instantlock;
pub mod quorum;

pub use instantlock::InstantLockValidator;
pub use quorum::{QuorumInfo, QuorumManager, QuorumType};
