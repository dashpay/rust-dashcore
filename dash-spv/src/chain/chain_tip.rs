//! Fork-candidate carrier used by the staged-fork pipeline.

use super::ChainWork;
use crate::types::HashedBlockHeader;

/// A buffered fork branch that has been validated against the active chain.
///
/// Carries the common-ancestor height in the active chain, the validated
/// headers that extend past that ancestor, and the resulting cumulative work
/// at the fork tip. A candidate is promoted once its `total_work` strictly
/// exceeds the active chain's work.
#[derive(Debug, Clone)]
pub(crate) struct ForkCandidate {
    pub(crate) ancestor_height: u32,
    pub(crate) headers: Vec<HashedBlockHeader>,
    pub(crate) total_work: ChainWork,
}
