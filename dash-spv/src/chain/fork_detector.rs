//! Fork detection logic for identifying blockchain forks
//!
//! This module detects when incoming headers create a fork in the blockchain
//! rather than extending the current chain tip.

use super::Fork;
use dashcore::BlockHash;
use std::collections::HashMap;

/// Detects and manages blockchain forks
pub struct ForkDetector {
    /// Currently known forks indexed by their tip hash
    forks: HashMap<BlockHash, Fork>,
}

impl ForkDetector {
    pub fn new(max_forks: usize) -> Result<Self, &'static str> {
        if max_forks == 0 {
            return Err("max_forks must be greater than 0");
        }
        Ok(Self {
            forks: HashMap::new(),
        })
    }

    /// Get all known forks
    pub fn get_forks(&self) -> Vec<&Fork> {
        self.forks.values().collect()
    }

    /// Get a specific fork by its tip hash
    pub fn get_fork(&self, tip_hash: &BlockHash) -> Option<&Fork> {
        self.forks.get(tip_hash)
    }

    /// Remove a fork (e.g., after it's been processed)
    pub fn remove_fork(&mut self, tip_hash: &BlockHash) -> Option<Fork> {
        self.forks.remove(tip_hash)
    }

    /// Check if we have any forks
    pub fn has_forks(&self) -> bool {
        !self.forks.is_empty()
    }

    /// Get the strongest fork (most cumulative work)
    pub fn get_strongest_fork(&self) -> Option<&Fork> {
        self.forks.values().max_by_key(|fork| &fork.chain_work)
    }

    /// Clear all forks
    pub fn clear_forks(&mut self) {
        self.forks.clear();
    }
}

/// Result of fork detection for a header
#[derive(Debug, Clone)]
pub enum ForkDetectionResult {
    /// Header extends the current main chain tip
    ExtendsMainChain,
    /// Header extends an existing fork
    ExtendsFork(Fork),
    /// Header creates a new fork from the main chain
    CreatesNewFork(Fork),
    /// Header doesn't connect to any known chain
    Orphan,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fork_detector_zero_max_forks() {
        let result = ForkDetector::new(0);
        assert!(result.is_err());
        assert_eq!(result.err(), Some("max_forks must be greater than 0"));
    }
}
