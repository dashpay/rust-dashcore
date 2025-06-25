//! Fork detection logic for identifying blockchain forks
//!
//! This module detects when incoming headers create a fork in the blockchain
//! rather than extending the current chain tip.

use dashcore::{BlockHash, Header as BlockHeader};
use std::collections::HashMap;
use crate::storage::ChainStorage;
use crate::types::ChainState;
use super::{Fork, ChainWork};

/// Detects and manages blockchain forks
pub struct ForkDetector {
    /// Currently known forks indexed by their tip hash
    forks: HashMap<BlockHash, Fork>,
    /// Maximum number of forks to track
    max_forks: usize,
}

impl ForkDetector {
    pub fn new(max_forks: usize) -> Self {
        Self {
            forks: HashMap::new(),
            max_forks,
        }
    }

    /// Check if a header creates or extends a fork
    pub fn check_header(
        &mut self,
        header: &BlockHeader,
        chain_state: &ChainState,
        storage: &dyn ChainStorage,
    ) -> ForkDetectionResult {
        let header_hash = header.block_hash();
        let prev_hash = header.prev_blockhash;

        // Check if this extends the main chain
        if let Some(tip_header) = chain_state.get_tip_header() {
            tracing::trace!("Checking main chain extension - prev_hash: {}, tip_hash: {}", 
                prev_hash, tip_header.block_hash());
            if prev_hash == tip_header.block_hash() {
                return ForkDetectionResult::ExtendsMainChain;
            }
        } else {
            // Special case: chain state is empty (shouldn't happen with genesis initialized)
            // But handle it just in case
            if chain_state.headers.is_empty() {
                // Check if this is connecting to genesis in storage
                if let Ok(Some(height)) = storage.get_header_height(&prev_hash) {
                    if height == 0 {
                        // This is the first header after genesis
                        return ForkDetectionResult::ExtendsMainChain;
                    }
                }
            }
        }
        
        // Special case: Check if header connects to genesis which might be at height 0
        // This handles the case where chain_state has genesis but we're syncing the first real block
        if chain_state.tip_height() == 0 {
            if let Some(genesis_header) = chain_state.header_at_height(0) {
                tracing::debug!("Checking if header connects to genesis - prev_hash: {}, genesis_hash: {}", 
                    prev_hash, genesis_header.block_hash());
                if prev_hash == genesis_header.block_hash() {
                    tracing::info!("Header extends genesis block - treating as main chain extension");
                    return ForkDetectionResult::ExtendsMainChain;
                }
            }
        }

        // Check if this extends a known fork
        // Need to find a fork whose tip matches our prev_hash
        let matching_fork = self.forks.iter()
            .find(|(_, fork)| fork.tip_hash == prev_hash)
            .map(|(_, fork)| fork.clone());
            
        if let Some(mut fork) = matching_fork {
            // Remove the old entry (indexed by old tip)
            self.forks.remove(&fork.tip_hash);
            
            // Update the fork
            fork.headers.push(*header);
            fork.tip_hash = header_hash;
            fork.tip_height += 1;
            fork.chain_work = fork.chain_work.add_header(header);
            
            // Re-insert with new tip hash
            let result_fork = fork.clone();
            self.forks.insert(header_hash, fork);
            
            return ForkDetectionResult::ExtendsFork(result_fork);
        }

        // Check if this connects to the main chain (creates new fork)
        if let Ok(Some(height)) = storage.get_header_height(&prev_hash) {
            // Found connection point - this creates a new fork
            let fork_height = height;
            let fork = Fork {
                fork_point: prev_hash,
                fork_height,
                tip_hash: header_hash,
                tip_height: fork_height + 1,
                headers: vec![*header],
                chain_work: ChainWork::from_height_and_header(fork_height, header),
            };
            
            self.add_fork(fork.clone());
            return ForkDetectionResult::CreatesNewFork(fork);
        }
        
        // Additional check: see if header connects to any header in chain_state
        // This helps when storage might be out of sync with chain_state
        for (height, state_header) in chain_state.headers.iter().enumerate() {
            if prev_hash == state_header.block_hash() {
                // This connects to a header in chain state but not in storage
                // Treat it as extending main chain if it's the tip
                if height == chain_state.headers.len() - 1 {
                    return ForkDetectionResult::ExtendsMainChain;
                } else {
                    // Creates a fork from an earlier point
                    let fork = Fork {
                        fork_point: prev_hash,
                        fork_height: height as u32,
                        tip_hash: header_hash,
                        tip_height: (height as u32) + 1,
                        headers: vec![*header],
                        chain_work: ChainWork::from_height_and_header(height as u32, header),
                    };
                    
                    self.add_fork(fork.clone());
                    return ForkDetectionResult::CreatesNewFork(fork);
                }
            }
        }

        // This header doesn't connect to anything we know
        ForkDetectionResult::Orphan
    }

    /// Add a new fork to track
    fn add_fork(&mut self, fork: Fork) {
        self.forks.insert(fork.tip_hash, fork);
        
        // Limit the number of forks we track
        if self.forks.len() > self.max_forks {
            // Remove the fork with least work
            if let Some(weakest) = self.find_weakest_fork() {
                self.forks.remove(&weakest);
            }
        }
    }

    /// Find the fork with the least cumulative work
    fn find_weakest_fork(&self) -> Option<BlockHash> {
        self.forks
            .iter()
            .min_by_key(|(_, fork)| &fork.chain_work)
            .map(|(hash, _)| *hash)
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
        self.forks
            .values()
            .max_by_key(|fork| &fork.chain_work)
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
    use dashcore::blockdata::constants::genesis_block;
    use dashcore::Network;
    use dashcore_hashes::Hash;
    use crate::storage::MemoryStorage;

    fn create_test_header(prev_hash: BlockHash, nonce: u32) -> BlockHeader {
        let mut header = genesis_block(Network::Dash).header;
        header.prev_blockhash = prev_hash;
        header.nonce = nonce;
        header
    }

    #[test]
    fn test_fork_detection() {
        let mut detector = ForkDetector::new(10);
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();
        
        // Add genesis
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).unwrap();
        chain_state.add_header(genesis.clone());
        
        // Header that extends main chain
        let header1 = create_test_header(genesis.block_hash(), 1);
        let result = detector.check_header(&header1, &chain_state, &storage);
        assert!(matches!(result, ForkDetectionResult::ExtendsMainChain));
        
        // Add header1 to chain
        storage.store_header(&header1, 1).unwrap();
        chain_state.add_header(header1.clone());
        
        // Header that creates a fork from genesis
        let fork_header = create_test_header(genesis.block_hash(), 2);
        let result = detector.check_header(&fork_header, &chain_state, &storage);
        
        match result {
            ForkDetectionResult::CreatesNewFork(fork) => {
                assert_eq!(fork.fork_point, genesis.block_hash());
                assert_eq!(fork.fork_height, 0);
                assert_eq!(fork.tip_height, 1);
                assert_eq!(fork.headers.len(), 1);
            }
            _ => panic!("Expected CreatesNewFork"),
        }
        
        // Header that extends the fork
        let fork_header2 = create_test_header(fork_header.block_hash(), 3);
        let result = detector.check_header(&fork_header2, &chain_state, &storage);
        
        assert!(matches!(result, ForkDetectionResult::ExtendsFork(_)));
        assert_eq!(detector.get_forks().len(), 1);
        
        // Orphan header
        let orphan = create_test_header(BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::all_zeros()), 4);
        let result = detector.check_header(&orphan, &chain_state, &storage);
        assert!(matches!(result, ForkDetectionResult::Orphan));
    }

    #[test]
    fn test_fork_limits() {
        let mut detector = ForkDetector::new(2);
        let storage = MemoryStorage::new();
        let chain_state = ChainState::new();
        
        // Add genesis
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).unwrap();
        
        // Create 3 forks, should only keep 2
        for i in 0..3 {
            let fork_header = create_test_header(genesis.block_hash(), i + 100);
            detector.check_header(&fork_header, &chain_state, &storage);
        }
        
        assert_eq!(detector.get_forks().len(), 2);
    }
}