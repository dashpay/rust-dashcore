//! Terminal blocks support for masternode list synchronization.
//!
//! Terminal blocks are specific blocks where masternode lists are known to be accurate
//! and can be used as synchronization checkpoints. This helps optimize masternode sync
//! by providing known-good states at specific heights.

use dashcore::{BlockHash, Network};
use dashcore_hashes::Hash;
use std::collections::HashMap;

use crate::error::SyncResult;
use crate::storage::StorageManager;
use crate::sync::terminal_block_data::{TerminalBlockDataManager, TerminalBlockMasternodeState};

/// A terminal block represents a known-good block where the masternode list state is accurate.
#[derive(Debug, Clone)]
pub struct TerminalBlock {
    /// The height of the terminal block.
    pub height: u32,
    /// The block hash of the terminal block.
    pub block_hash: BlockHash,
    /// Optional merkle root of the masternode list at this height (for validation).
    pub masternode_list_merkle_root: Option<[u8; 32]>,
}

impl TerminalBlock {
    /// Create a new terminal block.
    pub fn new(height: u32, block_hash: BlockHash) -> Self {
        Self {
            height,
            block_hash,
            masternode_list_merkle_root: None,
        }
    }

    /// Create a new terminal block with masternode list merkle root.
    pub fn with_merkle_root(height: u32, block_hash: BlockHash, merkle_root: [u8; 32]) -> Self {
        Self {
            height,
            block_hash,
            masternode_list_merkle_root: Some(merkle_root),
        }
    }
}

/// Manages terminal blocks for efficient masternode list synchronization.
pub struct TerminalBlockManager {
    /// Network this manager is operating on.
    network: Network,
    /// Map of height to terminal block.
    terminal_blocks: HashMap<u32, TerminalBlock>,
    /// The highest terminal block we have.
    highest_terminal_block: Option<TerminalBlock>,
    /// Manager for pre-calculated masternode data.
    data_manager: TerminalBlockDataManager,
}

impl TerminalBlockManager {
    /// Create a new terminal block manager for the given network.
    pub fn new(network: Network) -> Self {
        let mut data_manager = TerminalBlockDataManager::new();
        data_manager.load_embedded_data(network);

        let mut manager = Self {
            network,
            terminal_blocks: HashMap::new(),
            highest_terminal_block: None,
            data_manager,
        };

        // Initialize with known terminal blocks for the network
        manager.initialize_terminal_blocks();
        manager
    }

    /// Initialize terminal blocks based on the network.
    fn initialize_terminal_blocks(&mut self) {
        let blocks = match self.network {
            Network::Dash => {
                // Mainnet terminal blocks
                // These are blocks where masternode lists are known to be accurate
                vec![
                    // DIP3 activation (block 1088640)
                    (1088640, "00000000000000112c41b144f542e82648e5f72f960e1c2477a88b0ab7a29adb"),
                    // Additional checkpoints for masternode list sync
                    (1250000, "000000000000001b92397b6f7e70c1e3b35e95ff4b4f295c6ac6f97f4791a476"),
                    (1300000, "00000000000000066e19361c19bc30f24e83ad6c03b51cc12dcdb9b487f7f5d9"),
                    (1500000, "00000000000000105cfae44a995332d8ec256850ea33a1f7b700474e3dad82bc"),
                    (1750000, "0000000000000001342be6b8bdf33a92d68059d746db2681cf3f24117dd50089"),
                    // Latest terminal block
                    (2000000, "0000000000000021f7b88e014325c323dc41d20aec211e5cc5a81eeef2f91de2"),
                ]
            }
            Network::Testnet => {
                // Testnet terminal blocks
                vec![
                    // DIP3 activation on testnet (block 387480)
                    (387480, "000000a876f1d66e48e4b992e1701ca62c88cf7e3c4139f368e8bab89dc2eb6a"),
                    // Additional checkpoints
                    (760000, "000000cea02761fee136d16f5be1d71ef1ce7e064c17ecb04f12919fef13b3f5"),
                    // Latest terminal block
                    (900000, "0000011764a05571e0b3963b1422a8f3771e4c0d5b72e9b8e0799aabf07d28ef"),
                ]
            }
            Network::Devnet => {
                // Devnets don't have predefined terminal blocks
                vec![]
            }
            Network::Regtest => {
                // Regtest doesn't have predefined terminal blocks
                vec![]
            }
            _ => {
                // Other networks don't have predefined terminal blocks
                vec![]
            }
        };

        // Parse and add the terminal blocks
        for (height, hash_hex) in blocks {
            if let Ok(hash_bytes) = hex::decode(hash_hex) {
                if hash_bytes.len() == 32 {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&hash_bytes);
                    // Reverse bytes for little-endian
                    hash_array.reverse();
                    let block_hash = BlockHash::from_byte_array(hash_array);
                    self.add_terminal_block(TerminalBlock::new(height, block_hash));
                }
            }
        }
    }

    /// Add a terminal block to the manager.
    pub fn add_terminal_block(&mut self, block: TerminalBlock) {
        // Update highest terminal block if needed
        if self.highest_terminal_block.is_none()
            || block.height > self.highest_terminal_block.as_ref().map(|b| b.height).unwrap_or(0)
        {
            self.highest_terminal_block = Some(block.clone());
        }

        self.terminal_blocks.insert(block.height, block);
    }

    /// Get a terminal block by height.
    pub fn get_terminal_block(&self, height: u32) -> Option<&TerminalBlock> {
        self.terminal_blocks.get(&height)
    }

    /// Get the highest terminal block below or at the given height.
    pub fn get_terminal_block_before_or_at(&self, height: u32) -> Option<&TerminalBlock> {
        let mut best_block: Option<&TerminalBlock> = None;
        let mut best_height = 0;

        for (block_height, block) in &self.terminal_blocks {
            if *block_height <= height && *block_height > best_height {
                best_height = *block_height;
                best_block = Some(block);
            }
        }

        best_block
    }

    /// Get the next terminal block after the given height.
    pub fn get_next_terminal_block(&self, height: u32) -> Option<&TerminalBlock> {
        let mut next_block: Option<&TerminalBlock> = None;
        let mut next_height = u32::MAX;

        for (block_height, block) in &self.terminal_blocks {
            if *block_height > height && *block_height < next_height {
                next_height = *block_height;
                next_block = Some(block);
            }
        }

        next_block
    }

    /// Get all terminal blocks in ascending height order.
    pub fn get_all_terminal_blocks(&self) -> Vec<&TerminalBlock> {
        let mut blocks: Vec<&TerminalBlock> = self.terminal_blocks.values().collect();
        blocks.sort_by_key(|b| b.height);
        blocks
    }

    /// Check if a given height is a terminal block.
    pub fn is_terminal_block_height(&self, height: u32) -> bool {
        self.terminal_blocks.contains_key(&height)
    }

    /// Get the highest terminal block.
    pub fn get_highest_terminal_block(&self) -> Option<&TerminalBlock> {
        self.highest_terminal_block.as_ref()
    }

    /// Validate that a block hash matches the expected terminal block at the given height.
    pub async fn validate_terminal_block(
        &self,
        height: u32,
        block_hash: &BlockHash,
        _storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if let Some(terminal_block) = self.get_terminal_block(height) {
            if terminal_block.block_hash != *block_hash {
                tracing::warn!(
                    "Terminal block validation failed at height {}: expected hash {}, got {}",
                    height,
                    terminal_block.block_hash,
                    block_hash
                );
                return Ok(false);
            }

            // If we have a merkle root, we could validate the masternode list here
            // This would require loading the masternode list from storage and computing its merkle root
            if let Some(_expected_merkle_root) = terminal_block.masternode_list_merkle_root {
                // TODO: Implement masternode list merkle root validation
                tracing::debug!(
                    "Terminal block validated at height {} (merkle root validation not yet implemented)",
                    height
                );
            }

            Ok(true)
        } else {
            // Not a terminal block height
            Ok(true)
        }
    }

    /// Find the best terminal block to use as a base for syncing to the target height.
    pub fn find_best_base_terminal_block(&self, target_height: u32) -> Option<&TerminalBlock> {
        // Find the highest terminal block that's still below the target
        self.get_terminal_block_before_or_at(target_height)
    }

    /// Get terminal blocks within a height range.
    pub fn get_terminal_blocks_in_range(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Vec<&TerminalBlock> {
        let mut blocks: Vec<&TerminalBlock> = self
            .terminal_blocks
            .values()
            .filter(|block| block.height >= start_height && block.height <= end_height)
            .collect();
        blocks.sort_by_key(|b| b.height);
        blocks
    }

    /// Update terminal blocks from storage (for dynamic terminal blocks).
    pub async fn update_from_storage(&mut self, _storage: &dyn StorageManager) -> SyncResult<()> {
        // This method can be used to load additional terminal blocks from storage
        // that might have been discovered during sync or imported from other sources

        // For now, we just log that this functionality is available
        tracing::debug!(
            "Terminal block manager update from storage called (dynamic terminal blocks not yet implemented)"
        );

        Ok(())
    }

    /// Check if we have pre-calculated masternode data for a terminal block.
    pub fn has_masternode_data(&self, height: u32) -> bool {
        self.data_manager.has_state(height)
    }

    /// Get pre-calculated masternode data for a terminal block.
    pub fn get_masternode_data(&self, height: u32) -> Option<&TerminalBlockMasternodeState> {
        self.data_manager.get_state(height)
    }

    /// Find the best terminal block with pre-calculated masternode data.
    pub fn find_best_terminal_block_with_data(
        &self,
        target_height: u32,
    ) -> Option<&TerminalBlockMasternodeState> {
        self.data_manager.find_best_terminal_block_with_data(target_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_block_creation() {
        let height = 1000000;
        let hash = BlockHash::all_zeros();
        let block = TerminalBlock::new(height, hash);

        assert_eq!(block.height, height);
        assert_eq!(block.block_hash, hash);
        assert!(block.masternode_list_merkle_root.is_none());
    }

    #[test]
    fn test_terminal_block_with_merkle_root() {
        let height = 1088640;
        // Create a block hash from bytes
        let hash_bytes =
            hex::decode("00000000000000112c41b144f542e82648e5f72f960e1c2477a88b0ab7a29adb")
                .expect("hardcoded hex string should be valid");
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        hash_array.reverse(); // Little-endian
        let hash = BlockHash::from_byte_array(hash_array);
        let merkle_root = [42u8; 32];

        let block = TerminalBlock::with_merkle_root(height, hash, merkle_root);

        assert_eq!(block.height, height);
        assert_eq!(block.block_hash, hash);
        assert!(block.masternode_list_merkle_root.is_some());
        assert_eq!(block.masternode_list_merkle_root.expect("merkle root should be present"), merkle_root);
    }

    #[test]
    fn test_terminal_block_manager_initialization() {
        let manager = TerminalBlockManager::new(Network::Dash);
        assert!(!manager.terminal_blocks.is_empty());
        assert!(manager.get_highest_terminal_block().is_some());

        // Verify specific known terminal blocks exist
        assert!(manager.get_terminal_block(1088640).is_some()); // DIP3 activation
        assert!(manager.get_terminal_block(1500000).is_some());
        assert!(manager.get_terminal_block(2000000).is_some());
    }

    #[test]
    fn test_find_terminal_blocks() {
        let manager = TerminalBlockManager::new(Network::Dash);

        // Test finding blocks before or at a height
        let block = manager.get_terminal_block_before_or_at(1250000);
        assert!(block.is_some());
        assert_eq!(block.expect("terminal block should exist at 1250000").height, 1250000);

        // Test finding at exact height
        let block = manager.get_terminal_block_before_or_at(1300000);
        assert!(block.is_some());
        assert_eq!(block.expect("terminal block should exist at 1300000").height, 1300000);

        // Test finding next block
        let next = manager.get_next_terminal_block(1200000);
        assert!(next.is_some());
        assert_eq!(next.expect("next terminal block should exist after 1200000").height, 1250000);

        // Test edge cases
        let block = manager.get_terminal_block_before_or_at(500000);
        assert!(block.is_none()); // No terminal blocks this early

        let next = manager.get_next_terminal_block(3000000);
        assert!(next.is_none()); // No terminal blocks this high
    }

    #[test]
    fn test_terminal_block_range_queries() {
        let manager = TerminalBlockManager::new(Network::Dash);

        let blocks = manager.get_terminal_blocks_in_range(1100000, 1500000);
        assert!(!blocks.is_empty());
        assert!(blocks.iter().all(|b| b.height >= 1100000 && b.height <= 1500000));

        // Verify blocks are sorted
        for i in 1..blocks.len() {
            assert!(blocks[i].height > blocks[i - 1].height);
        }
    }

    #[test]
    fn test_is_terminal_block_height() {
        let manager = TerminalBlockManager::new(Network::Dash);

        assert!(manager.is_terminal_block_height(1088640));
        assert!(manager.is_terminal_block_height(1500000));
        assert!(!manager.is_terminal_block_height(1234567));
        assert!(!manager.is_terminal_block_height(999999));
    }

    #[test]
    fn test_testnet_terminal_blocks() {
        let manager = TerminalBlockManager::new(Network::Testnet);

        assert!(!manager.terminal_blocks.is_empty());
        assert!(manager.get_terminal_block(387480).is_some()); // DIP3 activation on testnet
        assert!(manager.get_terminal_block(760000).is_some());

        let highest = manager.get_highest_terminal_block();
        assert!(highest.is_some());
        assert!(highest.expect("highest terminal block should exist").height >= 760000);
    }

    #[test]
    fn test_devnet_terminal_blocks() {
        let manager = TerminalBlockManager::new(Network::Devnet);

        assert!(manager.terminal_blocks.is_empty());
        assert!(manager.get_highest_terminal_block().is_none());
    }

    #[test]
    fn test_add_terminal_block() {
        let mut manager = TerminalBlockManager::new(Network::Regtest);

        // Initially empty for regtest
        assert!(manager.terminal_blocks.is_empty());

        // Add a terminal block
        let block = TerminalBlock::new(1000, BlockHash::all_zeros());
        manager.add_terminal_block(block.clone());

        assert_eq!(manager.terminal_blocks.len(), 1);
        assert!(manager.get_terminal_block(1000).is_some());
        assert_eq!(manager.get_highest_terminal_block().expect("highest terminal block should exist").height, 1000);

        // Add another higher block
        let block2 = TerminalBlock::new(2000, BlockHash::all_zeros());
        manager.add_terminal_block(block2);

        assert_eq!(manager.terminal_blocks.len(), 2);
        assert_eq!(manager.get_highest_terminal_block().expect("highest terminal block should exist").height, 2000);
    }

    #[test]
    fn test_best_base_terminal_block() {
        let manager = TerminalBlockManager::new(Network::Dash);

        // Find best base for various target heights
        let base = manager.find_best_base_terminal_block(1750000);
        assert!(base.is_some());
        assert_eq!(base.expect("base terminal block should exist for 1750000").height, 1750000);

        let base = manager.find_best_base_terminal_block(1775000);
        assert!(base.is_some());
        assert_eq!(base.expect("base terminal block should exist for 1775000").height, 1750000);

        let base = manager.find_best_base_terminal_block(500000);
        assert!(base.is_none()); // No terminal blocks this early
    }
}