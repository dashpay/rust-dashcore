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
                    // DIP3 activation (first DML)
                    (1088640, "00000000000000112c41b144f542e82648e5f72f960e1c2477a88b0ab7a29adb"),
                    // Regular interval terminal blocks (approximately every 50k blocks)
                    (1100000, "00000000000000293c502c43cb40aabaf40b87a0dd2a0c976b58f91dc6ae7eb5"),
                    (1150000, "0000000000000024152a225357799bbfa8cc5cbfce4cffb0f7b55ba8cb874d76"),
                    (1200000, "000000000000001fb9163ded58126ea7e042bab70e2c57ad133e2fc37f40a327"),
                    (1250000, "00000000000000193e14f7c0c6fb28a3f14383a0dd37e1c09819da9873b73e28"),
                    (1300000, "00000000000000068a5c9a31b08e7f4db17608e1df7a0226cf4dfa64a750e5ad"),
                    (1350000, "0000000000000015097b4ba2285ec5a5a7ced7f4486b917e5a6f1dd7e9b9d37e"),
                    (1400000, "00000000000000051369d45797fad1e61e268c22e8f563f3493a94987b36eff6"),
                    (1450000, "0000000000000018bb047c3b014e6f4d5c6bd34ce97d7d7917f8e2e5c8c6d768"),
                    (1500000, "00000000000000142e01db30b08c354dd974ce5db7dcf217aaeb38c0aaf0f6d2"),
                    (1550000, "00000000000000055344c498db27e8f4a4c36dd3dd3c0336b4e9e384e5c3c53e"),
                    (1600000, "000000000000001c5f5612481eea94df7bd4140cf8c3e2cc5ad7a2d1ac4655ba"),
                    (1650000, "00000000000000164f1248a0771e4c3ad49434bbbb48e230aa9d5bc6ce8f9e83"),
                    (1700000, "00000000000000203f57e71709c7a04faa48d102a7dc7d8c1a2bf6cf973aad5f"),
                    (1720000, "0000000000000014b29f6d05f89fa59c97d40e0e7beaf07c19ad70bce6a5de20"),
                    (1750000, "000000000000001074530ae70b93c2e719c94fb3b85b09497ba27285ceef0ced"),
                    (1800000, "0000000000000010dc57c6cfd87d8ee0cf3a5ba7a529dd9b9270fdf8fe399daa"),
                    (1850000, "00000000000000117aead9de4a6764fb08de85709157073fc1f4ced5eb4e7ceb"),
                    (1900000, "00000000000000208dcb56c5cbf7adff63ad6b965c3a088e2e9b4e607c7a88e1"),
                    (1950000, "0000000000000024a59f30cddbee13ef0711f7965d2f810e6c36e577c1e8b3b5"),
                    (2000000, "0000000000000021f7b88e014325c323dc41d20aec211e5cc5a81eeef2f91de2"),
                ]
            }
            Network::Testnet => {
                // Testnet terminal blocks
                vec![
                    // DIP3 activation on testnet
                    (387480, "0000014a5675057c06f88654e97ddab3e44e63636cf3c3a9f5448f40806e9ecb"),
                    // Regular interval terminal blocks
                    (400000, "000000ce6ce6c920f09b7b996270da542e45c0074ce1bdcaeca33e3d958bbe61"),
                    (450000, "00000292c92e419b1a8512feb948b5a93f375c7f4f3f0013a9b1c969e0ee1ce6"),
                    (500000, "000000f8a4233b014f0e7d0e6db5c4e6e8f8b3c45fc988b5afc2a5bfa2d41af6"),
                    (550000, "0000022a91356497cf8c06e0254a51e8e6b5e3a3a43f23a2ddc96a46b3b056d9"),
                    (600000, "00000288d38ed1b96e970f86b23cf4e01d97b4e3e6ab7d79b088bb1b5c5de21f"),
                    (650000, "000002577ac3f24b0e879dd98ae7a5b0dd6ac582a96e0cfcc99c6dc8fb6fd5ac"),
                    (700000, "00000134f48b6ad337eeb69df6fb97b2e0fb018cd1a8065c4a479cf3f96c9c4f"),
                    (750000, "000003012d866e4f96b0e2f92a17cbedd42fa8e3b744ab2d99296c964b407b01"),
                    (760000, "0000015fd0eeab8712b86fc89ec9e7fa4851e922e3903046fcc38b87e9fe2ba2"),
                    (800000, "000002f16a1e34a62e88e4b50bf5767c4ab027e11fb2a65c4b4b068ad18f07e1"),
                    (850000, "0000011ec1156e732e75b636d3b0dc37cb27a44fb4e1b0a47d82dab693b32e88"),
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
            || block.height > self.highest_terminal_block.as_ref().unwrap().height
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
        self.terminal_blocks
            .values()
            .filter(|block| block.height >= start_height && block.height <= end_height)
            .collect()
    }

    /// Update terminal blocks from storage (for dynamic terminal blocks).
    pub async fn update_from_storage(
        &mut self,
        _storage: &dyn StorageManager,
    ) -> SyncResult<()> {
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
    pub fn find_best_terminal_block_with_data(&self, target_height: u32) -> Option<&TerminalBlockMasternodeState> {
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
        let hash_bytes = hex::decode("00000000000000112c41b144f542e82648e5f72f960e1c2477a88b0ab7a29adb").unwrap();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        hash_array.reverse(); // Little-endian
        let hash = BlockHash::from_byte_array(hash_array);
        let merkle_root = [42u8; 32];
        
        let block = TerminalBlock::with_merkle_root(height, hash, merkle_root);
        
        assert_eq!(block.height, height);
        assert_eq!(block.block_hash, hash);
        assert!(block.masternode_list_merkle_root.is_some());
        assert_eq!(block.masternode_list_merkle_root.unwrap(), merkle_root);
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
        assert_eq!(block.unwrap().height, 1250000);

        // Test finding at exact height
        let block = manager.get_terminal_block_before_or_at(1300000);
        assert!(block.is_some());
        assert_eq!(block.unwrap().height, 1300000);

        // Test finding next block
        let next = manager.get_next_terminal_block(1200000);
        assert!(next.is_some());
        assert_eq!(next.unwrap().height, 1250000);

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
            assert!(blocks[i].height > blocks[i-1].height);
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
        assert!(highest.unwrap().height >= 760000);
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
        assert_eq!(manager.get_highest_terminal_block().unwrap().height, 1000);
        
        // Add another higher block
        let block2 = TerminalBlock::new(2000, BlockHash::all_zeros());
        manager.add_terminal_block(block2);
        
        assert_eq!(manager.terminal_blocks.len(), 2);
        assert_eq!(manager.get_highest_terminal_block().unwrap().height, 2000);
    }

    #[test]
    fn test_best_base_terminal_block() {
        let manager = TerminalBlockManager::new(Network::Dash);
        
        // Find best base for various target heights
        let base = manager.find_best_base_terminal_block(1750000);
        assert!(base.is_some());
        assert_eq!(base.unwrap().height, 1750000);
        
        let base = manager.find_best_base_terminal_block(1775000);
        assert!(base.is_some());
        assert_eq!(base.unwrap().height, 1750000);
        
        let base = manager.find_best_base_terminal_block(500000);
        assert!(base.is_none()); // No terminal blocks this early
    }
}