//! Pre-calculated masternode list data for terminal blocks.
//!
//! This module contains pre-calculated masternode list states at terminal block heights
//! to optimize masternode synchronization. Instead of syncing from genesis, nodes can
//! start from the nearest terminal block with known masternode state.

pub mod mainnet;
pub mod testnet;

use dashcore::BlockHash;
use dashcore_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pre-calculated masternode entry at a terminal block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMasternodeEntry {
    /// ProRegTx hash (as hex string)
    pub pro_tx_hash: String,
    /// Service address (IP:port)
    pub service: String,
    /// BLS public key for operator
    pub pub_key_operator: String,
    /// Voting address
    pub voting_address: String,
    /// Whether the masternode is valid
    pub is_valid: bool,
    /// Masternode type (0 = regular, 1 = evonode)
    pub n_type: u16,
}

/// Pre-calculated masternode list state at a terminal block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalBlockMasternodeState {
    /// Block height
    pub height: u32,
    /// Block hash (as hex string)
    pub block_hash: String,
    /// Merkle root of the masternode list (as hex string)
    pub merkle_root_mn_list: String,
    /// List of masternodes at this height
    pub masternode_list: Vec<StoredMasternodeEntry>,
    /// Number of masternodes
    pub masternode_count: u32,
    /// Timestamp when this data was fetched
    pub fetched_at: u64,
}

impl TerminalBlockMasternodeState {
    /// Get the block hash as a BlockHash type
    pub fn get_block_hash(&self) -> Result<BlockHash, Box<dyn std::error::Error>> {
        let bytes = hex::decode(&self.block_hash)?;
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&bytes);
        Ok(BlockHash::from_byte_array(hash_array))
    }

    /// Validate the terminal block data
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Validate block hash format
        if self.block_hash.len() != 64 {
            return Err("Invalid block hash length".into());
        }
        hex::decode(&self.block_hash)?;

        // Validate merkle root format
        if self.merkle_root_mn_list.len() != 64 {
            return Err("Invalid merkle root length".into());
        }
        hex::decode(&self.merkle_root_mn_list)?;

        // Validate masternode count matches list length
        if self.masternode_count as usize != self.masternode_list.len() {
            return Err(format!(
                "Masternode count mismatch: expected {}, got {}",
                self.masternode_count,
                self.masternode_list.len()
            )
            .into());
        }

        // Validate each masternode entry
        for (i, mn) in self.masternode_list.iter().enumerate() {
            mn.validate().map_err(|e| format!("Invalid masternode at index {}: {}", i, e))?;
        }

        Ok(())
    }
}

impl StoredMasternodeEntry {
    /// Validate the masternode entry
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Validate ProTxHash (should be 64 hex chars)
        if self.pro_tx_hash.len() != 64 {
            return Err("Invalid ProTxHash length".into());
        }
        hex::decode(&self.pro_tx_hash)?;

        // Validate service address format (IP:port)
        if !self.service.contains(':') {
            return Err("Invalid service address format".into());
        }

        // Validate BLS public key (should be 96 hex chars)
        if self.pub_key_operator.len() != 96 {
            return Err("Invalid BLS public key length".into());
        }
        hex::decode(&self.pub_key_operator)?;

        // Validate voting address (basic check)
        if self.voting_address.is_empty() {
            return Err("Empty voting address".into());
        }

        // Validate masternode type
        if self.n_type > 1 {
            return Err(format!("Invalid masternode type: {}", self.n_type).into());
        }

        Ok(())
    }
}

/// Manager for pre-calculated terminal block masternode states
pub struct TerminalBlockDataManager {
    /// Map of height to pre-calculated masternode state
    states: HashMap<u32, TerminalBlockMasternodeState>,
}

impl TerminalBlockDataManager {
    /// Create a new terminal block data manager
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Load pre-calculated data from embedded resources for a specific network
    pub fn load_embedded_data(&mut self, network: dashcore::Network) {
        match network {
            dashcore::Network::Dash => self.load_mainnet_data(),
            dashcore::Network::Testnet => self.load_testnet_data(),
            _ => {
                // No pre-calculated data for other networks
                tracing::debug!("No pre-calculated terminal block data for network: {:?}", network);
            }
        }
    }

    /// Add a terminal block masternode state with validation
    pub fn add_state(&mut self, state: TerminalBlockMasternodeState) {
        // Validate the state before adding
        match state.validate() {
            Ok(_) => {
                tracing::debug!(
                    "Adding validated terminal block data at height {} with {} masternodes",
                    state.height,
                    state.masternode_count
                );
                self.states.insert(state.height, state);
            }
            Err(e) => {
                tracing::warn!(
                    "Skipping invalid terminal block data at height {}: {}",
                    state.height,
                    e
                );
            }
        }
    }

    /// Get a terminal block masternode state by height
    pub fn get_state(&self, height: u32) -> Option<&TerminalBlockMasternodeState> {
        self.states.get(&height)
    }

    /// Check if we have pre-calculated data for a height
    pub fn has_state(&self, height: u32) -> bool {
        self.states.contains_key(&height)
    }

    /// Get all available terminal block heights
    pub fn available_heights(&self) -> Vec<u32> {
        let mut heights: Vec<u32> = self.states.keys().copied().collect();
        heights.sort();
        heights
    }

    /// Find the best terminal block with pre-calculated data for a target height
    pub fn find_best_terminal_block_with_data(
        &self,
        target_height: u32,
    ) -> Option<&TerminalBlockMasternodeState> {
        let mut best_state: Option<&TerminalBlockMasternodeState> = None;
        let mut best_height = 0;

        for (height, state) in &self.states {
            if *height <= target_height && *height > best_height {
                best_height = *height;
                best_state = Some(state);
            }
        }

        best_state
    }

    fn load_testnet_data(&mut self) {
        // Load pre-calculated testnet data
        testnet::load_testnet_terminal_blocks(self);
    }

    fn load_mainnet_data(&mut self) {
        // Load pre-calculated mainnet data
        mainnet::load_mainnet_terminal_blocks(self);
    }
}

impl Default for TerminalBlockDataManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert RPC masternode entry to stored format
pub fn convert_rpc_masternode(
    pro_tx_hash: &str,
    service: &str,
    pub_key_operator: &str,
    voting_address: &str,
    is_valid: bool,
    n_type: u16,
) -> Result<StoredMasternodeEntry, Box<dyn std::error::Error>> {
    Ok(StoredMasternodeEntry {
        pro_tx_hash: pro_tx_hash.to_string(),
        service: service.to_string(),
        pub_key_operator: pub_key_operator.to_string(),
        voting_address: voting_address.to_string(),
        is_valid,
        n_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_block_data_manager() {
        let mut manager = TerminalBlockDataManager::new();

        // Create a test state
        let state = TerminalBlockMasternodeState {
            height: 900000,
            block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            merkle_root_mn_list: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            masternode_list: vec![],
            masternode_count: 0,
            fetched_at: 0,
        };

        manager.add_state(state);

        assert!(manager.has_state(900000));
        assert!(!manager.has_state(900001));

        let found = manager.find_best_terminal_block_with_data(950000);
        assert!(found.is_some());
        assert_eq!(found.expect("terminal block should be found").height, 900000);
    }
}
