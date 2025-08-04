//! Checkpoint system for chain validation and sync optimization
//!
//! Checkpoints are hardcoded blocks at specific heights that help:
//! - Prevent accepting blocks from invalid chains
//! - Optimize initial sync by starting from recent checkpoints
//! - Protect against deep reorganizations
//! - Bootstrap masternode lists at specific heights

use dashcore::{BlockHash, CompactTarget, Target};
use dashcore_hashes::{hex, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A checkpoint representing a known valid block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height
    pub height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Previous block hash
    pub prev_blockhash: BlockHash,
    /// Block timestamp
    pub timestamp: u32,
    /// Difficulty target
    pub target: Target,
    /// Original bits value (compact target)
    pub bits: u32,
    /// Merkle root (optional for older checkpoints)
    pub merkle_root: Option<BlockHash>,
    /// Cumulative chain work up to this block (as hex string)
    pub chain_work: String,
    /// Masternode list identifier (e.g., "ML1088640__70218")
    pub masternode_list_name: Option<String>,
    /// Whether to include merkle root in validation
    pub include_merkle_root: bool,
    /// Protocol version at this checkpoint
    pub protocol_version: Option<u32>,
    /// Nonce value for the block
    pub nonce: u32,
    /// Block version
    pub version: u32,
}

impl Checkpoint {
    /// Extract protocol version from masternode list name or use stored value
    pub fn protocol_version(&self) -> Option<u32> {
        // Prefer explicitly stored protocol version
        if let Some(version) = self.protocol_version {
            return Some(version);
        }

        // Otherwise extract from masternode list name
        self.masternode_list_name.as_ref().and_then(|name| {
            // Format: "ML{height}__{protocol_version}"
            name.split("__").nth(1).and_then(|s| s.parse().ok())
        })
    }

    /// Check if this checkpoint has an associated masternode list
    pub fn has_masternode_list(&self) -> bool {
        self.masternode_list_name.is_some()
    }
}

/// Checkpoint override settings
#[derive(Debug, Clone)]
pub struct CheckpointOverride {
    /// Override checkpoint height for sync chain
    pub sync_override_height: Option<u32>,
    /// Override checkpoint height for terminal chain
    pub terminal_override_height: Option<u32>,
    /// Whether to sync from genesis
    pub sync_from_genesis: bool,
}

impl Default for CheckpointOverride {
    fn default() -> Self {
        Self {
            sync_override_height: None,
            terminal_override_height: None,
            sync_from_genesis: false,
        }
    }
}

/// Manages checkpoints for a specific network
pub struct CheckpointManager {
    /// Checkpoints indexed by height
    checkpoints: HashMap<u32, Checkpoint>,
    /// Sorted list of checkpoint heights for efficient searching
    sorted_heights: Vec<u32>,
    /// Checkpoint override settings (not persisted)
    override_settings: CheckpointOverride,
}

impl CheckpointManager {
    /// Create a new checkpoint manager from a list of checkpoints
    pub fn new(checkpoints: Vec<Checkpoint>) -> Self {
        let mut checkpoint_map = HashMap::new();
        let mut heights = Vec::new();

        for checkpoint in checkpoints {
            heights.push(checkpoint.height);
            checkpoint_map.insert(checkpoint.height, checkpoint);
        }

        heights.sort_unstable();

        Self {
            checkpoints: checkpoint_map,
            sorted_heights: heights,
            override_settings: CheckpointOverride::default(),
        }
    }

    /// Get a checkpoint at a specific height
    pub fn get_checkpoint(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints.get(&height)
    }

    /// Check if a block hash matches the checkpoint at the given height
    pub fn validate_block(&self, height: u32, block_hash: &BlockHash) -> bool {
        match self.checkpoints.get(&height) {
            Some(checkpoint) => checkpoint.block_hash == *block_hash,
            None => true, // No checkpoint at this height, so it's valid
        }
    }

    /// Get the last checkpoint at or before the given height
    pub fn last_checkpoint_before_height(&self, height: u32) -> Option<&Checkpoint> {
        // Binary search for the highest checkpoint <= height
        let pos = self.sorted_heights.partition_point(|&h| h <= height);
        if pos > 0 {
            let checkpoint_height = self.sorted_heights[pos - 1];
            self.checkpoints.get(&checkpoint_height)
        } else {
            None
        }
    }

    /// Get the last checkpoint
    pub fn last_checkpoint(&self) -> Option<&Checkpoint> {
        self.sorted_heights.last().and_then(|&height| self.checkpoints.get(&height))
    }

    /// Get all checkpoint heights
    pub fn checkpoint_heights(&self) -> &[u32] {
        &self.sorted_heights
    }

    /// Check if we're past the last checkpoint
    pub fn is_past_last_checkpoint(&self, height: u32) -> bool {
        self.sorted_heights.last().map_or(true, |&last| height > last)
    }

    /// Get the last checkpoint before a given timestamp
    pub fn last_checkpoint_before_timestamp(&self, timestamp: u32) -> Option<&Checkpoint> {
        let mut best_checkpoint = None;
        let mut best_height = 0;

        for checkpoint in self.checkpoints.values() {
            if checkpoint.timestamp <= timestamp && checkpoint.height >= best_height {
                best_height = checkpoint.height;
                best_checkpoint = Some(checkpoint);
            }
        }

        best_checkpoint
    }

    /// Find the best checkpoint at or before a given height
    pub fn best_checkpoint_at_or_before_height(&self, height: u32) -> Option<&Checkpoint> {
        let mut best_checkpoint = None;
        let mut best_height = 0;

        for checkpoint in self.checkpoints.values() {
            if checkpoint.height <= height && checkpoint.height >= best_height {
                best_height = checkpoint.height;
                best_checkpoint = Some(checkpoint);
            }
        }

        best_checkpoint
    }

    /// Get the last checkpoint that has a masternode list
    pub fn last_checkpoint_having_masternode_list(&self) -> Option<&Checkpoint> {
        self.sorted_heights
            .iter()
            .rev()
            .filter_map(|height| self.checkpoints.get(height))
            .find(|checkpoint| checkpoint.has_masternode_list())
    }

    /// Set override checkpoint for sync chain
    pub fn set_sync_override(&mut self, height: Option<u32>) {
        self.override_settings.sync_override_height = height;
    }

    /// Set override checkpoint for terminal chain
    pub fn set_terminal_override(&mut self, height: Option<u32>) {
        self.override_settings.terminal_override_height = height;
    }

    /// Set whether to sync from genesis
    pub fn set_sync_from_genesis(&mut self, from_genesis: bool) {
        self.override_settings.sync_from_genesis = from_genesis;
    }

    /// Get the checkpoint to use for sync chain based on override settings
    pub fn get_sync_checkpoint(&self, wallet_creation_time: Option<u32>) -> Option<&Checkpoint> {
        if self.override_settings.sync_from_genesis {
            return self.get_checkpoint(0);
        }

        if let Some(override_height) = self.override_settings.sync_override_height {
            return self.last_checkpoint_before_height(override_height);
        }

        // Default to checkpoint based on wallet creation time
        if let Some(creation_time) = wallet_creation_time {
            self.last_checkpoint_before_timestamp(creation_time)
        } else {
            self.last_checkpoint()
        }
    }

    /// Get the checkpoint to use for terminal chain based on override settings
    pub fn get_terminal_checkpoint(&self) -> Option<&Checkpoint> {
        if let Some(override_height) = self.override_settings.terminal_override_height {
            self.last_checkpoint_before_height(override_height)
        } else {
            self.last_checkpoint()
        }
    }

    /// Check if a fork at the given height should be rejected due to checkpoint
    pub fn should_reject_fork(&self, fork_height: u32) -> bool {
        if let Some(last_checkpoint) = self.last_checkpoint() {
            fork_height <= last_checkpoint.height
        } else {
            false
        }
    }

    /// Validate a block header against checkpoints
    pub fn validate_header(
        &self,
        height: u32,
        block_hash: &BlockHash,
        merkle_root: Option<&BlockHash>,
    ) -> bool {
        if let Some(checkpoint) = self.get_checkpoint(height) {
            // Check block hash
            if checkpoint.block_hash != *block_hash {
                return false;
            }

            // Check merkle root if required
            if checkpoint.include_merkle_root {
                if let (Some(expected), Some(actual)) = (&checkpoint.merkle_root, merkle_root) {
                    if expected != actual {
                        return false;
                    }
                }
            }
        }

        true
    }
}

/// Create mainnet checkpoints
pub fn mainnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Genesis block (required)
        create_checkpoint(
            0,
            "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
            "0000000000000000000000000000000000000000000000000000000000000000",
            1390095618,
            0x1e0ffff0,
            "0x0000000000000000000000000000000000000000000000000000000100010001",
            "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
            28917698,
            None,
        ),
        // Early network checkpoint (1 week after genesis)
        create_checkpoint(
            4991,
            "000000003b01809551952460744d5dbb8fcbd6cbae3c220267bf7fa43f837367",
            "000000001263f3327dd2f6bc445b47beb82fb8807a62e252ba064e2d2b6f91a6",
            1390163520,
            0x1e0fffff,
            "0x00000000000000000000000000000000000000000000000000000000271027f0",
            "7faff642d9e914716c50e3406df522b2b9a10ea3df4fef4e2229997367a6cab1",
            357631712,
            None,
        ),
        // 3 months checkpoint
        create_checkpoint(
            107996,
            "00000000000a23840ac16115407488267aa3da2b9bc843e301185b7d17e4dc40",
            "000000000006fe4020a310786bd34e17aa7681c86a20a2e121e0e3dd599800e8",
            1395522898,
            0x1b04864c,
            "0x0000000000000000000000000000000000000000000000000056bf9caa56bf9d",
            "15c3852f9e71a6cbc0cfa96d88202746cfeae6fc645ccc878580bc29daeff193",
            10049236,
            None,
        ),
        // 2017 checkpoint
        create_checkpoint(
            750000,
            "00000000000000b4181bbbdddbae464ce11fede5d0292fb63fdede1e7c8ab21c",
            "00000000000001e115237541be8dd91bce2653edd712429d11371842f85bd3e1",
            1491953700,
            0x1a075a02,
            "0x00000000000000000000000000000000000000000000000485f01ee9f01ee9f8",
            "0ce99835e2de1240e230b5075024817aace2b03b3944967a88af079744d0aa62",
            2199533779,
            None,
        ),
        // Recent checkpoint with masternode list (2022)
        create_checkpoint(
            1700000,
            "000000000000001d7579a371e782fd9c4480f626a62b916fa4eb97e16a49043a",
            "000000000000001a5631d781a4be0d9cda08b470ac6f108843cedf32e4dc081e",
            1657142113,
            0x1927e30e,
            "000000000000000000000000000000000000000000007562df93a26b81386288",
            "dafe57cefc3bc265dfe8416e2f2e3a22af268fd587a48f36affd404bec738305",
            3820512540,
            Some("ML1700000__70227"),
        ),
        // Latest checkpoint with masternode list (2022/2023)
        create_checkpoint(
            1900000,
            "000000000000001b8187c744355da78857cca5b9aeb665c39d12f26a0e3a9af5",
            "000000000000000d41ff4e55f8ebc2e610ec74a0cbdd33e59ebbfeeb1f8a0a0d",
            1688744911,
            0x192946fd,
            "0x000000000000000000000000000000000000000000008798ed692b94a398aa4f",
            "3a6ff72336cf78e45b23101f755f4d7dce915b32336a8c242c33905b72b07b35",
            498598646,
            Some("ML1900000__70230"),
        ),
    ]
}

/// Create testnet checkpoints
pub fn testnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Genesis block
        create_checkpoint(
            0,
            "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
            "0000000000000000000000000000000000000000000000000000000000000000",
            1390666206,
            0x1e0ffff0,
            "0x0000000000000000000000000000000000000000000000000000000100010001",
            "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
            3861367235,
            None,
        ),
        // Height 500000
        create_checkpoint(
            500000,
            "000000d0f2239d3ea3d1e39e624f651c5a349b5ca729eec29540aeae0ecc94a7",
            "000001d6339e773dea2a9f1eae5e569a04963eb885008be9d553568932885745",
            1621049765,
            0x1e025b1b,
            "0x000000000000000000000000000000000000000000000000022f14e45fc51a2e",
            "618c77a7c45783f5f20e957a296e077220b50690aae51d714ae164eb8d669fdf",
            10457,
            None,
        ),
        // Height 800000
        create_checkpoint(
            800000,
            "00000075cdfa0a552e488406074bb95d831aee16c0ec30114319a587a8a8fb0c",
            "0000011921c298768dc2ab0f9ca5a3ff4527813bbd7cd77f45bf93efd0bb0799",
            1671238603,
            0x1e018b19,
            "0x00000000000000000000000000000000000000000000000002d68bf1d7e434f6",
            "d58300efccbace51cdf5c8a012979e310da21337a7f311b1dcea7c1c894dfb94",
            607529,
            None,
        ),
        // Height 1100000
        create_checkpoint(
            1100000,
            "000000078cc3952c7f594de921ae82fcf430a5f3b86755cd72acd819d0001015",
            "00000068da3dc19e54cefd3f7e2a7f380bf8d9a0eb1090a7197c3e0b10e2cf1f",
            1725934127,
            0x1e017da4,
            "0x000000000000000000000000000000000000000000000000031c3fcb33bc3a48",
            "4cc82bf21c5f1e0e712ca1a3d5bde2f92eee2700b86019c6d0ace9c91a8b9bd8",
            251545,
            None,
        ),
    ]
}

/// Helper to parse hex block hash strings
fn parse_block_hash(s: &str) -> Result<BlockHash, String> {
    use hex::FromHex;
    let bytes = Vec::<u8>::from_hex(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Invalid hash length: expected 32 bytes".to_string());
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    // Reverse for little-endian
    hash_bytes.reverse();
    Ok(BlockHash::from_byte_array(hash_bytes))
}

/// Helper to parse hex block hash strings, returning zero hash on error
fn parse_block_hash_safe(s: &str) -> BlockHash {
    parse_block_hash(s).unwrap_or_else(|e| {
        tracing::error!("Failed to parse checkpoint block hash '{}': {}", s, e);
        BlockHash::from_byte_array([0u8; 32])
    })
}

/// Helper to create a checkpoint with common defaults
fn create_checkpoint(
    height: u32,
    hash: &str,
    prev_hash: &str,
    timestamp: u32,
    bits: u32,
    chain_work: &str,
    merkle_root: &str,
    nonce: u32,
    masternode_list: Option<&str>,
) -> Checkpoint {
    // Determine version based on height
    let version = if height == 0 {
        1 // Genesis block version
    } else if height < 750000 {
        2 // Pre-v0.12 blocks
    } else if height < 1700000 {
        536870912 // v0.12+ blocks (0x20000000)
    } else {
        536870912 // v0.14+ blocks (0x20000000)
    };

    Checkpoint {
        height,
        block_hash: parse_block_hash_safe(hash),
        prev_blockhash: parse_block_hash_safe(prev_hash),
        timestamp,
        target: Target::from_compact(CompactTarget::from_consensus(bits)),
        bits,
        merkle_root: Some(parse_block_hash_safe(merkle_root)),
        chain_work: chain_work.to_string(),
        masternode_list_name: masternode_list.map(|s| s.to_string()),
        include_merkle_root: true,
        protocol_version: masternode_list.and_then(|ml| {
            // Extract protocol version from masternode list name
            ml.split("__").nth(1).and_then(|s| s.parse().ok())
        }),
        nonce,
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_validation() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test genesis block
        let genesis_checkpoint =
            manager.get_checkpoint(0).expect("Genesis checkpoint should exist");
        assert_eq!(genesis_checkpoint.height, 0);
        assert_eq!(genesis_checkpoint.timestamp, 1390095618);

        // Test validation
        let genesis_hash =
            parse_block_hash("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6")
                .expect("Failed to parse genesis hash for test");
        assert!(manager.validate_block(0, &genesis_hash));

        // Test invalid hash
        let invalid_hash = BlockHash::from_byte_array([1u8; 32]);
        assert!(!manager.validate_block(0, &invalid_hash));

        // Test no checkpoint at height
        assert!(manager.validate_block(1, &invalid_hash)); // No checkpoint at height 1

        // Test header validation
        assert!(manager.validate_header(0, &genesis_hash, None));
        assert!(!manager.validate_header(0, &invalid_hash, None));
    }

    #[test]
    fn test_last_checkpoint_before() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test finding checkpoint before various heights
        assert_eq!(
            manager.last_checkpoint_before_height(0).expect("Should find checkpoint").height,
            0
        );
        assert_eq!(
            manager.last_checkpoint_before_height(1000).expect("Should find checkpoint").height,
            0
        );
        assert_eq!(
            manager.last_checkpoint_before_height(5000).expect("Should find checkpoint").height,
            4991
        );
        assert_eq!(
            manager.last_checkpoint_before_height(200000).expect("Should find checkpoint").height,
            107996
        );
    }

    #[test]
    fn test_protocol_version_extraction() {
        let checkpoint = create_checkpoint(
            1088640,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0,
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            Some("ML1088640__70218"),
        );

        assert_eq!(checkpoint.protocol_version(), Some(70218));
        assert!(checkpoint.has_masternode_list());

        let checkpoint_no_version = create_checkpoint(
            0,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0,
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            None,
        );

        assert_eq!(checkpoint_no_version.protocol_version(), None);
        assert!(!checkpoint_no_version.has_masternode_list());
    }

    #[test]
    fn test_checkpoint_overrides() {
        let checkpoints = mainnet_checkpoints();
        let mut manager = CheckpointManager::new(checkpoints);

        // Test sync override
        manager.set_sync_override(Some(5000));
        let sync_checkpoint = manager.get_sync_checkpoint(None);
        assert_eq!(sync_checkpoint.expect("Should have sync checkpoint").height, 4991);

        // Test terminal override
        manager.set_terminal_override(Some(800000));
        let terminal_checkpoint = manager.get_terminal_checkpoint();
        assert_eq!(terminal_checkpoint.expect("Should have terminal checkpoint").height, 750000);

        // Test sync from genesis
        manager.set_sync_from_genesis(true);
        let genesis_checkpoint = manager.get_sync_checkpoint(None);
        assert_eq!(genesis_checkpoint.expect("Should have genesis checkpoint").height, 0);
    }

    #[test]
    fn test_fork_rejection() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Should reject fork at checkpoint height
        assert!(manager.should_reject_fork(1500));
        assert!(manager.should_reject_fork(750000));

        // Should not reject fork after last checkpoint
        assert!(!manager.should_reject_fork(2000000));
    }

    #[test]
    fn test_masternode_list_checkpoint() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Find last checkpoint with masternode list
        let ml_checkpoint = manager.last_checkpoint_having_masternode_list();
        assert!(ml_checkpoint.is_some());
        assert!(ml_checkpoint.expect("Should have ML checkpoint").has_masternode_list());
        assert_eq!(ml_checkpoint.expect("Should have ML checkpoint").height, 1900000);
    }

    #[test]
    fn test_checkpoint_by_timestamp() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test finding checkpoint by timestamp
        let checkpoint = manager.last_checkpoint_before_timestamp(1500000000);
        assert!(checkpoint.is_some());
        assert!(checkpoint.expect("Should find checkpoint by timestamp").timestamp <= 1500000000);
    }
}
