//! Checkpoint system for chain validation and sync optimization
//!
//! Checkpoints are hardcoded blocks at specific heights that help:
//! - Prevent accepting blocks from invalid chains
//! - Optimize initial sync by starting from recent checkpoints
//! - Protect against deep reorganizations
//! - Bootstrap masternode lists at specific heights

use dashcore::{BlockHash, CompactTarget, Target};
use dashcore_hashes::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A checkpoint representing a known valid block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height
    pub height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Block timestamp
    pub timestamp: u32,
    /// Difficulty target
    pub target: Target,
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
            name.split("__").nth(1)?.parse().ok()
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
        self.sorted_heights.last().and_then(|height| self.checkpoints.get(height))
    }

    /// Get all checkpoint heights
    pub fn checkpoint_heights(&self) -> &[u32] {
        &self.sorted_heights
    }

    /// Check if we're past the last checkpoint
    pub fn is_past_last_checkpoint(&self, height: u32) -> bool {
        self.sorted_heights.last().map(|&last| height > last).unwrap_or(true)
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
        // Genesis block
        create_checkpoint(
            0,
            "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
            1390095618,
            0x1e0ffff0,
            "0x0000000000000000000000000000000000000000000000000000000100010001",
            None,
        ),
        create_checkpoint(
            1500,
            "000000aaf0300f59f49bc3e970bad15c11f961fe2347accffff19d96ec9778e3",
            1390133640,
            0x1e0fffff,
            "0x00000000000000000000000000000000000000000000000000000000b3f3b3f4",
            None,
        ),
        Checkpoint {
            height: 4991,
            block_hash: parse_block_hash(
                "000000003b01809551952460744d5dbb8fcbd6cbae3c220267bf7fa43f837367",
            )
            .unwrap(),
            timestamp: 1390163520,
            target: Target::from_compact(CompactTarget::from_consensus(0x1e0fffff)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000000000000271027f0"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 9918,
            block_hash: parse_block_hash(
                "00000000213e229f332c0ffbe34defdaa9e74de87f2d8d1f01af8d121c3c170b",
            )
            .unwrap(),
            timestamp: 1390344765,
            target: Target::from_compact(CompactTarget::from_consensus(0x1e0fffff)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000000000000b5b3b5bf"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 16912,
            block_hash: parse_block_hash(
                "00000000075c0d10371d55a60634da70f197548dbbfa4123e12abfcbc5738af9",
            )
            .unwrap(),
            timestamp: 1390821265,
            target: Target::from_compact(CompactTarget::from_consensus(0x1e0fffff)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000000000001086108a1"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 45479,
            block_hash: parse_block_hash(
                "000000000063d411655d590590e16960f15ceea4257122ac430c6fbe39fbf02d",
            )
            .unwrap(),
            timestamp: 1391836907,
            target: Target::from_compact(CompactTarget::from_consensus(0x1c2ac4af)),
            merkle_root: None,
            chain_work: "0x0000000000000000000000000000000000000000000000000002c7875c78875f"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 107996,
            block_hash: parse_block_hash(
                "00000000000a23840ac16115407488267aa3da2b9bc843e301185b7d17e4dc40",
            )
            .unwrap(),
            timestamp: 1395522898,
            target: Target::from_compact(CompactTarget::from_consensus(0x1b04864c)),
            merkle_root: None,
            chain_work: "0x0000000000000000000000000000000000000000000000000056bf9caa56bf9d"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 312645,
            block_hash: parse_block_hash(
                "0000000000059dcb71ad35a9e40526c44e7aae6c99169a9e7017b7d84b1c2daf",
            )
            .unwrap(),
            timestamp: 1407621730,
            target: Target::from_compact(CompactTarget::from_consensus(0x1b345f4c)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000017d08c8717d08c89"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 750000,
            block_hash: parse_block_hash(
                "00000000000000b4181bbbdddbae464ce11fede5d0292fb63fdede1e7c8ab21c",
            )
            .unwrap(),
            timestamp: 1491953700,
            target: Target::from_compact(CompactTarget::from_consensus(0x1a075a02)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000485f01ee9f01ee9f8"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        create_checkpoint(
            1450000,
            "00000000000000105cfae44a995332d8ec256850ea33a1f7b700474e3dad82bc",
            1607611038,
            0x1946c21f,
            "0x00000000000000000000000000000000000000000000008c90b78c90b78c90b7",
            None,
        ),
        // Recent checkpoint with masternode list
        create_checkpoint(
            1700000,
            "00000000000000f50e46a529f588282b62e5b2e604fe604037f6eb39c68dc58f",
            1641154800,
            0x193b81f5,
            "0x0000000000000000000000000000000000000000000000a1c2b3a1c2b3a1c2b3",
            Some("ML1700000__70227"),
        ),
        // Even more recent checkpoint
        create_checkpoint(
            1900000,
            "00000000000000268c5f5dc9e3bdda0dc7e93cf7ebf256b45b3de75b3cc0b923",
            1672688400,
            0x1918b7a5,
            "0x0000000000000000000000000000000000000000000000b8d9eab8d9eab8d9ea",
            Some("ML1900000__70230"),
        ),
    ]
}

/// Create testnet checkpoints
pub fn testnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Genesis block
        Checkpoint {
            height: 0,
            block_hash: parse_block_hash(
                "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
            )
            .unwrap(),
            timestamp: 1390666206,
            target: Target::from_compact(CompactTarget::from_consensus(0x1e0ffff0)),
            merkle_root: None,
            chain_work: "0x0000000000000000000000000000000000000000000000000000000100010001"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        // Early testnet checkpoints
        Checkpoint {
            height: 255,
            block_hash: parse_block_hash(
                "0000080b600e06f4c07880673f027210f9314575f5f875fafe51971e268b886a",
            )
            .unwrap(),
            timestamp: 1390668900, // Approximate
            target: Target::from_compact(CompactTarget::from_consensus(0x1e0fffff)),
            merkle_root: None,
            chain_work: "0x0000000000000000000000000000000000000000000000000000000200020002"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 1999,
            block_hash: parse_block_hash(
                "00000052e538d27fa53693efe6fb6892a0c1d26c0235f599171c48a3cce553b1",
            )
            .unwrap(),
            timestamp: 1390700000, // Approximate
            target: Target::from_compact(CompactTarget::from_consensus(0x1e0fffff)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000000000fa0fa0fa0fa"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 96090,
            block_hash: parse_block_hash(
                "00000000033df4b94d17ab43e999caaf6c4735095cc77703685da81254d09bba",
            )
            .unwrap(),
            timestamp: 1392000000, // Approximate
            target: Target::from_compact(CompactTarget::from_consensus(0x1c0168fd)),
            merkle_root: None,
            chain_work: "0x00000000000000000000000000000000000000000000000000059f8a5f8a5f8a"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 200000,
            block_hash: parse_block_hash(
                "000000001015eb5ef86a8fe2b3074d947bc972c5befe32b28dd5ce915dc0d029",
            )
            .unwrap(),
            timestamp: 1394000000, // Approximate
            target: Target::from_compact(CompactTarget::from_consensus(0x1b342be5)),
            merkle_root: None,
            chain_work: "0x0000000000000000000000000000000000000000000000000030f5830f5830f5"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 470000,
            block_hash: parse_block_hash(
                "0000009303aeadf8cf3812f5c869691dbd4cb118ad20e9bf553be434bafe6a52",
            )
            .unwrap(),
            timestamp: 1500000000, // Approximate
            target: Target::from_compact(CompactTarget::from_consensus(0x1a1c3bbe)),
            merkle_root: None,
            chain_work: "0x000000000000000000000000000000000000000000000000072f17072f17072f"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
        Checkpoint {
            height: 794950,
            block_hash: parse_block_hash(
                "000001860e4c7248a9c5cc3bc7106041750560dc5cd9b3a2641b49494bcff5f2",
            )
            .unwrap(),
            timestamp: 1600000000, // Approximate
            target: Target::from_compact(CompactTarget::from_consensus(0x1a0b47cf)),
            merkle_root: None,
            chain_work: "0x0000000000000000000000000000000000000000000000000c1e270c1e270c1e"
                .to_string(),
            masternode_list_name: None,
            include_merkle_root: false,
            protocol_version: None,
        },
    ]
}

/// Helper to parse hex block hash strings
fn parse_block_hash(s: &str) -> Result<BlockHash, &'static str> {
    let bytes = hex::decode(s).map_err(|_| "Invalid hex")?;
    if bytes.len() != 32 {
        return Err("Invalid hash length");
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    // Reverse for little-endian
    hash_bytes.reverse();
    Ok(BlockHash::from_byte_array(hash_bytes))
}

/// Helper to create a checkpoint with common defaults
fn create_checkpoint(
    height: u32,
    hash: &str,
    timestamp: u32,
    bits: u32,
    chain_work: &str,
    masternode_list: Option<&str>,
) -> Checkpoint {
    Checkpoint {
        height,
        block_hash: parse_block_hash(hash).unwrap(),
        timestamp,
        target: Target::from_compact(CompactTarget::from_consensus(bits)),
        merkle_root: None,
        chain_work: chain_work.to_string(),
        masternode_list_name: masternode_list.map(|s| s.to_string()),
        include_merkle_root: false,
        protocol_version: None,
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
        let genesis_checkpoint = manager.get_checkpoint(0).unwrap();
        assert_eq!(genesis_checkpoint.height, 0);
        assert_eq!(genesis_checkpoint.timestamp, 1390095618);

        // Test validation
        let genesis_hash =
            parse_block_hash("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6")
                .unwrap();
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
        assert_eq!(manager.last_checkpoint_before_height(0).unwrap().height, 0);
        assert_eq!(manager.last_checkpoint_before_height(1000).unwrap().height, 0);
        assert_eq!(manager.last_checkpoint_before_height(2000).unwrap().height, 1500);
        assert_eq!(manager.last_checkpoint_before_height(50000).unwrap().height, 45479);
    }

    #[test]
    fn test_protocol_version_extraction() {
        let checkpoint = create_checkpoint(
            1088640,
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0,
            "",
            Some("ML1088640__70218"),
        );

        assert_eq!(checkpoint.protocol_version(), Some(70218));
        assert!(checkpoint.has_masternode_list());

        let checkpoint_no_version = create_checkpoint(
            0,
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0,
            "",
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
        manager.set_sync_override(Some(1500));
        let sync_checkpoint = manager.get_sync_checkpoint(None);
        assert_eq!(sync_checkpoint.unwrap().height, 1500);

        // Test terminal override
        manager.set_terminal_override(Some(100000));
        let terminal_checkpoint = manager.get_terminal_checkpoint();
        assert_eq!(terminal_checkpoint.unwrap().height, 45479);

        // Test sync from genesis
        manager.set_sync_from_genesis(true);
        let genesis_checkpoint = manager.get_sync_checkpoint(None);
        assert_eq!(genesis_checkpoint.unwrap().height, 0);
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
        assert!(ml_checkpoint.unwrap().has_masternode_list());
        assert_eq!(ml_checkpoint.unwrap().height, 1900000);
    }

    #[test]
    fn test_checkpoint_by_timestamp() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test finding checkpoint by timestamp
        let checkpoint = manager.last_checkpoint_before_timestamp(1500000000);
        assert!(checkpoint.is_some());
        assert!(checkpoint.unwrap().timestamp <= 1500000000);
    }
}
