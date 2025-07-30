//! Comprehensive tests for checkpoint functionality

#[cfg(test)]
mod tests {
    use super::super::checkpoints::*;
    use dashcore::{BlockHash, CompactTarget, Target};
    use dashcore_hashes::Hash;

    fn create_test_checkpoint(height: u32, timestamp: u32) -> Checkpoint {
        let hash_bytes = dashcore_hashes::hash_x11::Hash::hash(&height.to_le_bytes());
        let prev_bytes = if height > 0 {
            dashcore_hashes::hash_x11::Hash::hash(&(height - 1).to_le_bytes())
        } else {
            dashcore_hashes::hash_x11::Hash::all_zeros()
        };

        Checkpoint {
            height,
            block_hash: BlockHash::from_raw_hash(hash_bytes),
            prev_blockhash: BlockHash::from_raw_hash(prev_bytes),
            timestamp,
            target: Target::from_compact(CompactTarget::from_consensus(0x1d00ffff)),
            merkle_root: Some(BlockHash::from_raw_hash(hash_bytes)),
            chain_work: format!("0x{:064x}", height * 1000),
            masternode_list_name: if height % 100000 == 0 && height > 0 {
                Some(format!("ML{}__70230", height))
            } else {
                None
            },
            include_merkle_root: true,
            protocol_version: None,
            nonce: height * 123,
        }
    }

    #[test]
    fn test_merkle_root_validation() {
        // Create a specific merkle root for testing
        let specific_merkle =
            BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(b"specific_merkle"));

        let mut checkpoints = vec![
            create_test_checkpoint(0, 1000000),
            create_test_checkpoint(1000, 2000000),
            create_test_checkpoint(2000, 3000000),
        ];

        // Set the specific merkle root on the middle checkpoint
        checkpoints[1].merkle_root = Some(specific_merkle);
        checkpoints[1].include_merkle_root = true;

        let manager = CheckpointManager::new(checkpoints.clone());

        // Get the actual checkpoint block hash for height 1000
        let checkpoint = manager.get_checkpoint(1000).expect("Should have checkpoint at 1000");
        let checkpoint_hash = checkpoint.block_hash;

        // Test valid merkle root
        assert!(manager.validate_header(1000, &checkpoint_hash, Some(&specific_merkle)));

        // Test invalid merkle root
        let wrong_merkle =
            BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(b"wrong_merkle"));
        assert!(!manager.validate_header(1000, &checkpoint_hash, Some(&wrong_merkle)));

        // Test missing merkle root when required - should still pass as the implementation
        // doesn't fail on missing merkle roots
        assert!(manager.validate_header(1000, &checkpoint_hash, None));
    }

    #[test]
    fn test_wallet_creation_time_checkpoint_selection() {
        let checkpoints = vec![
            create_test_checkpoint(0, 1000000),         // Jan 1970
            create_test_checkpoint(100000, 1500000000), // July 2017
            create_test_checkpoint(200000, 1600000000), // Sept 2020
            create_test_checkpoint(300000, 1700000000), // Nov 2023
        ];

        let mut manager = CheckpointManager::new(checkpoints);

        // Test wallet created in 2019
        let wallet_time_2019 = 1550000000u32;
        let checkpoint = manager.get_sync_checkpoint(Some(wallet_time_2019));
        assert_eq!(checkpoint.unwrap().height, 100000);

        // Test wallet created in 2022
        let wallet_time_2022 = 1650000000u32;
        let checkpoint = manager.get_sync_checkpoint(Some(wallet_time_2022));
        assert_eq!(checkpoint.unwrap().height, 200000);

        // Test wallet created before any checkpoint - should return None
        let wallet_time_ancient = 500000u32;
        let checkpoint = manager.get_sync_checkpoint(Some(wallet_time_ancient));
        assert!(checkpoint.is_none());

        // Test no wallet creation time (should use latest)
        let checkpoint = manager.get_sync_checkpoint(None);
        assert_eq!(checkpoint.unwrap().height, 300000);
    }

    #[test]
    fn test_checkpoint_override_priority() {
        let checkpoints = vec![
            create_test_checkpoint(0, 1000000),
            create_test_checkpoint(100000, 1500000000),
            create_test_checkpoint(200000, 1600000000),
            create_test_checkpoint(300000, 1700000000),
        ];

        let mut manager = CheckpointManager::new(checkpoints);

        // Test sync from genesis override
        manager.set_sync_from_genesis(true);
        let checkpoint = manager.get_sync_checkpoint(Some(1650000000));
        assert_eq!(checkpoint.unwrap().height, 0);

        // Test sync height override (genesis flag still takes precedence)
        manager.set_sync_override(Some(150000));
        let checkpoint = manager.get_sync_checkpoint(Some(1650000000));
        assert_eq!(checkpoint.unwrap().height, 0); // Genesis flag takes precedence

        // Clear genesis flag and test height override alone
        manager.set_sync_from_genesis(false);
        let checkpoint = manager.get_sync_checkpoint(Some(1650000000));
        assert_eq!(checkpoint.unwrap().height, 100000);

        // Test terminal override
        manager.set_terminal_override(Some(250000));
        let checkpoint = manager.get_terminal_checkpoint();
        assert_eq!(checkpoint.unwrap().height, 200000); // Last before 250000
    }

    #[test]
    fn test_fork_rejection_logic() {
        let checkpoints = vec![
            create_test_checkpoint(0, 1000000),
            create_test_checkpoint(100000, 1500000000),
            create_test_checkpoint(200000, 1600000000),
        ];

        let manager = CheckpointManager::new(checkpoints.clone());

        // Should reject forks before or at last checkpoint
        assert!(manager.should_reject_fork(0));
        assert!(manager.should_reject_fork(50000));
        assert!(manager.should_reject_fork(100000));
        assert!(manager.should_reject_fork(200000));

        // Should not reject forks after last checkpoint
        assert!(!manager.should_reject_fork(200001));
        assert!(!manager.should_reject_fork(300000));
    }

    #[test]
    fn test_best_checkpoint_at_or_before_height() {
        let checkpoints = vec![
            create_test_checkpoint(0, 1000000),
            create_test_checkpoint(100000, 1500000000),
            create_test_checkpoint(200000, 1600000000),
            create_test_checkpoint(300000, 1700000000),
        ];

        let manager = CheckpointManager::new(checkpoints.clone());

        // Test exact matches
        assert_eq!(manager.best_checkpoint_at_or_before_height(100000).unwrap().height, 100000);
        assert_eq!(manager.best_checkpoint_at_or_before_height(200000).unwrap().height, 200000);

        // Test between checkpoints
        assert_eq!(manager.best_checkpoint_at_or_before_height(150000).unwrap().height, 100000);
        assert_eq!(manager.best_checkpoint_at_or_before_height(250000).unwrap().height, 200000);

        // Test edge cases
        assert_eq!(manager.best_checkpoint_at_or_before_height(0).unwrap().height, 0);
        assert_eq!(manager.best_checkpoint_at_or_before_height(500000).unwrap().height, 300000);
    }

    #[test]
    fn test_checkpoint_protocol_version_extraction() {
        let mut checkpoint = create_test_checkpoint(100000, 1500000000);

        // Test with masternode list name
        checkpoint.masternode_list_name = Some("ML100000__70227".to_string());
        assert_eq!(checkpoint.protocol_version(), Some(70227));

        // Test with explicit protocol version (should take precedence)
        checkpoint.protocol_version = Some(70230);
        assert_eq!(checkpoint.protocol_version(), Some(70230));

        // Test with invalid masternode list format
        checkpoint.protocol_version = None;
        checkpoint.masternode_list_name = Some("ML100000_invalid".to_string());
        assert_eq!(checkpoint.protocol_version(), None);

        // Test with no masternode list
        checkpoint.masternode_list_name = None;
        assert_eq!(checkpoint.protocol_version(), None);
    }

    #[test]
    fn test_checkpoint_binary_search_efficiency() {
        // Create many checkpoints to test binary search
        let mut checkpoints = Vec::new();
        for i in 0..1000 {
            checkpoints.push(create_test_checkpoint(i * 1000, 1000000 + i * 86400));
        }

        let manager = CheckpointManager::new(checkpoints.clone());

        // Test various heights
        assert_eq!(manager.last_checkpoint_before_height(0).unwrap().height, 0);
        assert_eq!(manager.last_checkpoint_before_height(5500).unwrap().height, 5000);
        assert_eq!(manager.last_checkpoint_before_height(999999).unwrap().height, 999000);

        // Test edge case: height before first checkpoint
        assert!(manager.last_checkpoint_before_height(0).is_some());
    }

    #[test]
    fn test_is_past_last_checkpoint() {
        let checkpoints = vec![
            create_test_checkpoint(0, 1000000),
            create_test_checkpoint(100000, 1500000000),
            create_test_checkpoint(200000, 1600000000),
        ];

        let manager = CheckpointManager::new(checkpoints.clone());

        assert!(!manager.is_past_last_checkpoint(0));
        assert!(!manager.is_past_last_checkpoint(100000));
        assert!(!manager.is_past_last_checkpoint(200000));
        assert!(manager.is_past_last_checkpoint(200001));
        assert!(manager.is_past_last_checkpoint(300000));
    }

    #[test]
    fn test_empty_checkpoint_manager() {
        let manager = CheckpointManager::new(vec![]);

        assert!(manager.get_checkpoint(0).is_none());
        assert!(manager.last_checkpoint().is_none());
        assert!(manager.last_checkpoint_before_height(100000).is_none());
        assert!(manager.last_checkpoint_before_timestamp(1700000000).is_none());
        assert!(manager.last_checkpoint_having_masternode_list().is_none());
        assert!(manager.checkpoint_heights().is_empty());
        assert!(manager.is_past_last_checkpoint(0));
        assert!(!manager.should_reject_fork(100000));
    }

    #[test]
    fn test_checkpoint_validation_edge_cases() {
        let checkpoints = vec![create_test_checkpoint(100000, 1500000000)];
        let manager = CheckpointManager::new(checkpoints.clone());

        let correct_hash = manager.get_checkpoint(100000).unwrap().block_hash;
        let wrong_hash = BlockHash::all_zeros();

        // Test validation at checkpoint height
        assert!(manager.validate_block(100000, &correct_hash));
        assert!(!manager.validate_block(100000, &wrong_hash));

        // Test validation at non-checkpoint height (should always pass)
        assert!(manager.validate_block(99999, &wrong_hash));
        assert!(manager.validate_block(100001, &wrong_hash));
    }

    #[test]
    fn test_checkpoint_sorting_and_lookup() {
        // Create checkpoints in random order
        let checkpoints = vec![
            create_test_checkpoint(200000, 1600000000),
            create_test_checkpoint(0, 1000000),
            create_test_checkpoint(300000, 1700000000),
            create_test_checkpoint(100000, 1500000000),
        ];

        let manager = CheckpointManager::new(checkpoints.clone());

        // Verify heights are sorted
        let heights = manager.checkpoint_heights();
        assert_eq!(heights, &[0, 100000, 200000, 300000]);

        // Verify lookups work correctly
        assert_eq!(manager.get_checkpoint(0).unwrap().height, 0);
        assert_eq!(manager.get_checkpoint(100000).unwrap().height, 100000);
        assert_eq!(manager.get_checkpoint(200000).unwrap().height, 200000);
        assert_eq!(manager.get_checkpoint(300000).unwrap().height, 300000);
    }

    #[test]
    fn test_mainnet_checkpoint_consistency() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints.clone());

        // Verify all checkpoints are properly ordered
        let heights = manager.checkpoint_heights();
        for i in 1..heights.len() {
            assert!(heights[i] > heights[i - 1], "Checkpoints not in ascending order");
        }

        // Verify all checkpoints have valid data
        for checkpoint in &checkpoints {
            assert!(checkpoint.timestamp > 0);
            assert!(checkpoint.nonce > 0);
            assert!(!checkpoint.chain_work.is_empty());

            if checkpoint.height > 0 {
                assert_ne!(checkpoint.prev_blockhash, BlockHash::all_zeros());
            }
        }

        // Verify masternode list checkpoints
        let ml_checkpoint = manager.last_checkpoint_having_masternode_list();
        assert!(ml_checkpoint.is_some());
        assert!(ml_checkpoint.unwrap().protocol_version().is_some());
    }

    #[test]
    fn test_testnet_checkpoint_consistency() {
        let checkpoints = testnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints.clone());

        // Similar validations as mainnet
        let heights = manager.checkpoint_heights();
        for i in 1..heights.len() {
            assert!(heights[i] > heights[i - 1]);
        }

        for checkpoint in &checkpoints {
            assert!(checkpoint.timestamp > 0);
            assert!(!checkpoint.chain_work.is_empty());
        }
    }
}
