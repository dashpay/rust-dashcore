//! Comprehensive tests for checkpoint functionality

#[cfg(test)]
mod tests {
    use super::super::checkpoints::*;
    use dashcore::BlockHash;

    #[test]
    fn test_wallet_creation_time_checkpoint_selection() {
        let checkpoints = vec![
            Checkpoint::dummy(0, 1000000),         // Jan 1970
            Checkpoint::dummy(100000, 1500000000), // July 2017
            Checkpoint::dummy(200000, 1600000000), // Sept 2020
            Checkpoint::dummy(300000, 1700000000), // Nov 2023
        ];

        let manager = CheckpointManager::new(checkpoints);

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
    fn test_fork_rejection_logic() {
        let checkpoints = vec![
            Checkpoint::dummy(0, 1000000),
            Checkpoint::dummy(100000, 1500000000),
            Checkpoint::dummy(200000, 1600000000),
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
    fn test_checkpoint_protocol_version_extraction() {
        let mut checkpoint = Checkpoint::dummy(100000, 1500000000);

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
            checkpoints.push(Checkpoint::dummy(i * 1000, 1000000 + i * 86400));
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
    fn test_empty_checkpoint_manager() {
        let manager = CheckpointManager::new(vec![]);

        assert!(manager.get_checkpoint(0).is_none());
        assert!(manager.last_checkpoint().is_none());
        assert!(manager.last_checkpoint_before_height(100000).is_none());
        assert!(manager.last_checkpoint_before_timestamp(1700000000).is_none());
        assert!(manager.checkpoint_heights().is_empty());
        assert!(!manager.should_reject_fork(100000));
    }

    #[test]
    fn test_checkpoint_validation_edge_cases() {
        let checkpoints = vec![Checkpoint::dummy(100000, 1500000000)];
        let manager = CheckpointManager::new(checkpoints.clone());

        let correct_hash = manager.get_checkpoint(100000).unwrap().block_hash;
        let wrong_hash = BlockHash::from([0u8; 32]);

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
            Checkpoint::dummy(200000, 1600000000),
            Checkpoint::dummy(0, 1000000),
            Checkpoint::dummy(300000, 1700000000),
            Checkpoint::dummy(100000, 1500000000),
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
                assert_ne!(checkpoint.prev_blockhash, BlockHash::from([0u8; 32]));
            }
        }
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
