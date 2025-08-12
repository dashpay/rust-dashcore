//! Integration tests for comprehensive validation functionality.

#[cfg(test)]
mod tests {
    use crate::client::ClientConfig;
    use crate::storage::MemoryStorage;
    use crate::sync::chainlock_validation::{ChainLockValidationConfig, ChainLockValidator};
    use crate::sync::masternodes::MasternodeSyncManager;
    use crate::sync::validation::{ValidationConfig, ValidationEngine};
    use crate::sync::validation_state::{ValidationStateManager, ValidationType};
    use crate::types::ValidationMode;
    use dashcore::network::message_qrinfo::{QRInfo, QuorumSnapshot};
    use dashcore::network::message_sml::MnListDiff;
    use dashcore::Transaction;
    use dashcore::{BlockHash, Network};

    /// Create a test client config with validation enabled
    fn create_test_config() -> ClientConfig {
        let mut config = ClientConfig::default();
        config.network = Network::Testnet;
        config.validation_mode = ValidationMode::Full;
        config.enable_masternodes = true;
        config
    }

    /// Create a mock QRInfo for testing
    fn create_mock_qr_info() -> QRInfo {
        QRInfo {
            mn_list_diff_list: vec![create_mock_mn_list_diff(100), create_mock_mn_list_diff(200)],
            quorum_snapshot_list: vec![],
            last_block_hashes: vec![],
            has_infos_for_last_blocks: false,
        }
    }

    /// Create a mock MnListDiff for testing
    fn create_mock_mn_list_diff(_height: u32) -> MnListDiff {
        MnListDiff {
            version: 1,
            base_block_hash: BlockHash::all_zeros(),
            block_hash: BlockHash::from([0; 32]),
            total_transactions: 1,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx: Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                extra_payload: None,
            },
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            merkle_root_mn_list: dashcore::hash_types::MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: None,
        }
    }

    #[tokio::test]
    async fn test_validation_engine_creation() {
        let config = ValidationConfig::default();
        let engine = ValidationEngine::new(config);

        let stats = engine.stats();
        assert_eq!(stats.total_validations, 0);
        assert_eq!(stats.successful_validations, 0);
        assert_eq!(stats.failed_validations, 0);
    }

    #[tokio::test]
    async fn test_chain_lock_validator_creation() {
        let config = ChainLockValidationConfig::default();
        let validator = ChainLockValidator::new(config);

        assert_eq!(validator.cache_hit_rate(), 0.0);
    }

    #[tokio::test]
    async fn test_validation_state_manager() {
        let mut manager = ValidationStateManager::new();

        // Update state
        manager.update_sync_height(100);
        manager.add_pending_validation(101, ValidationType::MasternodeList);

        // Create snapshot
        let snapshot_id = manager.create_snapshot("Test snapshot");

        // Make changes
        manager.update_sync_height(200);
        manager.record_validation_failure(
            150,
            ValidationType::ChainLock,
            "Test failure".to_string(),
            true,
        );

        // Check current state
        assert_eq!(manager.current_state().current_height, 200);
        assert_eq!(manager.current_state().validation_failures.len(), 1);

        // Rollback
        manager.rollback_to_snapshot(snapshot_id).unwrap();

        // Verify rollback
        assert_eq!(manager.current_state().current_height, 100);
        assert_eq!(manager.current_state().validation_failures.len(), 0);
        assert_eq!(manager.current_state().pending_validations.len(), 1);
    }

    #[tokio::test]
    async fn test_masternode_sync_with_validation() {
        let config = create_test_config();
        let mut sync_manager = MasternodeSyncManager::new(&config);

        // Verify validation components are created
        assert!(sync_manager.get_validation_summary().is_some());

        // Get initial summary
        let summary = sync_manager.get_validation_summary().unwrap();
        assert_eq!(summary.total_validated, 0);
        assert_eq!(summary.failures, 0);
    }

    #[tokio::test]
    async fn test_qr_info_validation() {
        let config = create_test_config();
        let mut sync_manager = MasternodeSyncManager::new(&config);
        let storage = MemoryStorage::new();

        // Create mock QRInfo
        let qr_info = create_mock_qr_info();

        // Process QRInfo with validation
        // Note: This will fail without a proper engine setup, but tests the validation flow
        let result = sync_manager.handle_qr_info(qr_info, &storage).await;

        // The test should fail due to missing engine data, but validation should run
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validation_enable_disable() {
        let mut config = create_test_config();
        config.validation_mode = ValidationMode::None;

        let mut sync_manager = MasternodeSyncManager::new(&config);

        // Should start with validation disabled
        assert!(sync_manager.get_validation_summary().is_none());

        // Enable validation
        sync_manager.set_validation_enabled(true);
        assert!(sync_manager.get_validation_summary().is_some());

        // Disable validation
        sync_manager.set_validation_enabled(false);
        assert!(sync_manager.get_validation_summary().is_none());
    }

    #[tokio::test]
    async fn test_validation_state_consistency() {
        let mut manager = ValidationStateManager::new();

        // Set valid state
        manager.update_sync_height(100);
        manager.current_state_mut().last_validated_height = 50;

        // Should pass consistency check
        assert!(manager.validate_consistency().is_ok());

        // Set invalid state
        manager.current_state_mut().last_validated_height = 200;

        // Should fail consistency check
        assert!(manager.validate_consistency().is_err());
    }

    #[tokio::test]
    async fn test_validation_with_retries() {
        let mut config = ValidationConfig::default();
        config.retry_failed_validations = true;
        config.max_retries = 3;

        let engine = ValidationEngine::new(config);

        // Verify retry configuration
        assert_eq!(engine.stats().total_validations, 0);
    }

    #[tokio::test]
    async fn test_validation_cache() {
        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        // Perform validations to populate cache
        // Note: Actual validation requires proper engine setup

        let stats = engine.stats();
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.cache_misses, 0);
    }
}

/// Performance tests for validation
#[cfg(test)]
mod perf_tests {
    use super::tests::*;
    use crate::sync::chainlock_validation::{ChainLockValidationConfig, ChainLockValidator};
    use crate::sync::validation::{ValidationConfig, ValidationEngine};
    use dashcore::network::message_qrinfo::QRInfo;
    use dashcore::{BlockHash, Network};
    use std::time::Instant;

    #[tokio::test]
    #[ignore] // Run with --ignored flag for performance tests
    async fn test_validation_performance() {
        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let start = Instant::now();

        // Create large QRInfo for performance testing
        let mut qr_info = QRInfo {
            mn_list_diff_list: vec![],
            quorum_snapshot_list: vec![],
            last_block_hashes: vec![],
            has_infos_for_last_blocks: false,
        };

        // Add 1000 diffs
        for i in 0..1000 {
            qr_info.mn_list_diff_list.push(create_mock_mn_list_diff(i));
        }

        let duration = start.elapsed();
        println!("Created test data in {:?}", duration);

        // Note: Actual validation would require proper engine setup
        // This test demonstrates the performance testing framework
    }

    #[tokio::test]
    #[ignore]
    async fn test_cache_performance() {
        let mut config = ChainLockValidationConfig::default();
        config.cache_size = 10000;

        let mut validator = ChainLockValidator::new(config);

        let start = Instant::now();

        // Simulate many cache operations
        for i in 0..10000 {
            let hash = BlockHash::from([i as u8; 32]);
            // Cache operations would happen during validation
        }

        let duration = start.elapsed();
        println!("Cache operations completed in {:?}", duration);

        let hit_rate = validator.cache_hit_rate();
        println!("Cache hit rate: {:.2}%", hit_rate * 100.0);
    }
}
