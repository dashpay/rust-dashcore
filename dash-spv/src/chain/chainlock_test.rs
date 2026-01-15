#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{
        storage::{BlockHeaderStorage, DiskStorageManager},
        types::ChainState,
    };
    use dashcore::{constants::genesis_block, ChainLock, Network};
    use dashcore_test_utils::fixtures::test_block_hash;

    /// Create a test ChainLock with minimal valid data
    fn create_test_chainlock(height: u32, block_hash: BlockHash) -> ChainLock {
        ChainLock {
            block_height: height,
            block_hash,
            signature: dashcore::bls_sig_utils::BLSSignature::from([0u8; 96]), // BLS signature placeholder
        }
    }

    #[tokio::test]
    async fn test_chainlock_processing() {
        // Create storage and ChainLock manager
        let mut storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);

        // Create a test ChainLock
        let chainlock = ChainLock {
            block_height: 1000,
            block_hash: test_block_hash(1),
            signature: dashcore::bls_sig_utils::BLSSignature::from([0; 96]),
        };

        // Process the ChainLock
        let result = chainlock_manager
            .process_chain_lock(chainlock.clone(), &chain_state, &mut storage)
            .await;

        // Should succeed even without full validation
        assert!(result.is_ok(), "ChainLock processing should succeed");

        // Verify it was stored
        assert!(chainlock_manager.has_chain_lock_at_height(1000));

        // Verify we can retrieve it
        let entry = chainlock_manager
            .get_chain_lock_by_height(1000)
            .expect("ChainLock should be retrievable after storing");
        assert_eq!(entry.chain_lock.block_height, 1000);
        assert_eq!(entry.chain_lock.block_hash, chainlock.block_hash);
    }

    #[tokio::test]
    async fn test_chainlock_superseding() {
        let mut storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);

        // Process first ChainLock at height 1000
        let chainlock1 = create_test_chainlock(1000, test_block_hash(1));

        chainlock_manager
            .process_chain_lock(chainlock1.clone(), &chain_state, &mut storage)
            .await
            .expect("First ChainLock should process successfully");

        // Process second ChainLock at height 2000
        let chainlock2 = ChainLock {
            block_height: 2000,
            block_hash: test_block_hash(2),
            signature: dashcore::bls_sig_utils::BLSSignature::from([1; 96]),
        };
        chainlock_manager
            .process_chain_lock(chainlock2.clone(), &chain_state, &mut storage)
            .await
            .expect("Second ChainLock should process successfully");

        // Verify both are stored
        assert!(chainlock_manager.has_chain_lock_at_height(1000));
        assert!(chainlock_manager.has_chain_lock_at_height(2000));

        // Get highest ChainLock
        let highest = chainlock_manager.get_highest_chain_locked_height();
        assert_eq!(highest, Some(2000));
    }

    #[tokio::test]
    async fn test_reorganization_protection() {
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);
        let mut storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");

        // Add ChainLocks at heights 1000, 2000, 3000
        for height in [1000, 2000, 3000] {
            let chainlock = ChainLock {
                block_height: height,
                block_hash: test_block_hash(height),
                signature: dashcore::bls_sig_utils::BLSSignature::from([0; 96]),
            };
            chainlock_manager
                .process_chain_lock(chainlock, &chain_state, &mut storage)
                .await
                .unwrap_or_else(|_| {
                    panic!("ChainLock at height {} should process successfully", height)
                });
        }

        // Test reorganization protection
        assert!(!chainlock_manager.would_violate_chain_lock(500, 999)); // Before ChainLocks - OK
        assert!(chainlock_manager.would_violate_chain_lock(1500, 2500)); // Would reorg ChainLock at 2000
        assert!(!chainlock_manager.would_violate_chain_lock(3001, 4000)); // After ChainLocks - OK
    }

    #[tokio::test]
    async fn test_chainlock_queue_and_process_flow() {
        let chainlock_manager = ChainLockManager::new(true);

        // Queue multiple ChainLocks
        let chain_lock1 = create_test_chainlock(100, BlockHash::from([1u8; 32]));
        let chain_lock2 = create_test_chainlock(200, BlockHash::from([2u8; 32]));
        let chain_lock3 = create_test_chainlock(300, BlockHash::from([3u8; 32]));

        chainlock_manager.queue_pending_chainlock(chain_lock1).unwrap();
        chainlock_manager.queue_pending_chainlock(chain_lock2).unwrap();
        chainlock_manager.queue_pending_chainlock(chain_lock3).unwrap();

        // Verify all are queued
        {
            // Note: pending_chainlocks is private, can't access directly
            let pending = chainlock_manager.pending_chainlocks.read().unwrap();
            assert_eq!(pending.len(), 3);
            assert_eq!(pending[0].block_height, 100);
            assert_eq!(pending[1].block_height, 200);
            assert_eq!(pending[2].block_height, 300);
        }
    }

    #[tokio::test]
    async fn test_chainlock_manager_cache_operations() {
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();

        let chainlock_manager = ChainLockManager::new(true);

        // Add test headers
        let genesis = genesis_block(Network::Dash).header;
        storage.store_headers_at_height(&[genesis], 0).await.unwrap();

        // Create and process a ChainLock
        let chain_lock = create_test_chainlock(0, genesis.block_hash());
        let chain_state = ChainState::new();
        let _ = chainlock_manager
            .process_chain_lock(chain_lock.clone(), &chain_state, &mut storage)
            .await;

        // Test cache operations
        assert!(chainlock_manager.has_chain_lock_at_height(0));

        let entry = chainlock_manager.get_chain_lock_by_height(0);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().chain_lock.block_height, 0);

        let entry_by_hash = chainlock_manager.get_chain_lock_by_hash(&genesis.block_hash());
        assert!(entry_by_hash.is_some());
        assert_eq!(entry_by_hash.unwrap().chain_lock.block_height, 0);
    }
}
