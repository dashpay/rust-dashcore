#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{storage::DiskStorageManager, types::ChainState};
    use dashcore::Network;

    #[tokio::test]
    async fn test_chainlock_processing() {
        // Create storage and ChainLock manager
        let mut storage =
            DiskStorageManager::with_temp_dir().await.expect("Failed to create tmp storage");
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);

        let chainlock = ChainLock::dummy(1000);

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

        let chainlock1 = ChainLock::dummy(1000);

        chainlock_manager
            .process_chain_lock(chainlock1.clone(), &chain_state, &mut storage)
            .await
            .expect("First ChainLock should process successfully");

        let chainlock2 = ChainLock::dummy(2000);

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
            let chainlock = ChainLock::dummy(height);
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
}
