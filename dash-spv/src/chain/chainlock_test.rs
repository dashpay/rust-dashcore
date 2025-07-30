#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::storage::MemoryStorageManager;
    use crate::types::ChainState;
    use dashcore::{BlockHash, ChainLock, Network};
    use dashcore_hashes::Hash;

    #[tokio::test]
    async fn test_chainlock_processing() {
        // Create storage and ChainLock manager
        let mut storage =
            MemoryStorageManager::new().await.expect("Failed to create memory storage");
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);

        // Create a test ChainLock
        let chainlock = ChainLock {
            block_height: 1000,
            block_hash: BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[1, 2, 3])),
            signature: dashcore::bls_sig_utils::BLSSignature::from([0; 96]),
        };

        // Process the ChainLock
        let result = chainlock_manager
            .process_chain_lock(chainlock.clone(), &chain_state, &mut storage)
            .await;

        // Should succeed even without full validation
        assert!(result.is_ok(), "ChainLock processing should succeed");

        // Verify it was stored
        assert!(chainlock_manager.has_chain_lock_at_height(1000).await);

        // Verify we can retrieve it
        let entry = chainlock_manager
            .get_chain_lock_by_height(1000)
            .await
            .expect("ChainLock should be retrievable after storing");
        assert_eq!(entry.chain_lock.block_height, 1000);
        assert_eq!(entry.chain_lock.block_hash, chainlock.block_hash);
    }

    #[tokio::test]
    async fn test_chainlock_superseding() {
        let mut storage =
            MemoryStorageManager::new().await.expect("Failed to create memory storage");
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);

        // Process first ChainLock at height 1000
        let chainlock1 = ChainLock {
            block_height: 1000,
            block_hash: BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[1, 2, 3])),
            signature: dashcore::bls_sig_utils::BLSSignature::from([0; 96]),
        };
        chainlock_manager
            .process_chain_lock(chainlock1.clone(), &chain_state, &mut storage)
            .await
            .expect("First ChainLock should process successfully");

        // Process second ChainLock at height 2000
        let chainlock2 = ChainLock {
            block_height: 2000,
            block_hash: BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[4, 5, 6])),
            signature: dashcore::bls_sig_utils::BLSSignature::from([1; 96]),
        };
        chainlock_manager
            .process_chain_lock(chainlock2.clone(), &chain_state, &mut storage)
            .await
            .expect("Second ChainLock should process successfully");

        // Verify both are stored
        assert!(chainlock_manager.has_chain_lock_at_height(1000).await);
        assert!(chainlock_manager.has_chain_lock_at_height(2000).await);

        // Get highest ChainLock
        let highest = chainlock_manager.get_highest_chain_locked_height().await;
        assert_eq!(highest, Some(2000));
    }

    #[tokio::test]
    async fn test_reorganization_protection() {
        let chainlock_manager = ChainLockManager::new(true);
        let chain_state = ChainState::new_for_network(Network::Testnet);
        let mut storage =
            MemoryStorageManager::new().await.expect("Failed to create memory storage");

        // Add ChainLocks at heights 1000, 2000, 3000
        for height in [1000, 2000, 3000] {
            let chainlock = ChainLock {
                block_height: height,
                block_hash: BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(
                    &height.to_le_bytes(),
                )),
                signature: dashcore::bls_sig_utils::BLSSignature::from([0; 96]),
            };
            chainlock_manager
                .process_chain_lock(chainlock, &chain_state, &mut storage)
                .await
                .expect(&format!("ChainLock at height {} should process successfully", height));
        }

        // Test reorganization protection
        assert!(!chainlock_manager.would_violate_chain_lock(500, 999).await); // Before ChainLocks - OK
        assert!(chainlock_manager.would_violate_chain_lock(1500, 2500).await); // Would reorg ChainLock at 2000
        assert!(!chainlock_manager.would_violate_chain_lock(3001, 4000).await); // After ChainLocks - OK
    }
}
