//! Tests for chain reorganization functionality

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::chain::ChainWork;
    use crate::storage::{MemoryStorageManager, StorageManager};
    use crate::types::ChainState;
    use crate::wallet::WalletState;
    use dashcore::{blockdata::constants::genesis_block, Network};
    use dashcore_hashes::Hash;

    fn create_test_header(prev: &BlockHeader, nonce: u32) -> BlockHeader {
        let mut header = prev.clone();
        header.prev_blockhash = prev.block_hash();
        header.nonce = nonce;
        header.time = prev.time + 600; // 10 minutes later
        header
    }

    #[tokio::test]
    async fn test_reorganization_no_borrow_conflict() {
        // Create test components
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let mut chain_state = ChainState::new_for_network(network);
        let mut wallet_state = WalletState::new(network);
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        // Build main chain: genesis -> block1 -> block2
        let block1 = create_test_header(&genesis, 1);
        let block2 = create_test_header(&block1, 2);
        
        // Store main chain
        storage.store_headers(&[genesis]).await.unwrap();
        storage.store_headers(&[block1]).await.unwrap();
        storage.store_headers(&[block2]).await.unwrap();
        
        // Update chain state - genesis is already added by new_for_network
        chain_state.add_header(block1);
        chain_state.add_header(block2);
        
        // Build fork chain: genesis -> block1' -> block2' -> block3'
        let block1_fork = create_test_header(&genesis, 100); // Different nonce
        let block2_fork = create_test_header(&block1_fork, 101);
        let block3_fork = create_test_header(&block2_fork, 102);
        
        // Create fork with more work
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 0, // Fork from genesis
            tip_hash: block3_fork.block_hash(),
            tip_height: 3,
            headers: vec![block1_fork, block2_fork, block3_fork],
            chain_work: ChainWork::from_bytes([255u8; 32]), // Maximum work
        };
        
        // Create reorg manager
        let reorg_manager = ReorgManager::new(100, false);
        
        // This should now work without borrow conflicts!
        let result = reorg_manager.reorganize(
            &mut chain_state,
            &mut wallet_state,
            &fork,
            &mut storage,
        ).await;
        
        // Verify reorganization succeeded
        assert!(result.is_ok());
        let event = result.unwrap();
        
        // Check reorganization details
        assert_eq!(event.common_ancestor, genesis.block_hash());
        assert_eq!(event.common_height, 0);
        assert_eq!(event.disconnected_headers.len(), 2); // block1 and block2
        assert_eq!(event.connected_headers.len(), 3); // block1', block2', block3'
        
        // Verify chain state was updated
        assert_eq!(chain_state.get_height(), 3);
        
        // Verify new headers were stored
        assert!(storage.get_header(1).await.unwrap().is_some());
        assert!(storage.get_header(2).await.unwrap().is_some());
        assert!(storage.get_header(3).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_find_common_ancestor_in_main_chain() {
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        // Store genesis
        storage.store_headers(&[genesis]).await.unwrap();
        
        // Create fork that references genesis (which is in our chain)
        let block1_fork = create_test_header(&genesis, 100);
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 0,
            tip_hash: block1_fork.block_hash(),
            tip_height: 1,
            headers: vec![block1_fork],
            chain_work: ChainWork::from_header(&block1_fork),
        };
        
        let reorg_manager = ReorgManager::new(100, false);
        let chain_state = ChainState::new_for_network(network);
        
        // Test finding common ancestor
        let reorg_data = reorg_manager.collect_reorg_data(
            &chain_state,
            &fork,
            &storage,
        ).await.unwrap();
        
        assert_eq!(reorg_data.common_ancestor, genesis.block_hash());
        assert_eq!(reorg_data.common_height, 0);
    }

    #[tokio::test]
    async fn test_deep_reorganization() {
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let mut chain_state = ChainState::new_for_network(network);
        let mut wallet_state = WalletState::new(network);
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        // Build a long main chain
        let mut current = genesis;
        storage.store_headers(&[current]).await.unwrap();
        // genesis is already in chain_state from new_for_network
        
        for i in 1..=10 {
            let next = create_test_header(&current, i);
            storage.store_headers(&[next]).await.unwrap();
            chain_state.add_header(next);
            current = next;
        }
        
        // Build a longer fork from block 5
        let block5 = storage.get_header(5).await.unwrap().unwrap();
        let mut fork_headers = Vec::new();
        current = block5;
        
        for i in 100..108 { // 8 blocks, making fork 13 blocks total (5 + 8)
            let next = create_test_header(&current, i);
            fork_headers.push(next);
            current = next;
        }
        
        let fork = Fork {
            fork_point: block5.block_hash(),
            fork_height: 5,
            tip_hash: current.block_hash(),
            tip_height: 13,
            headers: fork_headers,
            chain_work: ChainWork::from_bytes([255u8; 32]), // Max work
        };
        
        let reorg_manager = ReorgManager::new(100, false);
        let result = reorg_manager.reorganize(
            &mut chain_state,
            &mut wallet_state,
            &fork,
            &mut storage,
        ).await;
        
        assert!(result.is_ok());
        let event = result.unwrap();
        
        // Should have disconnected blocks 6-10 (5 blocks)
        assert_eq!(event.disconnected_headers.len(), 5);
        // Should have connected 8 new blocks
        assert_eq!(event.connected_headers.len(), 8);
        // Chain height should now be 13
        assert_eq!(chain_state.get_height(), 13);
    }
}