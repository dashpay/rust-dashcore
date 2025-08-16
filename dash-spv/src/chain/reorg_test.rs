//! Tests for chain reorganization functionality

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::chain::ChainWork;
    use crate::storage::{MemoryStorageManager, StorageManager};
    use crate::types::ChainState;
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
    async fn test_should_reorganize() {
        // Create test components
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let chain_state = ChainState::new_for_network(network);
        let storage = MemoryStorageManager::new().await.unwrap();

        // Build main chain: genesis -> block1 -> block2
        let block1 = create_test_header(&genesis, 1);
        let block2 = create_test_header(&block1, 2);

        // Create chain tip for main chain
        let main_tip = ChainTip::new(block2, 2, ChainWork::from_header(&block2));

        // Build fork chain: genesis -> block1' -> block2' -> block3'
        let block1_fork = create_test_header(&genesis, 100); // Different nonce
        let block2_fork = create_test_header(&block1_fork, 101);
        let block3_fork = create_test_header(&block2_fork, 102);

        // Create fork with more work
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 0,
            tip_hash: block3_fork.block_hash(),
            tip_height: 3,
            headers: vec![block1_fork, block2_fork, block3_fork],
            chain_work: ChainWork::from_bytes([255u8; 32]), // Max work
        };

        // Create reorg manager
        let reorg_mgr = ReorgManager::new(100, false);

        // Should reorganize because fork has more work
        let should_reorg = reorg_mgr
            .should_reorganize_with_chain_state(&main_tip, &fork, &*storage, Some(&chain_state))
            .unwrap();
        assert!(should_reorg);
    }

    #[tokio::test]
    async fn test_max_reorg_depth() {
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let chain_state = ChainState::new_for_network(network);
        let storage = MemoryStorageManager::new().await.unwrap();

        // Create a deep main chain
        let main_tip = ChainTip::new(genesis, 100, ChainWork::from_header(&genesis));

        // Create fork from genesis (depth 100)
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 0,
            tip_hash: BlockHash::from(dashcore_hashes::hash_x11::Hash::all_zeros()),
            tip_height: 101,
            headers: vec![],
            chain_work: ChainWork::from_bytes([255u8; 32]), // Max work
        };

        // Create reorg manager with max depth of 10
        let reorg_mgr = ReorgManager::new(10, false);

        // Should not reorganize due to depth limit
        let result = reorg_mgr.should_reorganize_with_chain_state(
            &main_tip,
            &fork,
            &*storage,
            Some(&chain_state),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn test_checkpoint_sync_reorg_protection() {
        let network = Network::Dash;
        let genesis = genesis_block(network).header;
        let mut chain_state = ChainState::new_for_network(network);
        let storage = MemoryStorageManager::new().await.unwrap();

        // Simulate checkpoint sync from height 50000
        chain_state.synced_from_checkpoint = true;
        chain_state.sync_base_height = 50000;

        // Current tip at height 50100
        let main_tip = ChainTip::new(genesis, 50100, ChainWork::from_header(&genesis));

        // Fork from before checkpoint (should be rejected)
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 49999, // Before checkpoint
            tip_hash: BlockHash::from(dashcore_hashes::hash_x11::Hash::all_zeros()),
            tip_height: 50101,
            headers: vec![],
            chain_work: ChainWork::from_bytes([255u8; 32]), // Max work
        };

        let reorg_mgr = ReorgManager::new(1000, false);

        // Should reject reorg past checkpoint
        let result = reorg_mgr.should_reorganize_with_chain_state(
            &main_tip,
            &fork,
            &*storage,
            Some(&chain_state),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("checkpoint"));
    }
}
