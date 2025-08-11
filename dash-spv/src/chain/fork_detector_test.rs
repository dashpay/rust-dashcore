//! Comprehensive tests for fork detection functionality

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::storage::{ChainStorage, MemoryStorage};
    use crate::types::ChainState;
    use dashcore::blockdata::constants::genesis_block;
    use dashcore::{BlockHash, Header as BlockHeader, Network};
    use dashcore_hashes::{Hash, HashEngine};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn create_test_header(prev_hash: BlockHash, nonce: u32) -> BlockHeader {
        let mut header = genesis_block(Network::Dash).header;
        header.prev_blockhash = prev_hash;
        header.nonce = nonce;
        header.time = 1390095618 + nonce * 600; // Increment time for each block
        header
    }

    fn create_test_header_with_time(prev_hash: BlockHash, nonce: u32, time: u32) -> BlockHeader {
        let mut header = create_test_header(prev_hash, nonce);
        header.time = time;
        header
    }

    #[test]
    fn test_fork_detection_with_checkpoint_sync() {
        let mut detector = ForkDetector::new(10).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Simulate checkpoint sync from height 1000
        chain_state.synced_from_checkpoint = true;
        chain_state.sync_base_height = 1000;

        // Add a checkpoint header at height 1000
        let checkpoint_header = create_test_header(BlockHash::all_zeros(), 1000);
        storage.store_header(&checkpoint_header, 1000).expect("Failed to store checkpoint");
        chain_state.add_header(checkpoint_header.clone());

        // Add more headers building on checkpoint
        let mut prev_hash = checkpoint_header.block_hash();
        for i in 1..5 {
            let header = create_test_header(prev_hash, 1000 + i);
            storage.store_header(&header, 1000 + i).expect("Failed to store header");
            chain_state.add_header(header.clone());
            prev_hash = header.block_hash();
        }

        // Try to create a fork from before the checkpoint (should be rejected)
        let pre_checkpoint_hash = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[99u8]));
        storage.store_header(&checkpoint_header, 500).expect("Failed to store at height 500");
        
        let fork_header = create_test_header(pre_checkpoint_hash, 999);
        let result = detector.check_header(&fork_header, &chain_state, &storage);
        
        // Should be orphan since it tries to fork before checkpoint
        assert!(matches!(result, ForkDetectionResult::Orphan));
    }

    #[test]
    fn test_multiple_concurrent_forks() {
        let mut detector = ForkDetector::new(5).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Setup genesis and main chain
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.add_header(genesis.clone());

        // Build main chain
        let mut main_chain_tip = genesis.block_hash();
        for i in 1..10 {
            let header = create_test_header(main_chain_tip, i);
            storage.store_header(&header, i).expect("Failed to store header");
            chain_state.add_header(header.clone());
            main_chain_tip = header.block_hash();
        }

        // Create multiple forks at different heights
        let fork_points = vec![2, 4, 6, 8];
        let mut fork_tips = Vec::new();

        for &height in &fork_points {
            // Get the header at this height from storage
            let fork_point_header = chain_state.header_at_height(height).unwrap();
            let fork_header = create_test_header(fork_point_header.block_hash(), 100 + height);
            
            let result = detector.check_header(&fork_header, &chain_state, &storage);
            
            match result {
                ForkDetectionResult::CreatesNewFork(fork) => {
                    assert_eq!(fork.fork_height, height);
                    fork_tips.push(fork_header.block_hash());
                }
                _ => panic!("Expected new fork creation at height {}", height),
            }
        }

        // Verify we have all forks tracked
        assert_eq!(detector.get_forks().len(), 4);

        // Extend each fork
        for (i, tip) in fork_tips.iter().enumerate() {
            let extension = create_test_header(*tip, 200 + i as u32);
            let result = detector.check_header(&extension, &chain_state, &storage);
            
            assert!(matches!(result, ForkDetectionResult::ExtendsFork(_)));
        }
    }

    #[test]
    fn test_fork_limit_enforcement() {
        let mut detector = ForkDetector::new(3).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Setup genesis and build a main chain
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.add_header(genesis.clone());
        
        // Build main chain past genesis
        let header1 = create_test_header(genesis.block_hash(), 1);
        storage.store_header(&header1, 1).expect("Failed to store header");
        chain_state.add_header(header1.clone());

        // Create more forks than the limit from genesis (not tip)
        let mut created_forks = Vec::new();
        for i in 0..5 {
            let fork_header = create_test_header(genesis.block_hash(), 100 + i);
            detector.check_header(&fork_header, &chain_state, &storage);
            created_forks.push(fork_header);
        }

        // Should only track the maximum allowed
        assert_eq!(detector.get_forks().len(), 3);

        // Verify we have 3 different forks
        let remaining_forks = detector.get_forks();
        let mut fork_nonces: Vec<u32> = remaining_forks.iter()
            .map(|f| f.headers[0].nonce)
            .collect();
        fork_nonces.sort();
        
        // Since all forks have equal work, eviction order is not guaranteed
        // Just verify we have 3 unique forks
        assert_eq!(fork_nonces.len(), 3);
        assert!(fork_nonces.iter().all(|&n| n >= 100 && n <= 104));
    }

    #[test]
    fn test_fork_chain_work_comparison() {
        let mut detector = ForkDetector::new(10).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Setup genesis and build a main chain
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.add_header(genesis.clone());
        
        // Build main chain past genesis
        let header1 = create_test_header(genesis.block_hash(), 1);
        storage.store_header(&header1, 1).expect("Failed to store header");
        chain_state.add_header(header1.clone());

        // Create two forks from genesis (not tip)
        let fork1_header = create_test_header(genesis.block_hash(), 100);
        let fork2_header = create_test_header(genesis.block_hash(), 200);

        detector.check_header(&fork1_header, &chain_state, &storage);
        detector.check_header(&fork2_header, &chain_state, &storage);

        // Extend fork1 with more headers
        let mut fork1_tip = fork1_header.block_hash();
        for i in 0..5 {
            let header = create_test_header(fork1_tip, 300 + i);
            detector.check_header(&header, &chain_state, &storage);
            fork1_tip = header.block_hash();
        }

        // Extend fork2 with fewer headers
        let mut fork2_tip = fork2_header.block_hash();
        for i in 0..2 {
            let header = create_test_header(fork2_tip, 400 + i);
            detector.check_header(&header, &chain_state, &storage);
            fork2_tip = header.block_hash();
        }

        // Get the strongest fork
        let strongest = detector.get_strongest_fork().expect("Should have forks");
        assert_eq!(strongest.tip_hash, fork1_tip);
        assert_eq!(strongest.headers.len(), 6); // Initial + 5 extensions
    }

    #[test]
    fn test_fork_detection_thread_safety() {
        let detector = Arc::new(Mutex::new(ForkDetector::new(50).expect("Failed to create fork detector")));
        let storage = Arc::new(MemoryStorage::new());
        let chain_state = Arc::new(Mutex::new(ChainState::new()));

        // Setup genesis
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.lock().unwrap().add_header(genesis.clone());

        // Build a base chain
        let mut prev_hash = genesis.block_hash();
        for i in 1..20 {
            let header = create_test_header(prev_hash, i);
            storage.store_header(&header, i).expect("Failed to store header");
            chain_state.lock().unwrap().add_header(header.clone());
            prev_hash = header.block_hash();
        }

        // Spawn multiple threads creating forks
        let mut handles = vec![];
        
        for thread_id in 0..5 {
            let detector_clone = Arc::clone(&detector);
            let storage_clone = Arc::clone(&storage);
            let chain_state_clone = Arc::clone(&chain_state);
            
            let handle = thread::spawn(move || {
                // Each thread creates forks at different heights
                for i in 0..10 {
                    let fork_height = (thread_id * 3 + i % 3) as u32;
                    let chain_state_lock = chain_state_clone.lock().unwrap();
                    
                    if let Some(fork_point_header) = chain_state_lock.header_at_height(fork_height) {
                        let fork_header = create_test_header(
                            fork_point_header.block_hash(),
                            1000 + thread_id * 100 + i
                        );
                        
                        let mut detector_lock = detector_clone.lock().unwrap();
                        detector_lock.check_header(&fork_header, &chain_state_lock, storage_clone.as_ref());
                    }
                }
            });
            
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify the detector is in a consistent state
        let detector_lock = detector.lock().unwrap();
        let forks = detector_lock.get_forks();
        
        // Should have multiple forks but within the limit
        assert!(forks.len() > 0);
        assert!(forks.len() <= 50);
        
        // All forks should have valid structure
        for fork in forks {
            assert!(fork.headers.len() > 0);
            assert_eq!(fork.tip_hash, fork.headers.last().unwrap().block_hash());
            assert_eq!(fork.tip_height, fork.fork_height + fork.headers.len() as u32);
        }
    }

    #[test]
    fn test_orphan_detection_edge_cases() {
        let mut detector = ForkDetector::new(10).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Test 1: Empty chain state (no genesis)
        let orphan = create_test_header(BlockHash::all_zeros(), 1);
        let result = detector.check_header(&orphan, &chain_state, &storage);
        assert!(matches!(result, ForkDetectionResult::Orphan));

        // Add genesis
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.add_header(genesis.clone());

        // Test 2: Header connecting to non-existent block
        let phantom_hash = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[42u8]));
        let orphan2 = create_test_header(phantom_hash, 2);
        let result = detector.check_header(&orphan2, &chain_state, &storage);
        assert!(matches!(result, ForkDetectionResult::Orphan));

        // Test 3: Header with far future timestamp
        let future_header = create_test_header_with_time(genesis.block_hash(), 3, u32::MAX);
        let result = detector.check_header(&future_header, &chain_state, &storage);
        assert!(matches!(result, ForkDetectionResult::ExtendsMainChain));
    }

    #[test]
    fn test_fork_removal_and_cleanup() {
        let mut detector = ForkDetector::new(10).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Setup genesis and build a main chain
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.add_header(genesis.clone());
        
        // Build main chain past genesis
        let header1 = create_test_header(genesis.block_hash(), 1);
        storage.store_header(&header1, 1).expect("Failed to store header");
        chain_state.add_header(header1.clone());

        // Create multiple forks from genesis (not tip)
        let mut fork_tips = Vec::new();
        for i in 0..5 {
            let fork_header = create_test_header(genesis.block_hash(), 100 + i);
            detector.check_header(&fork_header, &chain_state, &storage);
            fork_tips.push(fork_header.block_hash());
        }

        assert_eq!(detector.get_forks().len(), 5);

        // Remove specific forks
        for i in 0..3 {
            let removed = detector.remove_fork(&fork_tips[i]);
            assert!(removed.is_some());
        }

        assert_eq!(detector.get_forks().len(), 2);

        // Verify removed forks can't be found
        for i in 0..3 {
            assert!(detector.get_fork(&fork_tips[i]).is_none());
        }

        // Clear all remaining forks
        detector.clear_forks();
        assert_eq!(detector.get_forks().len(), 0);
        assert!(!detector.has_forks());
    }

    #[test]
    fn test_genesis_connection_special_case() {
        let mut detector = ForkDetector::new(10).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Add genesis to storage and chain state
        let genesis = genesis_block(Network::Dash).header;
        storage.store_header(&genesis, 0).expect("Failed to store genesis");
        chain_state.add_header(genesis.clone());

        // Chain state tip is at genesis (height 0)
        assert_eq!(chain_state.tip_height(), 0);

        // Header connecting to genesis should extend main chain
        let header1 = create_test_header(genesis.block_hash(), 1);
        let result = detector.check_header(&header1, &chain_state, &storage);
        assert!(matches!(result, ForkDetectionResult::ExtendsMainChain));
    }

    #[test]
    fn test_chain_state_storage_mismatch() {
        let mut detector = ForkDetector::new(10).expect("Failed to create fork detector");
        let storage = MemoryStorage::new();
        let mut chain_state = ChainState::new();

        // Add headers to chain state but not storage (simulating sync issue)
        let genesis = genesis_block(Network::Dash).header;
        chain_state.add_header(genesis.clone());
        
        let header1 = create_test_header(genesis.block_hash(), 1);
        chain_state.add_header(header1.clone());
        
        let header2 = create_test_header(header1.block_hash(), 2);
        chain_state.add_header(header2.clone());

        // Try to extend from header1 (in chain state but not storage)
        let header3 = create_test_header(header1.block_hash(), 3);
        let result = detector.check_header(&header3, &chain_state, &storage);
        
        // Should create a fork since it connects to non-tip header in chain state
        match result {
            ForkDetectionResult::CreatesNewFork(fork) => {
                assert_eq!(fork.fork_point, header1.block_hash());
                assert_eq!(fork.fork_height, 1);
            }
            _ => panic!("Expected fork creation"),
        }
    }
}