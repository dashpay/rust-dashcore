//! Comprehensive tests for orphan pool functionality

#[cfg(test)]
mod tests {
    use super::super::orphan_pool::*;
    use dashcore::hashes::Hash;
    use dashcore::{BlockHash, Header as BlockHeader};
    use std::collections::HashSet;
    use std::thread;
    use std::time::{Duration, Instant};

    fn create_test_header(prev: BlockHash, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: dashcore::block::Version::from_consensus(1),
            prev_blockhash: prev,
            merkle_root: dashcore::TxMerkleNode::all_zeros(),
            time: 1234567890 + nonce,
            bits: dashcore::CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }

    #[test]
    fn test_orphan_expiration() {
        // Create pool with short timeout for testing
        let mut pool = OrphanPool::with_config(10, Duration::from_millis(100));

        // Add orphans
        let mut hashes = Vec::new();
        for i in 0..5 {
            let header = create_test_header(BlockHash::from([0u8; 32]), i);
            hashes.push(header.block_hash());
            pool.add_orphan(header);
        }

        assert_eq!(pool.len(), 5);

        // Wait for timeout
        thread::sleep(Duration::from_millis(150));

        // Add a fresh orphan
        let fresh_header = create_test_header(BlockHash::from([0u8; 32]), 100);
        let fresh_hash = fresh_header.block_hash();
        pool.add_orphan(fresh_header);

        // Remove expired orphans
        let removed = pool.remove_expired();

        // All original orphans should be expired
        assert_eq!(removed.len(), 5);
        assert!(removed.iter().all(|h| hashes.contains(h)));

        // Fresh orphan should remain
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&fresh_hash));
    }

    #[test]
    fn test_orphan_chain_reactions() {
        let mut pool = OrphanPool::new();

        // Create a chain of orphans: A -> B -> C -> D
        let header_a = create_test_header(BlockHash::from([0u8; 32]), 1);
        let hash_a = header_a.block_hash();

        let header_b = create_test_header(hash_a, 2);
        let hash_b = header_b.block_hash();

        let header_c = create_test_header(hash_b, 3);
        let hash_c = header_c.block_hash();

        let header_d = create_test_header(hash_c, 4);

        // Add them out of order (A is not an orphan since it connects to genesis)
        pool.add_orphan(header_d.clone());
        pool.add_orphan(header_b.clone());
        pool.add_orphan(header_c.clone());

        assert_eq!(pool.len(), 3);

        // Process when block A is accepted - should return B
        let orphans = pool.process_new_block(&hash_a);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], header_b);
        assert_eq!(pool.len(), 2); // C and D remain

        // Process when block B is accepted - should return C
        let orphans = pool.process_new_block(&hash_b);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], header_c);
        assert_eq!(pool.len(), 1); // Only D remains

        // Process when block C is accepted - should return D
        let orphans = pool.process_new_block(&hash_c);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], header_d);
        assert_eq!(pool.len(), 0); // Pool is now empty
    }

    #[test]
    fn test_orphan_statistics() {
        let mut pool = OrphanPool::with_config(100, Duration::from_secs(3600));

        // Add orphans with different parent blocks
        let parent1 = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[1u8]));
        let parent2 = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[2u8]));
        let parent3 = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[3u8]));

        // Add multiple orphans for parent1
        for i in 0..5 {
            pool.add_orphan(create_test_header(parent1, i));
        }

        // Add orphans for parent2
        for i in 5..8 {
            pool.add_orphan(create_test_header(parent2, i));
        }

        // Add one orphan for parent3
        pool.add_orphan(create_test_header(parent3, 8));

        let stats = pool.stats();
        assert_eq!(stats.total_orphans, 9);
        assert_eq!(stats.unique_parents, 3);
        assert_eq!(stats.max_process_attempts, 0);

        // Process some orphans to increase attempts
        pool.get_orphans_by_prev(&parent1);
        pool.get_orphans_by_prev(&parent1);
        pool.get_orphans_by_prev(&parent2);

        let stats = pool.stats();
        assert_eq!(stats.max_process_attempts, 2); // parent1 orphans processed twice
    }

    #[test]
    fn test_orphan_pool_size_limit_with_different_parents() {
        let mut pool = OrphanPool::with_config(5, Duration::from_secs(3600));

        // Add orphans with different parents
        let mut all_hashes = Vec::new();
        for i in 0..10 {
            let parent =
                BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[i as u8]));
            let header = create_test_header(parent, i);
            all_hashes.push(header.block_hash());
            pool.add_orphan(header);
        }

        // Pool should only contain the last 5 orphans
        assert_eq!(pool.len(), 5);

        // First 5 should have been evicted
        for i in 0..5 {
            assert!(!pool.contains(&all_hashes[i]));
        }

        // Last 5 should still be present
        for i in 5..10 {
            assert!(pool.contains(&all_hashes[i]));
        }
    }

    #[test]
    fn test_orphan_pool_multiple_orphans_same_parent() {
        let mut pool = OrphanPool::new();
        let parent = BlockHash::from([0u8; 32]);

        // Add multiple orphans with the same parent
        let mut headers = Vec::new();
        for i in 0..5 {
            let header = create_test_header(parent, i);
            headers.push(header.clone());
            pool.add_orphan(header);
        }

        assert_eq!(pool.len(), 5);

        // Get all orphans for this parent
        let orphans = pool.get_orphans_by_prev(&parent);
        assert_eq!(orphans.len(), 5);

        // Verify all orphans were returned
        let orphan_set: HashSet<_> = orphans.iter().map(|h| h.block_hash()).collect();
        let header_set: HashSet<_> = headers.iter().map(|h| h.block_hash()).collect();
        assert_eq!(orphan_set, header_set);

        // get_orphans_by_prev doesn't remove orphans, so they should still be there
        assert_eq!(pool.len(), 5);

        // Use process_new_block to actually remove them
        let processed = pool.process_new_block(&parent);
        assert_eq!(processed.len(), 5);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_orphan_removal_consistency() {
        let mut pool = OrphanPool::new();

        // Create complex orphan relationships
        let parent1 = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[1u8]));
        let parent2 = BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[2u8]));

        let header1a = create_test_header(parent1, 1);
        let header1b = create_test_header(parent1, 2);
        let header2a = create_test_header(parent2, 3);

        let hash1a = header1a.block_hash();
        let hash1b = header1b.block_hash();
        let hash2a = header2a.block_hash();

        pool.add_orphan(header1a);
        pool.add_orphan(header1b);
        pool.add_orphan(header2a);

        assert_eq!(pool.len(), 3);

        // Remove one orphan from parent1
        pool.remove_orphan(&hash1a);

        // Verify pool consistency
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&hash1a));
        assert!(pool.contains(&hash1b));
        assert!(pool.contains(&hash2a));

        // Parent1 should still have one orphan
        let orphans = pool.get_orphans_by_prev(&parent1);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].block_hash(), hash1b);

        // Parent2 should still have its orphan
        let orphans = pool.get_orphans_by_prev(&parent2);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].block_hash(), hash2a);
    }

    #[test]
    fn test_orphan_pool_clear_removes_all_indexes() {
        let mut pool = OrphanPool::new();

        // Add various orphans
        for i in 0..10 {
            let parent =
                BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[i as u8]));
            pool.add_orphan(create_test_header(parent, i));
        }

        assert_eq!(pool.len(), 10);
        assert!(!pool.is_empty());

        pool.clear();

        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());

        // Verify all indexes are cleared
        for i in 0..10 {
            let parent =
                BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[i as u8]));
            let orphans = pool.get_orphans_by_prev(&parent);
            assert_eq!(orphans.len(), 0);
        }
    }

    #[test]
    fn test_orphan_age_tracking() {
        let mut pool = OrphanPool::with_config(10, Duration::from_secs(3600));

        // Add orphans with delays
        let header1 = create_test_header(BlockHash::from([0u8; 32]), 1);
        pool.add_orphan(header1);

        thread::sleep(Duration::from_millis(50));

        let header2 = create_test_header(BlockHash::from([0u8; 32]), 2);
        pool.add_orphan(header2);

        thread::sleep(Duration::from_millis(50));

        let header3 = create_test_header(BlockHash::from([0u8; 32]), 3);
        pool.add_orphan(header3);

        let stats = pool.stats();

        // Oldest orphan should be at least 100ms old
        assert!(stats.oldest_age >= Duration::from_millis(100));

        // But not unreasonably old
        assert!(stats.oldest_age < Duration::from_secs(1));
    }

    #[test]
    fn test_process_attempts_tracking() {
        let mut pool = OrphanPool::new();
        let parent = BlockHash::from([0u8; 32]);

        let header = create_test_header(parent, 1);
        let hash = header.block_hash();
        pool.add_orphan(header);

        // Process multiple times without removing
        for expected_attempts in 1..=5 {
            pool.get_orphans_by_prev(&parent);

            // Don't remove the orphan, just check attempts
            let stats = pool.stats();
            assert_eq!(stats.max_process_attempts, expected_attempts);
        }

        // Verify the orphan is still there with correct attempt count
        assert!(pool.contains(&hash));
    }

    #[test]
    fn test_eviction_queue_ordering() {
        let mut pool = OrphanPool::with_config(3, Duration::from_secs(3600));

        // Add orphans in specific order
        let mut hashes = Vec::new();
        for i in 0..5 {
            let header = create_test_header(BlockHash::from([0u8; 32]), i);
            hashes.push(header.block_hash());
            pool.add_orphan(header);

            // Small delay to ensure different timestamps
            thread::sleep(Duration::from_millis(10));
        }

        // Pool should contain only the last 3
        assert_eq!(pool.len(), 3);

        // First two should have been evicted (FIFO)
        assert!(!pool.contains(&hashes[0]));
        assert!(!pool.contains(&hashes[1]));

        // Last three should remain
        assert!(pool.contains(&hashes[2]));
        assert!(pool.contains(&hashes[3]));
        assert!(pool.contains(&hashes[4]));
    }

    #[test]
    fn test_remove_orphan_returns_removed_data() {
        let mut pool = OrphanPool::new();

        let header = create_test_header(BlockHash::from([0u8; 32]), 1);
        let hash = header.block_hash();
        let original_time = Instant::now();

        pool.add_orphan(header.clone());

        // Process a few times to increment attempts
        for _ in 0..3 {
            pool.get_orphans_by_prev(&BlockHash::from([0u8; 32]));
        }

        // Remove and verify returned data
        let removed = pool.remove_orphan(&hash).expect("Should remove orphan");

        assert_eq!(removed.header, header);
        assert_eq!(removed.process_attempts, 3);
        assert!(removed.received_at >= original_time);
        assert!(removed.received_at <= Instant::now());
    }

    #[test]
    fn test_concurrent_orphan_operations() {
        use std::sync::{Arc, Mutex};

        let pool = Arc::new(Mutex::new(OrphanPool::with_config(100, Duration::from_secs(3600))));
        let mut handles = vec![];

        // Spawn threads that add orphans
        for thread_id in 0..5 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                for i in 0..20 {
                    let parent =
                        BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[
                            thread_id as u8,
                            i as u8,
                        ]));
                    let header = create_test_header(parent, (thread_id as u32) * 100 + (i as u32));
                    pool_clone.lock().unwrap().add_orphan(header);
                }
            });
            handles.push(handle);
        }

        // Spawn threads that process orphans
        for thread_id in 0..3 {
            let pool_clone = Arc::clone(&pool);
            let handle = thread::spawn(move || {
                for i in 0..30 {
                    let parent =
                        BlockHash::from_raw_hash(dashcore_hashes::hash_x11::Hash::hash(&[
                            (thread_id % 5) as u8,
                            (i % 20) as u8,
                        ]));
                    let mut pool = pool_clone.lock().unwrap();
                    pool.get_orphans_by_prev(&parent);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify pool is in consistent state
        let pool = pool.lock().unwrap();
        assert!(pool.len() <= 100);

        let stats = pool.stats();
        assert_eq!(stats.total_orphans, pool.len());
        assert!(stats.unique_parents <= pool.len());
    }
}
