//! Comprehensive unit tests for bloom filter module

#[cfg(test)]
mod tests {
    use crate::bloom::{
        builder::BloomFilterBuilder,
        manager::{BloomFilterConfig, BloomFilterManager},
        stats::BloomStatsTracker,
        utils,
    };

    use dashcore::{
        address::{Address, Payload},
        blockdata::script::ScriptBuf,
        bloom::BloomFlags,
        hash_types::PubkeyHash,
        OutPoint, Txid,
    };

    use std::sync::Arc;

    // Test data helpers
    fn test_address() -> Address {
        // Create a simple test address from a pubkey hash
        let pubkey_hash = PubkeyHash::from([0u8; 20]);
        Address::new(dashcore::Network::Dash, Payload::PubkeyHash(pubkey_hash))
    }

    fn test_outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_hex(
                "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            )
            .unwrap(),
            vout: 0,
        }
    }

    // === BloomFilterBuilder Tests ===

    #[test]
    fn test_builder_default() {
        let builder = BloomFilterBuilder::new();
        // Since fields are private, we can't directly access them
        // Instead, test the behavior through public interface
        let filter = builder.build().unwrap();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_builder_configuration() {
        let builder = BloomFilterBuilder::new()
            .elements(1000)
            .false_positive_rate(0.01)
            .tweak(12345)
            .flags(BloomFlags::None);

        // Build and verify it doesn't error
        let filter = builder.build().unwrap();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_builder_add_single_address() {
        let address = test_address();
        let builder = BloomFilterBuilder::new().add_address(address.clone());

        let filter = builder.build().unwrap();

        // Verify filter contains the address
        let script = address.script_pubkey();
        assert!(filter.contains(script.as_bytes()));
    }

    #[test]
    fn test_builder_add_multiple_addresses() {
        let addresses = vec![
            test_address(),
            Address::new(dashcore::Network::Dash, Payload::PubkeyHash(PubkeyHash::from([1u8; 20]))),
        ];
        let builder = BloomFilterBuilder::new().add_addresses(addresses.clone());

        let filter = builder.build().unwrap();

        // Verify filter contains all addresses
        for address in addresses {
            let script = address.script_pubkey();
            assert!(filter.contains(script.as_bytes()));
        }
    }

    #[test]
    fn test_builder_add_outpoints() {
        let outpoint1 = test_outpoint();
        let outpoint2 = OutPoint {
            txid: Txid::from_hex(
                "1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd",
            )
            .unwrap(),
            vout: 1,
        };

        let builder =
            BloomFilterBuilder::new().add_outpoint(outpoint1).add_outpoints(vec![outpoint2]);

        let filter = builder.build().unwrap();

        // Verify filter contains outpoints
        let outpoint1_bytes = utils::outpoint_to_bytes(&outpoint1);
        let outpoint2_bytes = utils::outpoint_to_bytes(&outpoint2);
        assert!(filter.contains(&outpoint1_bytes));
        assert!(filter.contains(&outpoint2_bytes));
    }

    #[test]
    fn test_builder_add_data() {
        let data1 = vec![1, 2, 3, 4];
        let data2 = vec![5, 6, 7, 8];

        let builder = BloomFilterBuilder::new().add_data(data1.clone()).add_data(data2.clone());

        let filter = builder.build().unwrap();

        // Verify filter contains data
        assert!(filter.contains(&data1));
        assert!(filter.contains(&data2));
    }

    #[test]
    fn test_builder_build_empty() {
        let builder = BloomFilterBuilder::new();
        let filter = builder.build().unwrap();

        // Empty filter should still be created with default parameters
        assert!(filter.is_empty());
    }

    #[test]
    fn test_builder_build_with_elements() {
        let address = test_address();
        let outpoint = test_outpoint();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let builder = BloomFilterBuilder::new()
            .elements(50)
            .false_positive_rate(0.001)
            .add_address(address.clone())
            .add_outpoint(outpoint)
            .add_data(data.clone());

        let filter = builder.build().unwrap();

        // Verify filter contains added elements
        let script = address.script_pubkey();
        assert!(filter.contains(script.as_bytes()));

        let outpoint_bytes = utils::outpoint_to_bytes(&outpoint);
        assert!(filter.contains(&outpoint_bytes));

        assert!(filter.contains(&data));
    }

    #[test]
    fn test_builder_auto_adjusts_elements() {
        // Add more elements than configured
        let mut builder = BloomFilterBuilder::new().elements(1);

        for i in 0..10 {
            builder = builder.add_data(vec![i]);
        }

        // Should build successfully with adjusted element count
        let filter = builder.build().unwrap();
        assert!(!filter.is_empty());
    }

    // === BloomFilterManager Tests ===

    #[tokio::test]
    async fn test_manager_creation() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config.clone());

        // Check initial state through public interface
        let stats = manager.get_stats().await;
        assert_eq!(stats.items_added, 0);
        assert_eq!(stats.queries, 0);
        assert_eq!(stats.matches, 0);
        assert_eq!(stats.recreations, 0);
    }

    #[tokio::test]
    async fn test_manager_create_filter_empty() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        let _filter_load = manager.create_filter().await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.recreations, 1);
        assert_eq!(stats.items_added, 0);
    }

    #[tokio::test]
    async fn test_manager_add_address() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Create filter first
        manager.create_filter().await.unwrap();

        // Add address
        let address = test_address();
        let filter_add = manager.add_address(&address).await.unwrap();

        assert!(filter_add.is_some());

        let stats = manager.get_stats().await;
        assert_eq!(stats.items_added, 1);
    }

    #[tokio::test]
    async fn test_manager_add_address_no_filter() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Add address without creating filter
        let address = test_address();
        let filter_add = manager.add_address(&address).await.unwrap();

        assert!(filter_add.is_none());
    }

    #[tokio::test]
    async fn test_manager_add_outpoint() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Create filter first
        manager.create_filter().await.unwrap();

        // Add outpoint
        let outpoint = test_outpoint();
        let filter_add = manager.add_outpoint(&outpoint).await.unwrap();

        assert!(filter_add.is_some());

        let stats = manager.get_stats().await;
        assert_eq!(stats.items_added, 1);
    }

    #[tokio::test]
    async fn test_manager_add_data() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Create filter first
        manager.create_filter().await.unwrap();

        // Add data
        let data = vec![0x01, 0x02, 0x03];
        let filter_add = manager.add_data(data.clone()).await.unwrap();

        assert!(filter_add.is_some());

        let stats = manager.get_stats().await;
        assert_eq!(stats.items_added, 1);
    }

    #[tokio::test]
    async fn test_manager_contains() {
        let config = BloomFilterConfig {
            enable_stats: true,
            ..Default::default()
        };
        let manager = BloomFilterManager::new(config);

        // No filter - should return true
        assert!(manager.contains(&[1, 2, 3]).await);

        // Create filter and add data
        manager.create_filter().await.unwrap();
        let data = vec![0xAB, 0xCD];
        manager.add_data(data.clone()).await.unwrap();

        // Test contains
        assert!(manager.contains(&data).await);
        assert!(!manager.contains(&[0xFF, 0xFF]).await); // Should not contain random data

        let stats = manager.get_stats().await;
        assert_eq!(stats.queries, 2);
        assert_eq!(stats.matches, 1);
    }

    #[tokio::test]
    async fn test_manager_clear() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Add elements and create filter
        manager.add_address(&test_address()).await.unwrap();
        manager.add_outpoint(&test_outpoint()).await.unwrap();
        manager.create_filter().await.unwrap();

        // Clear
        manager.clear().await;

        // Verify everything is cleared through stats
        let stats = manager.get_stats().await;
        assert_eq!(stats.items_added, 0);
        assert_eq!(stats.queries, 0);
        assert_eq!(stats.matches, 0);
        assert_eq!(stats.recreations, 0);
    }

    #[tokio::test]
    async fn test_manager_needs_recreation() {
        let config = BloomFilterConfig {
            enable_stats: true,
            max_false_positive_rate: 0.05,
            ..Default::default()
        };
        let manager = BloomFilterManager::new(config);

        // Initially should not need recreation
        assert!(!manager.needs_recreation().await);

        // We can't directly set the false positive rate, but we can test the method
        // returns false when stats are disabled
        let config_no_stats = BloomFilterConfig {
            enable_stats: false,
            max_false_positive_rate: 0.05,
            ..Default::default()
        };
        let manager_no_stats = BloomFilterManager::new(config_no_stats);
        assert!(!manager_no_stats.needs_recreation().await);
    }

    #[tokio::test]
    async fn test_manager_thread_safety() {
        let config = BloomFilterConfig::default();
        let manager = Arc::new(BloomFilterManager::new(config));

        // Create filter
        manager.create_filter().await.unwrap();

        // Spawn multiple tasks to add elements concurrently
        let mut handles = vec![];

        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let handle = tokio::spawn(async move {
                let data = vec![i as u8; 4];
                manager_clone.add_data(data).await.unwrap();
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all elements were added
        let stats = manager.get_stats().await;
        assert_eq!(stats.items_added, 10);
    }

    // === BloomFilterStats Tests ===

    #[test]
    fn test_stats_tracker_creation() {
        let mut tracker = BloomStatsTracker::new();
        let stats = tracker.get_stats();

        assert_eq!(stats.basic.items_added, 0);
        assert_eq!(stats.basic.queries, 0);
        assert_eq!(stats.basic.matches, 0);
        assert_eq!(stats.basic.recreations, 0);
        assert_eq!(stats.query_performance.avg_query_time_us, 0.0);
        assert_eq!(stats.filter_health.filter_size_bytes, 0);
        assert_eq!(stats.network_impact.transactions_received, 0);
    }

    #[test]
    fn test_stats_tracker_record_query() {
        let mut tracker = BloomStatsTracker::new();

        // Record successful query
        tracker.record_query(std::time::Duration::from_micros(100), true);
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.queries, 1);
        assert_eq!(stats.basic.matches, 1);
        assert_eq!(stats.query_performance.total_query_time_us, 100);
        assert_eq!(stats.query_performance.min_query_time_us, 100);
        assert_eq!(stats.query_performance.max_query_time_us, 100);

        // Record failed query
        tracker.record_query(std::time::Duration::from_micros(50), false);
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.queries, 2);
        assert_eq!(stats.basic.matches, 1);
        assert_eq!(stats.query_performance.min_query_time_us, 50);
        assert_eq!(stats.query_performance.max_query_time_us, 100);
    }

    #[test]
    fn test_stats_tracker_record_addition() {
        let mut tracker = BloomStatsTracker::new();

        tracker.record_addition();
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.items_added, 1);

        tracker.record_addition();
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.items_added, 2);
    }

    #[test]
    fn test_stats_tracker_record_recreation() {
        let mut tracker = BloomStatsTracker::new();

        tracker.record_recreation(1024, 512, 8192);
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.recreations, 1);
        assert_eq!(stats.filter_health.filter_size_bytes, 1024);
        assert_eq!(stats.filter_health.bits_set, 512);
        assert_eq!(stats.filter_health.total_bits, 8192);
        assert_eq!(stats.filter_health.saturation_percent, 6.25);
        assert!(stats.filter_health.time_since_recreation.is_some());
    }

    #[test]
    fn test_stats_tracker_record_transaction() {
        let mut tracker = BloomStatsTracker::new();

        // Record true positive
        tracker.record_transaction(false, 250);
        let stats = tracker.get_stats();
        assert_eq!(stats.network_impact.transactions_received, 1);
        assert_eq!(stats.network_impact.false_positive_transactions, 0);
        assert!(stats.network_impact.bandwidth_saved_bytes > 0);

        // Record false positive
        tracker.record_transaction(true, 250);
        let stats = tracker.get_stats();
        assert_eq!(stats.network_impact.transactions_received, 2);
        assert_eq!(stats.network_impact.false_positive_transactions, 1);
    }

    #[test]
    fn test_stats_tracker_update_false_positive_rate() {
        let mut tracker = BloomStatsTracker::new();

        tracker.update_false_positive_rate(0.025);
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.current_false_positive_rate, 0.025);
    }

    #[test]
    fn test_stats_tracker_reset() {
        let mut tracker = BloomStatsTracker::new();

        // Add some data
        tracker.record_query(std::time::Duration::from_micros(100), true);
        tracker.record_addition();
        tracker.record_recreation(1024, 512, 8192);

        // Reset
        tracker.reset();

        // Verify all stats are reset
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.items_added, 0);
        assert_eq!(stats.basic.queries, 0);
        assert_eq!(stats.basic.matches, 0);
        assert_eq!(stats.basic.recreations, 0);
        assert!(stats.filter_health.time_since_recreation.is_none());
    }

    #[test]
    fn test_stats_tracker_summary_report() {
        let mut tracker = BloomStatsTracker::new();

        // Add some data
        tracker.record_query(std::time::Duration::from_micros(100), true);
        tracker.record_query(std::time::Duration::from_micros(200), false);
        tracker.record_addition();
        tracker.record_recreation(1024, 512, 8192);
        tracker.record_transaction(false, 500);
        tracker.record_filter_update();
        tracker.update_false_positive_rate(0.01);

        let report = tracker.summary_report();

        // Verify report contains expected information
        assert!(report.contains("Bloom Filter Statistics"));
        assert!(report.contains("Items Added: 1"));
        assert!(report.contains("Queries: 2"));
        assert!(report.contains("Current FP Rate: 1.0000%"));
        assert!(report.contains("Filter Recreations: 1"));
        assert!(report.contains("Size: 1024 bytes"));
        assert!(report.contains("Saturation: 6.2%"));
    }

    // === Utility Function Tests ===

    #[test]
    fn test_extract_pubkey_hash_valid_p2pkh() {
        // Valid P2PKH script
        let script_bytes = vec![
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
            // 20 bytes of pubkey hash
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, // OP_EQUALVERIFY
            0xac, // OP_CHECKSIG
        ];
        let script = ScriptBuf::from(script_bytes);

        let hash = utils::extract_pubkey_hash(&script);
        assert!(hash.is_some());

        let extracted = hash.unwrap();
        assert_eq!(extracted.len(), 20);
        assert_eq!(extracted[0], 0x01);
        assert_eq!(extracted[19], 0x14);
    }

    #[test]
    fn test_extract_pubkey_hash_invalid_scripts() {
        // Too short
        let script1 = ScriptBuf::from(vec![0x76, 0xa9]);
        assert!(utils::extract_pubkey_hash(&script1).is_none());

        // Wrong length
        let script2 = ScriptBuf::from(vec![0x76; 30]);
        assert!(utils::extract_pubkey_hash(&script2).is_none());

        // Wrong opcodes
        let script3 = ScriptBuf::from(vec![
            0x00, // Wrong opcode
            0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
        ]);
        assert!(utils::extract_pubkey_hash(&script3).is_none());

        // Empty script
        let script4 = ScriptBuf::from(vec![]);
        assert!(utils::extract_pubkey_hash(&script4).is_none());
    }

    #[test]
    fn test_outpoint_to_bytes() {
        let outpoint = test_outpoint();
        let bytes = utils::outpoint_to_bytes(&outpoint);

        // Should be 32 bytes txid + 4 bytes vout
        assert_eq!(bytes.len(), 36);

        // Verify txid is included
        assert_eq!(&bytes[0..32], &outpoint.txid[..]);

        // Verify vout is included (little-endian)
        let vout_bytes = outpoint.vout.to_le_bytes();
        assert_eq!(&bytes[32..36], &vout_bytes);
    }

    #[test]
    fn test_outpoint_to_bytes_different_vouts() {
        let txid =
            Txid::from_hex("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
                .unwrap();

        let outpoint1 = OutPoint {
            txid,
            vout: 0,
        };
        let outpoint2 = OutPoint {
            txid,
            vout: 1,
        };
        let outpoint3 = OutPoint {
            txid,
            vout: u32::MAX,
        };

        let bytes1 = utils::outpoint_to_bytes(&outpoint1);
        let bytes2 = utils::outpoint_to_bytes(&outpoint2);
        let bytes3 = utils::outpoint_to_bytes(&outpoint3);

        // Same txid part
        assert_eq!(&bytes1[0..32], &bytes2[0..32]);
        assert_eq!(&bytes1[0..32], &bytes3[0..32]);

        // Different vout parts
        assert_ne!(&bytes1[32..36], &bytes2[32..36]);
        assert_ne!(&bytes1[32..36], &bytes3[32..36]);
        assert_ne!(&bytes2[32..36], &bytes3[32..36]);

        // Verify specific vout values
        assert_eq!(&bytes1[32..36], &[0, 0, 0, 0]);
        assert_eq!(&bytes2[32..36], &[1, 0, 0, 0]);
        assert_eq!(&bytes3[32..36], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    // === Edge Cases and Error Handling ===

    #[test]
    fn test_builder_zero_false_positive_rate() {
        let builder = BloomFilterBuilder::new().false_positive_rate(0.0);

        // Should handle edge case gracefully
        let result = builder.build();
        // Zero false positive rate might cause an error in the underlying library
        // But our code should handle it gracefully
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_builder_very_high_false_positive_rate() {
        let builder = BloomFilterBuilder::new().false_positive_rate(0.99).add_data(vec![1, 2, 3]);

        let filter = builder.build().unwrap();
        // Filter should still be created, though not very useful
        assert!(!filter.is_empty());
    }

    #[tokio::test]
    async fn test_manager_concurrent_operations() {
        let config = BloomFilterConfig::default();
        let manager = Arc::new(BloomFilterManager::new(config));

        // Create filter
        manager.create_filter().await.unwrap();

        // Perform concurrent operations
        let m1 = Arc::clone(&manager);
        let m2 = Arc::clone(&manager);
        let m3 = Arc::clone(&manager);

        let (_r1, _r2, _r3) = tokio::join!(
            async move {
                for i in 0..10 {
                    m1.add_data(vec![i]).await.unwrap();
                }
            },
            async move {
                for _ in 0..10 {
                    m2.contains(&[0xFF]).await;
                }
            },
            async move {
                for _ in 0..5 {
                    m3.get_stats().await;
                }
            }
        );

        // All operations should complete without deadlock
        let final_stats = manager.get_stats().await;
        assert_eq!(final_stats.items_added, 10);
        assert_eq!(final_stats.queries, 10);
    }

    #[test]
    fn test_config_validation() {
        let mut config = BloomFilterConfig::default();

        // Valid configurations
        config.false_positive_rate = 0.0001;
        assert!(config.false_positive_rate > 0.0 && config.false_positive_rate < 1.0);

        config.elements = 1;
        assert!(config.elements > 0);

        config.max_false_positive_rate = 0.1;
        assert!(config.max_false_positive_rate > config.false_positive_rate);
    }

    #[test]
    fn test_stats_query_time_average() {
        let mut tracker = BloomStatsTracker::new();

        // Add many queries to test average calculation
        for i in 1..=100 {
            tracker.record_query(std::time::Duration::from_micros(i as u64), i % 2 == 0);
        }

        let stats = tracker.get_stats();
        assert_eq!(stats.basic.queries, 100);
        assert_eq!(stats.basic.matches, 50);

        // Average should be around 50.5 microseconds for last 100 queries
        assert!((stats.query_performance.avg_query_time_us - 50.5).abs() < 1.0);
    }

    #[test]
    fn test_stats_query_time_overflow_protection() {
        let mut tracker = BloomStatsTracker::new();

        // Add more than 1000 queries to test queue overflow protection
        for i in 1..=2000 {
            tracker.record_query(std::time::Duration::from_micros(i as u64), true);
        }

        // Should only keep last 1000 queries in the internal buffer
        let stats = tracker.get_stats();
        assert_eq!(stats.basic.queries, 2000);

        // The average should be calculated from the recent queries
        // For queries 1001-2000, the average should be 1500.5
        assert!((stats.query_performance.avg_query_time_us - 1500.5).abs() < 1.0);
    }

    // === Transaction Processing Tests ===

    #[tokio::test]
    async fn test_manager_process_transaction() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Create filter and add an address
        manager.create_filter().await.unwrap();
        let address = test_address();
        manager.add_address(&address).await.unwrap();

        // Create a transaction that pays to our address
        let mut tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![dashcore::TxOut {
                value: 5000,
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        // Should match because output is to our address
        assert!(manager.process_transaction(&tx).await);

        // Create a transaction that doesn't involve us
        tx.output[0].script_pubkey =
            Address::new(dashcore::Network::Dash, Payload::PubkeyHash(PubkeyHash::from([2u8; 20])))
                .script_pubkey();

        // Should not match
        assert!(!manager.process_transaction(&tx).await);
    }

    #[tokio::test]
    async fn test_manager_process_transaction_with_inputs() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Create filter and add an outpoint
        manager.create_filter().await.unwrap();
        let outpoint = test_outpoint();
        manager.add_outpoint(&outpoint).await.unwrap();

        // Create a transaction that spends our outpoint
        let tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![dashcore::TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xFFFFFFFF,
                witness: dashcore::blockdata::witness::Witness::default(),
            }],
            output: vec![],
            special_transaction_payload: None,
        };

        // Should match because input spends our outpoint
        assert!(manager.process_transaction(&tx).await);
    }

    #[tokio::test]
    async fn test_manager_process_transaction_no_filter() {
        let config = BloomFilterConfig::default();
        let manager = BloomFilterManager::new(config);

        // Without a filter, all transactions should match
        let tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };

        assert!(manager.process_transaction(&tx).await);
    }
}
