#[cfg(test)]
mod tests {
    use crate::*;
    use key_wallet_ffi::FFINetwork;

    #[test]
    fn test_ffi_string_utf8_edge_cases() {
        // Test empty string
        let empty = FFIString::new("");
        unsafe {
            let recovered = FFIString::from_ptr(empty.ptr).unwrap();
            assert_eq!(recovered, "");
            dash_spv_ffi_string_destroy(empty);
        }

        // Test with emojis
        let emoji_str = "Hello 👋 World 🌍!";
        let emoji = FFIString::new(emoji_str);
        unsafe {
            let recovered = FFIString::from_ptr(emoji.ptr).unwrap();
            assert_eq!(recovered, emoji_str);
            dash_spv_ffi_string_destroy(emoji);
        }

        // Test with special characters
        let special = "Tab\tNewline\nCarriage\rReturn";
        let special_ffi = FFIString::new(special);
        unsafe {
            let recovered = FFIString::from_ptr(special_ffi.ptr).unwrap();
            assert_eq!(recovered, special);
            dash_spv_ffi_string_destroy(special_ffi);
        }

        // Test with very long string
        let long_str = "a".repeat(10000);
        let long_ffi = FFIString::new(&long_str);
        unsafe {
            let recovered = FFIString::from_ptr(long_ffi.ptr).unwrap();
            assert_eq!(recovered, long_str);
            dash_spv_ffi_string_destroy(long_ffi);
        }
    }

    #[test]
    fn test_ffi_string_null_handling() {
        unsafe {
            // Test null pointer
            let result = FFIString::from_ptr(std::ptr::null());
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), "Null pointer");

            // Test destroying null (should be safe)
            dash_spv_ffi_string_destroy(FFIString {
                ptr: std::ptr::null_mut(),
                length: 0,
            });
        }
    }

    #[test]
    fn test_ffi_array_different_sizes() {
        // Test empty array
        let empty: Vec<u32> = vec![];
        let mut empty_array = FFIArray::new(empty);
        assert_eq!(empty_array.len, 0);
        assert!(!empty_array.data.is_null()); // Even empty vec has allocated pointer
        unsafe {
            let slice = empty_array.as_slice::<u32>();
            assert_eq!(slice.len(), 0);
            dash_spv_ffi_array_destroy(&mut empty_array as *mut FFIArray);
        }

        // Test single element
        let single = vec![42u32];
        let mut single_array = FFIArray::new(single);
        assert_eq!(single_array.len, 1);
        unsafe {
            let slice = single_array.as_slice::<u32>();
            assert_eq!(slice.len(), 1);
            assert_eq!(slice[0], 42);
            dash_spv_ffi_array_destroy(&mut single_array as *mut FFIArray);
        }

        // Test large array
        let large: Vec<u32> = (0..10000).collect();
        let mut large_array = FFIArray::new(large.clone());
        assert_eq!(large_array.len, 10000);
        unsafe {
            let slice = large_array.as_slice::<u32>();
            assert_eq!(slice.len(), 10000);
            for (i, &val) in slice.iter().enumerate() {
                assert_eq!(val, i as u32);
            }
            dash_spv_ffi_array_destroy(&mut large_array as *mut FFIArray);
        }
    }

    #[test]
    fn test_ffi_array_memory_alignment() {
        // Test with u8
        let bytes: Vec<u8> = vec![1, 2, 3, 4];
        let mut byte_array = FFIArray::new(bytes);
        unsafe {
            let slice = byte_array.as_slice::<u8>();
            assert_eq!(slice, &[1, 2, 3, 4]);
            dash_spv_ffi_array_destroy(&mut byte_array as *mut FFIArray);
        }

        // Test with u64 (requires 8-byte alignment)
        let longs: Vec<u64> = vec![u64::MAX, 0, 42];
        let mut long_array = FFIArray::new(longs);
        unsafe {
            let slice = long_array.as_slice::<u64>();
            assert_eq!(slice[0], u64::MAX);
            assert_eq!(slice[1], 0);
            assert_eq!(slice[2], 42);
            dash_spv_ffi_array_destroy(&mut long_array as *mut FFIArray);
        }
    }

    #[test]
    fn test_network_conversions() {
        // Test all network conversions
        let networks = [
            (FFINetwork::Dash, dashcore::Network::Dash),
            (FFINetwork::Testnet, dashcore::Network::Testnet),
            (FFINetwork::Regtest, dashcore::Network::Regtest),
            (FFINetwork::Devnet, dashcore::Network::Devnet),
        ];

        for (ffi_net, dash_net) in networks.iter() {
            let converted: dashcore::Network = (*ffi_net).into();
            assert_eq!(converted, *dash_net);

            let back: FFINetwork = (*dash_net).into();
            assert_eq!(back as i32, *ffi_net as i32);
        }
    }

    #[test]
    fn test_sync_progress_extreme_values() {
        let progress = dash_spv::SyncProgress {
            header_height: u32::MAX,
            filter_header_height: u32::MAX,
            masternode_height: u32::MAX,
            peer_count: u32::MAX,
            filter_sync_available: true,
            filters_downloaded: u64::MAX,
            last_synced_filter_height: Some(u32::MAX),
            sync_start: std::time::SystemTime::now(),
            last_update: std::time::SystemTime::now(),
        };

        let ffi_progress = FFISyncProgress::from(progress);
        assert_eq!(ffi_progress.header_height, u32::MAX);
        assert_eq!(ffi_progress.filter_header_height, u32::MAX);
        assert_eq!(ffi_progress.masternode_height, u32::MAX);
        assert_eq!(ffi_progress.peer_count, u32::MAX);
        assert_eq!(ffi_progress.filters_downloaded, u32::MAX); // Note: truncated from u64
        assert_eq!(ffi_progress.last_synced_filter_height, u32::MAX);
    }

    #[test]
    fn test_chain_state_none_values() {
        let state = dash_spv::ChainState {
            last_chainlock_height: None,
            last_chainlock_hash: None,
            current_filter_tip: None,
            masternode_engine: None,
            last_masternode_diff_height: None,
            sync_base_height: 0,
        };

        let ffi_state = FFIChainState::from(state);

        assert_eq!(ffi_state.masternode_height, 0);
        assert_eq!(ffi_state.last_chainlock_height, 0);
        assert_eq!(ffi_state.current_filter_tip, 0);

        unsafe {
            let hash_str = FFIString::from_ptr(ffi_state.last_chainlock_hash.ptr).unwrap();
            assert_eq!(hash_str, "");
            dash_spv_ffi_string_destroy(ffi_state.last_chainlock_hash);
        }
    }

    #[test]
    fn test_spv_stats_extreme_values() {
        let stats = dash_spv::SpvStats {
            headers_downloaded: u64::MAX,
            filter_headers_downloaded: u64::MAX,
            filters_downloaded: u64::MAX,
            filters_matched: u64::MAX,
            blocks_with_relevant_transactions: u64::MAX,
            blocks_requested: u64::MAX,
            blocks_processed: u64::MAX,
            masternode_diffs_processed: u64::MAX,
            bytes_received: u64::MAX,
            bytes_sent: u64::MAX,
            uptime: std::time::Duration::from_secs(u64::MAX),
            filters_requested: u64::MAX,
            filters_received: u64::MAX,
            filter_sync_start_time: None,
            last_filter_received_time: None,
            received_filter_heights: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            active_filter_requests: 0,
            pending_filter_requests: 0,
            filter_request_timeouts: u64::MAX,
            filter_requests_retried: u64::MAX,
            connected_peers: 0,
            total_peers: 0,
            header_height: 0,
            filter_height: 0,
        };

        let ffi_stats = FFISpvStats::from(stats);
        assert_eq!(ffi_stats.headers_downloaded, u64::MAX);
        assert_eq!(ffi_stats.filter_headers_downloaded, u64::MAX);
        assert_eq!(ffi_stats.filters_downloaded, u64::MAX);
        assert_eq!(ffi_stats.filters_matched, u64::MAX);
        assert_eq!(ffi_stats.blocks_processed, u64::MAX);
        assert_eq!(ffi_stats.bytes_received, u64::MAX);
        assert_eq!(ffi_stats.bytes_sent, u64::MAX);
        assert_eq!(ffi_stats.uptime, u64::MAX);
    }

    #[test]
    fn test_concurrent_ffi_string_creation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        for i in 0..10 {
            let counter_clone = counter.clone();
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let s = format!("Thread {} iteration {}", i, j);
                    let ffi = FFIString::new(&s);
                    unsafe {
                        let recovered = FFIString::from_ptr(ffi.ptr).unwrap();
                        assert_eq!(recovered, s);
                        dash_spv_ffi_string_destroy(ffi);
                    }
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1000);
    }
}
