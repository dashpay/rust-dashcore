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
