#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::FFINetwork;

    #[test]
    fn test_ffi_string_new_and_destroy() {
        let test_str = "Hello, FFI!";
        let ffi_string = FFIString::new(test_str);

        assert!(!ffi_string.ptr.is_null());

        unsafe {
            let recovered = FFIString::from_ptr(ffi_string.ptr);
            assert_eq!(recovered.unwrap(), test_str);

            dash_spv_ffi_string_destroy(ffi_string);
        }
    }

    #[test]
    fn test_ffi_string_null_handling() {
        unsafe {
            let result = FFIString::from_ptr(std::ptr::null());
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ffi_network_conversion() {
        assert_eq!(dashcore::Network::Dash, FFINetwork::Dash.into());
        assert_eq!(dashcore::Network::Testnet, FFINetwork::Testnet.into());
        assert_eq!(dashcore::Network::Regtest, FFINetwork::Regtest.into());
        assert_eq!(dashcore::Network::Devnet, FFINetwork::Devnet.into());

        assert_eq!(FFINetwork::Dash, dashcore::Network::Dash.into());
        assert_eq!(FFINetwork::Testnet, dashcore::Network::Testnet.into());
        assert_eq!(FFINetwork::Regtest, dashcore::Network::Regtest.into());
        assert_eq!(FFINetwork::Devnet, dashcore::Network::Devnet.into());
    }

    #[test]
    fn test_ffi_array_new_and_destroy() {
        let test_data = vec![1u32, 2, 3, 4, 5];
        let len = test_data.len();
        let array = FFIArray::new(test_data);

        assert!(!array.data.is_null());
        assert_eq!(array.len, len);
        assert!(array.capacity >= len);

        unsafe {
            let slice = array.as_slice::<u32>();
            assert_eq!(slice.len(), len);
            assert_eq!(slice, &[1, 2, 3, 4, 5]);

            // Allocate on heap for proper FFI destroy
            let array_ptr = Box::into_raw(Box::new(array));
            dash_spv_ffi_array_destroy(array_ptr);
        }
    }

    #[test]
    fn test_ffi_array_empty() {
        let empty_vec: Vec<u8> = vec![];
        let array = FFIArray::new(empty_vec);

        assert_eq!(array.len, 0);

        unsafe {
            let slice = array.as_slice::<u8>();
            assert_eq!(slice.len(), 0);

            // Allocate on heap for proper FFI destroy
            let array_ptr = Box::into_raw(Box::new(array));
            dash_spv_ffi_array_destroy(array_ptr);
        }
    }

    #[test]
    fn test_sync_progress_conversion() {
        let progress = dash_spv::SyncProgress {
            header_height: 100,
            filter_header_height: 90,
            masternode_height: 80,
            peer_count: 5,
            headers_synced: true,
            filter_headers_synced: false,
            masternodes_synced: false,
            filters_downloaded: 50,
            filter_sync_available: true,
            last_synced_filter_height: Some(45),
            sync_start: std::time::SystemTime::now(),
            last_update: std::time::SystemTime::now(),
        };

        let ffi_progress = FFISyncProgress::from(progress);

        assert_eq!(ffi_progress.header_height, 100);
        assert_eq!(ffi_progress.filter_header_height, 90);
        assert_eq!(ffi_progress.masternode_height, 80);
        assert_eq!(ffi_progress.peer_count, 5);
        assert!(ffi_progress.headers_synced);
        assert!(!ffi_progress.filter_headers_synced);
        assert!(!ffi_progress.masternodes_synced);
        assert_eq!(ffi_progress.filters_downloaded, 50);
        assert_eq!(ffi_progress.last_synced_filter_height, 45);
    }
}
