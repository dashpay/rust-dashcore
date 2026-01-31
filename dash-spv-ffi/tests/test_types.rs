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
    fn test_sync_progress_conversion() {
        let progress = dash_spv::SyncProgress {
            header_height: 100,
            filter_header_height: 90,
            masternode_height: 80,
            peer_count: 5,
            filter_sync_available: true,
            filters_downloaded: 50,
            last_synced_filter_height: Some(45),
            sync_start: std::time::SystemTime::now(),
            last_update: std::time::SystemTime::now(),
        };

        let ffi_progress = FFISyncProgress::from(progress);

        assert_eq!(ffi_progress.header_height, 100);
        assert_eq!(ffi_progress.filter_header_height, 90);
        assert_eq!(ffi_progress.masternode_height, 80);
        assert_eq!(ffi_progress.peer_count, 5);
        assert_eq!(ffi_progress.filters_downloaded, 50);
        assert_eq!(ffi_progress.last_synced_filter_height, 45);
    }
}
