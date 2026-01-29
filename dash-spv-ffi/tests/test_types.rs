#[cfg(test)]
mod tests {
    use dash_spv::sync::{
        BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
        FiltersProgress, InstantSendProgress, MasternodesProgress, SyncProgress, SyncState,
    };
    use dash_spv::SyncProgress as LegacySyncProgress;
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
        let mut array = FFIArray::new(test_data);

        assert!(!array.data.is_null());
        assert_eq!(array.len, len);
        assert!(array.capacity >= len);

        unsafe {
            let slice = array.as_slice::<u32>();
            assert_eq!(slice.len(), len);
            assert_eq!(slice, &[1, 2, 3, 4, 5]);

            dash_spv_ffi_array_destroy(&mut array as *mut FFIArray);
        }
    }

    #[test]
    fn test_ffi_array_empty() {
        let empty_vec: Vec<u8> = vec![];
        let mut array = FFIArray::new(empty_vec);

        assert_eq!(array.len, 0);

        unsafe {
            let slice = array.as_slice::<u8>();
            assert_eq!(slice.len(), 0);

            dash_spv_ffi_array_destroy(&mut array as *mut FFIArray);
        }
    }

    #[test]
    fn test_legacy_sync_progress_conversion() {
        let progress = LegacySyncProgress {
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

        let ffi_progress = FFILegacySyncProgress::from(progress);

        assert_eq!(ffi_progress.header_height, 100);
        assert_eq!(ffi_progress.filter_header_height, 90);
        assert_eq!(ffi_progress.masternode_height, 80);
        assert_eq!(ffi_progress.peer_count, 5);
        assert_eq!(ffi_progress.filters_downloaded, 50);
        assert_eq!(ffi_progress.last_synced_filter_height, 45);
    }

    #[test]
    fn test_sync_progress_conversion() {
        let mut progress = SyncProgress::default();

        let mut headers = BlockHeadersProgress::default();
        headers.set_state(SyncState::Syncing);
        headers.update_current_height(100);
        headers.update_target_height(200);
        headers.add_processed(20);
        headers.update_buffered(5);
        progress.update_headers(headers);

        let mut filter_headers = FilterHeadersProgress::default();
        filter_headers.set_state(SyncState::WaitingForConnections);
        filter_headers.update_current_height(150);
        filter_headers.update_target_height(200);
        filter_headers.update_block_header_tip_height(180);
        filter_headers.add_processed(30);
        progress.update_filter_headers(filter_headers);

        let mut filters = FiltersProgress::default();
        filters.set_state(SyncState::WaitForEvents);
        filters.update_current_height(120);
        filters.update_target_height(200);
        filters.update_filter_header_tip_height(150);
        filters.add_downloaded(40);
        filters.add_processed(35);
        filters.add_matched(10);
        progress.update_filters(filters);

        let mut blocks = BlocksProgress::default();
        blocks.set_state(SyncState::Syncing);
        blocks.update_last_processed(400);
        blocks.add_requested(50);
        blocks.add_from_storage(20);
        blocks.add_downloaded(15);
        blocks.add_processed(12);
        blocks.add_relevant(8);
        blocks.add_transactions(25);
        progress.update_blocks(blocks);

        let mut masternodes = MasternodesProgress::default();
        masternodes.set_state(SyncState::Synced);
        masternodes.update_current_height(500);
        masternodes.update_target_height(550);
        masternodes.update_block_header_tip_height(560);
        masternodes.add_diffs_processed(3);
        progress.update_masternodes(masternodes);

        let mut chainlocks = ChainLockProgress::default();
        chainlocks.set_state(SyncState::Error);
        chainlocks.update_best_validated_height(600);
        chainlocks.add_valid(10);
        chainlocks.add_invalid(2);
        progress.update_chainlocks(chainlocks);

        let mut instantsend = InstantSendProgress::default();
        instantsend.set_state(SyncState::Initializing);
        instantsend.update_pending(700);
        instantsend.add_valid(200);
        instantsend.add_invalid(15);
        progress.update_instantsend(instantsend);

        let ffi_progress = FFISyncProgress::from(progress);

        assert_eq!(ffi_progress.state, FFISyncState::Syncing);
        assert_eq!(ffi_progress.percentage, 0.625);

        // Verify headers progress
        assert!(!ffi_progress.headers.is_null());
        unsafe {
            let headers = &*ffi_progress.headers;
            assert_eq!(headers.state, FFISyncState::Syncing);
            assert_eq!(headers.current_height, 100);
            assert_eq!(headers.target_height, 200);
            assert_eq!(headers.processed, 20);
            assert_eq!(headers.buffered, 5);
        }

        // Verify filter_headers progress
        assert!(!ffi_progress.filter_headers.is_null());
        unsafe {
            let filter_headers = &*ffi_progress.filter_headers;
            assert_eq!(filter_headers.state, FFISyncState::WaitingForConnections);
            assert_eq!(filter_headers.current_height, 150);
            assert_eq!(filter_headers.target_height, 200);
            assert_eq!(filter_headers.block_header_tip_height, 180);
            assert_eq!(filter_headers.processed, 30);
        }

        // Verify filters progress
        assert!(!ffi_progress.filters.is_null());
        unsafe {
            let filters = &*ffi_progress.filters;
            assert_eq!(filters.state, FFISyncState::WaitForEvents);
            assert_eq!(filters.current_height, 120);
            assert_eq!(filters.target_height, 200);
            assert_eq!(filters.filter_header_tip_height, 150);
            assert_eq!(filters.downloaded, 40);
            assert_eq!(filters.processed, 35);
            assert_eq!(filters.matched, 10);
        }

        // Verify blocks progress
        assert!(!ffi_progress.blocks.is_null());
        unsafe {
            let blocks = &*ffi_progress.blocks;
            assert_eq!(blocks.state, FFISyncState::Syncing);
            assert_eq!(blocks.last_processed, 400);
            assert_eq!(blocks.requested, 50);
            assert_eq!(blocks.from_storage, 20);
            assert_eq!(blocks.downloaded, 15);
            assert_eq!(blocks.processed, 12);
            assert_eq!(blocks.relevant, 8);
            assert_eq!(blocks.transactions, 25);
        }

        // Verify masternodes progress
        assert!(!ffi_progress.masternodes.is_null());
        unsafe {
            let masternodes = &*ffi_progress.masternodes;
            assert_eq!(masternodes.state, FFISyncState::Synced);
            assert_eq!(masternodes.current_height, 500);
            assert_eq!(masternodes.target_height, 550);
            assert_eq!(masternodes.block_header_tip_height, 560);
            assert_eq!(masternodes.diffs_processed, 3);
        }

        // Verify chainlocks progress
        assert!(!ffi_progress.chainlocks.is_null());
        unsafe {
            let chainlocks = &*ffi_progress.chainlocks;
            assert_eq!(chainlocks.state, FFISyncState::Error);
            assert_eq!(chainlocks.best_validated_height, 600);
            assert_eq!(chainlocks.valid, 10);
            assert_eq!(chainlocks.invalid, 2);
        }

        // Verify instantsend progress
        assert!(!ffi_progress.instantsend.is_null());
        unsafe {
            let instantsend = &*ffi_progress.instantsend;
            assert_eq!(instantsend.state, FFISyncState::Initializing);
            assert_eq!(instantsend.pending, 700);
            assert_eq!(instantsend.valid, 200);
            assert_eq!(instantsend.invalid, 15);
        }

        // Cleanup all allocated memory
        unsafe {
            dash_spv_ffi_manager_sync_progress_destroy(Box::into_raw(Box::new(ffi_progress)));
        }
    }
}
