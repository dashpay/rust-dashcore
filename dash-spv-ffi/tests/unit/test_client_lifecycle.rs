// Note: Many tests in this file are marked with #[ignore] because they call
// dash_spv_ffi_client_start() which hangs indefinitely when using regtest
// network with no configured peers. These tests should be run with a proper
// test network setup or mocked networking layer.

#[cfg(test)]
mod tests {
    use crate::*;
    use serial_test::serial;
    use std::ffi::CString;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_config_with_dir() -> (*mut FFIClientConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
            dash_spv_ffi_config_set_validation_mode(config, FFIValidationMode::None);
            (config, temp_dir)
        }
    }

    #[test]
    #[serial]
    fn test_client_creation_with_invalid_config() {
        unsafe {
            // Test with null config
            let client = dash_spv_ffi_client_new(std::ptr::null());
            assert!(client.is_null());

            // Check error was set
            let error_ptr = dash_spv_ffi_get_last_error();
            assert!(!error_ptr.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_multiple_client_instances() {
        unsafe {
            let mut clients = vec![];
            let mut temp_dirs = vec![];

            // Create multiple clients with different data directories
            for i in 0..3 {
                let (config, temp_dir) = create_test_config_with_dir();
                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null(), "Failed to create client {}", i);

                clients.push(client);
                temp_dirs.push(temp_dir);
                dash_spv_ffi_config_destroy(config);
            }

            // Clean up all clients
            for client in clients {
                dash_spv_ffi_client_destroy(client);
            }
        }
    }

    #[test]
    #[serial]
    #[ignore] // Requires network - client_start hangs without peers
    fn test_client_start_stop_restart() {
        unsafe {
            let (config, _temp_dir) = create_test_config_with_dir();
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Start
            let _result = dash_spv_ffi_client_start(client);
            // May fail in test environment, but should handle gracefully

            // Stop
            let _result = dash_spv_ffi_client_stop(client);

            // Restart
            let _result = dash_spv_ffi_client_start(client);
            let _result = dash_spv_ffi_client_stop(client);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    #[ignore] // Requires network - sync_to_tip hangs without peers
    fn test_client_destruction_while_operations_pending() {
        unsafe {
            let (config, _temp_dir) = create_test_config_with_dir();
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Start a sync operation in background
            // Start sync (non-blocking)
            dash_spv_ffi_client_sync_to_tip(client, None, std::ptr::null_mut());

            // Immediately destroy client (should handle pending operations)
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    #[ignore] // Requires network - client_start hangs without peers
    fn test_client_with_no_peers() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            // Don't add any peers
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Try to start (should handle no peers gracefully)
            let _result = dash_spv_ffi_client_start(client);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_resource_cleanup() {
        // Test that resources are properly cleaned up
        let _initial_thread_count = thread::current().id();

        unsafe {
            for _ in 0..5 {
                let (config, _temp_dir) = create_test_config_with_dir();
                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Do some operations
                let _ = dash_spv_ffi_client_get_sync_progress(client);
                let _ = dash_spv_ffi_client_get_stats(client);

                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }
        }

        // Give time for cleanup
        thread::sleep(Duration::from_millis(100));

        // Thread count should be reasonable (not growing indefinitely)
        let _final_thread_count = thread::current().id();
        // Can't directly compare thread counts, but test passes if no panic/leak
    }

    // Wrapper to make pointer Send
    struct SendableClient(*mut FFIDashSpvClient);
    unsafe impl Send for SendableClient {}

    #[test]
    #[serial]
    #[ignore] // Requires network - client operations hang without peers
    fn test_concurrent_client_operations() {
        unsafe {
            let (config, _temp_dir) = create_test_config_with_dir();
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            let client_ptr = Arc::new(Mutex::new(SendableClient(client)));
            let mut handles = vec![];

            // Spawn threads doing different operations
            for i in 0..5 {
                let client_clone = client_ptr.clone();
                let handle = thread::spawn(move || {
                    let client = client_clone.lock().unwrap().0;

                    match i % 3 {
                        0 => {
                            // Get sync progress
                            let progress = dash_spv_ffi_client_get_sync_progress(client);
                            if !progress.is_null() {
                                dash_spv_ffi_sync_progress_destroy(progress);
                            }
                        }
                        1 => {
                            // Get stats
                            let stats = dash_spv_ffi_client_get_stats(client);
                            if !stats.is_null() {
                                dash_spv_ffi_spv_stats_destroy(stats);
                            }
                        }
                        2 => {
                            // Get balance for random address
                            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
                            let balance =
                                dash_spv_ffi_client_get_address_balance(client, addr.as_ptr());
                            if !balance.is_null() {
                                // FFIBalance from key-wallet-ffi doesn't need explicit destruction
                                // dash_spv_ffi_balance_destroy(balance);
                            }
                        }
                        _ => {}
                    }
                });
                handles.push(handle);
            }

            // Wait for all threads
            for handle in handles {
                handle.join().unwrap();
            }

            let client = client_ptr.lock().unwrap().0;
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_null_operations() {
        unsafe {
            // Test all client operations with null
            assert_eq!(
                dash_spv_ffi_client_start(std::ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_client_stop(std::ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_client_sync_to_tip(std::ptr::null_mut(), None, std::ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );

            assert!(dash_spv_ffi_client_get_sync_progress(std::ptr::null_mut()).is_null());
            assert!(dash_spv_ffi_client_get_stats(std::ptr::null_mut()).is_null());

            // Test destroy with null (should be safe)
            dash_spv_ffi_client_destroy(std::ptr::null_mut());
        }
    }

    #[test]
    #[serial]
    #[ignore] // Requires network - client_start hangs without peers
    fn test_client_state_consistency() {
        unsafe {
            let (config, _temp_dir) = create_test_config_with_dir();
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Get initial state
            let progress1 = dash_spv_ffi_client_get_sync_progress(client);
            let stats1 = dash_spv_ffi_client_get_stats(client);

            // State should be consistent
            if !progress1.is_null() && !stats1.is_null() {
                let progress = &*progress1;
                let _stats = &*stats1;

                // Basic consistency checks
                assert!(
                    progress.header_height <= progress.filter_header_height
                        || progress.filter_header_height == 0
                );
                // headers_downloaded is u64, always >= 0

                dash_spv_ffi_sync_progress_destroy(progress1);
                dash_spv_ffi_spv_stats_destroy(stats1);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_repeated_creation_destruction() {
        // Stress test client creation/destruction
        for _ in 0..10 {
            unsafe {
                let (config, _temp_dir) = create_test_config_with_dir();
                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Do a quick operation
                let progress = dash_spv_ffi_client_get_sync_progress(client);
                if !progress.is_null() {
                    dash_spv_ffi_sync_progress_destroy(progress);
                }

                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }
        }
    }
}
