// Note: Many tests in this file are marked with #[ignore] because they call
// dash_spv_ffi_client_run() which hangs indefinitely when using regtest
// network with no configured peers. These tests should be run with a proper
// test network setup or mocked networking layer.

#[cfg(test)]
mod tests {
    use crate::*;
    use dashcore::ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::sync::mpsc;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_config_with_dir() -> (*mut FFIClientConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
            (config, temp_dir)
        }
    }

    #[test]
    #[serial]
    fn test_client_creation_with_invalid_config() {
        unsafe {
            // Test with null config
            let client = dash_spv_ffi_client_new(std::ptr::null(), FFIEventCallbacks::default());
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
                let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
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
            let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
            assert!(!client.is_null());

            // Start
            let _result = dash_spv_ffi_client_run(client);
            // May fail in test environment, but should handle gracefully

            // Stop
            let _result = dash_spv_ffi_client_stop(client);

            // Restart
            let _result = dash_spv_ffi_client_run(client);
            let _result = dash_spv_ffi_client_stop(client);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    #[ignore] // Requires network
    fn test_client_destruction_while_operations_pending() {
        unsafe {
            let (config, _temp_dir) = create_test_config_with_dir();
            let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
            assert!(!client.is_null());

            // Start a sync operation in background
            // Start sync (non-blocking)
            dash_spv_ffi_client_run(client);

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
            let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
            assert!(!client.is_null());

            // Try to start (should handle no peers gracefully)
            let _result = dash_spv_ffi_client_run(client);

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
                let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
                assert!(!client.is_null());

                // Do some operations
                let progress = dash_spv_ffi_client_get_sync_progress(client);

                dash_spv_ffi_sync_progress_destroy(progress);

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

    #[test]
    #[serial]
    fn test_client_null_operations() {
        unsafe {
            // Test all client operations with null
            assert_eq!(
                dash_spv_ffi_client_run(std::ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_client_stop(std::ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );

            assert!(dash_spv_ffi_client_get_sync_progress(std::ptr::null_mut()).is_null());

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
            let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
            assert!(!client.is_null());

            // Get initial state
            let progress1 = dash_spv_ffi_client_get_sync_progress(client);

            let progress = &*progress1;
            let headers = &*progress.headers;
            let filter_headers = &*progress.filter_headers;

            // Basic consistency checks
            assert!(
                headers.tip_height <= filter_headers.target_height
                    || filter_headers.current_height == 0
            );
            // headers_downloaded is u64, always >= 0

            dash_spv_ffi_sync_progress_destroy(progress1);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_error_callback_fires_on_start_failure() {
        let (tx, rx) = mpsc::channel::<String>();
        let tx_ptr = Box::into_raw(Box::new(tx));

        extern "C" fn on_error(
            error: *const std::os::raw::c_char,
            user_data: *mut std::os::raw::c_void,
        ) {
            let tx = unsafe { &*(user_data as *const mpsc::Sender<String>) };
            let error_str = unsafe { std::ffi::CStr::from_ptr(error) }.to_str().unwrap().to_owned();
            let _ = tx.send(error_str);
        }

        unsafe {
            let (config, _temp_dir) = create_test_config_with_dir();
            let callbacks = FFIEventCallbacks {
                error: FFIClientErrorCallback {
                    on_error: Some(on_error),
                    user_data: tx_ptr as *mut std::os::raw::c_void,
                },
                ..FFIEventCallbacks::default()
            };
            let client = dash_spv_ffi_client_new(config, callbacks);
            assert!(!client.is_null());

            // Call run() twice — the second run's sync thread will call
            // start() on the already-running client, triggering "already running"
            let run_result = dash_spv_ffi_client_run(client);
            assert_eq!(run_result, FFIErrorCode::Success as i32);

            // Brief wait for the first run's sync thread to complete start()
            thread::sleep(Duration::from_millis(200));

            let _run_result2 = dash_spv_ffi_client_run(client);

            // Wait for the error callback to fire (with timeout)
            let error_msg = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("Error callback should have been called on start failure");
            assert!(
                error_msg.contains("already running"),
                "Expected 'already running' error, got: {}",
                error_msg
            );

            dash_spv_ffi_client_stop(client);

            // Free the sender only after stop has joined all threads,
            // so no background thread can call on_error with a dangling user_data.
            drop(Box::from_raw(tx_ptr));

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_error_callback_dispatch() {
        let error_store: StdArc<StdMutex<Option<String>>> = StdArc::new(StdMutex::new(None));
        let error_store_raw = StdArc::into_raw(error_store.clone());

        extern "C" fn on_error(
            error: *const std::os::raw::c_char,
            user_data: *mut std::os::raw::c_void,
        ) {
            assert!(!error.is_null());
            let store = unsafe { StdArc::from_raw(user_data as *const StdMutex<Option<String>>) };
            let error_str = unsafe { std::ffi::CStr::from_ptr(error) }.to_str().unwrap().to_owned();
            *store.lock().unwrap() = Some(error_str);
            let _ = StdArc::into_raw(store);
        }

        let callback = FFIClientErrorCallback {
            on_error: Some(on_error),
            user_data: error_store_raw as *mut std::os::raw::c_void,
        };

        callback.dispatch("test error message");

        let received = error_store.lock().unwrap();
        assert_eq!(received.as_deref(), Some("test error message"));
        drop(received);

        unsafe { drop(StdArc::from_raw(error_store_raw)) };
    }

    #[test]
    #[serial]
    fn test_client_run_null_client() {
        unsafe {
            assert_eq!(
                dash_spv_ffi_client_run(std::ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );
        }
    }

    #[test]
    #[serial]
    fn test_client_error_callback_no_callback_set() {
        // Dispatch with no callback set should not panic
        let callback = FFIClientErrorCallback::default();
        callback.dispatch("should not panic");
    }

    #[test]
    #[serial]
    fn test_client_repeated_creation_destruction() {
        // Stress test client creation/destruction
        for _ in 0..10 {
            unsafe {
                let (config, _temp_dir) = create_test_config_with_dir();
                let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
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
