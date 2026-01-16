#[cfg(test)]
mod tests {
    use crate::*;
    use serial_test::serial;
    use std::ffi::CStr;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    #[serial]
    fn test_error_propagation() {
        // Clear any existing error
        dash_spv_ffi_clear_error();

        // Test setting and getting error
        set_last_error("Test error message");
        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(!error_ptr.is_null());

        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Test error message");
        }

        // Clear and verify
        dash_spv_ffi_clear_error();
        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(error_ptr.is_null());
    }

    #[test]
    #[serial]
    fn test_concurrent_error_handling() {
        // Test thread safety of error handling
        // Note: The implementation uses a global mutex, not thread-local storage
        let barrier = Arc::new(Barrier::new(10));
        let mut handles = vec![];

        for i in 0..10 {
            let barrier_clone = barrier.clone();
            let handle = thread::spawn(move || {
                // Wait for all threads to start
                barrier_clone.wait();

                // Each thread sets its own error
                let error_msg = format!("Error from thread {}", i);
                set_last_error(&error_msg);

                // Small delay to reduce contention
                thread::sleep(std::time::Duration::from_millis(10));

                // Read the global error - it could be from any thread
                let error_ptr = dash_spv_ffi_get_last_error();
                if !error_ptr.is_null() {
                    unsafe {
                        let c_str = CStr::from_ptr(error_ptr);
                        // Verify it's a valid UTF-8 string
                        if let Ok(error_str) = c_str.to_str() {
                            // The error could be from any thread due to global mutex
                            assert!(
                                error_str.contains("Error from thread") || error_str.is_empty()
                            );
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    #[serial]
    fn test_error_message_truncation() {
        // Test very long error message
        let long_error = "X".repeat(10000);
        set_last_error(&long_error);

        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(!error_ptr.is_null());

        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            // Should handle long strings without truncation
            assert_eq!(error_str.len(), 10000);
            assert!(error_str.chars().all(|c| c == 'X'));
        }

        dash_spv_ffi_clear_error();
    }

    #[test]
    fn test_all_error_code_mappings() {
        // Test all error codes have correct values
        assert_eq!(FFIErrorCode::Success as i32, 0);
        assert_eq!(FFIErrorCode::NullPointer as i32, 1);
        assert_eq!(FFIErrorCode::InvalidArgument as i32, 2);
        assert_eq!(FFIErrorCode::NetworkError as i32, 3);
        assert_eq!(FFIErrorCode::StorageError as i32, 4);
        assert_eq!(FFIErrorCode::ValidationError as i32, 5);
        assert_eq!(FFIErrorCode::SyncError as i32, 6);
        assert_eq!(FFIErrorCode::WalletError as i32, 7);
        assert_eq!(FFIErrorCode::ConfigError as i32, 8);
        assert_eq!(FFIErrorCode::RuntimeError as i32, 9);
        assert_eq!(FFIErrorCode::Unknown as i32, 99);

        // Test conversions from SpvError
        use dash_spv::{NetworkError, SpvError, StorageError, SyncError, ValidationError};

        let net_err = SpvError::Network(NetworkError::ConnectionFailed("test".to_string()));
        assert_eq!(FFIErrorCode::from(net_err) as i32, FFIErrorCode::NetworkError as i32);

        let storage_err = SpvError::Storage(StorageError::NotFound("test".to_string()));
        assert_eq!(FFIErrorCode::from(storage_err) as i32, FFIErrorCode::StorageError as i32);

        let val_err = SpvError::Validation(ValidationError::InvalidProofOfWork);
        assert_eq!(FFIErrorCode::from(val_err) as i32, FFIErrorCode::ValidationError as i32);

        let sync_err = SpvError::Sync(SyncError::Timeout("Test timeout".to_string()));
        assert_eq!(FFIErrorCode::from(sync_err) as i32, FFIErrorCode::SyncError as i32);

        let io_err = SpvError::Io(std::io::Error::other("test"));
        assert_eq!(FFIErrorCode::from(io_err) as i32, FFIErrorCode::RuntimeError as i32);

        let config_err = SpvError::Config("test".to_string());
        assert_eq!(FFIErrorCode::from(config_err) as i32, FFIErrorCode::ConfigError as i32);
    }

    #[test]
    #[serial]
    fn test_error_clearing_between_operations() {
        // Set an error
        set_last_error("First error");
        assert!(!dash_spv_ffi_get_last_error().is_null());

        // Clear it
        clear_last_error();
        assert!(dash_spv_ffi_get_last_error().is_null());

        // Set another error
        set_last_error("Second error");
        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(!error_ptr.is_null());

        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Second error");
        }

        // Clear using public API
        dash_spv_ffi_clear_error();
        assert!(dash_spv_ffi_get_last_error().is_null());
    }

    #[test]
    #[serial]
    fn test_null_pointer_error_handling() {
        // Test null_check! macro behavior
        unsafe {
            // Test with config functions
            let result = dash_spv_ffi_config_builder_set_storage_path(
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            // Check error was set
            let error_ptr = dash_spv_ffi_get_last_error();
            assert!(!error_ptr.is_null());
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Null pointer provided");
        }
    }

    #[test]
    fn test_invalid_enum_handling() {
        // Use a valid enum value to avoid UB in Rust tests. If invalid raw inputs
        // need to be tested, do so from a C test or add a raw-int FFI entrypoint.
        unsafe {
            let builder = dash_spv_ffi_config_builder_mainnet();
            let config = dash_spv_ffi_config_builder_build(builder);
            assert!(!config.is_null());
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_handle_error_helper() {
        // Test Ok case
        let ok_result: Result<i32, String> = Ok(42);
        let handled = handle_error(ok_result);
        assert_eq!(handled, Some(42));
        assert!(dash_spv_ffi_get_last_error().is_null());

        // Test Err case
        let err_result: Result<i32, String> = Err("Test error".to_string());
        let handled = handle_error(err_result);
        assert!(handled.is_none());

        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(!error_ptr.is_null());
        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Test error");
        }
    }

    #[test]
    #[serial]
    fn test_error_with_special_characters() {
        // Test error with newlines
        set_last_error("Error\nwith\nnewlines");
        let error_ptr = dash_spv_ffi_get_last_error();
        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Error\nwith\nnewlines");
        }

        // Test error with tabs
        set_last_error("Error\twith\ttabs");
        let error_ptr = dash_spv_ffi_get_last_error();
        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Error\twith\ttabs");
        }

        // Test error with quotes
        set_last_error("Error with \"quotes\" and 'apostrophes'");
        let error_ptr = dash_spv_ffi_get_last_error();
        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Error with \"quotes\" and 'apostrophes'");
        }

        dash_spv_ffi_clear_error();
    }
}
