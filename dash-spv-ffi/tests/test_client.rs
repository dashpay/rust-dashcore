#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::os::raw::c_void;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct _TestCallbackData {
        progress_called: Arc<Mutex<bool>>,
        completion_called: Arc<Mutex<bool>>,
        last_progress: Arc<Mutex<f64>>,
    }

    extern "C" fn _test_progress_callback(
        progress: f64,
        _message: *const std::os::raw::c_char,
        user_data: *mut c_void,
    ) {
        let data = unsafe { &*(user_data as *const _TestCallbackData) };
        *data.progress_called.lock().unwrap() = true;
        *data.last_progress.lock().unwrap() = progress;
    }

    extern "C" fn _test_completion_callback(
        _success: bool,
        _error: *const std::os::raw::c_char,
        user_data: *mut c_void,
    ) {
        let data = unsafe { &*(user_data as *const _TestCallbackData) };
        *data.completion_called.lock().unwrap() = true;
    }

    fn create_test_config() -> (*mut FFIClientConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = dash_spv_ffi_config_new(FFINetwork::Regtest);

        unsafe {
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
        }

        (config, temp_dir)
    }

    #[test]
    #[serial]
    fn test_client_creation() {
        unsafe {
            let (config, _temp_dir) = create_test_config();

            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_null_config() {
        unsafe {
            let client = dash_spv_ffi_client_new(std::ptr::null());
            assert!(client.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_client_lifecycle() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);

            // Note: Start/stop may fail in test environment without network
            let _result = dash_spv_ffi_client_start(client);
            let _result = dash_spv_ffi_client_stop(client);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_null_checks() {
        unsafe {
            let result = dash_spv_ffi_client_start(std::ptr::null_mut());
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            let result = dash_spv_ffi_client_stop(std::ptr::null_mut());
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            let progress = dash_spv_ffi_client_get_sync_progress(std::ptr::null_mut());
            assert!(progress.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_sync_progress() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);

            let progress = dash_spv_ffi_client_get_sync_progress(client);
            if !progress.is_null() {
                let _progress_ref = &*progress;
                // header_height and filter_header_height are u32, always >= 0
                dash_spv_ffi_sync_progress_destroy(progress);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_stats() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_sync_diagnostic() {
        unsafe {
            // Allow running this test only when explicitly enabled
            if std::env::var("RUST_DASH_FFI_RUN_NETWORK_TESTS").unwrap_or_default() != "1" {
                println!(
                    "Skipping test_sync_diagnostic (set RUST_DASH_FFI_RUN_NETWORK_TESTS=1 to run)"
                );
                return;
            }

            // Create testnet config for the diagnostic test
            let config = dash_spv_ffi_config_testnet();
            let temp_dir = TempDir::new().unwrap();
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            // Create client
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null(), "Failed to create client");

            // Start the client
            let start_result = dash_spv_ffi_client_start(client);
            if start_result != FFIErrorCode::Success as i32 {
                println!("Warning: Failed to start client, error code: {}", start_result);
                let error = dash_spv_ffi_get_last_error();
                if !error.is_null() {
                    let error_str = std::ffi::CStr::from_ptr(error);
                    println!("Error message: {:?}", error_str);
                }
            }

            // Run the diagnostic sync test
            println!("Running sync diagnostic test...");
            let test_result = client_test_sync(&*client);

            if test_result == FFIErrorCode::Success as i32 {
                println!("✅ Sync test passed!");
            } else {
                println!("❌ Sync test failed with error code: {}", test_result);
                let error = dash_spv_ffi_get_last_error();
                if !error.is_null() {
                    let error_str = std::ffi::CStr::from_ptr(error);
                    println!("Error message: {:?}", error_str);
                }
            }

            // Stop and cleanup
            let _stop_result = dash_spv_ffi_client_stop(client);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
