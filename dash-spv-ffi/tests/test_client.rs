#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
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
            dash_spv_ffi_config_set_validation_mode(config, FFIValidationMode::None);
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

            let stats = dash_spv_ffi_client_get_stats(std::ptr::null_mut());
            assert!(stats.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_watch_items() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);

            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let item = dash_spv_ffi_watch_item_address(addr.as_ptr());

            let result = dash_spv_ffi_client_add_watch_item(client, item);
            // Client is not started, so we expect either Success (queued), NetworkError, or InvalidArgument
            assert!(
                result == FFIErrorCode::Success as i32
                    || result == FFIErrorCode::NetworkError as i32
                    || result == FFIErrorCode::InvalidArgument as i32,
                "Expected Success, NetworkError, or InvalidArgument, got error code: {}",
                result
            );

            dash_spv_ffi_watch_item_destroy(item);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
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

            let stats = dash_spv_ffi_client_get_stats(client);
            if !stats.is_null() {
                let _stats_ref = &*stats;
                // headers_downloaded and bytes_received are u64, always >= 0
                dash_spv_ffi_spv_stats_destroy(stats);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_address_balance() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);

            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let balance = dash_spv_ffi_client_get_address_balance(client, addr.as_ptr());

            if !balance.is_null() {
                let balance_ref = &*balance;
                assert_eq!(
                    balance_ref.total,
                    balance_ref.confirmed + balance_ref.pending + balance_ref.instantlocked
                );
                dash_spv_ffi_balance_destroy(balance);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_utxos() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);

            let utxos = dash_spv_ffi_client_get_utxos(client);
            assert!(utxos.len == 0 || !utxos.data.is_null());

            if utxos.len > 0 {
                let utxos_ptr = Box::into_raw(Box::new(utxos));
                dash_spv_ffi_array_destroy(utxos_ptr);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
