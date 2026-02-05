#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    use std::os::raw::c_void;

    struct _TestCallbackData {
        progress_called: Arc<Mutex<bool>>,
        completion_called: Arc<Mutex<bool>>,
        last_progress: Arc<Mutex<f64>>,
    }

    struct ProgressCallbackData {
        called: Mutex<bool>,
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

    extern "C" fn test_progress_callback(progress: *const FFISyncProgress, user_data: *mut c_void) {
        assert!(!progress.is_null());
        let data = unsafe { &*(user_data as *const ProgressCallbackData) };
        *data.called.lock().unwrap() = true;
    }

    #[test]
    #[serial]
    fn test_set_progress_callback_emits_initial_progress() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            let callback_data = Box::new(ProgressCallbackData {
                called: Mutex::new(false),
            });
            let data_ptr = &*callback_data as *const ProgressCallbackData as *mut c_void;

            let progress_callback = FFIProgressCallback {
                on_progress: Some(test_progress_callback),
                user_data: data_ptr,
            };

            let result = dash_spv_ffi_client_set_progress_callback(client, progress_callback);
            assert_eq!(result, FFIErrorCode::Success as i32);

            assert!(
                *callback_data.called.lock().unwrap(),
                "progress callback should be invoked immediately when set"
            );

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
