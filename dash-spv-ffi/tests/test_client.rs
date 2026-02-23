#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::os::raw::c_void;
    use std::sync::Mutex;
    use tempfile::TempDir;

    struct ProgressCallbackData {
        state: Mutex<Option<FFISyncState>>,
        is_synced: Mutex<Option<bool>>,
    }

    impl ProgressCallbackData {
        fn new() -> Self {
            Self {
                state: Mutex::new(None),
                is_synced: Mutex::new(None),
            }
        }
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
            let _result = dash_spv_ffi_client_run(client);
            let _result = dash_spv_ffi_client_stop(client);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_client_null_checks() {
        unsafe {
            let result = dash_spv_ffi_client_run(std::ptr::null_mut());
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
        let p = unsafe { &*progress };

        *data.state.lock().unwrap() = Some(p.state);
        *data.is_synced.lock().unwrap() = Some(p.is_synced);
    }

    #[test]
    #[serial]
    fn test_set_progress_callback_emits_progress() {
        unsafe {
            let (config, _temp_dir) = create_test_config();
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            let callback_data = Box::new(ProgressCallbackData::new());
            let data_ptr = &*callback_data as *const ProgressCallbackData as *mut c_void;

            let progress_callback = FFIProgressCallback {
                on_progress: Some(test_progress_callback),
                user_data: data_ptr,
            };

            let result = dash_spv_ffi_client_set_progress_callback(client, progress_callback);
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Verify callback was invoked with expected initial values
            assert_eq!(
                callback_data.state.lock().unwrap().unwrap(),
                FFISyncState::WaitingForConnections,
                "initial state should be WaitingForConnections"
            );
            assert!(
                !callback_data.is_synced.lock().unwrap().unwrap(),
                "initial is_synced should be false"
            );

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
