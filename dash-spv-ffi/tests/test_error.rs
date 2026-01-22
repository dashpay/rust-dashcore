#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use serial_test::serial;
    use std::ffi::CStr;

    #[test]
    #[serial]
    fn test_error_handling() {
        clear_last_error();

        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(error_ptr.is_null());

        set_last_error("Test error message");

        let error_ptr = dash_spv_ffi_get_last_error();
        assert!(!error_ptr.is_null());

        unsafe {
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert_eq!(error_str, "Test error message");
        }
    }

    #[test]
    #[serial]
    fn test_error_codes() {
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
    }

    #[test]
    #[serial]
    fn test_handle_error() {
        let ok_result: Result<i32, String> = Ok(42);
        let handled = handle_error(ok_result);
        assert_eq!(handled, Some(42));

        let err_ptr = dash_spv_ffi_get_last_error();
        assert!(err_ptr.is_null());

        let err_result: Result<i32, String> = Err("Test error".to_string());
        let handled = handle_error(err_result);
        assert!(handled.is_none());

        let err_ptr = dash_spv_ffi_get_last_error();
        assert!(!err_ptr.is_null());

        unsafe {
            let error_str = CStr::from_ptr(err_ptr).to_str().unwrap();
            assert_eq!(error_str, "Test error");
        }
    }
}
