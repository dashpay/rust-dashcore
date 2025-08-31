#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::types::ffi_network_get_name;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::{CStr, CString};

    #[test]
    #[serial]
    fn test_init_logging() {
        unsafe {
            let level = CString::new("debug").unwrap();
            let result = dash_spv_ffi_init_logging(level.as_ptr());
            // May fail if already initialized, but should handle gracefully
            assert!(
                result == FFIErrorCode::Success as i32
                    || result == FFIErrorCode::RuntimeError as i32
            );

            // Test with null pointer (should use default)
            let result = dash_spv_ffi_init_logging(std::ptr::null());
            assert!(
                result == FFIErrorCode::Success as i32
                    || result == FFIErrorCode::RuntimeError as i32
            );
        }
    }

    #[test]
    fn test_version() {
        unsafe {
            let version_ptr = dash_spv_ffi_version();
            assert!(!version_ptr.is_null());

            let version = CStr::from_ptr(version_ptr).to_str().unwrap();
            assert!(!version.is_empty());
            assert!(version.contains("."));
        }
    }

    #[test]
    fn test_network_names() {
        unsafe {
            let name = ffi_network_get_name(FFINetwork::Dash);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "dash");

            let name = ffi_network_get_name(FFINetwork::Testnet);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "testnet");

            let name = ffi_network_get_name(FFINetwork::Regtest);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "regtest");

            let name = ffi_network_get_name(FFINetwork::Devnet);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "devnet");
        }
    }

    #[test]
    fn test_enable_test_mode() {
        dash_spv_ffi_enable_test_mode();
        assert_eq!(std::env::var("DASH_SPV_TEST_MODE").unwrap_or_default(), "1");
    }
}
