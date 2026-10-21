#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use serial_test::serial;
    use std::ffi::{CStr, CString};

    #[test]
    #[serial]
    fn test_init_logging() {
        unsafe {
            let level = CString::new("debug").unwrap();
            let result = dash_spv_ffi_init_logging(level.as_ptr(), true, std::ptr::null(), 0);
            // May fail if already initialized, but should handle gracefully
            assert!(
                result == FFIErrorCode::Success as i32
                    || result == FFIErrorCode::RuntimeError as i32
            );

            // Test with null level pointer (should use RUST_LOG or default to INFO)
            let result = dash_spv_ffi_init_logging(std::ptr::null(), true, std::ptr::null(), 0);
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
}
