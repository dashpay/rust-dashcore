//! Unit tests for utils FFI module

#[cfg(test)]
#[allow(clippy::module_inception)]
mod util_tests {
    use crate::utils;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_string_utils() {
        // Test string allocation and deallocation
        let test_str = "Hello, FFI!";
        let c_string = CString::new(test_str).unwrap();
        let raw_ptr = c_string.into_raw();

        // Verify the string is valid
        let retrieved = unsafe { std::ffi::CStr::from_ptr(raw_ptr).to_str().unwrap() };
        assert_eq!(retrieved, test_str);

        // Free the string
        unsafe {
            utils::string_free(raw_ptr);
        }
    }

    #[test]
    fn test_string_free() {
        // Test freeing null pointer (should not crash)
        unsafe {
            utils::string_free(ptr::null_mut());
        }

        // Test freeing valid string
        let c_string = CString::new("test").unwrap();
        let raw_ptr = c_string.into_raw();
        unsafe {
            utils::string_free(raw_ptr);
        }
    }

    #[test]
    fn test_c_string_to_rust() {
        // Test converting C string to Rust string
        let test_str = "Test String";
        let c_string = CString::new(test_str).unwrap();

        let rust_str = unsafe { std::ffi::CStr::from_ptr(c_string.as_ptr()).to_str().unwrap() };

        assert_eq!(rust_str, test_str);
    }

    #[test]
    fn test_version() {
        let version = crate::key_wallet_ffi_version();
        assert!(!version.is_null());

        let version_str = unsafe { std::ffi::CStr::from_ptr(version).to_str().unwrap() };

        // Version should match Cargo.toml version
        assert!(!version_str.is_empty());

        // Note: We don't free the version string as it's likely a static
        // or should be handled by the library's own cleanup
    }
}
