//! Minimal platform integration test to verify FFI functions

use dash_spv_ffi::*;
use std::ptr;

#[test]
fn test_basic_null_checks() {
    unsafe {
        // Test error code
        let mut height: u32 = 0;
        let result =
            ffi_dash_spv_get_platform_activation_height(ptr::null_mut(), &mut height as *mut u32);
        assert_eq!(result.error_code, FFIErrorCode::NullPointer as i32);
    }
}
