//! Utility functions for FFI

#[cfg(test)]
#[path = "utils_tests.rs"]
mod util_tests;

use std::ffi::CString;
use std::os::raw::c_char;

/// Free a string
///
/// # Safety
///
/// - `s` must be a valid pointer created by C string creation functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Helper function to convert Rust string to C string
pub fn rust_string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Helper function to convert C string to Rust string
///
/// # Safety
///
/// - `s` must be a valid null-terminated C string or null
/// - The string must remain valid for the duration of this function call
pub unsafe fn c_string_to_rust(s: *const c_char) -> Result<String, std::str::Utf8Error> {
    use std::ffi::CStr;

    if s.is_null() {
        return Ok(String::new());
    }

    CStr::from_ptr(s).to_str().map(|s| s.to_string())
}
