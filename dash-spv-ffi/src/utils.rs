use crate::{set_last_error, FFIErrorCode};
use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_init_logging(level: *const c_char) -> i32 {
    let level_str = if level.is_null() {
        "info"
    } else {
        match CStr::from_ptr(level).to_str() {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("Invalid UTF-8 in log level: {}", e));
                return FFIErrorCode::InvalidArgument as i32;
            }
        }
    };

    match dash_spv::init_logging(level_str) {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to initialize logging: {}", e));
            FFIErrorCode::RuntimeError as i32
        }
    }
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_get_network_name(network: crate::FFINetwork) -> *const c_char {
    match network {
        crate::FFINetwork::Dash => "dash\0".as_ptr() as *const c_char,
        crate::FFINetwork::Testnet => "testnet\0".as_ptr() as *const c_char,
        crate::FFINetwork::Regtest => "regtest\0".as_ptr() as *const c_char,
        crate::FFINetwork::Devnet => "devnet\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_enable_test_mode() {
    std::env::set_var("DASH_SPV_TEST_MODE", "1");
}
