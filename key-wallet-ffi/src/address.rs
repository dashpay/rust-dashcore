//! Address derivation and management

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFINetwork;

/// Free address string
///
/// # Safety
///
/// - `address` must be a valid pointer created by address functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn address_free(address: *mut c_char) {
    if !address.is_null() {
        unsafe {
            let _ = CString::from_raw(address);
        }
    }
}

/// Free address array
///
/// # Safety
///
/// - `addresses` must be a valid pointer to an array of address strings or null
/// - Each address in the array must be a valid C string pointer
/// - `count` must be the correct number of addresses in the array
/// - After calling this function, all pointers become invalid
#[no_mangle]
pub unsafe extern "C" fn address_array_free(addresses: *mut *mut c_char, count: usize) {
    if !addresses.is_null() {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(addresses, count);
            for addr in slice {
                if !addr.is_null() {
                    let _ = CString::from_raw(*addr);
                }
            }
            // Free the array itself
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(addresses, count));
        }
    }
}

/// Validate an address
///
/// # Safety
///
/// - `address` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn address_validate(
    address: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> bool {
    if address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Address is null".to_string());
        return false;
    }

    let address_str = unsafe {
        match CStr::from_ptr(address).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in address".to_string(),
                );
                return false;
            }
        }
    };

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return ptr::null_mut();
        }
    };
    use std::str::FromStr;

    match key_wallet::Address::from_str(address_str) {
        Ok(addr) => {
            // Check if address is valid for the given network
            let dash_network = network_rust;
            match addr.require_network(dash_network) {
                Ok(_) => {
                    FFIError::set_success(error);
                    true
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidAddress,
                        format!("Address not valid for network {:?}", network_rust),
                    );
                    false
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidAddress,
                format!("Invalid address: {}", e),
            );
            false
        }
    }
}

/// Get address type
///
/// Returns:
/// - 0: P2PKH address
/// - 1: P2SH address
/// - 2: Other address type
/// - u8::MAX (255): Error occurred
///
/// # Safety
///
/// - `address` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn address_get_type(
    address: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> c_uchar {
    if address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Address is null".to_string());
        return u8::MAX;
    }

    let address_str = unsafe {
        match CStr::from_ptr(address).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in address".to_string(),
                );
                return u8::MAX;
            }
        }
    };

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return ptr::null_mut();
        }
    };
    use std::str::FromStr;

    match key_wallet::Address::from_str(address_str) {
        Ok(addr) => {
            let dash_network = network_rust;
            match addr.require_network(dash_network) {
                Ok(checked_addr) => {
                    FFIError::set_success(error);
                    // Get the actual address type
                    match checked_addr.address_type() {
                        Some(key_wallet::AddressType::P2pkh) => 0,
                        Some(key_wallet::AddressType::P2sh) => 1,
                        Some(_) => 2, // Other address type
                        None => 2,    // Unknown type
                    }
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidAddress,
                        "Address not valid for network".to_string(),
                    );
                    u8::MAX // Error
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidAddress,
                format!("Invalid address: {}", e),
            );
            u8::MAX // Error
        }
    }
}
