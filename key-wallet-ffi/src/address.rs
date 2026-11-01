//! Address derivation and management

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;

use crate::error::FFIError;
use crate::{deref_ptr, unwrap_or_return};
use dash_network::ffi::FFINetwork;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

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
    use std::str::FromStr;

    let address = deref_ptr!(address, error);
    let address_str = unwrap_or_return!(CStr::from_ptr(address).to_str(), error);
    let network_rust: key_wallet::Network = network.into();

    let addr = unwrap_or_return!(key_wallet::Address::from_str(address_str), error);
    let _ = unwrap_or_return!(addr.require_network(network_rust), error);
    true
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
    use std::str::FromStr;

    let address = deref_ptr!(address, error, u8::MAX);
    let address_str = unwrap_or_return!(CStr::from_ptr(address).to_str(), error, u8::MAX);
    let network_rust: key_wallet::Network = network.into();
    let addr = unwrap_or_return!(key_wallet::Address::from_str(address_str), error, u8::MAX);
    let checked = unwrap_or_return!(addr.require_network(network_rust), error, u8::MAX);

    match checked.address_type() {
        Some(key_wallet::AddressType::P2pkh) => 0,
        Some(key_wallet::AddressType::P2sh) => 1,
        Some(_) | None => 2,
    }
}
