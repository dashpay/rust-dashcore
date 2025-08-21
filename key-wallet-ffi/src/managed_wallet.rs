//! Managed wallet FFI bindings
//!
//! This module provides FFI bindings for ManagedWalletInfo which includes
//! address management, UTXO tracking, and transaction building capabilities.
//!
//! NOTE: This is a placeholder implementation. Full implementation requires
//! proper integration with WalletManager which handles the managed wallet state.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

/// FFI wrapper for ManagedWalletInfo
#[repr(C)]
pub struct FFIManagedWalletInfo {
    inner: ManagedWalletInfo,
}

impl FFIManagedWalletInfo {
    /// Create a new FFIManagedWalletInfo from a ManagedWalletInfo
    pub fn new(inner: ManagedWalletInfo) -> Self {
        Self {
            inner,
        }
    }

    pub fn inner(&self) -> &ManagedWalletInfo {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut ManagedWalletInfo {
        &mut self.inner
    }
}

/// Mark an address as used in the managed wallet
///
/// NOTE: This is a placeholder. Address management is typically handled
/// automatically by WalletManager when processing transactions.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo or null
/// - `address` must be a valid null-terminated C string or null
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_mark_address_used(
    _managed_wallet: *mut FFIManagedWalletInfo,
    _network: FFINetwork,
    address: *const c_char,
    error: *mut FFIError,
) -> bool {
    if address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
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

    // Validate address format
    use std::str::FromStr;
    match key_wallet::Address::from_str(address_str) {
        Ok(_) => {
            // Placeholder: In a real implementation, this would update
            // the address state in the managed account
            FFIError::set_success(error);
            true
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

/// Get the next unused receive address
///
/// NOTE: This is a placeholder. Use WalletManager for proper address generation
/// with gap limit management.
#[no_mangle]
pub extern "C" fn managed_wallet_get_next_receive_address(
    _managed_wallet: *mut FFIManagedWalletInfo,
    _wallet: *const FFIWallet,
    _network: FFINetwork,
    _account_index: std::os::raw::c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    FFIError::set_error(
        error,
        FFIErrorCode::WalletError,
        "Not implemented - use WalletManager for address generation".to_string(),
    );
    ptr::null_mut()
}

/// Get the next unused change address
///
/// NOTE: This is a placeholder. Use WalletManager for proper address generation
/// with gap limit management.
#[no_mangle]
pub extern "C" fn managed_wallet_get_next_change_address(
    _managed_wallet: *mut FFIManagedWalletInfo,
    _wallet: *const FFIWallet,
    _network: FFINetwork,
    _account_index: std::os::raw::c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    FFIError::set_error(
        error,
        FFIErrorCode::WalletError,
        "Not implemented - use WalletManager for address generation".to_string(),
    );
    ptr::null_mut()
}

/// Get all addresses from a managed account
///
/// NOTE: This is a placeholder. Use WalletManager for proper address management.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo or null
/// - `addresses_out` must be a valid pointer to store the address array pointer
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError
/// - The returned addresses must be freed individually and the array must be freed
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_all_addresses(
    _managed_wallet: *const FFIManagedWalletInfo,
    _network: FFINetwork,
    _account_index: std::os::raw::c_uint,
    addresses_out: *mut *mut *mut c_char,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if addresses_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        // Return empty list as placeholder
        *count_out = 0;
        *addresses_out = ptr::null_mut();
        FFIError::set_success(error);
        true
    }
}

/// Free managed wallet info
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo or null
/// - After calling this function, the pointer becomes invalid and must not be used
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) {
    if !managed_wallet.is_null() {
        unsafe {
            let _ = Box::from_raw(managed_wallet);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::managed_wallet::*;
    use crate::types::FFINetwork;
    use std::ffi::CString;
    use std::ptr;

    // Note: managed_wallet_create has been removed as client libraries
    // should only get ManagedWalletInfo through WalletManager

    #[test]
    fn test_managed_wallet_free_null() {
        // Should not crash when freeing null
        unsafe {
            managed_wallet_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_null_address() {
        let mut error = FFIError::success();

        let success = unsafe {
            managed_wallet_mark_address_used(
                ptr::null_mut(),
                FFINetwork::Testnet,
                ptr::null(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_get_next_receive_address_not_implemented() {
        let mut error = FFIError::success();

        let address = managed_wallet_get_next_receive_address(
            ptr::null_mut(),
            ptr::null(),
            FFINetwork::Testnet,
            0,
            &mut error,
        );

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);
    }

    #[test]
    fn test_managed_wallet_get_next_change_address_not_implemented() {
        let mut error = FFIError::success();

        let address = managed_wallet_get_next_change_address(
            ptr::null_mut(),
            ptr::null(),
            FFINetwork::Testnet,
            0,
            &mut error,
        );

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);
    }

    #[test]
    fn test_managed_wallet_get_all_addresses_success() {
        let mut error = FFIError::success();
        let mut addresses_out: *mut *mut std::os::raw::c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            managed_wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 0);
        assert!(addresses_out.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);
    }

    #[test]
    fn test_managed_wallet_get_all_addresses_null_outputs() {
        let mut error = FFIError::success();

        // Test with null addresses_out
        let success = unsafe {
            managed_wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                ptr::null_mut(),
                &mut 0,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null count_out
        let mut addresses_out: *mut *mut std::os::raw::c_char = ptr::null_mut();
        let success = unsafe {
            managed_wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut addresses_out,
                ptr::null_mut(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_mark_address_used_utf8_error() {
        let mut error = FFIError::success();

        // Create invalid UTF-8 string
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD, 0x00]; // Invalid UTF-8 bytes with null terminator
        let success = unsafe {
            managed_wallet_mark_address_used(
                ptr::null_mut(),
                FFINetwork::Testnet,
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }
}
