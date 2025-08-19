//! Managed wallet FFI bindings
//!
//! This module provides FFI bindings for ManagedWalletInfo which includes
//! address management, UTXO tracking, and transaction building capabilities.
//!
//! NOTE: This is a placeholder implementation. Full implementation requires
//! proper integration with WalletManager which handles the managed wallet state.

use std::ffi::{CStr, CString};
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
    pub fn inner(&self) -> &ManagedWalletInfo {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut ManagedWalletInfo {
        &mut self.inner
    }
}

/// Create a new managed wallet info from a wallet
///
/// NOTE: This is a placeholder. Proper managed wallet functionality
/// should be accessed through WalletManager instead.
#[no_mangle]
pub extern "C" fn managed_wallet_create(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> *mut FFIManagedWalletInfo {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let wallet = &*wallet;
        let managed_info = ManagedWalletInfo::from_wallet(wallet.inner());

        FFIError::set_success(error);
        Box::into_raw(Box::new(FFIManagedWalletInfo {
            inner: managed_info,
        }))
    }
}

/// Mark an address as used in the managed wallet
///
/// NOTE: This is a placeholder. Address management is typically handled
/// automatically by WalletManager when processing transactions.
#[no_mangle]
pub extern "C" fn managed_wallet_mark_address_used(
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
#[no_mangle]
pub extern "C" fn managed_wallet_get_all_addresses(
    _managed_wallet: *const FFIManagedWalletInfo,
    _network: FFINetwork,
    _account_index: std::os::raw::c_uint,
    addresses_out: *mut *mut c_char,
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
#[no_mangle]
pub extern "C" fn managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) {
    if !managed_wallet.is_null() {
        unsafe {
            let _ = Box::from_raw(managed_wallet);
        }
    }
}
