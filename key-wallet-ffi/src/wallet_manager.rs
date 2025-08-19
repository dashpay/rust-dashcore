//! FFI bindings for WalletManager from key-wallet-manager crate
//!
//! NOTE: This is a placeholder implementation. Full implementation requires
//! fixing the API mismatches with the actual WalletManager implementation.

#[cfg(test)]
#[path = "wallet_manager_tests.rs"]
mod tests;

use std::ffi::CString;
use std::os::raw::{c_char, c_uint, c_ulong};
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFINetwork;

/// Placeholder FFI wrapper for WalletManager
#[repr(C)]
pub struct FFIWalletManager {
    _placeholder: u8,
}

/// Create a new wallet manager
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_create(error: *mut FFIError) -> *mut FFIWalletManager {
    FFIError::set_success(error);
    Box::into_raw(Box::new(FFIWalletManager {
        _placeholder: 0,
    }))
}

/// Add a wallet from mnemonic to the manager
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_add_wallet_from_mnemonic(
    _manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    _passphrase: *const c_char,
    _network: FFINetwork,
    _account_count: c_uint,
    error: *mut FFIError,
) -> bool {
    if mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    // Placeholder: Just validate the mnemonic
    let mnemonic_str = unsafe {
        match std::ffi::CStr::from_ptr(mnemonic).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in mnemonic".to_string(),
                );
                return false;
            }
        }
    };

    // Basic validation - check word count
    let word_count = mnemonic_str.split_whitespace().count();
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidMnemonic,
            "Invalid mnemonic word count".to_string(),
        );
        return false;
    }

    FFIError::set_success(error);
    true
}

/// Get wallet IDs
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_wallet_ids(
    _manager: *const FFIWalletManager,
    wallet_ids_out: *mut *mut u8,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if wallet_ids_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        // Return empty list as placeholder
        *count_out = 0;
        *wallet_ids_out = ptr::null_mut();
        FFIError::set_success(error);
        true
    }
}

/// Get a wallet from the manager
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_wallet(
    _manager: *const FFIWalletManager,
    _wallet_id: *const u8,
    error: *mut FFIError,
) -> *const crate::types::FFIWallet {
    FFIError::set_error(
        error,
        FFIErrorCode::NotFound,
        "Placeholder - wallet not found".to_string(),
    );
    ptr::null()
}

/// Get next receive address for a wallet
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_receive_address(
    _manager: *mut FFIWalletManager,
    _wallet_id: *const u8,
    _network: FFINetwork,
    _account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    FFIError::set_error(error, FFIErrorCode::WalletError, "Not implemented".to_string());
    ptr::null_mut()
}

/// Get next change address for a wallet
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_change_address(
    _manager: *mut FFIWalletManager,
    _wallet_id: *const u8,
    _network: FFINetwork,
    _account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    FFIError::set_error(error, FFIErrorCode::WalletError, "Not implemented".to_string());
    ptr::null_mut()
}

/// Get wallet balance
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_wallet_balance(
    _manager: *const FFIWalletManager,
    _wallet_id: *const u8,
    confirmed_out: *mut c_ulong,
    unconfirmed_out: *mut c_ulong,
    error: *mut FFIError,
) -> bool {
    if confirmed_out.is_null() || unconfirmed_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        *confirmed_out = 0;
        *unconfirmed_out = 0;
        FFIError::set_success(error);
        true
    }
}

/// Get total balance across all wallets
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_total_balance(
    _manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> c_ulong {
    FFIError::set_success(error);
    0
}

/// Process a transaction through all wallets
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_process_transaction(
    _manager: *mut FFIWalletManager,
    _tx_bytes: *const u8,
    _tx_len: usize,
    _height: c_uint,
    _block_time: c_uint,
    error: *mut FFIError,
) -> bool {
    FFIError::set_success(error);
    false
}

/// Get monitored addresses for a network
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_monitored_addresses(
    _manager: *const FFIWalletManager,
    _network: FFINetwork,
    addresses_out: *mut *mut c_char,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if addresses_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        *count_out = 0;
        *addresses_out = ptr::null_mut();
        FFIError::set_success(error);
        true
    }
}

/// Update block height for a network
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_update_height(
    _manager: *mut FFIWalletManager,
    _network: FFINetwork,
    _height: c_uint,
    error: *mut FFIError,
) -> bool {
    FFIError::set_success(error);
    true
}

/// Get current height for a network
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_current_height(
    _manager: *const FFIWalletManager,
    _network: FFINetwork,
    error: *mut FFIError,
) -> c_uint {
    FFIError::set_success(error);
    0
}

/// Get wallet count
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_wallet_count(
    manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> usize {
    if manager.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Manager is null".to_string());
        return 0;
    }

    FFIError::set_success(error);
    0
}

/// Free wallet manager
#[no_mangle]
pub extern "C" fn wallet_manager_free(manager: *mut FFIWalletManager) {
    if !manager.is_null() {
        unsafe {
            let _ = Box::from_raw(manager);
        }
    }
}

/// Free wallet IDs buffer
#[no_mangle]
pub extern "C" fn wallet_manager_free_wallet_ids(wallet_ids: *mut u8, count: usize) {
    if !wallet_ids.is_null() && count > 0 {
        unsafe {
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(wallet_ids, count * 32));
        }
    }
}

/// Free address array
#[no_mangle]
pub extern "C" fn wallet_manager_free_addresses(addresses: *mut *mut c_char, count: usize) {
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
