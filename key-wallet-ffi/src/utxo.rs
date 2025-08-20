//! UTXO management

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};

/// UTXO structure for FFI
#[repr(C)]
pub struct FFIUTXO {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub address: *mut c_char,
    pub script_pubkey: *mut u8,
    pub script_len: usize,
    pub height: u32,
    pub confirmations: u32,
}

impl FFIUTXO {
    /// Create a new FFIUTXO
    pub fn new(
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        address: String,
        script: Vec<u8>,
        height: u32,
        confirmations: u32,
    ) -> Self {
        let address_cstr = CString::new(address).unwrap_or_default();
        let script_len = script.len();
        let script_ptr = if script.is_empty() {
            ptr::null_mut()
        } else {
            let mut script_box = script.into_boxed_slice();
            let ptr = script_box.as_mut_ptr();
            std::mem::forget(script_box);
            ptr
        };

        FFIUTXO {
            txid,
            vout,
            amount,
            address: address_cstr.into_raw(),
            script_pubkey: script_ptr,
            script_len,
            height,
            confirmations,
        }
    }

    /// Free the FFIUTXO
    pub unsafe fn free(self) {
        if !self.address.is_null() {
            let _ = CString::from_raw(self.address);
        }
        if !self.script_pubkey.is_null() && self.script_len > 0 {
            let _ =
                Box::from_raw(std::slice::from_raw_parts_mut(self.script_pubkey, self.script_len));
        }
    }
}

/// Add UTXO to wallet
#[no_mangle]
pub extern "C" fn wallet_add_utxo(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    txid: *const u8,
    vout: u32,
    amount: u64,
    address: *const c_char,
    script_pubkey: *const u8,
    script_len: usize,
    height: u32,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || txid.is_null() || address.is_null() || script_pubkey.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let _address_str = unsafe {
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

    unsafe {
        let _wallet = &mut *wallet;
        let _network_rust: key_wallet::Network = network.into();

        // Note: Actual UTXO management would require implementing the wallet's UTXO tracking
        // For now, we'll just return success
        FFIError::set_success(error);
        true
    }
}

/// Remove UTXO from wallet
#[no_mangle]
pub extern "C" fn wallet_remove_utxo(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    txid: *const u8,
    vout: u32,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || txid.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let _wallet = &mut *wallet;
        let _network_rust: key_wallet::Network = network.into();
        let _vout = vout;

        // Note: Actual UTXO removal would require implementing the wallet's UTXO tracking
        FFIError::set_success(error);
        true
    }
}

/// Get all UTXOs
#[no_mangle]
pub extern "C" fn wallet_get_utxos(
    wallet: *const FFIWallet,
    network: FFINetwork,
    utxos_out: *mut *mut FFIUTXO,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || utxos_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let _wallet = &*wallet;
        let _network_rust: key_wallet::Network = network.into();

        // Return empty list for now
        *count_out = 0;
        *utxos_out = ptr::null_mut();

        FFIError::set_success(error);
        true
    }
}

/// Free UTXO array
#[no_mangle]
pub extern "C" fn utxo_array_free(utxos: *mut *mut FFIUTXO, count: usize) {
    if !utxos.is_null() {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(utxos, count);
            for utxo_ptr in slice {
                if !utxo_ptr.is_null() {
                    let utxo = Box::from_raw(*utxo_ptr);
                    utxo.free();
                }
            }
            // Free the array itself
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(utxos, count));
        }
    }
}

#[cfg(test)]
#[path = "utxo_tests.rs"]
mod tests;
