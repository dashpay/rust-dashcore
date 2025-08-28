//! UTXO management

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::managed_wallet::FFIManagedWalletInfo;
use crate::types::FFINetwork;

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
            let script_box = script.into_boxed_slice();
            Box::into_raw(script_box) as *mut u8
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

    /// Free the FFIUTXO's allocated memory
    ///
    /// # Safety
    ///
    /// - `self.address` must be a valid pointer created by CString or null
    /// - `self.script_pubkey` must be a valid pointer to a Box allocation or null
    /// - After calling this function, the pointers become invalid
    pub unsafe fn free(&mut self) {
        if !self.address.is_null() {
            let _ = CString::from_raw(self.address);
            self.address = ptr::null_mut();
        }
        if !self.script_pubkey.is_null() && self.script_len > 0 {
            // Reconstruct the boxed slice with DST pointer
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.script_pubkey,
                self.script_len,
            ));
            self.script_pubkey = ptr::null_mut();
            self.script_len = 0;
        }
    }
}

/// Get all UTXOs from managed wallet info
///
/// # Safety
///
/// - `managed_info` must be a valid pointer to an FFIManagedWalletInfo instance
/// - `utxos_out` must be a valid pointer to store the UTXO array pointer
/// - `count_out` must be a valid pointer to store the UTXO count
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned UTXO array must be freed with `utxo_array_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_utxos(
    managed_info: *const FFIManagedWalletInfo,
    network: FFINetwork,
    utxos_out: *mut *mut FFIUTXO,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if managed_info.is_null() || utxos_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_info = &*managed_info;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    // Get UTXOs from the managed wallet info
    let utxos = managed_info.inner().get_utxos(network_rust);

    if utxos.is_empty() {
        *count_out = 0;
        *utxos_out = ptr::null_mut();
    } else {
        // Convert UTXOs to FFI format
        let mut ffi_utxos = Vec::with_capacity(utxos.len());

        for (outpoint, utxo) in utxos {
            // Convert txid to byte array
            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&outpoint.txid[..]);

            // Convert address to string
            let address_str = utxo.address.to_string();

            // Get script bytes
            let script_bytes = utxo.txout.script_pubkey.as_bytes().to_vec();

            // Calculate confirmations (0 if unconfirmed)
            let confirmations = if utxo.is_confirmed {
                1
            } else {
                0
            };

            let ffi_utxo = FFIUTXO::new(
                txid_bytes,
                outpoint.vout,
                utxo.value(),
                address_str,
                script_bytes,
                utxo.height,
                confirmations,
            );

            ffi_utxos.push(ffi_utxo);
        }

        *count_out = ffi_utxos.len();
        // Convert Vec to boxed slice for consistent memory layout
        let boxed_utxos = ffi_utxos.into_boxed_slice();
        let ptr = Box::into_raw(boxed_utxos) as *mut FFIUTXO;
        *utxos_out = ptr;
    }

    FFIError::set_success(error);
    true
}

/// Get all UTXOs (deprecated - use managed_wallet_get_utxos instead)
///
/// # Safety
///
/// This function is deprecated and returns an empty list.
/// Use `managed_wallet_get_utxos` with a ManagedWalletInfo instead.
#[no_mangle]
#[deprecated(note = "Use managed_wallet_get_utxos with ManagedWalletInfo instead")]
pub unsafe extern "C" fn wallet_get_utxos(
    _wallet: *const crate::types::FFIWallet,
    _network: FFINetwork,
    utxos_out: *mut *mut FFIUTXO,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if utxos_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    // Return empty list for backwards compatibility
    *count_out = 0;
    *utxos_out = ptr::null_mut();

    FFIError::set_success(error);
    true
}

/// Free UTXO array
///
/// # Safety
///
/// - `utxos` must be a valid pointer to an array of FFIUTXO structs allocated by this library
/// - `count` must match the number of UTXOs in the array
/// - The pointer must not be used after calling this function
/// - This function must only be called once per array
#[no_mangle]
pub unsafe extern "C" fn utxo_array_free(utxos: *mut FFIUTXO, count: usize) {
    if !utxos.is_null() && count > 0 {
        // Create a slice from the raw pointer
        let slice = std::slice::from_raw_parts_mut(utxos, count);

        // Free each UTXO's allocated memory (address and script)
        for utxo in slice {
            utxo.free();
        }

        // Free the array itself by reconstructing the boxed slice with DST pointer
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(utxos, count));
    }
}

#[cfg(test)]
#[path = "utxo_tests.rs"]
mod tests;
