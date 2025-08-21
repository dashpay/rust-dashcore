//! BIP38 encryption support

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFINetwork;

/// Encrypt a private key with BIP38
#[no_mangle]
pub extern "C" fn bip38_encrypt_private_key(
    private_key: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut c_char {
    #[cfg(feature = "bip38")]
    {
        if private_key.is_null() || passphrase.is_null() {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Null pointer provided".to_string(),
            );
            return ptr::null_mut();
        }

        let privkey_str = unsafe {
            match CStr::from_ptr(private_key).to_str() {
                Ok(s) => s,
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidInput,
                        "Invalid UTF-8 in private key".to_string(),
                    );
                    return ptr::null_mut();
                }
            }
        };

        let passphrase_str = unsafe {
            match CStr::from_ptr(passphrase).to_str() {
                Ok(s) => s,
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidInput,
                        "Invalid UTF-8 in passphrase".to_string(),
                    );
                    return ptr::null_mut();
                }
            }
        };

        // Note: key_wallet doesn't have built-in BIP38 support
        // This would need to be implemented using a BIP38 library
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "BIP38 encryption not yet implemented".to_string(),
        );
        ptr::null_mut()
    }
    #[cfg(not(feature = "bip38"))]
    {
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "BIP38 support not enabled".to_string(),
        );
        ptr::null_mut()
    }
}

/// Decrypt a BIP38 encrypted private key
#[no_mangle]
pub extern "C" fn bip38_decrypt_private_key(
    encrypted_key: *const c_char,
    passphrase: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    #[cfg(feature = "bip38")]
    {
        if encrypted_key.is_null() || passphrase.is_null() {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Null pointer provided".to_string(),
            );
            return ptr::null_mut();
        }

        let encrypted_str = unsafe {
            match CStr::from_ptr(encrypted_key).to_str() {
                Ok(s) => s,
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidInput,
                        "Invalid UTF-8 in encrypted key".to_string(),
                    );
                    return ptr::null_mut();
                }
            }
        };

        let passphrase_str = unsafe {
            match CStr::from_ptr(passphrase).to_str() {
                Ok(s) => s,
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidInput,
                        "Invalid UTF-8 in passphrase".to_string(),
                    );
                    return ptr::null_mut();
                }
            }
        };

        // Note: key_wallet doesn't have built-in BIP38 support
        // This would need to be implemented using a BIP38 library
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "BIP38 decryption not yet implemented".to_string(),
        );
        ptr::null_mut()
    }
    #[cfg(not(feature = "bip38"))]
    {
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "BIP38 support not enabled".to_string(),
        );
        ptr::null_mut()
    }
}
