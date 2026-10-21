//! BIP38 encryption support

use std::os::raw::c_char;
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};

/// Encrypt a private key with BIP38
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `private_key` must be a valid, null-terminated C string
/// - `passphrase` must be a valid, null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn bip38_encrypt_private_key(
    _private_key: *const c_char,
    _passphrase: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    (*error).set(FFIErrorCode::InternalError, "BIP38 encryption not yet implemented");
    ptr::null_mut()
}

/// Decrypt a BIP38 encrypted private key
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers:
/// - `encrypted_key` must be a valid, null-terminated C string
/// - `passphrase` must be a valid, null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn bip38_decrypt_private_key(
    _encrypted_key: *const c_char,
    _passphrase: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    (*error).set(FFIErrorCode::InternalError, "BIP38 decryption not yet implemented");
    ptr::null_mut()
}
