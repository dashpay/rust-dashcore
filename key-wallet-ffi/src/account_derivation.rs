//! Account-level derivation functions exposed over FFI

use crate::account::FFIAccount;
use crate::error::{FFIError, FFIErrorCode};
use crate::keys::FFIExtendedPrivateKey;
use key_wallet::account::derivation::AccountDerivation;
use key_wallet::account::AccountTrait;
use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

/// Derive a private key from an account at a given chain/index and return as WIF string.
/// Caller must free the returned string with `string_free`.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid pointers allocated by this library
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_as_wif_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivateKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if account.is_null() || master_xpriv.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let master_xpriv = &*master_xpriv;

    if account.inner().is_watch_only() {
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed".to_string(),
        );
        return ptr::null_mut();
    }

    match account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index) {
        Ok(derived) => {
            // Wrap into dashcore::PrivateKey to WIF encode
            let dash_priv = dashcore::PrivateKey {
                compressed: true,
                network: account.inner().network(),
                inner: derived.private_key,
            };
            match CString::new(dash_priv.to_wif()) {
                Ok(c_str) => {
                    FFIError::set_success(error);
                    c_str.into_raw()
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Failed to allocate WIF string".to_string(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive private key: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}
