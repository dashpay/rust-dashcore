//! Key derivation and management

use dashcore::ffi::FFINetwork;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFIWallet;
use crate::{check_ptr, deref_ptr, unwrap_or_return};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;

/// Opaque type for a private key (SecretKey)
pub struct FFIPrivateKey {
    inner: secp256k1::SecretKey,
}

/// Opaque type for an extended private key
pub struct FFIExtendedPrivKey {
    inner: key_wallet::bip32::ExtendedPrivKey,
}

/// Opaque type for a public key
pub struct FFIPublicKey {
    inner: secp256k1::PublicKey,
}

/// Opaque type for an extended public key
pub struct FFIExtendedPubKey {
    inner: key_wallet::bip32::ExtendedPubKey,
}

impl FFIExtendedPrivKey {
    #[inline]
    pub(crate) fn inner(&self) -> &key_wallet::bip32::ExtendedPrivKey {
        &self.inner
    }

    #[inline]
    pub(crate) fn from_inner(inner: key_wallet::bip32::ExtendedPrivKey) -> Self {
        FFIExtendedPrivKey {
            inner,
        }
    }
}

impl FFIExtendedPubKey {
    #[inline]
    pub(crate) fn inner(&self) -> &key_wallet::bip32::ExtendedPubKey {
        &self.inner
    }

    #[inline]
    pub(crate) fn from_inner(inner: key_wallet::bip32::ExtendedPubKey) -> Self {
        FFIExtendedPubKey {
            inner,
        }
    }
}

impl FFIPrivateKey {
    #[inline]
    pub(crate) fn from_secret(inner: secp256k1::SecretKey) -> Self {
        FFIPrivateKey {
            inner,
        }
    }
}

/// Get extended private key for account
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_get_account_xpriv(
    wallet: *const FFIWallet,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let wallet = deref_ptr!(wallet, error);

    let account = unwrap_or_return!(wallet.inner().get_bip44_account(account_index), error);

    if account.is_watch_only {
        (*error).set(FFIErrorCode::NotFound, "Private key not available (watch-only wallet)");
        return ptr::null_mut();
    }

    (*error).set(FFIErrorCode::InternalError, "Private key extraction not implemented");
    ptr::null_mut()
}

/// Get extended public key for account
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_get_account_xpub(
    wallet: *const FFIWallet,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let wallet = deref_ptr!(wallet, error);
    let account = unwrap_or_return!(wallet.inner().get_bip44_account(account_index), error);
    unwrap_or_return!(CString::new(account.extended_public_key().to_string()), error).into_raw()
}

/// Derive private key at a specific path
/// Returns an opaque FFIPrivateKey pointer that must be freed with private_key_free
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `derivation_path` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `private_key_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_private_key(
    wallet: *const FFIWallet,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let wallet = deref_ptr!(wallet, error);
    let derivation_path = deref_ptr!(derivation_path, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(derivation_path).to_str(), error);
    let path = unwrap_or_return!(DerivationPath::from_str(path_str), error);
    let private_key = unwrap_or_return!(wallet.inner().derive_private_key(&path), error);
    Box::into_raw(Box::new(FFIPrivateKey {
        inner: private_key,
    }))
}

/// Derive extended private key at a specific path
/// Returns an opaque FFIExtendedPrivKey pointer that must be freed with extended_private_key_free
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `derivation_path` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `extended_private_key_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_extended_private_key(
    wallet: *const FFIWallet,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let wallet = deref_ptr!(wallet, error);
    let derivation_path = deref_ptr!(derivation_path, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(derivation_path).to_str(), error);
    let path = unwrap_or_return!(DerivationPath::from_str(path_str), error);
    let extended_private_key =
        unwrap_or_return!(wallet.inner().derive_extended_private_key(&path), error);
    Box::into_raw(Box::new(FFIExtendedPrivKey {
        inner: extended_private_key,
    }))
}

/// Derive private key at a specific path and return as WIF string
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `derivation_path` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_private_key_as_wif(
    wallet: *const FFIWallet,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let wallet = deref_ptr!(wallet, error);
    let derivation_path = deref_ptr!(derivation_path, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(derivation_path).to_str(), error);
    let path = unwrap_or_return!(DerivationPath::from_str(path_str), error);
    let wif = unwrap_or_return!(wallet.inner().derive_private_key_as_wif(&path), error);
    unwrap_or_return!(CString::new(wif), error).into_raw()
}

/// Free a private key
///
/// # Safety
///
/// - `key` must be a valid pointer created by private key functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn private_key_free(key: *mut FFIPrivateKey) {
    if !key.is_null() {
        let _ = unsafe { Box::from_raw(key) };
    }
}

/// Free an extended private key
///
/// # Safety
///
/// - `key` must be a valid pointer created by extended private key functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn extended_private_key_free(key: *mut FFIExtendedPrivKey) {
    if !key.is_null() {
        let _ = unsafe { Box::from_raw(key) };
    }
}

/// Get extended private key as string (xprv format)
///
/// Returns the extended private key in base58 format (xprv... for mainnet, tprv... for testnet)
///
/// # Safety
///
/// - `key` must be a valid pointer to an FFIExtendedPrivKey
/// - `network` is ignored; the network is encoded in the extended key
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn extended_private_key_to_string(
    key: *const FFIExtendedPrivKey,
    _network: FFINetwork,
    error: *mut FFIError,
) -> *mut c_char {
    // Network is already encoded in the extended key.
    let key = deref_ptr!(key, error);
    unwrap_or_return!(CString::new(key.inner.to_string()), error).into_raw()
}

/// Get the private key from an extended private key
///
/// Extracts the non-extended private key from an extended private key.
///
/// # Safety
///
/// - `extended_key` must be a valid pointer to an FFIExtendedPrivKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned FFIPrivateKey must be freed with `private_key_free`
#[no_mangle]
pub unsafe extern "C" fn extended_private_key_get_private_key(
    extended_key: *const FFIExtendedPrivKey,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    let extended = deref_ptr!(extended_key, error);
    Box::into_raw(Box::new(FFIPrivateKey {
        inner: extended.inner.private_key,
    }))
}

/// Get private key as WIF string from FFIPrivateKey
///
/// # Safety
///
/// - `key` must be a valid pointer to an FFIPrivateKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn private_key_to_wif(
    key: *const FFIPrivateKey,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut c_char {
    let key = deref_ptr!(key, error);

    let network_rust: key_wallet::Network = network.into();

    // Convert to WIF format
    use dashcore::PrivateKey as DashPrivateKey;
    let dash_key = DashPrivateKey {
        compressed: true,
        network: network_rust,
        inner: key.inner,
    };

    let wif = dash_key.to_wif();
    unwrap_or_return!(CString::new(wif), error).into_raw()
}

/// Derive public key at a specific path
/// Returns an opaque FFIPublicKey pointer that must be freed with public_key_free
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `derivation_path` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `public_key_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_public_key(
    wallet: *const FFIWallet,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIPublicKey {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let wallet = deref_ptr!(wallet, error);
    let derivation_path = deref_ptr!(derivation_path, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(derivation_path).to_str(), error);
    let path = unwrap_or_return!(DerivationPath::from_str(path_str), error);
    let public_key = unwrap_or_return!(wallet.inner().derive_public_key(&path), error);
    Box::into_raw(Box::new(FFIPublicKey {
        inner: public_key,
    }))
}

/// Derive extended public key at a specific path
/// Returns an opaque FFIExtendedPubKey pointer that must be freed with extended_public_key_free
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `derivation_path` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `extended_public_key_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_extended_public_key(
    wallet: *const FFIWallet,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIExtendedPubKey {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let wallet = deref_ptr!(wallet, error);
    let derivation_path = deref_ptr!(derivation_path, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(derivation_path).to_str(), error);
    let path = unwrap_or_return!(DerivationPath::from_str(path_str), error);
    let extended_public_key =
        unwrap_or_return!(wallet.inner().derive_extended_public_key(&path), error);
    Box::into_raw(Box::new(FFIExtendedPubKey {
        inner: extended_public_key,
    }))
}

/// Derive public key at a specific path and return as hex string
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `derivation_path` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_public_key_as_hex(
    wallet: *const FFIWallet,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let wallet = deref_ptr!(wallet, error);
    let derivation_path = deref_ptr!(derivation_path, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(derivation_path).to_str(), error);
    let path = unwrap_or_return!(DerivationPath::from_str(path_str), error);
    let hex = unwrap_or_return!(wallet.inner().derive_public_key_as_hex(&path), error);
    unwrap_or_return!(CString::new(hex), error).into_raw()
}

/// Free a public key
///
/// # Safety
///
/// - `key` must be a valid pointer created by public key functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn public_key_free(key: *mut FFIPublicKey) {
    if !key.is_null() {
        unsafe {
            let _ = Box::from_raw(key);
        }
    }
}

/// Free an extended public key
///
/// # Safety
///
/// - `key` must be a valid pointer created by extended public key functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn extended_public_key_free(key: *mut FFIExtendedPubKey) {
    if !key.is_null() {
        unsafe {
            let _ = Box::from_raw(key);
        }
    }
}

/// Get extended public key as string (xpub format)
///
/// Returns the extended public key in base58 format (xpub... for mainnet, tpub... for testnet)
///
/// # Safety
///
/// - `key` must be a valid pointer to an FFIExtendedPubKey
/// - `network` is ignored; the network is encoded in the extended key
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn extended_public_key_to_string(
    key: *const FFIExtendedPubKey,
    _network: FFINetwork,
    error: *mut FFIError,
) -> *mut c_char {
    // Network is already encoded in the extended key.
    let key = deref_ptr!(key, error);
    unwrap_or_return!(CString::new(key.inner.to_string()), error).into_raw()
}

/// Get the public key from an extended public key
///
/// Extracts the non-extended public key from an extended public key.
///
/// # Safety
///
/// - `extended_key` must be a valid pointer to an FFIExtendedPubKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned FFIPublicKey must be freed with `public_key_free`
#[no_mangle]
pub unsafe extern "C" fn extended_public_key_get_public_key(
    extended_key: *const FFIExtendedPubKey,
    error: *mut FFIError,
) -> *mut FFIPublicKey {
    let extended = deref_ptr!(extended_key, error);
    Box::into_raw(Box::new(FFIPublicKey {
        inner: extended.inner.public_key,
    }))
}

/// Get public key as hex string from FFIPublicKey
///
/// # Safety
///
/// - `key` must be a valid pointer to an FFIPublicKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn public_key_to_hex(
    key: *const FFIPublicKey,
    error: *mut FFIError,
) -> *mut c_char {
    let key = deref_ptr!(key, error);
    unwrap_or_return!(CString::new(hex::encode(key.inner.serialize())), error).into_raw()
}

/// Convert derivation path string to indices
///
/// # Safety
///
/// - `path` must be a valid null-terminated C string or null
/// - `indices_out` must be a valid pointer to store the indices array pointer
/// - `hardened_out` must be a valid pointer to store the hardened flags array pointer
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError
/// - The returned arrays must be freed with `derivation_path_free`
#[no_mangle]
pub unsafe extern "C" fn derivation_path_parse(
    path: *const c_char,
    indices_out: *mut *mut u32,
    hardened_out: *mut *mut bool,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let path = deref_ptr!(path, error);
    check_ptr!(indices_out, error);
    check_ptr!(hardened_out, error);
    check_ptr!(count_out, error);
    let path_str = unwrap_or_return!(CStr::from_ptr(path).to_str(), error);
    let derivation_path = unwrap_or_return!(DerivationPath::from_str(path_str), error);

    let children: Vec<_> = derivation_path.into_iter().collect();
    let count = children.len();

    let mut indices = Vec::with_capacity(count);
    let mut hardened = Vec::with_capacity(count);

    for child in children {
        let (index, is_hardened) = match child {
            key_wallet::ChildNumber::Normal {
                index,
            } => (*index, false),
            key_wallet::ChildNumber::Hardened {
                index,
            } => (*index, true),
            _ => {
                (*error).set(
                    FFIErrorCode::InvalidDerivationPath,
                    "Unsupported ChildNumber variant encountered",
                );
                return false;
            }
        };
        indices.push(index);
        hardened.push(is_hardened);
    }

    unsafe {
        *count_out = count;
        if count > 0 {
            *indices_out = Box::into_raw(indices.into_boxed_slice()) as *mut u32;
            *hardened_out = Box::into_raw(hardened.into_boxed_slice()) as *mut bool;
        } else {
            *indices_out = ptr::null_mut();
            *hardened_out = ptr::null_mut();
        }
    }
    true
}

/// Free derivation path arrays
/// Note: This function expects the count to properly free the slices
///
/// # Safety
///
/// - `indices` must be a valid pointer created by `derivation_path_parse` or null
/// - `hardened` must be a valid pointer created by `derivation_path_parse` or null
/// - `count` must match the count from `derivation_path_parse`
/// - After calling this function, the pointers become invalid
#[no_mangle]
pub unsafe extern "C" fn derivation_path_free(
    indices: *mut u32,
    hardened: *mut bool,
    count: usize,
) {
    if !indices.is_null() && count > 0 {
        unsafe {
            // Reconstruct the boxed slice from the raw pointer and let it drop
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(indices, count));
        }
    }
    if !hardened.is_null() && count > 0 {
        unsafe {
            // Reconstruct the boxed slice from the raw pointer and let it drop
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(hardened, count));
        }
    }
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
