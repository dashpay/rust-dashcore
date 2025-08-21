//! Key derivation and management

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;

/// Opaque type for a private key (SecretKey)
pub struct FFIPrivateKey {
    inner: secp256k1::SecretKey,
}

/// Opaque type for an extended private key
pub struct FFIExtendedPrivateKey {
    inner: key_wallet::bip32::ExtendedPrivKey,
}

/// Opaque type for a public key
pub struct FFIPublicKey {
    inner: secp256k1::PublicKey,
}

/// Opaque type for an extended public key
pub struct FFIExtendedPublicKey {
    inner: key_wallet::bip32::ExtendedPubKey,
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
    network: FFINetwork,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        match wallet.inner().get_bip44_account(network_rust, account_index) {
            Some(account) => {
                // Extended private key is not available on Account
                // Only the wallet has access to private keys
                if account.is_watch_only {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::NotFound,
                        "Private key not available (watch-only wallet)".to_string(),
                    );
                    ptr::null_mut()
                } else {
                    // Private key extraction not implemented for security reasons
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        "Private key extraction not implemented".to_string(),
                    );
                    ptr::null_mut()
                }
            }
            None => {
                FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
                ptr::null_mut()
            }
        }
    }
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
    network: FFINetwork,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        match wallet.inner().get_bip44_account(network_rust, account_index) {
            Some(account) => {
                let xpub = account.extended_public_key();
                FFIError::set_success(error);
                match CString::new(xpub.to_string()) {
                    Ok(c_str) => c_str.into_raw(),
                    Err(_) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::AllocationFailed,
                            "Failed to allocate string".to_string(),
                        );
                        ptr::null_mut()
                    }
                }
            }
            None => {
                FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
                ptr::null_mut()
            }
        }
    }
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
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(derivation_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in derivation path".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    // Parse the derivation path
    use key_wallet::DerivationPath;
    use std::str::FromStr;
    let path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid derivation path: {}", e),
            );
            return ptr::null_mut();
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Use the new wallet method to derive the private key
        match wallet.inner().derive_private_key(network_rust, &path) {
            Ok(private_key) => {
                FFIError::set_success(error);
                Box::into_raw(Box::new(FFIPrivateKey {
                    inner: private_key,
                }))
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
}

/// Derive extended private key at a specific path
/// Returns an opaque FFIExtendedPrivateKey pointer that must be freed with extended_private_key_free
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
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivateKey {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(derivation_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in derivation path".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    // Parse the derivation path
    use key_wallet::DerivationPath;
    use std::str::FromStr;
    let path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid derivation path: {}", e),
            );
            return ptr::null_mut();
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Use the new wallet method to derive the extended private key
        match wallet.inner().derive_extended_private_key(network_rust, &path) {
            Ok(extended_private_key) => {
                FFIError::set_success(error);
                Box::into_raw(Box::new(FFIExtendedPrivateKey {
                    inner: extended_private_key,
                }))
            }
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to derive extended private key: {:?}", e),
                );
                ptr::null_mut()
            }
        }
    }
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
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(derivation_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in derivation path".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    // Parse the derivation path
    use key_wallet::DerivationPath;
    use std::str::FromStr;
    let path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid derivation path: {}", e),
            );
            return ptr::null_mut();
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Use the new wallet method to derive the private key as WIF
        match wallet.inner().derive_private_key_as_wif(network_rust, &path) {
            Ok(wif) => {
                FFIError::set_success(error);
                match CString::new(wif) {
                    Ok(c_str) => c_str.into_raw(),
                    Err(_) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::AllocationFailed,
                            "Failed to allocate string".to_string(),
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
        unsafe {
            let _ = Box::from_raw(key);
        }
    }
}

/// Free an extended private key
///
/// # Safety
///
/// - `key` must be a valid pointer created by extended private key functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn extended_private_key_free(key: *mut FFIExtendedPrivateKey) {
    if !key.is_null() {
        unsafe {
            let _ = Box::from_raw(key);
        }
    }
}

/// Get extended private key as string (xprv format)
///
/// Returns the extended private key in base58 format (xprv... for mainnet, tprv... for testnet)
///
/// # Safety
///
/// - `key` must be a valid pointer to an FFIExtendedPrivateKey
/// - `network` specifies the network for the key encoding
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn extended_private_key_to_string(
    key: *const FFIExtendedPrivateKey,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut c_char {
    if key.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended private key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let key = &*key;
        let _ = network; // Network is already encoded in the extended key

        // Convert to string - the network is already encoded in the extended key
        let key_string = key.inner.to_string();

        FFIError::set_success(error);
        match CString::new(key_string) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::AllocationFailed,
                    "Failed to allocate string".to_string(),
                );
                ptr::null_mut()
            }
        }
    }
}

/// Get the private key from an extended private key
///
/// Extracts the non-extended private key from an extended private key.
///
/// # Safety
///
/// - `extended_key` must be a valid pointer to an FFIExtendedPrivateKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned FFIPrivateKey must be freed with `private_key_free`
#[no_mangle]
pub unsafe extern "C" fn extended_private_key_get_private_key(
    extended_key: *const FFIExtendedPrivateKey,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    if extended_key.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended private key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let extended = &*extended_key;

        // Extract the private key
        let private_key = FFIPrivateKey {
            inner: extended.inner.private_key,
        };

        FFIError::set_success(error);
        Box::into_raw(Box::new(private_key))
    }
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
    if key.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Private key is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let key = &*key;
        let network_rust: key_wallet::Network = network.into();

        // Convert to WIF format
        use dashcore::PrivateKey as DashPrivateKey;
        let dash_key = DashPrivateKey {
            compressed: true,
            network: network_rust,
            inner: key.inner,
        };

        let wif = dash_key.to_wif();
        FFIError::set_success(error);
        match CString::new(wif) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::AllocationFailed,
                    "Failed to allocate string".to_string(),
                );
                ptr::null_mut()
            }
        }
    }
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
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIPublicKey {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(derivation_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in derivation path".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    // Parse the derivation path
    use key_wallet::DerivationPath;
    use std::str::FromStr;
    let path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid derivation path: {}", e),
            );
            return ptr::null_mut();
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Use the new wallet method to derive the public key
        match wallet.inner().derive_public_key(network_rust, &path) {
            Ok(public_key) => {
                FFIError::set_success(error);
                Box::into_raw(Box::new(FFIPublicKey {
                    inner: public_key,
                }))
            }
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to derive public key: {:?}", e),
                );
                ptr::null_mut()
            }
        }
    }
}

/// Derive extended public key at a specific path
/// Returns an opaque FFIExtendedPublicKey pointer that must be freed with extended_public_key_free
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
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut FFIExtendedPublicKey {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(derivation_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in derivation path".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    // Parse the derivation path
    use key_wallet::DerivationPath;
    use std::str::FromStr;
    let path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid derivation path: {}", e),
            );
            return ptr::null_mut();
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Use the new wallet method to derive the extended public key
        match wallet.inner().derive_extended_public_key(network_rust, &path) {
            Ok(extended_public_key) => {
                FFIError::set_success(error);
                Box::into_raw(Box::new(FFIExtendedPublicKey {
                    inner: extended_public_key,
                }))
            }
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to derive extended public key: {:?}", e),
                );
                ptr::null_mut()
            }
        }
    }
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
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(derivation_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in derivation path".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    // Parse the derivation path
    use key_wallet::DerivationPath;
    use std::str::FromStr;
    let path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid derivation path: {}", e),
            );
            return ptr::null_mut();
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Use the new wallet method to derive the public key as hex
        match wallet.inner().derive_public_key_as_hex(network_rust, &path) {
            Ok(hex) => {
                FFIError::set_success(error);
                match CString::new(hex) {
                    Ok(c_str) => c_str.into_raw(),
                    Err(_) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::AllocationFailed,
                            "Failed to allocate string".to_string(),
                        );
                        ptr::null_mut()
                    }
                }
            }
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to derive public key: {:?}", e),
                );
                ptr::null_mut()
            }
        }
    }
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
pub unsafe extern "C" fn extended_public_key_free(key: *mut FFIExtendedPublicKey) {
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
/// - `key` must be a valid pointer to an FFIExtendedPublicKey
/// - `network` specifies the network for the key encoding
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn extended_public_key_to_string(
    key: *const FFIExtendedPublicKey,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut c_char {
    if key.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended public key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let key = &*key;
        let _ = network; // Network is already encoded in the extended key

        // Convert to string - the network is already encoded in the extended key
        let key_string = key.inner.to_string();

        FFIError::set_success(error);
        match CString::new(key_string) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::AllocationFailed,
                    "Failed to allocate string".to_string(),
                );
                ptr::null_mut()
            }
        }
    }
}

/// Get the public key from an extended public key
///
/// Extracts the non-extended public key from an extended public key.
///
/// # Safety
///
/// - `extended_key` must be a valid pointer to an FFIExtendedPublicKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned FFIPublicKey must be freed with `public_key_free`
#[no_mangle]
pub unsafe extern "C" fn extended_public_key_get_public_key(
    extended_key: *const FFIExtendedPublicKey,
    error: *mut FFIError,
) -> *mut FFIPublicKey {
    if extended_key.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended public key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let extended = &*extended_key;

        // Extract the public key
        let public_key = FFIPublicKey {
            inner: extended.inner.public_key,
        };

        FFIError::set_success(error);
        Box::into_raw(Box::new(public_key))
    }
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
    if key.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Public key is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let key = &*key;
        let bytes = key.inner.serialize();
        let hex = hex::encode(bytes);

        FFIError::set_success(error);
        match CString::new(hex) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::AllocationFailed,
                    "Failed to allocate string".to_string(),
                );
                ptr::null_mut()
            }
        }
    }
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
    if path.is_null() || indices_out.is_null() || hardened_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in path".to_string(),
                );
                return false;
            }
        }
    };

    use key_wallet::DerivationPath;
    use std::str::FromStr;

    let derivation_path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidDerivationPath,
                format!("Invalid derivation path: {}", e),
            );
            return false;
        }
    };

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
                // Fail fast for unsupported ChildNumber variants
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidDerivationPath,
                    "Unsupported ChildNumber variant encountered".to_string(),
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
            // For empty paths, set to null
            *indices_out = ptr::null_mut();
            *hardened_out = ptr::null_mut();
        }
    }

    FFIError::set_success(error);
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
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(indices, count));
        }
    }
    if !hardened.is_null() && count > 0 {
        unsafe {
            // Reconstruct the boxed slice from the raw pointer and let it drop
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(hardened, count));
        }
    }
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
