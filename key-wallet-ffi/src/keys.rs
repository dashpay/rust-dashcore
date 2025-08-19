//! Key derivation and management

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};

/// Get extended private key for account
#[no_mangle]
pub extern "C" fn wallet_get_account_xpriv(
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
#[no_mangle]
pub extern "C" fn wallet_get_account_xpub(
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

/// Derive private key for address
#[no_mangle]
pub extern "C" fn wallet_derive_private_key(
    wallet: *const FFIWallet,
    network: FFINetwork,
    derivation_path: *const c_char,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() || derivation_path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let _path_str = unsafe {
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

    unsafe {
        let _wallet = &*wallet;
        let _network_rust: key_wallet::Network = network.into();

        // Note: Direct key derivation not exposed in key_wallet
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Direct key derivation not yet implemented".to_string(),
        );
        ptr::null_mut()
    }
}

/// Derive public key for address
#[no_mangle]
pub extern "C" fn wallet_derive_public_key(
    wallet: *const FFIWallet,
    network: FFINetwork,
    derivation_path: *const c_char,
    key_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || derivation_path.is_null() || key_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
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
                return false;
            }
        }
    };

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Parse the derivation path to determine account and indices
        // Expected format: m/44'/5'/account'/change/index
        let parts: Vec<&str> = path_str.trim_start_matches("m/").split('/').collect();
        if parts.len() < 5 {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidDerivationPath,
                "Invalid BIP44 path format".to_string(),
            );
            return false;
        }

        // Extract account index from path (third component, remove ')
        let account_str = parts[2].trim_end_matches('\'');
        let account_index: u32 = match account_str.parse() {
            Ok(idx) => idx,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidDerivationPath,
                    "Invalid account index in path".to_string(),
                );
                return false;
            }
        };

        // Extract change index (0 for receive, 1 for change)
        let change_index: u32 = match parts[3].parse() {
            Ok(idx) => idx,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidDerivationPath,
                    "Invalid change index in path".to_string(),
                );
                return false;
            }
        };

        // Extract address index
        let address_index: u32 = match parts[4].parse() {
            Ok(idx) => idx,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidDerivationPath,
                    "Invalid address index in path".to_string(),
                );
                return false;
            }
        };

        match wallet.inner().get_bip44_account(network_rust, account_index) {
            Some(account) => {
                use key_wallet::ChildNumber;
                use secp256k1::Secp256k1;
                let secp = Secp256k1::new();

                let child_change = match ChildNumber::from_normal_idx(change_index) {
                    Ok(c) => c,
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to create child number: {}", e),
                        );
                        return false;
                    }
                };

                let child_index = match ChildNumber::from_normal_idx(address_index) {
                    Ok(c) => c,
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to create child number: {}", e),
                        );
                        return false;
                    }
                };

                match account.account_xpub.derive_pub(&secp, &[child_change, child_index]) {
                    Ok(derived_key) => {
                        let public_key_bytes = derived_key.public_key.serialize();
                        ptr::copy_nonoverlapping(public_key_bytes.as_ptr(), key_out, 33);

                        FFIError::set_success(error);
                        true
                    }
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to derive public key: {}", e),
                        );
                        false
                    }
                }
            }
            None => {
                FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
                false
            }
        }
    }
}

/// Convert derivation path string to indices
#[no_mangle]
pub extern "C" fn derivation_path_parse(
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
            _ => (0u32, false), // Not supported
        };
        indices.push(index);
        hardened.push(is_hardened);
    }

    unsafe {
        *count_out = count;
        *indices_out = Box::into_raw(indices.into_boxed_slice()) as *mut u32;
        *hardened_out = Box::into_raw(hardened.into_boxed_slice()) as *mut bool;
    }

    FFIError::set_success(error);
    true
}

/// Free derivation path arrays
#[no_mangle]
pub extern "C" fn derivation_path_free(indices: *mut u32, hardened: *mut bool) {
    if !indices.is_null() {
        unsafe {
            let _ = Box::from_raw(indices);
        }
    }
    if !hardened.is_null() {
        unsafe {
            let _ = Box::from_raw(hardened);
        }
    }
}
