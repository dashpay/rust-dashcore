//! Wallet creation and management

#[cfg(test)]
#[path = "wallet_tests.rs"]
mod tests;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::{Mnemonic, Network, Seed, Wallet};

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetworks, FFIWallet, FFIWalletAccountCreationOptions};

/// Create a new wallet from mnemonic with options
///
/// # Safety
///
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `passphrase` must be a valid pointer to a null-terminated C string or null
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned pointer must be freed with `wallet_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn wallet_create_from_mnemonic_with_options(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    networks: FFINetworks,
    account_options: *const FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> *mut FFIWallet {
    if mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Mnemonic is null".to_string());
        return ptr::null_mut();
    }

    let mnemonic_str = unsafe {
        match CStr::from_ptr(mnemonic).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in mnemonic".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    let passphrase_str = if passphrase.is_null() {
        ""
    } else {
        unsafe {
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
        }
    };

    use key_wallet::mnemonic::Language;
    let mnemonic = match Mnemonic::from_phrase(mnemonic_str, Language::English) {
        Ok(m) => m,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidMnemonic,
                format!("Invalid mnemonic: {}", e),
            );
            return ptr::null_mut();
        }
    };

    // Convert networks bit flags to vector
    let networks_rust = networks.parse_networks();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        WalletAccountCreationOptions::Default
    } else {
        unsafe { (*account_options).to_wallet_options() }
    };

    let wallet = if passphrase_str.is_empty() {
        match Wallet::from_mnemonic(mnemonic, &networks_rust, creation_options) {
            Ok(w) => w,
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to create wallet: {}", e),
                );
                return ptr::null_mut();
            }
        }
    } else {
        // For wallets with passphrase, we need to handle account creation differently
        // First create the wallet without accounts
        match Wallet::from_mnemonic_with_passphrase(
            mnemonic,
            passphrase_str.to_string(),
            &networks_rust,
            creation_options,
        ) {
            Ok(w) => w,
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to create wallet with passphrase: {}", e),
                );
                return ptr::null_mut();
            }
        }
    };

    FFIError::set_success(error);
    Box::into_raw(Box::new(FFIWallet::new(wallet)))
}

/// Create a new wallet from mnemonic (backward compatibility - single network)
///
/// # Safety
///
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `passphrase` must be a valid pointer to a null-terminated C string or null
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned pointer must be freed with `wallet_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn wallet_create_from_mnemonic(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetworks,
    error: *mut FFIError,
) -> *mut FFIWallet {
    wallet_create_from_mnemonic_with_options(
        mnemonic,
        passphrase,
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Create a new wallet from seed with options
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_create_from_seed_with_options(
    seed: *const u8,
    seed_len: usize,
    networks: FFINetworks,
    account_options: *const FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> *mut FFIWallet {
    if seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed is null".to_string());
        return ptr::null_mut();
    }

    if seed_len != 64 {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Invalid seed length: {}, expected 64", seed_len),
        );
        return ptr::null_mut();
    }

    let seed_bytes = slice::from_raw_parts(seed, seed_len);
    let mut seed_array = [0u8; 64];
    seed_array.copy_from_slice(seed_bytes);
    let seed = Seed::new(seed_array);

    // Convert networks bit flags to vector
    let networks_rust = networks.parse_networks();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        WalletAccountCreationOptions::Default
    } else {
        (*account_options).to_wallet_options()
    };

    match Wallet::from_seed(seed, &networks_rust, creation_options) {
        Ok(wallet) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIWallet::new(wallet)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create wallet from seed: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Create a new wallet from seed (backward compatibility)
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_create_from_seed(
    seed: *const u8,
    seed_len: usize,
    network: FFINetworks,
    error: *mut FFIError,
) -> *mut FFIWallet {
    wallet_create_from_seed_with_options(
        seed,
        seed_len,
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Create a new random wallet with options
///
/// # Safety
///
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_create_random_with_options(
    networks: FFINetworks,
    account_options: *const FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> *mut FFIWallet {
    // Convert networks bit flags to vector
    let networks_rust = networks.parse_networks();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        WalletAccountCreationOptions::Default
    } else {
        (*account_options).to_wallet_options()
    };

    match Wallet::new_random(&networks_rust, creation_options) {
        Ok(wallet) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIWallet::new(wallet)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create random wallet: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Create a new random wallet (backward compatibility)
///
/// # Safety
///
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure the pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_create_random(
    network: FFINetworks,
    error: *mut FFIError,
) -> *mut FFIWallet {
    wallet_create_random_with_options(
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Get wallet ID (32-byte hash)
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `id_out` must be a valid pointer to a 32-byte buffer
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_get_id(
    wallet: *const FFIWallet,
    id_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || id_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let wallet = &*wallet;
    let wallet_id = wallet.inner().wallet_id;

    std::ptr::copy_nonoverlapping(wallet_id.as_ptr(), id_out, 32);
    FFIError::set_success(error);
    true
}

/// Check if wallet has mnemonic
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_has_mnemonic(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return false;
    }

    unsafe {
        let wallet = &*wallet;
        FFIError::set_success(error);
        wallet.inner().has_mnemonic()
    }
}

/// Check if wallet is watch-only
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_is_watch_only(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return false;
    }

    unsafe {
        let wallet = &*wallet;
        FFIError::set_success(error);
        wallet.inner().is_watch_only()
    }
}

/// Get extended public key for account
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned C string must be freed by the caller when no longer needed
#[no_mangle]
pub unsafe extern "C" fn wallet_get_xpub(
    wallet: *const FFIWallet,
    network: FFINetworks,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let wallet = &*wallet;

        use std::convert::TryInto;
        // Try to convert to a single network
        let network_rust: Network = match network.try_into() {
            Ok(n) => n,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Must specify exactly one network for getting xpub".to_string(),
                );
                return ptr::null_mut();
            }
        };

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

/// Free a wallet
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet that was created by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per wallet
#[no_mangle]
pub unsafe extern "C" fn wallet_free(wallet: *mut FFIWallet) {
    if !wallet.is_null() {
        unsafe {
            let _ = Box::from_raw(wallet);
        }
    }
}

/// Free a const wallet handle
///
/// This is a const-safe wrapper for wallet_free() that accepts a const pointer.
/// Use this function when you have a *const FFIWallet that needs to be freed,
/// such as wallets returned from wallet_manager_get_wallet().
///
/// # Safety
///
/// - `wallet` must be a valid pointer created by wallet creation functions or null
/// - After calling this function, the pointer becomes invalid
/// - This function must only be called once per wallet
/// - The wallet must have been allocated by this library (not stack or static memory)
#[no_mangle]
pub unsafe extern "C" fn wallet_free_const(wallet: *const FFIWallet) {
    if !wallet.is_null() {
        unsafe {
            // Cast away const and free - this is safe because we know the wallet
            // was originally allocated as mutable memory by Box::into_raw
            let _ = Box::from_raw(wallet as *mut FFIWallet);
        }
    }
}

/// Add an account to the wallet without xpub
///
/// # Safety
///
/// This function dereferences a raw pointer to FFIWallet.
/// The caller must ensure that:
/// - The wallet pointer is either null or points to a valid FFIWallet
/// - The FFIWallet remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_add_account(
    wallet: *mut FFIWallet,
    network: FFINetworks,
    account_type: crate::types::FFIAccountType,
    account_index: c_uint,
) -> crate::types::FFIAccountResult {
    if wallet.is_null() {
        return crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Wallet is null".to_string(),
        );
    }

    let wallet = &mut *wallet;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
        }
    };

    let account_type_rust = account_type.to_account_type(account_index);

    match wallet.inner_mut() {
        Some(w) => {
            // Use the proper add_account method
            match w.add_account(account_type_rust, network_rust, None) {
                Ok(()) => {
                    // Get the account we just added
                    if let Some(account_collection) = w.accounts.get(&network_rust) {
                        if let Some(account) = account_collection.account_of_type(account_type_rust)
                        {
                            let ffi_account = crate::types::FFIAccount::new(account);
                            return crate::types::FFIAccountResult::success(Box::into_raw(
                                Box::new(ffi_account),
                            ));
                        }
                    }
                    crate::types::FFIAccountResult::error(
                        FFIErrorCode::WalletError,
                        "Failed to retrieve account after adding".to_string(),
                    )
                }
                Err(e) => crate::types::FFIAccountResult::error(
                    FFIErrorCode::WalletError,
                    format!("Failed to add account: {}", e),
                ),
            }
        }
        None => crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidState,
            "Cannot modify wallet".to_string(),
        ),
    }
}

/// Add an account to the wallet with xpub as byte array
///
/// # Safety
///
/// This function dereferences raw pointers.
/// The caller must ensure that:
/// - The wallet pointer is either null or points to a valid FFIWallet
/// - The xpub_bytes pointer is either null or points to at least xpub_len bytes
/// - The FFIWallet remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_add_account_with_xpub_bytes(
    wallet: *mut FFIWallet,
    network: FFINetworks,
    account_type: crate::types::FFIAccountType,
    account_index: c_uint,
    xpub_bytes: *const u8,
    xpub_len: usize,
) -> crate::types::FFIAccountResult {
    if wallet.is_null() {
        return crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Wallet is null".to_string(),
        );
    }

    if xpub_bytes.is_null() {
        return crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Xpub bytes are null".to_string(),
        );
    }

    let wallet = &mut *wallet;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
        }
    };

    use key_wallet::ExtendedPubKey;

    let account_type_rust = account_type.to_account_type(account_index);

    // Parse the xpub from bytes (assuming it's a string representation)
    let xpub_slice = slice::from_raw_parts(xpub_bytes, xpub_len);
    let xpub_str = match std::str::from_utf8(xpub_slice) {
        Ok(s) => s,
        Err(_) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Invalid UTF-8 in xpub bytes".to_string(),
            );
        }
    };

    let xpub = match xpub_str.parse::<ExtendedPubKey>() {
        Ok(xpub) => xpub,
        Err(e) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                format!("Invalid extended public key: {}", e),
            );
        }
    };

    match wallet.inner_mut() {
        Some(w) => match w.add_account(account_type_rust, network_rust, Some(xpub)) {
            Ok(()) => {
                // Get the account we just added
                if let Some(account_collection) = w.accounts.get(&network_rust) {
                    if let Some(account) = account_collection.account_of_type(account_type_rust) {
                        let ffi_account = crate::types::FFIAccount::new(account);
                        return crate::types::FFIAccountResult::success(Box::into_raw(Box::new(
                            ffi_account,
                        )));
                    }
                }
                crate::types::FFIAccountResult::error(
                    FFIErrorCode::WalletError,
                    "Failed to retrieve account after adding".to_string(),
                )
            }
            Err(e) => crate::types::FFIAccountResult::error(
                FFIErrorCode::WalletError,
                format!("Failed to add account with xpub: {}", e),
            ),
        },
        None => crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidState,
            "Cannot modify wallet".to_string(),
        ),
    }
}

/// Add an account to the wallet with xpub as string
///
/// # Safety
///
/// This function dereferences raw pointers.
/// The caller must ensure that:
/// - The wallet pointer is either null or points to a valid FFIWallet
/// - The xpub_string pointer is either null or points to a valid null-terminated C string
/// - The FFIWallet remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_add_account_with_string_xpub(
    wallet: *mut FFIWallet,
    network: FFINetworks,
    account_type: crate::types::FFIAccountType,
    account_index: c_uint,
    xpub_string: *const c_char,
) -> crate::types::FFIAccountResult {
    if wallet.is_null() {
        return crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Wallet is null".to_string(),
        );
    }

    if xpub_string.is_null() {
        return crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Xpub string is null".to_string(),
        );
    }

    let wallet = &mut *wallet;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
        }
    };

    use key_wallet::ExtendedPubKey;

    let account_type_rust = account_type.to_account_type(account_index);

    // Parse the xpub from C string
    let xpub_str = match CStr::from_ptr(xpub_string).to_str() {
        Ok(s) => s,
        Err(_) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Invalid UTF-8 in xpub string".to_string(),
            );
        }
    };

    let xpub = match xpub_str.parse::<ExtendedPubKey>() {
        Ok(xpub) => xpub,
        Err(e) => {
            return crate::types::FFIAccountResult::error(
                FFIErrorCode::InvalidInput,
                format!("Invalid extended public key: {}", e),
            );
        }
    };

    match wallet.inner_mut() {
        Some(w) => match w.add_account(account_type_rust, network_rust, Some(xpub)) {
            Ok(()) => {
                // Get the account we just added
                if let Some(account_collection) = w.accounts.get(&network_rust) {
                    if let Some(account) = account_collection.account_of_type(account_type_rust) {
                        let ffi_account = crate::types::FFIAccount::new(account);
                        return crate::types::FFIAccountResult::success(Box::into_raw(Box::new(
                            ffi_account,
                        )));
                    }
                }
                crate::types::FFIAccountResult::error(
                    FFIErrorCode::WalletError,
                    "Failed to retrieve account after adding".to_string(),
                )
            }
            Err(e) => crate::types::FFIAccountResult::error(
                FFIErrorCode::WalletError,
                format!("Failed to add account with xpub: {}", e),
            ),
        },
        None => crate::types::FFIAccountResult::error(
            FFIErrorCode::InvalidState,
            "Cannot modify wallet".to_string(),
        ),
    }
}
