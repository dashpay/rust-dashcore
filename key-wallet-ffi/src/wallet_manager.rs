//! FFI bindings for WalletManager from key-wallet-manager crate

#[cfg(test)]
#[path = "wallet_manager_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "wallet_manager_serialization_tests.rs"]
mod serialization_tests;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::sync::Mutex;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFINetwork;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Network;
use key_wallet_manager::wallet_manager::{WalletId, WalletManager};

/// FFI wrapper for WalletManager
pub struct FFIWalletManager {
    manager: Mutex<WalletManager<ManagedWalletInfo>>,
    // Track wallet IDs for FFI purposes
    wallet_ids: Mutex<Vec<WalletId>>,
}

/// Create a new wallet manager
#[no_mangle]
pub extern "C" fn wallet_manager_create(error: *mut FFIError) -> *mut FFIWalletManager {
    let manager = WalletManager::new();
    FFIError::set_success(error);
    Box::into_raw(Box::new(FFIWalletManager {
        manager: Mutex::new(manager),
        wallet_ids: Mutex::new(Vec::new()),
    }))
}

/// Add a wallet from mnemonic to the manager with options
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `passphrase` must be a valid pointer to a null-terminated C string or null
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_add_wallet_from_mnemonic_with_options(
    manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    account_options: *const crate::types::FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() || mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
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
                return false;
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
                    return false;
                }
            }
        }
    };

    let network_rust: Network = match network.try_into() {
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

    unsafe {
        let manager_ref = &*manager;
        let mut manager_guard = match manager_ref.manager.lock() {
            Ok(g) => g,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    "Failed to lock manager".to_string(),
                );
                return false;
            }
        };

        // Convert account creation options
        let creation_options = if account_options.is_null() {
            key_wallet::wallet::initialization::WalletAccountCreationOptions::Default
        } else {
            (*account_options).to_wallet_options()
        };

        // Use the WalletManager's public method to create the wallet
        match manager_guard.create_wallet_from_mnemonic(
            mnemonic_str,
            passphrase_str,
            network_rust,
            None, // birth_height
            creation_options,
        ) {
            Ok(wallet_id) => {
                // Track the wallet ID
                let mut ids_guard = match manager_ref.wallet_ids.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            "Failed to lock wallet IDs".to_string(),
                        );
                        return false;
                    }
                };
                ids_guard.push(wallet_id);

                FFIError::set_success(error);
                true
            }
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to create wallet: {:?}", e),
                );
                false
            }
        }
    }
}

/// Add a wallet from mnemonic to the manager (backward compatibility)
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `passphrase` must be a valid pointer to a null-terminated C string or null
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_add_wallet_from_mnemonic(
    manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> bool {
    wallet_manager_add_wallet_from_mnemonic_with_options(
        manager,
        mnemonic,
        passphrase,
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Add a wallet from mnemonic to the manager and return serialized bytes
///
/// Creates a wallet from a mnemonic phrase, adds it to the manager, optionally downgrading it
/// to a pubkey-only wallet (watch-only or externally signable), and returns the serialized wallet bytes.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `passphrase` must be a valid pointer to a null-terminated C string or null
/// - `birth_height` is optional, pass 0 for default
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `downgrade_to_pubkey_wallet` if true, creates a watch-only or externally signable wallet
/// - `allow_external_signing` if true AND downgrade_to_pubkey_wallet is true, creates an externally signable wallet
/// - `wallet_bytes_out` must be a valid pointer to a pointer that will receive the serialized bytes
/// - `wallet_bytes_len_out` must be a valid pointer that will receive the byte length
/// - `wallet_id_out` must be a valid pointer to a 32-byte array that will receive the wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The caller must free the returned wallet_bytes using wallet_manager_free_wallet_bytes()
#[cfg(feature = "bincode")]
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
    manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    birth_height: c_uint,
    account_options: *const crate::types::FFIWalletAccountCreationOptions,
    downgrade_to_pubkey_wallet: bool,
    allow_external_signing: bool,
    wallet_bytes_out: *mut *mut u8,
    wallet_bytes_len_out: *mut usize,
    wallet_id_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    // Validate input parameters
    if manager.is_null()
        || mnemonic.is_null()
        || wallet_bytes_out.is_null()
        || wallet_bytes_len_out.is_null()
        || wallet_id_out.is_null()
    {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    // Parse mnemonic string
    let mnemonic_str = unsafe {
        match CStr::from_ptr(mnemonic).to_str() {
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

    // Parse passphrase string
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
                    return false;
                }
            }
        }
    };

    // Convert networks
    let networks = network.parse_networks();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        key_wallet::wallet::initialization::WalletAccountCreationOptions::Default
    } else {
        unsafe { (*account_options).to_wallet_options() }
    };

    // Get the manager and call the proper method
    let manager_ref = unsafe { &*manager };
    let mut manager_guard = match manager_ref.manager.lock() {
        Ok(guard) => guard,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Failed to lock manager".to_string(),
            );
            return false;
        }
    };

    // Convert birth_height: 0 means None, any other value means Some(value)
    let birth_height = if birth_height == 0 {
        None
    } else {
        Some(birth_height)
    };

    let (serialized, wallet_id) = match manager_guard
        .create_wallet_from_mnemonic_return_serialized_bytes(
            mnemonic_str,
            passphrase_str,
            &networks,
            birth_height,
            creation_options,
            downgrade_to_pubkey_wallet,
            allow_external_signing,
        ) {
        Ok(result) => result,
        Err(e) => {
            let ffi_error: FFIError = e.into();
            if !error.is_null() {
                unsafe {
                    *error = ffi_error;
                }
            }
            return false;
        }
    };

    // Track the wallet ID in the FFI manager
    if let Ok(mut wallet_ids) = manager_ref.wallet_ids.lock() {
        wallet_ids.push(wallet_id);
    }

    // Allocate memory for the serialized bytes
    let boxed_bytes = serialized.into_boxed_slice();
    let bytes_len = boxed_bytes.len();
    let bytes_ptr = Box::into_raw(boxed_bytes) as *mut u8;

    // Write output values
    unsafe {
        *wallet_bytes_out = bytes_ptr;
        *wallet_bytes_len_out = bytes_len;
        ptr::copy_nonoverlapping(wallet_id.as_ptr(), wallet_id_out, 32);
    }

    FFIError::set_success(error);
    true
}

/// Free wallet bytes buffer
///
/// # Safety
///
/// - `wallet_bytes` must be a valid pointer to a buffer allocated by wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes
/// - `bytes_len` must match the original allocation size
/// - The pointer must not be used after calling this function
/// - This function must only be called once per buffer
#[cfg(feature = "bincode")]
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_wallet_bytes(wallet_bytes: *mut u8, bytes_len: usize) {
    if !wallet_bytes.is_null() && bytes_len > 0 {
        unsafe {
            // Reconstruct the boxed slice with the correct DST pointer
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(wallet_bytes, bytes_len));
        }
    }
}

/// Import a wallet from bincode-serialized bytes
///
/// Deserializes a wallet from bytes and adds it to the manager.
/// Returns a 32-byte wallet ID on success.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_bytes` must be a valid pointer to bincode-serialized wallet bytes
/// - `wallet_bytes_len` must be the exact length of the wallet bytes
/// - `wallet_id_out` must be a valid pointer to a 32-byte array that will receive the wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[cfg(feature = "bincode")]
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_import_wallet_from_bytes(
    manager: *mut FFIWalletManager,
    wallet_bytes: *const u8,
    wallet_bytes_len: usize,
    wallet_id_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    // Validate input parameters
    if manager.is_null()
        || wallet_bytes.is_null()
        || wallet_bytes_len == 0
        || wallet_id_out.is_null()
    {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Null pointer or invalid length provided".to_string(),
        );
        return false;
    }

    // Create a byte slice from the raw pointer
    let wallet_bytes_slice = unsafe { std::slice::from_raw_parts(wallet_bytes, wallet_bytes_len) };

    // Get the manager reference
    let manager_ref = unsafe { &*manager };

    // Lock the manager
    let mut manager_guard = match manager_ref.manager.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock wallet manager".to_string(),
            );
            return false;
        }
    };

    // Import the wallet
    match manager_guard.import_wallet_from_bytes(wallet_bytes_slice) {
        Ok(wallet_id) => {
            // Copy the wallet ID to the output buffer
            unsafe {
                ptr::copy_nonoverlapping(wallet_id.as_ptr(), wallet_id_out, 32);
            }

            // Track the wallet ID in our FFI manager
            let mut ids_guard = match manager_ref.wallet_ids.lock() {
                Ok(g) => g,
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        "Failed to lock wallet IDs".to_string(),
                    );
                    return false;
                }
            };
            ids_guard.push(wallet_id);

            FFIError::set_success(error);
            true
        }
        Err(e) => {
            // Convert the error to FFI error
            match e {
                key_wallet_manager::wallet_manager::WalletError::WalletExists(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidState,
                        "Wallet already exists in the manager".to_string(),
                    );
                }
                key_wallet_manager::wallet_manager::WalletError::InvalidParameter(msg) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::SerializationError,
                        format!("Failed to deserialize wallet: {}", msg),
                    );
                }
                _ => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        format!("Failed to import wallet: {:?}", e),
                    );
                }
            }
            false
        }
    }
}

/// Get wallet IDs
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `wallet_ids_out` must be a valid pointer to a pointer that will receive the wallet IDs
/// - `count_out` must be a valid pointer to receive the count
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_wallet_ids(
    manager: *const FFIWalletManager,
    wallet_ids_out: *mut *mut u8,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() || wallet_ids_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let manager_ref = &*manager;
    let ids_guard = match manager_ref.wallet_ids.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock wallet IDs".to_string(),
            );
            return false;
        }
    };

    let count = ids_guard.len();
    if count == 0 {
        *count_out = 0;
        *wallet_ids_out = ptr::null_mut();
    } else {
        // Allocate memory for wallet IDs (32 bytes each) as a boxed slice
        let mut ids_buffer = Vec::with_capacity(count * 32);
        for wallet_id in ids_guard.iter() {
            ids_buffer.extend_from_slice(wallet_id);
        }
        // Convert to boxed slice for consistent memory layout
        let boxed_slice = ids_buffer.into_boxed_slice();
        let ids_ptr = Box::into_raw(boxed_slice) as *mut u8;

        *wallet_ids_out = ids_ptr;
        *count_out = count;
    }

    FFIError::set_success(error);
    true
}

/// Get a wallet from the manager
///
/// Returns a reference to the wallet if found
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned wallet must be freed with wallet_free_const()
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_wallet(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    error: *mut FFIError,
) -> *const crate::types::FFIWallet {
    if manager.is_null() || wallet_id.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null();
    }

    // Convert wallet_id pointer to array
    let mut wallet_id_array = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);
    }

    // Get the manager
    let manager_ref = unsafe { &*manager };

    // Lock the manager and get the wallet
    let manager_guard = match manager_ref.manager.lock() {
        Ok(guard) => guard,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock wallet manager".to_string(),
            );
            return ptr::null();
        }
    };

    // Get the wallet
    match manager_guard.get_wallet(&wallet_id_array) {
        Some(wallet) => {
            // Create an FFIWallet wrapper
            // Note: We need to store this somewhere that will outlive this function
            // For now, we'll return a raw pointer to the wallet
            // In a real implementation, you might want to store these in the FFIWalletManager
            let ffi_wallet = Box::new(crate::types::FFIWallet::new(wallet.clone()));
            FFIError::set_success(error);
            Box::into_raw(ffi_wallet)
        }
        None => {
            FFIError::set_error(error, FFIErrorCode::NotFound, "Wallet not found".to_string());
            ptr::null()
        }
    }
}

/// Get managed wallet info from the manager
///
/// Returns a reference to the managed wallet info if found
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned managed wallet info must be freed with managed_wallet_info_free()
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_managed_wallet_info(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    error: *mut FFIError,
) -> *mut crate::managed_wallet::FFIManagedWalletInfo {
    if manager.is_null() || wallet_id.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    // Convert wallet_id pointer to array
    let mut wallet_id_array = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);
    }

    // Get the manager
    let manager_ref = unsafe { &*manager };

    // Lock the manager and get the wallet info
    let manager_guard = match manager_ref.manager.lock() {
        Ok(guard) => guard,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock wallet manager".to_string(),
            );
            return ptr::null_mut();
        }
    };

    // Get the wallet info
    match manager_guard.get_wallet_info(&wallet_id_array) {
        Some(wallet_info) => {
            // Create an FFIManagedWalletInfo wrapper
            let ffi_wallet_info =
                Box::new(crate::managed_wallet::FFIManagedWalletInfo::new(wallet_info.clone()));
            FFIError::set_success(error);
            Box::into_raw(ffi_wallet_info)
        }
        None => {
            FFIError::set_error(error, FFIErrorCode::NotFound, "Wallet info not found".to_string());
            ptr::null_mut()
        }
    }
}

/// Get next receive address for a wallet
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_receive_address(
    manager: *mut FFIWalletManager,
    wallet_id: *const u8,
    network: FFINetwork,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if manager.is_null() || wallet_id.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let wallet_id_slice = std::slice::from_raw_parts(wallet_id, 32);
    let mut wallet_id_array = [0u8; 32];
    wallet_id_array.copy_from_slice(wallet_id_slice);

    let manager_ref = &*manager;
    let mut manager_guard = match manager_ref.manager.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock manager".to_string(),
            );
            return ptr::null_mut();
        }
    };

    let network_rust: Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return ptr::null_mut();
        }
    };

    // Use the WalletManager's public method to get next receive address
    use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
    match manager_guard.get_receive_address(
        &wallet_id_array,
        network_rust,
        account_index,
        AccountTypePreference::BIP44,
        true, // mark_as_used
    ) {
        Ok(result) => {
            if let Some(address) = result.address {
                FFIError::set_success(error);
                match CString::new(address.to_string()) {
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
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::NotFound,
                    "Failed to generate address".to_string(),
                );
                ptr::null_mut()
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to get receive address: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Get next change address for a wallet
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_change_address(
    manager: *mut FFIWalletManager,
    wallet_id: *const u8,
    network: FFINetwork,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if manager.is_null() || wallet_id.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let wallet_id_slice = std::slice::from_raw_parts(wallet_id, 32);
    let mut wallet_id_array = [0u8; 32];
    wallet_id_array.copy_from_slice(wallet_id_slice);

    let manager_ref = &*manager;
    let mut manager_guard = match manager_ref.manager.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock manager".to_string(),
            );
            return ptr::null_mut();
        }
    };

    let network_rust: Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return ptr::null_mut();
        }
    };

    // Use the WalletManager's public method to get next change address
    use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
    match manager_guard.get_change_address(
        &wallet_id_array,
        network_rust,
        account_index,
        AccountTypePreference::BIP44,
        true, // mark_as_used
    ) {
        Ok(result) => {
            if let Some(address) = result.address {
                FFIError::set_success(error);
                match CString::new(address.to_string()) {
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
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::NotFound,
                    "Failed to generate address".to_string(),
                );
                ptr::null_mut()
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to get change address: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Get wallet balance
///
/// Returns the confirmed and unconfirmed balance for a specific wallet
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `confirmed_out` must be a valid pointer to a u64 (maps to C uint64_t)
/// - `unconfirmed_out` must be a valid pointer to a u64 (maps to C uint64_t)
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_wallet_balance(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    confirmed_out: *mut u64,
    unconfirmed_out: *mut u64,
    error: *mut FFIError,
) -> bool {
    if manager.is_null()
        || wallet_id.is_null()
        || confirmed_out.is_null()
        || unconfirmed_out.is_null()
    {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    // Convert wallet_id pointer to array
    let mut wallet_id_array = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);
    }

    // Get the manager
    let manager_ref = unsafe { &*manager };

    // Lock the manager and get the wallet balance
    let manager_guard = match manager_ref.manager.lock() {
        Ok(guard) => guard,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock wallet manager".to_string(),
            );
            return false;
        }
    };

    // Get the wallet balance
    match manager_guard.get_wallet_balance(&wallet_id_array) {
        Ok(balance) => {
            unsafe {
                *confirmed_out = balance.confirmed;
                *unconfirmed_out = balance.unconfirmed;
            }
            FFIError::set_success(error);
            true
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to get wallet balance: {}", e),
            );
            false
        }
    }
}

/// Process a transaction through all wallets
///
/// Checks a transaction against all wallets and updates their states if relevant.
/// Returns true if the transaction was relevant to at least one wallet.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `tx_bytes` must be a valid pointer to transaction bytes
/// - `tx_len` must be the length of the transaction bytes
/// - `network` is the network type
/// - `context` must be a valid pointer to FFITransactionContextDetails
/// - `update_state_if_found` indicates whether to update wallet state when transaction is relevant
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_process_transaction(
    manager: *mut FFIWalletManager,
    tx_bytes: *const u8,
    tx_len: usize,
    network: FFINetwork,
    context: *const crate::types::FFITransactionContextDetails,
    update_state_if_found: bool,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() || tx_bytes.is_null() || tx_len == 0 || context.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Null pointer or empty transaction provided".to_string(),
        );
        return false;
    }

    // Convert transaction bytes to slice
    let tx_slice = unsafe { std::slice::from_raw_parts(tx_bytes, tx_len) };

    // Deserialize the transaction
    use dashcore::blockdata::transaction::Transaction;
    use dashcore::consensus::encode::deserialize;

    let tx: Transaction = match deserialize(tx_slice) {
        Ok(tx) => tx,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Failed to deserialize transaction: {}", e),
            );
            return false;
        }
    };

    // Convert FFINetwork to Network
    let network = match network.try_into() {
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

    // Convert FFI context to native TransactionContext
    let context = unsafe { (*context).to_transaction_context() };

    // Get the manager
    let manager_ref = unsafe { &mut *manager };

    // Lock the manager and process the transaction
    let mut manager_guard = match manager_ref.manager.lock() {
        Ok(guard) => guard,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock wallet manager".to_string(),
            );
            return false;
        }
    };

    // Check the transaction against all wallets
    let relevant_wallets = manager_guard.check_transaction_in_all_wallets(
        &tx,
        network,
        context,
        update_state_if_found,
    );

    FFIError::set_success(error);
    !relevant_wallets.is_empty()
}

/// Get monitored addresses for a network
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `addresses_out` must be a valid pointer to a pointer that will receive the addresses array
/// - `count_out` must be a valid pointer to receive the count
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_monitored_addresses(
    manager: *const FFIWalletManager,
    network: FFINetwork,
    addresses_out: *mut *mut *mut c_char,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() || addresses_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let manager_ref = &*manager;
    let manager_guard = match manager_ref.manager.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock manager".to_string(),
            );
            return false;
        }
    };

    let network_rust: Network = match network.try_into() {
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
    let mut all_addresses: Vec<*mut c_char> = Vec::new();

    // Collect addresses from all wallets for this network
    for wallet in manager_guard.get_all_wallets().values() {
        if let Some(account) = wallet.get_bip44_account(network_rust, 0) {
            // Generate a few addresses from each wallet (simplified)
            use key_wallet::ChildNumber;
            use secp256k1::Secp256k1;
            let secp = Secp256k1::new();

            // Generate first 3 receive addresses
            for i in 0..3 {
                let child_external = match ChildNumber::from_normal_idx(0) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let child_index = match ChildNumber::from_normal_idx(i) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                if let Ok(derived_key) =
                    account.account_xpub.derive_pub(&secp, &[child_external, child_index])
                {
                    let public_key = derived_key.public_key;
                    let dash_pubkey = dashcore::PublicKey::new(public_key);
                    let dash_network = network_rust;
                    let address = key_wallet::Address::p2pkh(&dash_pubkey, dash_network);

                    if let Ok(c_str) = CString::new(address.to_string()) {
                        all_addresses.push(c_str.into_raw());
                    }
                }
            }
        }
    }

    if all_addresses.is_empty() {
        *count_out = 0;
        *addresses_out = ptr::null_mut();
    } else {
        *count_out = all_addresses.len();
        // Convert Vec to boxed slice for consistent memory layout
        let boxed = all_addresses.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut *mut c_char;
        *addresses_out = ptr;
    }

    FFIError::set_success(error);
    true
}

/// Update block height for a network
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_update_height(
    manager: *mut FFIWalletManager,
    network: FFINetwork,
    height: c_uint,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Manager is null".to_string());
        return false;
    }

    let manager_ref = &*manager;
    let mut manager_guard = match manager_ref.manager.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock manager".to_string(),
            );
            return false;
        }
    };

    let network_rust: Network = match network.try_into() {
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
    manager_guard.update_height(network_rust, height);

    FFIError::set_success(error);
    true
}

/// Get current height for a network
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_current_height(
    manager: *const FFIWalletManager,
    network: FFINetwork,
    error: *mut FFIError,
) -> c_uint {
    if manager.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Manager is null".to_string());
        return 0;
    }

    let manager_ref = &*manager;
    let manager_guard = match manager_ref.manager.lock() {
        Ok(g) => g,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Failed to lock manager".to_string(),
            );
            return 0;
        }
    };

    let network_rust: Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return 0;
        }
    };

    // Get current height from network state if it exists
    let height = manager_guard
        .get_network_state(network_rust)
        .map(|state| state.current_height)
        .unwrap_or(0);

    FFIError::set_success(error);
    height
}

/// Get wallet count
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_wallet_count(
    manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> usize {
    if manager.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Manager is null".to_string());
        return 0;
    }

    unsafe {
        let manager_ref = &*manager;
        let manager_guard = match manager_ref.manager.lock() {
            Ok(g) => g,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    "Failed to lock manager".to_string(),
                );
                return 0;
            }
        };

        FFIError::set_success(error);
        manager_guard.wallet_count()
    }
}

/// Free wallet manager
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager that was created by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per manager
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free(manager: *mut FFIWalletManager) {
    if !manager.is_null() {
        unsafe {
            let _ = Box::from_raw(manager);
        }
    }
}

/// Free wallet IDs buffer
///
/// # Safety
///
/// - `wallet_ids` must be a valid pointer to a buffer allocated by this library
/// - `count` must match the number of wallet IDs in the buffer
/// - The pointer must not be used after calling this function
/// - This function must only be called once per buffer
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_wallet_ids(wallet_ids: *mut u8, count: usize) {
    if !wallet_ids.is_null() && count > 0 {
        unsafe {
            // Reconstruct the boxed slice with the correct DST pointer
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(wallet_ids, count * 32));
        }
    }
}

/// Free address array
///
/// # Safety
///
/// - `addresses` must be a valid pointer to an array of C string pointers allocated by this library
/// - `count` must match the original allocation size
/// - Each address pointer in the array must be either null or a valid C string allocated by this library
/// - The pointers must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_addresses(addresses: *mut *mut c_char, count: usize) {
    if !addresses.is_null() {
        let slice = std::slice::from_raw_parts_mut(addresses, count);
        for addr in slice {
            if !addr.is_null() {
                let _ = CString::from_raw(*addr);
            }
        }
        // Free the array itself (matches boxed slice allocation)
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(addresses, count));
    }
}
