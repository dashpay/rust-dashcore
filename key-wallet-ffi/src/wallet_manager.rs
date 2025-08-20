//! FFI bindings for WalletManager from key-wallet-manager crate

#[cfg(test)]
#[path = "wallet_manager_tests.rs"]
mod tests;

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint, c_ulong};
use std::ptr;
use std::sync::Mutex;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Network;
use key_wallet_manager::wallet_manager::{WalletError, WalletId, WalletManager};

/// FFI wrapper for WalletManager
#[repr(C)]
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
#[no_mangle]
pub extern "C" fn wallet_manager_add_wallet_from_mnemonic_with_options(
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

    // Generate wallet ID from mnemonic + passphrase
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(mnemonic_str.as_bytes());
    hasher.update(passphrase_str.as_bytes());
    let hash = hasher.finalize();
    let mut wallet_id = [0u8; 32];
    wallet_id.copy_from_slice(&hash);

    let network_rust: Network = network.into();
    let name = format!("Wallet {}", hex::encode(&wallet_id[0..4]));

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

        // Check if wallet already exists
        if manager_guard.get_wallet(&wallet_id).is_some() {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                "Wallet already exists".to_string(),
            );
            return false;
        }

        // Convert account creation options
        let creation_options = if account_options.is_null() {
            key_wallet::wallet::initialization::WalletAccountCreationOptions::Default
        } else {
            unsafe { (*account_options).to_wallet_options() }
        };

        // Use the WalletManager's public method to create the wallet
        match manager_guard.create_wallet_from_mnemonic(
            wallet_id,
            name,
            mnemonic_str,
            passphrase_str,
            Some(network_rust),
            None, // birth_height
            creation_options,
        ) {
            Ok(_) => {
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
#[no_mangle]
pub extern "C" fn wallet_manager_add_wallet_from_mnemonic(
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
        std::ptr::null(), // Use default options
        error,
    )
}

/// Get wallet IDs
#[no_mangle]
pub extern "C" fn wallet_manager_get_wallet_ids(
    manager: *const FFIWalletManager,
    wallet_ids_out: *mut *mut u8,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() || wallet_ids_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
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
            // Allocate memory for wallet IDs (32 bytes each)
            let mut ids_buffer = Vec::with_capacity(count * 32);
            for wallet_id in ids_guard.iter() {
                ids_buffer.extend_from_slice(wallet_id);
            }
            let ids_ptr = ids_buffer.as_mut_ptr();
            std::mem::forget(ids_buffer);

            *wallet_ids_out = ids_ptr;
            *count_out = count;
        }

        FFIError::set_success(error);
        true
    }
}

/// Get a wallet from the manager
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_wallet(
    _manager: *const FFIWalletManager,
    _wallet_id: *const u8,
    error: *mut FFIError,
) -> *const crate::types::FFIWallet {
    FFIError::set_error(
        error,
        FFIErrorCode::NotFound,
        "Placeholder - wallet not found".to_string(),
    );
    ptr::null()
}

/// Get next receive address for a wallet
#[no_mangle]
pub extern "C" fn wallet_manager_get_receive_address(
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

    let wallet_id_slice = unsafe { std::slice::from_raw_parts(wallet_id, 32) };
    let mut wallet_id_array = [0u8; 32];
    wallet_id_array.copy_from_slice(wallet_id_slice);

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
                return ptr::null_mut();
            }
        };

        let network_rust: Network = network.into();

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
}

/// Get next change address for a wallet
#[no_mangle]
pub extern "C" fn wallet_manager_get_change_address(
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

    let wallet_id_slice = unsafe { std::slice::from_raw_parts(wallet_id, 32) };
    let mut wallet_id_array = [0u8; 32];
    wallet_id_array.copy_from_slice(wallet_id_slice);

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
                return ptr::null_mut();
            }
        };

        let network_rust: Network = network.into();

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
}

/// Get wallet balance
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_wallet_balance(
    _manager: *const FFIWalletManager,
    _wallet_id: *const u8,
    confirmed_out: *mut c_ulong,
    unconfirmed_out: *mut c_ulong,
    error: *mut FFIError,
) -> bool {
    if confirmed_out.is_null() || unconfirmed_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        *confirmed_out = 0;
        *unconfirmed_out = 0;
        FFIError::set_success(error);
        true
    }
}

/// Get total balance across all wallets
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_get_total_balance(
    _manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> c_ulong {
    FFIError::set_success(error);
    0
}

/// Process a transaction through all wallets
///
/// NOTE: This is a placeholder implementation
#[no_mangle]
pub extern "C" fn wallet_manager_process_transaction(
    _manager: *mut FFIWalletManager,
    _tx_bytes: *const u8,
    _tx_len: usize,
    _height: c_uint,
    _block_time: c_uint,
    error: *mut FFIError,
) -> bool {
    FFIError::set_success(error);
    false
}

/// Get monitored addresses for a network
#[no_mangle]
pub extern "C" fn wallet_manager_get_monitored_addresses(
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
                return false;
            }
        };

        let network_rust: Network = network.into();
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
                        let dash_network = dashcore::Network::from(network_rust);
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
            let ptr = all_addresses.as_mut_ptr();
            std::mem::forget(all_addresses);
            *addresses_out = ptr;
        }

        FFIError::set_success(error);
        true
    }
}

/// Update block height for a network
#[no_mangle]
pub extern "C" fn wallet_manager_update_height(
    manager: *mut FFIWalletManager,
    network: FFINetwork,
    height: c_uint,
    error: *mut FFIError,
) -> bool {
    if manager.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Manager is null".to_string());
        return false;
    }

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

        let network_rust: Network = network.into();
        manager_guard.update_height(network_rust, height);

        FFIError::set_success(error);
        true
    }
}

/// Get current height for a network
#[no_mangle]
pub extern "C" fn wallet_manager_current_height(
    manager: *const FFIWalletManager,
    network: FFINetwork,
    error: *mut FFIError,
) -> c_uint {
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

        let network_rust: Network = network.into();

        // Get current height from network state if it exists
        let height = manager_guard
            .get_network_state(network_rust)
            .map(|state| state.current_height)
            .unwrap_or(0);

        FFIError::set_success(error);
        height
    }
}

/// Get wallet count
#[no_mangle]
pub extern "C" fn wallet_manager_wallet_count(
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
#[no_mangle]
pub extern "C" fn wallet_manager_free(manager: *mut FFIWalletManager) {
    if !manager.is_null() {
        unsafe {
            let _ = Box::from_raw(manager);
        }
    }
}

/// Free wallet IDs buffer
#[no_mangle]
pub extern "C" fn wallet_manager_free_wallet_ids(wallet_ids: *mut u8, count: usize) {
    if !wallet_ids.is_null() && count > 0 {
        unsafe {
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(wallet_ids, count * 32));
        }
    }
}

/// Free address array
#[no_mangle]
pub extern "C" fn wallet_manager_free_addresses(addresses: *mut *mut c_char, count: usize) {
    if !addresses.is_null() {
        unsafe {
            let slice = std::slice::from_raw_parts_mut(addresses, count);
            for addr in slice {
                if !addr.is_null() {
                    let _ = CString::from_raw(*addr);
                }
            }
            // Free the array itself
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(addresses, count));
        }
    }
}
