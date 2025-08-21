//! Address derivation and management

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};

/// Derive a new receive address at specific index
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `address_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_receive_address(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    address_index: c_uint,
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
                // Derive external address at index
                use key_wallet::ChildNumber;
                use secp256k1::Secp256k1;
                let secp = Secp256k1::new();

                // External addresses use derivation path m/0/index
                let child_external = match ChildNumber::from_normal_idx(0) {
                    Ok(c) => c,
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to create child number: {}", e),
                        );
                        return ptr::null_mut();
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
                        return ptr::null_mut();
                    }
                };

                match account.account_xpub.derive_pub(&secp, &[child_external, child_index]) {
                    Ok(derived_key) => {
                        let public_key = derived_key.public_key;
                        let dash_pubkey = dashcore::PublicKey::new(public_key);
                        let dash_network = network_rust;
                        let address = key_wallet::Address::p2pkh(&dash_pubkey, dash_network);

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
                    }
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to derive address: {}", e),
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

/// Derive a new change address at specific index
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `address_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_derive_change_address(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    address_index: c_uint,
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
                // Derive internal (change) address at index
                use key_wallet::ChildNumber;
                use secp256k1::Secp256k1;
                let secp = Secp256k1::new();

                // Internal addresses use derivation path m/1/index
                let child_internal = match ChildNumber::from_normal_idx(1) {
                    Ok(c) => c,
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to create child number: {}", e),
                        );
                        return ptr::null_mut();
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
                        return ptr::null_mut();
                    }
                };

                match account.account_xpub.derive_pub(&secp, &[child_internal, child_index]) {
                    Ok(derived_key) => {
                        let public_key = derived_key.public_key;
                        let dash_pubkey = dashcore::PublicKey::new(public_key);
                        let dash_network = network_rust;
                        let address = key_wallet::Address::p2pkh(&dash_pubkey, dash_network);

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
                    }
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to derive address: {}", e),
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

/// Get address at specific index
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `address_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_get_address_at_index(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    is_change: bool,
    address_index: c_uint,
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
                // Derive address at specific index
                use key_wallet::ChildNumber;
                use secp256k1::Secp256k1;
                let secp = Secp256k1::new();

                // Choose external (0) or internal (1) chain
                let chain_index = if is_change {
                    1
                } else {
                    0
                };
                let child_chain = match ChildNumber::from_normal_idx(chain_index) {
                    Ok(c) => c,
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to create child number: {}", e),
                        );
                        return ptr::null_mut();
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
                        return ptr::null_mut();
                    }
                };

                match account.account_xpub.derive_pub(&secp, &[child_chain, child_index]) {
                    Ok(derived_key) => {
                        let public_key = derived_key.public_key;
                        let dash_pubkey = dashcore::PublicKey::new(public_key);
                        let dash_network = network_rust;
                        let address = key_wallet::Address::p2pkh(&dash_pubkey, dash_network);

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
                    }
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to derive address: {}", e),
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

/// Mark address as used (placeholder - requires ManagedAccount)
///
/// # Safety
///
/// - `wallet` must be a valid mutable pointer to an FFIWallet
/// - `address` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn wallet_mark_address_used(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    address: *const c_char,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let address_str = unsafe {
        match CStr::from_ptr(address).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in address".to_string(),
                );
                return false;
            }
        }
    };

    unsafe {
        let _wallet = &mut *wallet;
        let _network_rust: key_wallet::Network = network.into();

        use std::str::FromStr;
        let _addr = match key_wallet::Address::from_str(address_str) {
            Ok(a) => a,
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidAddress,
                    format!("Invalid address: {}", e),
                );
                return false;
            }
        };

        // For now, we'll just validate the address and return success
        // Full implementation would require ManagedAccount functionality
        // to maintain address state and usage tracking
        FFIError::set_success(error);
        true
    }
}

/// Get all addresses for an account (placeholder - requires ManagedAccount)
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `addresses_out` must be a valid pointer to store the address array pointer
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError
/// - The returned addresses must be freed with `address_array_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_get_all_addresses(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    addresses_out: *mut *mut *mut c_char,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || addresses_out.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // Generate a few addresses to return (this is a simplified implementation)
        // In a real implementation, you'd track all generated addresses
        match wallet.inner().get_bip44_account(network_rust, account_index) {
            Some(account) => {
                use key_wallet::ChildNumber;
                use secp256k1::Secp256k1;
                let secp = Secp256k1::new();

                let mut addresses: Vec<*mut c_char> = Vec::new();

                // Generate first 5 receive addresses
                for i in 0..5 {
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
                            addresses.push(c_str.into_raw());
                        }
                    }
                }

                if addresses.is_empty() {
                    *count_out = 0;
                    *addresses_out = ptr::null_mut();
                } else {
                    *count_out = addresses.len();
                    // addresses is Vec<*mut c_char>
                    // We need to get a raw pointer to the array and leak it
                    let ptr = addresses.as_mut_ptr(); // This is *mut *mut c_char
                    std::mem::forget(addresses);
                    *addresses_out = ptr;
                }

                FFIError::set_success(error);
                true
            }
            None => {
                FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
                false
            }
        }
    }
}

/// Free address string
///
/// # Safety
///
/// - `address` must be a valid pointer created by address functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn address_free(address: *mut c_char) {
    if !address.is_null() {
        unsafe {
            let _ = CString::from_raw(address);
        }
    }
}

/// Free address array
///
/// # Safety
///
/// - `addresses` must be a valid pointer to an array of address strings or null
/// - Each address in the array must be a valid C string pointer
/// - `count` must be the correct number of addresses in the array
/// - After calling this function, all pointers become invalid
#[no_mangle]
pub unsafe extern "C" fn address_array_free(addresses: *mut *mut c_char, count: usize) {
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

/// Validate an address
///
/// # Safety
///
/// - `address` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn address_validate(
    address: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> bool {
    if address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Address is null".to_string());
        return false;
    }

    let address_str = unsafe {
        match CStr::from_ptr(address).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in address".to_string(),
                );
                return false;
            }
        }
    };

    let network_rust: key_wallet::Network = network.into();
    use std::str::FromStr;

    match key_wallet::Address::from_str(address_str) {
        Ok(addr) => {
            // Check if address is valid for the given network
            let dash_network = network_rust;
            match addr.require_network(dash_network) {
                Ok(_) => {
                    FFIError::set_success(error);
                    true
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidAddress,
                        format!("Address not valid for network {:?}", network_rust),
                    );
                    false
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidAddress,
                format!("Invalid address: {}", e),
            );
            false
        }
    }
}

/// Get address type
///
/// # Safety
///
/// - `address` must be a valid null-terminated C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn address_get_type(
    address: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> c_uint {
    if address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Address is null".to_string());
        return 0;
    }

    let address_str = unsafe {
        match CStr::from_ptr(address).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in address".to_string(),
                );
                return 0;
            }
        }
    };

    let network_rust: key_wallet::Network = network.into();
    use std::str::FromStr;

    match key_wallet::Address::from_str(address_str) {
        Ok(addr) => {
            let dash_network = network_rust;
            match addr.require_network(dash_network) {
                Ok(checked_addr) => {
                    FFIError::set_success(error);
                    // Get the actual address type
                    match checked_addr.address_type() {
                        Some(key_wallet::AddressType::P2pkh) => 0,
                        Some(key_wallet::AddressType::P2sh) => 1,
                        Some(_) => 2, // Other address type
                        None => 2,    // Unknown type
                    }
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidAddress,
                        "Address not valid for network".to_string(),
                    );
                    2 // Invalid
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidAddress,
                format!("Invalid address: {}", e),
            );
            2 // Invalid
        }
    }
}
