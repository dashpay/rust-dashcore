//! Address pool management FFI bindings
//!
//! This module provides FFI bindings for managing address pools within
//! managed accounts, including gap limit management and address generation.

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};

use crate::error::{FFIError, FFIErrorCode};
use crate::utils::rust_string_to_c;
use crate::{check_ptr, deref_ptr, unwrap_or_return};
use key_wallet::managed_account::address_pool::{AddressInfo, AddressPool, PublicKeyType};

/// Address pool type
#[repr(C)]
pub enum FFIAddressPoolType {
    /// External (receive) addresses
    External = 0,
    /// Internal (change) addresses
    Internal = 1,
    /// Single pool (for non-standard accounts)
    Single = 2,
}

/// FFI wrapper for an AddressPool from a ManagedAccount
///
/// This is a lightweight wrapper that holds a reference to an AddressPool
/// from within a ManagedAccount. It allows querying addresses and pool information.
pub struct FFIAddressPool {
    /// Reference to the address pool (mutable for internal consistency even if not modified)
    pub(crate) pool: *mut AddressPool,
    /// Pool type to track what kind of pool this is
    #[allow(dead_code)]
    pub(crate) pool_type: FFIAddressPoolType,
}

/// FFI-compatible version of AddressInfo
#[repr(C)]
pub struct FFIAddressInfo {
    /// Address as string
    pub address: *mut c_char,
    /// Script pubkey bytes
    pub script_pubkey: *mut u8,
    /// Length of script pubkey
    pub script_pubkey_len: usize,
    /// Public key bytes (nullable)
    pub public_key: *mut u8,
    /// Length of public key
    pub public_key_len: usize,
    /// Derivation index
    pub index: u32,
    /// Derivation path as string
    pub path: *mut c_char,
    /// Whether address has been used
    pub used: bool,
    /// Transaction count
    pub tx_count: u32,
    /// Total received
    pub total_received: u64,
    /// Total sent
    pub total_sent: u64,
    /// Current balance
    pub balance: u64,
    /// Custom label (nullable)
    pub label: *mut c_char,
}

/// Convert from AddressInfo to FFIAddressInfo
fn address_info_to_ffi(info: &AddressInfo) -> FFIAddressInfo {
    // Convert address to string
    let address_str = rust_string_to_c(info.address.to_string());

    // Convert script pubkey to bytes
    let script_bytes = info.script_pubkey.as_bytes();
    let script_pubkey_len = script_bytes.len();
    let script_pubkey = if script_pubkey_len > 0 {
        let mut bytes = Vec::with_capacity(script_pubkey_len);
        bytes.extend_from_slice(script_bytes);
        Box::into_raw(bytes.into_boxed_slice()) as *mut u8
    } else {
        std::ptr::null_mut()
    };

    // Convert public key to bytes if present
    let (public_key, public_key_len) = match &info.public_key {
        Some(pk) => match pk {
            PublicKeyType::ECDSA(bytes)
            | PublicKeyType::EdDSA(bytes)
            | PublicKeyType::BLS(bytes) => {
                let len = bytes.len();
                if len > 0 {
                    let mut key_bytes = Vec::with_capacity(len);
                    key_bytes.extend_from_slice(bytes);
                    (Box::into_raw(key_bytes.into_boxed_slice()) as *mut u8, len)
                } else {
                    (std::ptr::null_mut(), 0)
                }
            }
        },
        None => (std::ptr::null_mut(), 0),
    };

    // Convert derivation path to string
    let path_str = rust_string_to_c(info.path.to_string());

    // Convert label if present
    let label =
        info.label.as_ref().map(|l| rust_string_to_c(l.clone())).unwrap_or(std::ptr::null_mut());

    FFIAddressInfo {
        address: address_str,
        script_pubkey,
        script_pubkey_len,
        public_key,
        public_key_len,
        index: info.index,
        path: path_str,
        used: info.is_used(),
        tx_count: info.tx_count,
        total_received: info.total_received,
        total_sent: info.total_sent,
        balance: info.balance,
        label,
    }
}

/// Free an address pool handle
///
/// # Safety
///
/// - `pool` must be a valid pointer to an FFIAddressPool that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn address_pool_free(pool: *mut FFIAddressPool) {
    if !pool.is_null() {
        let _ = Box::from_raw(pool);
    }
}

/// Address pool info
#[repr(C)]
pub struct FFIAddressPoolInfo {
    /// Pool type
    pub pool_type: FFIAddressPoolType,
    /// Number of generated addresses
    pub generated_count: c_uint,
    /// Number of used addresses
    pub used_count: c_uint,
    /// Current gap (unused addresses at the end)
    pub current_gap: c_uint,
    /// Gap limit setting
    pub gap_limit: c_uint,
    /// Highest used index (-1 if none used)
    pub highest_used_index: i32,
}

/// Get a single address info at a specific index from the pool
///
/// Returns detailed information about the address at the given index, or NULL
/// if the index is out of bounds or not generated yet.
///
/// # Safety
///
/// - `pool` must be a valid pointer to an FFIAddressPool
/// - `error` must be a valid pointer to an FFIError
/// - The returned FFIAddressInfo must be freed using `address_info_free`
#[no_mangle]
pub unsafe extern "C" fn address_pool_get_address_at_index(
    pool: *const FFIAddressPool,
    index: u32,
    error: *mut FFIError,
) -> *mut FFIAddressInfo {
    let pool = deref_ptr!(pool, error);
    let address_pool = &*pool.pool;

    // Get the address info at the specified index
    let info = unwrap_or_return!(address_pool.info_at_index(index), error);
    let ffi_info = address_info_to_ffi(info);
    Box::into_raw(Box::new(ffi_info))
}

/// Get a range of addresses from the pool
///
/// Returns an array of FFIAddressInfo structures for addresses in the range [start_index, end_index).
/// The count_out parameter will be set to the actual number of addresses returned.
///
/// Note: This function only reads existing addresses from the pool. It does not generate new addresses.
///
/// # Safety
///
/// - `pool` must be a valid pointer to an FFIAddressPool
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError
/// - The returned array must be freed using `address_info_array_free`
#[no_mangle]
pub unsafe extern "C" fn address_pool_get_addresses_in_range(
    pool: *const FFIAddressPool,
    start_index: u32,
    end_index: u32,
    count_out: *mut usize,
    error: *mut FFIError,
) -> *mut *mut FFIAddressInfo {
    let pool = deref_ptr!(pool, error);
    check_ptr!(count_out, error);

    *count_out = 0;
    let address_pool = &*pool.pool;

    // Collect address infos in the range
    let mut infos = Vec::new();

    // Special case: if start_index == 0 and end_index == 0, return all addresses
    if start_index == 0 && end_index == 0 {
        for idx in 0..=address_pool.highest_generated.unwrap_or(0) {
            if let Some(info) = address_pool.info_at_index(idx) {
                infos.push(Box::into_raw(Box::new(address_info_to_ffi(info))));
            }
        }
    } else {
        // Normal range query
        if end_index <= start_index {
            (*error).set(FFIErrorCode::InvalidInput, "End index must be greater than start index");
            return std::ptr::null_mut();
        }

        for idx in start_index..end_index {
            if let Some(info) = address_pool.info_at_index(idx) {
                infos.push(Box::into_raw(Box::new(address_info_to_ffi(info))));
            }
        }
    }

    if infos.is_empty() {
        (*error).set(FFIErrorCode::NotFound, "No addresses found in the specified range");
        return std::ptr::null_mut();
    }

    *count_out = infos.len();
    let array_ptr = Box::into_raw(infos.into_boxed_slice()) as *mut *mut FFIAddressInfo;

    (*error).clean();
    array_ptr
}

/// Free a single FFIAddressInfo structure
///
/// # Safety
///
/// - `info` must be a valid pointer to an FFIAddressInfo allocated by this library or null
/// - The pointer must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn address_info_free(info: *mut FFIAddressInfo) {
    if !info.is_null() {
        let info = Box::from_raw(info);

        // Free the C strings
        if !info.address.is_null() {
            let _ = CString::from_raw(info.address);
        }
        if !info.path.is_null() {
            let _ = CString::from_raw(info.path);
        }
        if !info.label.is_null() {
            let _ = CString::from_raw(info.label);
        }

        // Free the byte arrays
        if !info.script_pubkey.is_null() && info.script_pubkey_len > 0 {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                info.script_pubkey,
                info.script_pubkey_len,
            ));
        }
        if !info.public_key.is_null() && info.public_key_len > 0 {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                info.public_key,
                info.public_key_len,
            ));
        }
    }
}

/// Free an array of FFIAddressInfo structures
///
/// # Safety
///
/// - `infos` must be a valid pointer to an array of FFIAddressInfo pointers allocated by this library or null
/// - `count` must be the exact number of elements in the array
/// - The pointers must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn address_info_array_free(infos: *mut *mut FFIAddressInfo, count: usize) {
    if !infos.is_null() && count > 0 {
        let array = Box::from_raw(std::ptr::slice_from_raw_parts_mut(infos, count));
        for info_ptr in array.iter() {
            address_info_free(*info_ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FFIAccountKind;
    use dash_network::ffi::FFINetwork;
    use key_wallet::managed_account::address_pool::AddressState;

    #[test]
    fn test_address_pool_type_values() {
        assert_eq!(FFIAddressPoolType::External as u32, 0);
        assert_eq!(FFIAddressPoolType::Internal as u32, 1);
        assert_eq!(FFIAddressPoolType::Single as u32, 2);
    }

    #[test]
    fn test_address_info_conversion() {
        // Test the FFI conversion function with a mock AddressInfo
        use key_wallet::bip32::DerivationPath;
        use std::str::FromStr;

        // Create a test address programmatically
        use dashcore::PublicKey;

        // Use a valid compressed public key (this is a well-known test key)
        let pubkey_bytes = [
            0x02, // Compressed pubkey prefix
            0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8,
            0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88,
            0x7e, 0x5b, 0x23, 0x52,
        ];
        let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
        let test_address = dashcore::Address::p2pkh(&pubkey, key_wallet::Network::Testnet);

        let test_path = DerivationPath::from_str("m/44'/5'/0'/0/0").unwrap();

        let info = AddressInfo {
            address: test_address.clone(),
            script_pubkey: test_address.script_pubkey(),
            public_key: Some(PublicKeyType::ECDSA(vec![0x02, 0x03, 0x04])),
            index: 0,
            path: test_path,
            state: AddressState::Available,
            tx_count: 0,
            total_received: 0,
            total_sent: 0,
            balance: 0,
            label: Some("Test Label".to_string()),
            metadata: std::collections::BTreeMap::new(),
        };

        // Convert to FFI
        let ffi_info = address_info_to_ffi(&info);

        // Verify basic fields
        assert_eq!(ffi_info.index, 0);
        assert!(!ffi_info.used);
        assert_eq!(ffi_info.public_key_len, 3);
        assert!(ffi_info.script_pubkey_len > 0);

        // Clean up the FFI structure
        unsafe {
            let boxed = Box::new(ffi_info);
            address_info_free(Box::into_raw(boxed));
        }
    }

    #[test]
    fn test_address_info_free() {
        // Test that free functions handle NULL gracefully
        unsafe {
            address_info_free(std::ptr::null_mut());
            address_info_array_free(std::ptr::null_mut(), 0);
            address_info_array_free(std::ptr::null_mut(), 10);
        }
    }

    #[test]
    fn test_address_pool_get_address_at_index() {
        // Test the simplified address_pool_get_address_at_index function
        unsafe {
            use crate::managed_account::{
                managed_core_account_free, managed_core_account_get_external_address_pool,
            };
            use crate::wallet_manager::{
                wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
                wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
            };
            use std::ffi::CString;
            use std::ptr;

            let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mut error = FFIError::default();

            // Create wallet manager
            let manager = wallet_manager_create(FFINetwork::Testnet, &mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(test_mnemonic).unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                &mut error,
            );
            assert!(success);
            assert_eq!(error.code, FFIErrorCode::Success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);
            assert!(!wallet_ids_out.is_null());

            // Get a standard BIP44 managed account
            let result = crate::managed_account::managed_wallet_get_account(
                manager,
                wallet_ids_out,
                0,
                FFIAccountKind::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);

            let account = result.account;

            // Get external address pool
            let external_pool = managed_core_account_get_external_address_pool(account);
            assert!(!external_pool.is_null());

            // Test getting address at index 0 (should exist by default)
            let address_info = address_pool_get_address_at_index(external_pool, 0, &mut error);

            if !address_info.is_null() {
                // Verify the address info
                let info = &*address_info;
                assert_eq!(info.index, 0);
                assert!(!info.address.is_null());
                assert!(!info.path.is_null());

                // Clean up address info
                address_info_free(address_info);
            }

            // Test getting address at an out-of-bounds index
            let invalid_info = address_pool_get_address_at_index(external_pool, 10000, &mut error);
            assert!(invalid_info.is_null());
            assert_eq!(error.code, FFIErrorCode::NotFound);

            // Test null pool
            let null_info = address_pool_get_address_at_index(ptr::null(), 0, &mut error);
            assert!(null_info.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Clean up
            address_pool_free(external_pool);
            managed_core_account_free(account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_address_pool_get_addresses_in_range() {
        // Test the simplified address_pool_get_addresses_in_range function
        unsafe {
            use crate::managed_account::{
                managed_core_account_free, managed_core_account_get_external_address_pool,
            };
            use crate::wallet_manager::{
                wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
                wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
            };
            use std::ffi::CString;
            use std::ptr;

            let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mut error = FFIError::default();

            // Create wallet manager
            let manager = wallet_manager_create(FFINetwork::Testnet, &mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(test_mnemonic).unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                &mut error,
            );
            assert!(success);
            assert_eq!(error.code, FFIErrorCode::Success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);
            assert!(!wallet_ids_out.is_null());

            // Get a standard BIP44 managed account
            let result = crate::managed_account::managed_wallet_get_account(
                manager,
                wallet_ids_out,
                0,
                FFIAccountKind::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);

            let account = result.account;

            // Get external address pool
            let external_pool = managed_core_account_get_external_address_pool(account);
            assert!(!external_pool.is_null());

            // Test getting a range of addresses
            let mut addresses_count: usize = 0;
            let addresses = address_pool_get_addresses_in_range(
                external_pool,
                0,
                5,
                &mut addresses_count,
                &mut error,
            );

            // The pool might not have 5 addresses generated yet, but should have at least 1
            if !addresses.is_null() && addresses_count > 0 {
                // Verify we got some addresses
                assert!(addresses_count <= 5);
                assert_eq!(error.code, FFIErrorCode::Success);

                // Clean up addresses
                address_info_array_free(addresses, addresses_count);
            }

            // Test invalid range (end <= start)
            let invalid_addresses = address_pool_get_addresses_in_range(
                external_pool,
                5,
                5,
                &mut addresses_count,
                &mut error,
            );
            assert!(invalid_addresses.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Test null pool
            let null_addresses = address_pool_get_addresses_in_range(
                ptr::null(),
                0,
                5,
                &mut addresses_count,
                &mut error,
            );
            assert!(null_addresses.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Test null count_out
            let null_count_addresses = address_pool_get_addresses_in_range(
                external_pool,
                0,
                5,
                ptr::null_mut(),
                &mut error,
            );
            assert!(null_count_addresses.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Clean up
            address_pool_free(external_pool);
            managed_core_account_free(account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }
}
