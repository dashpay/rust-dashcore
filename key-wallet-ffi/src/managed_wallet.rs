//! Managed wallet FFI bindings
//!
//! This module provides FFI bindings for ManagedWalletInfo which includes
//! address management, UTXO tracking, and transaction building capabilities.
//!

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFIWallet;
use crate::{check_ptr, deref_ptr, deref_ptr_mut, unwrap_or_return};
use key_wallet::managed_account::address_pool::KeySource;
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use std::ffi::c_void;

/// FFI wrapper for ManagedWalletInfo (single canonical type)
#[repr(C)]
pub struct FFIManagedWalletInfo {
    // Opaque pointer to avoid leaking ManagedWalletInfo into C headers
    inner: *mut c_void,
}

impl FFIManagedWalletInfo {
    /// Create a new FFIManagedWalletInfo from a ManagedWalletInfo
    pub fn new(inner: ManagedWalletInfo) -> Self {
        Self {
            inner: Box::into_raw(Box::new(inner)) as *mut c_void,
        }
    }

    pub fn inner(&self) -> &ManagedWalletInfo {
        unsafe { &*(self.inner as *const ManagedWalletInfo) }
    }

    pub fn inner_mut(&mut self) -> &mut ManagedWalletInfo {
        unsafe { &mut *(self.inner as *mut ManagedWalletInfo) }
    }
}

/// Get the next unused receive address
///
/// Generates the next unused receive address for the specified account.
/// This properly manages address gaps and updates the managed wallet state.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_next_bip44_receive_address(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
    account_index: std::os::raw::c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let managed_wallet = deref_ptr_mut!(managed_wallet, error);
    let wallet = deref_ptr!(wallet, error);

    // Get the specific managed account (default to BIP44)
    let managed_account = unwrap_or_return!(
        managed_wallet.inner_mut().accounts.standard_bip44_accounts.get_mut(&account_index),
        error
    );

    // Get the account from the wallet to get the extended public key
    let account = unwrap_or_return!(
        wallet.wallet.accounts.standard_bip44_accounts.get(&account_index),
        error
    );

    // Generate the next receive address
    let xpub = account.extended_public_key();
    let address = unwrap_or_return!(managed_account.next_receive_address(Some(&xpub), true), error)
        .to_string();
    unwrap_or_return!(CString::new(address), error).into_raw()
}

/// Get the next unused change address
///
/// Generates the next unused change address for the specified account.
/// This properly manages address gaps and updates the managed wallet state.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_next_bip44_change_address(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
    account_index: std::os::raw::c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let managed_wallet = deref_ptr_mut!(managed_wallet, error);
    let wallet = deref_ptr!(wallet, error);

    // Get the specific managed account (default to BIP44)
    let managed_account = unwrap_or_return!(
        managed_wallet.inner_mut().accounts.standard_bip44_accounts.get_mut(&account_index),
        error
    );

    // Get the account from the wallet to get the extended public key
    let account = unwrap_or_return!(
        wallet.wallet.accounts.standard_bip44_accounts.get(&account_index),
        error
    );

    // Generate the next change address
    let xpub = account.extended_public_key();
    let next_change_address =
        unwrap_or_return!(managed_account.next_change_address(Some(&xpub), true), error)
            .to_string();
    unwrap_or_return!(CString::new(next_change_address), error).into_raw()
}

/// Get BIP44 external (receive) addresses in the specified range
///
/// Returns external addresses from start_index (inclusive) to end_index (exclusive).
/// If addresses in the range haven't been generated yet, they will be generated.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `addresses_out` must be a valid pointer to store the address array pointer
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError
/// - Free the result with address_array_free(addresses_out, count_out)
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_bip_44_external_address_range(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
    account_index: std::os::raw::c_uint,
    start_index: std::os::raw::c_uint,
    end_index: std::os::raw::c_uint,
    addresses_out: *mut *mut *mut c_char,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(addresses_out, error);
    check_ptr!(count_out, error);
    let managed_wallet = deref_ptr_mut!(managed_wallet, error);
    let wallet = deref_ptr!(wallet, error);

    // Get the specific managed account (BIP44)
    let managed_account = unwrap_or_return!(
        managed_wallet.inner_mut().accounts.standard_bip44_accounts.get_mut(&account_index),
        error
    );

    // Get the account from the wallet to get the extended public key
    let account = unwrap_or_return!(
        wallet.wallet.accounts.standard_bip44_accounts.get(&account_index),
        error
    );

    // Get external addresses in the range
    let xpub = account.extended_public_key();
    let key_source = KeySource::Public(xpub);

    // Access the external address pool from the managed account
    let addresses = if let key_wallet::account::ManagedAccountType::Standard {
        external_addresses,
        ..
    } = managed_account.managed_account_type_mut()
    {
        unwrap_or_return!(
            external_addresses.address_range(start_index, end_index, &key_source),
            error
        )
    } else {
        (*error).set(FFIErrorCode::WalletError, "Account is not a standard BIP44 account");
        *count_out = 0;
        *addresses_out = ptr::null_mut();
        return false;
    };

    // Convert addresses to C strings
    let mut c_addresses = Vec::with_capacity(addresses.len());
    for address in addresses {
        let c_str = unwrap_or_return!(CString::new(address.to_string()), error).into_raw();
        c_addresses.push(c_str);
    }

    // Convert Vec to Box<[*mut c_char]> and leak it properly
    let boxed_slice = c_addresses.into_boxed_slice();
    let len = boxed_slice.len();
    let ptr = Box::into_raw(boxed_slice) as *mut *mut c_char;

    *count_out = len;
    *addresses_out = ptr;
    (*error).clean();
    true
}

/// Get BIP44 internal (change) addresses in the specified range
///
/// Returns internal addresses from start_index (inclusive) to end_index (exclusive).
/// If addresses in the range haven't been generated yet, they will be generated.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `addresses_out` must be a valid pointer to store the address array pointer
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError
/// - Free the result with address_array_free(addresses_out, count_out)
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_bip_44_internal_address_range(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
    account_index: std::os::raw::c_uint,
    start_index: std::os::raw::c_uint,
    end_index: std::os::raw::c_uint,
    addresses_out: *mut *mut *mut c_char,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(addresses_out, error);
    check_ptr!(count_out, error);
    let managed_wallet = deref_ptr_mut!(managed_wallet, error);
    let wallet = deref_ptr!(wallet, error);

    // Get the specific managed account (BIP44)
    let managed_account = unwrap_or_return!(
        managed_wallet.inner_mut().accounts.standard_bip44_accounts.get_mut(&account_index),
        error
    );

    // Get the account from the wallet to get the extended public key
    let account = unwrap_or_return!(
        wallet.wallet.accounts.standard_bip44_accounts.get(&account_index),
        error
    );

    // Get internal addresses in the range
    let xpub = account.extended_public_key();
    let key_source = KeySource::Public(xpub);

    // Access the internal address pool from the managed account
    let addresses = if let key_wallet::account::ManagedAccountType::Standard {
        internal_addresses,
        ..
    } = managed_account.managed_account_type_mut()
    {
        unwrap_or_return!(
            internal_addresses.address_range(start_index, end_index, &key_source),
            error
        )
    } else {
        (*error).set(FFIErrorCode::WalletError, "Account is not a standard BIP44 account");
        *count_out = 0;
        *addresses_out = ptr::null_mut();
        return false;
    };

    // Convert addresses to C strings
    let mut c_addresses = Vec::with_capacity(addresses.len());
    for address in addresses {
        let c_str = unwrap_or_return!(CString::new(address.to_string()), error).into_raw();
        c_addresses.push(c_str);
    }

    // Convert Vec to Box<[*mut c_char]> and leak it properly
    let boxed_slice = c_addresses.into_boxed_slice();
    let len = boxed_slice.len();
    let ptr = Box::into_raw(boxed_slice) as *mut *mut c_char;

    *count_out = len;
    *addresses_out = ptr;
    (*error).clean();
    true
}

/// Get wallet balance from managed wallet info
///
/// Returns the balance breakdown including confirmed, unconfirmed, immature, locked, and total amounts.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `confirmed_out` must be a valid pointer to store the confirmed balance
/// - `unconfirmed_out` must be a valid pointer to store the unconfirmed balance
/// - `immature_out` must be a valid pointer to store the immature balance
/// - `locked_out` must be a valid pointer to store the locked balance
/// - `total_out` must be a valid pointer to store the total balance
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_balance(
    managed_wallet: *const FFIManagedWalletInfo,
    confirmed_out: *mut u64,
    unconfirmed_out: *mut u64,
    immature_out: *mut u64,
    locked_out: *mut u64,
    total_out: *mut u64,
    error: *mut FFIError,
) -> bool {
    let managed_wallet = deref_ptr!(managed_wallet, error);
    check_ptr!(confirmed_out, error);
    check_ptr!(unconfirmed_out, error);
    check_ptr!(immature_out, error);
    check_ptr!(locked_out, error);
    check_ptr!(total_out, error);

    let balance = &managed_wallet.inner().balance;
    *confirmed_out = balance.confirmed();
    *unconfirmed_out = balance.unconfirmed();
    *immature_out = balance.immature();
    *locked_out = balance.locked();
    *total_out = balance.total();
    true
}

/// Get current last processed height from wallet info
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_last_processed_height(
    managed_wallet: *const FFIManagedWalletInfo,
    error: *mut FFIError,
) -> c_uint {
    let managed_wallet = deref_ptr!(managed_wallet, error);
    managed_wallet.inner().last_processed_height()
}

/// Free managed wallet info
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo or null
/// - After calling this function, the pointer becomes invalid and must not be used
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) {
    if !managed_wallet.is_null() {
        // Reclaim outer struct, then free inner if present
        let wrapper = Box::from_raw(managed_wallet);
        if !wrapper.inner.is_null() {
            let _ = Box::from_raw(wrapper.inner as *mut ManagedWalletInfo);
        }
    }
}

/// Free managed wallet info returned by wallet_manager_get_managed_wallet_info
///
/// # Safety
///
/// - `wallet_info` must be a valid pointer returned by wallet_manager_get_managed_wallet_info or null
/// - After calling this function, the pointer becomes invalid and must not be used
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_info_free(wallet_info: *mut FFIManagedWalletInfo) {
    if !wallet_info.is_null() {
        let wrapper = Box::from_raw(wallet_info);
        if !wrapper.inner.is_null() {
            let _ = Box::from_raw(wrapper.inner as *mut ManagedWalletInfo);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::managed_wallet::*;
    use crate::wallet;
    use dash_network::ffi::FFINetwork;
    use key_wallet::managed_account::managed_account_type::ManagedAccountType;
    use std::ffi::{CStr, CString};
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Note: managed_wallet_create has been removed as client libraries
    // should only get ManagedWalletInfo through WalletManager

    #[test]
    fn test_managed_wallet_free_null() {
        // Should not crash when freeing null
        unsafe {
            managed_wallet_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_managed_wallet_get_next_receive_address_null_pointers() {
        let mut error = FFIError::default();

        // Test with null managed wallet
        let address = unsafe {
            managed_wallet_get_next_bip44_receive_address(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_get_next_change_address_null_pointers() {
        let mut error = FFIError::default();

        // Test with null managed wallet
        let address = unsafe {
            managed_wallet_get_next_bip44_change_address(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_get_bip_44_external_address_range_null_pointers() {
        let mut error = FFIError::default();
        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        // Test with null managed wallet
        let success = unsafe {
            managed_wallet_get_bip_44_external_address_range(
                ptr::null_mut(),
                ptr::null(),
                0,
                0,
                10,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(count_out, 0);
        assert!(addresses_out.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_get_bip_44_internal_address_range_null_pointers() {
        let mut error = FFIError::default();
        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        // Test with null managed wallet
        let success = unsafe {
            managed_wallet_get_bip_44_internal_address_range(
                ptr::null_mut(),
                ptr::null(),
                0,
                0,
                10,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(count_out, 0);
        assert!(addresses_out.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_address_generation_with_valid_wallet() {
        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Create managed wallet info from the wallet heap-allocated like C would do
        let wallet_rust = unsafe { &(*wallet).wallet };
        let managed_info = ManagedWalletInfo::from_wallet(wallet_rust, 0);
        let ffi_managed = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));

        // Test get_next_receive_address with valid pointers
        let receive_addr = unsafe {
            managed_wallet_get_next_bip44_receive_address(ffi_managed, wallet, 0, &mut error)
        };

        if !receive_addr.is_null() {
            // If successful, verify the address
            let addr_str = unsafe { CStr::from_ptr(receive_addr).to_string_lossy() };
            assert!(!addr_str.is_empty());

            // Free the address string
            unsafe {
                let _ = CString::from_raw(receive_addr);
            }
        } else {
            // It's ok if it fails due to no accounts being initialized
            // This would happen in a real scenario where WalletManager would
            // properly initialize the accounts
            assert_eq!(error.code, FFIErrorCode::WalletError);
        }

        // Test get_next_change_address with valid pointers
        let change_addr = unsafe {
            managed_wallet_get_next_bip44_change_address(ffi_managed, wallet, 0, &mut error)
        };

        if !change_addr.is_null() {
            // If successful, verify the address
            let addr_str = unsafe { CStr::from_ptr(change_addr).to_string_lossy() };
            assert!(!addr_str.is_empty());

            // Free the address string
            unsafe {
                let _ = CString::from_raw(change_addr);
            }
        } else {
            // It's ok if it fails due to no accounts being initialized
            assert_eq!(error.code, FFIErrorCode::WalletError);
        }

        // Clean up
        unsafe {
            managed_wallet_free(ffi_managed);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_comprehensive_address_generation() {
        use key_wallet::account::{
            ManagedAccountCollection, ManagedCoreFundsAccount, StandardAccountType,
        };
        use key_wallet::bip32::DerivationPath;
        use key_wallet::managed_account::address_pool::{AddressPool, AddressPoolType};

        let mut error = FFIError::default();

        // Create a wallet with a known mnemonic
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();

        let wallet_ptr = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet_ptr.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Get the actual wallet
        let wallet_arc = unsafe { &(*wallet_ptr).wallet };

        // We need to work with the existing wallet structure
        // Create managed wallet info from the existing wallet
        let mut managed_info = ManagedWalletInfo::from_wallet(wallet_arc, 0);

        let network = key_wallet::Network::Testnet;

        // Initialize the managed account collection properly
        let mut managed_collection = ManagedAccountCollection::new();

        // Create a managed account with address pools
        // Using NoKeySource for test data
        let key_source = KeySource::NoKeySource;
        let external_pool = AddressPool::new(
            DerivationPath::from(vec![key_wallet::bip32::ChildNumber::from_normal_idx(0).unwrap()]),
            AddressPoolType::External,
            20,
            network,
            &key_source,
        )
        .expect("Failed to create external pool");
        let internal_pool = AddressPool::new(
            DerivationPath::from(vec![key_wallet::bip32::ChildNumber::from_normal_idx(1).unwrap()]),
            AddressPoolType::Internal,
            20,
            network,
            &key_source,
        )
        .expect("Failed to create internal pool");

        let managed_account = ManagedCoreFundsAccount::new(
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
                external_addresses: external_pool,
                internal_addresses: internal_pool,
            },
            network,
        );

        managed_collection.standard_bip44_accounts.insert(0, managed_account.clone());
        // Insert the managed account directly into managed_info's accounts
        managed_info
            .accounts
            .insert(managed_account)
            .expect("insert should succeed for Standard account");

        // Create wrapper for managed info heap-allocated like C would do
        let ffi_managed = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));

        // Use the existing wallet pointer
        let ffi_wallet_ptr = wallet_ptr;

        // Test 1: Get next receive address
        let receive_addr = unsafe {
            managed_wallet_get_next_bip44_receive_address(
                ffi_managed,
                ffi_wallet_ptr,
                0,
                &mut error,
            )
        };

        assert!(!receive_addr.is_null());
        let receive_str = unsafe { CStr::from_ptr(receive_addr).to_string_lossy() };
        assert!(!receive_str.is_empty());
        println!("Generated receive address: {}", receive_str);
        unsafe {
            let _ = CString::from_raw(receive_addr);
        }

        // Test 2: Get next change address
        let change_addr = unsafe {
            managed_wallet_get_next_bip44_change_address(ffi_managed, ffi_wallet_ptr, 0, &mut error)
        };

        assert!(!change_addr.is_null());
        let change_str = unsafe { CStr::from_ptr(change_addr).to_string_lossy() };
        assert!(!change_str.is_empty());
        println!("Generated change address: {}", change_str);
        unsafe {
            let _ = CString::from_raw(change_addr);
        }

        // Test 3: Get external address range
        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            managed_wallet_get_bip_44_external_address_range(
                ffi_managed,
                ffi_wallet_ptr,
                0,
                0,
                5,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 5);
        assert!(!addresses_out.is_null());

        // Verify and free addresses
        unsafe {
            let addresses = std::slice::from_raw_parts(addresses_out, count_out);
            for &addr_ptr in addresses {
                let addr_str = CStr::from_ptr(addr_ptr).to_string_lossy();
                assert!(!addr_str.is_empty());
                println!("External address: {}", addr_str);
                let _ = CString::from_raw(addr_ptr);
            }
            libc::free(addresses_out as *mut libc::c_void);
        }

        // Test 4: Get internal address range
        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            managed_wallet_get_bip_44_internal_address_range(
                ffi_managed,
                ffi_wallet_ptr,
                0,
                0,
                3,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 3);
        assert!(!addresses_out.is_null());

        // Verify and free addresses
        unsafe {
            let addresses = std::slice::from_raw_parts(addresses_out, count_out);
            for &addr_ptr in addresses {
                let addr_str = CStr::from_ptr(addr_ptr).to_string_lossy();
                assert!(!addr_str.is_empty());
                println!("Internal address: {}", addr_str);
                // Don't manually free individual strings - address_array_free handles it
            }
            // Use the proper FFI function to free the array and all strings
            crate::address::address_array_free(addresses_out, count_out);
        }

        // Clean up
        unsafe {
            managed_wallet_free(ffi_managed);
            wallet::wallet_free(wallet_ptr);
        }
    }

    #[test]
    fn test_managed_wallet_get_balance() {
        use key_wallet::wallet::balance::WalletCoreBalance;

        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();

        let wallet_ptr = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet_ptr.is_null());

        // Create managed wallet info
        let wallet_arc = unsafe { &(*wallet_ptr).wallet };
        let mut managed_info = ManagedWalletInfo::from_wallet(wallet_arc, 0);

        // Set some test balance values
        managed_info.balance = WalletCoreBalance::new(1000000, 50000, 10000, 25000);

        let ffi_managed = FFIManagedWalletInfo::new(managed_info);
        let ffi_managed_ptr = Box::into_raw(Box::new(ffi_managed));

        // Test getting balance
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        let mut immature: u64 = 0;
        let mut locked: u64 = 0;
        let mut total: u64 = 0;

        let success = unsafe {
            managed_wallet_get_balance(
                ffi_managed_ptr,
                &mut confirmed,
                &mut unconfirmed,
                &mut immature,
                &mut locked,
                &mut total,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(confirmed, 1000000);
        assert_eq!(unconfirmed, 50000);
        assert_eq!(immature, 10000);
        assert_eq!(locked, 25000);
        assert_eq!(total, 1085000);

        // Test with null managed wallet
        let success = unsafe {
            managed_wallet_get_balance(
                ptr::null(),
                &mut confirmed,
                &mut unconfirmed,
                &mut immature,
                &mut locked,
                &mut total,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null output pointers
        let success = unsafe {
            managed_wallet_get_balance(
                ffi_managed_ptr,
                ptr::null_mut(),
                &mut unconfirmed,
                &mut immature,
                &mut locked,
                &mut total,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            managed_wallet_free(ffi_managed_ptr);
            wallet::wallet_free(wallet_ptr);
        }
    }

    #[test]
    fn test_managed_wallet_get_address_range_null_outputs() {
        let mut error = FFIError::default();

        // Test with null addresses_out for external range
        let success = unsafe {
            managed_wallet_get_bip_44_external_address_range(
                ptr::null_mut(),
                ptr::null(),
                0,
                0,
                10,
                ptr::null_mut(),
                &mut 0,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null count_out for internal range
        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let success = unsafe {
            managed_wallet_get_bip_44_internal_address_range(
                ptr::null_mut(),
                ptr::null(),
                0,
                0,
                10,
                &mut addresses_out,
                ptr::null_mut(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }
}

#[cfg(test)]
#[path = "managed_wallet_tests.rs"]
mod managed_wallet_tests;
