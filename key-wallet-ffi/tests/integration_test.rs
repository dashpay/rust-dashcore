//! Integration tests for key-wallet-ffi
//!
//! These tests verify the interaction between different FFI modules

use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use key_wallet_ffi::types::FFINetworks;
use std::ffi::CString;
use std::ptr;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_full_wallet_workflow() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // 1. Generate a mnemonic
    let mnemonic = key_wallet_ffi::mnemonic::mnemonic_generate(12, error);
    assert!(!mnemonic.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // 2. Validate the mnemonic
    let is_valid = unsafe { key_wallet_ffi::mnemonic::mnemonic_validate(mnemonic, error) };
    assert!(is_valid);

    // 3. Create wallet manager
    let manager = key_wallet_ffi::wallet_manager::wallet_manager_create(error);
    assert!(!manager.is_null());

    // 4. Add wallet to manager
    let passphrase = CString::new("").unwrap();
    let success = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic(
            manager,
            mnemonic,
            passphrase.as_ptr(),
            FFINetworks::Testnet,
            error,
        )
    };
    assert!(success);

    // 5. Get wallet IDs
    let mut wallet_ids: *mut u8 = ptr::null_mut();
    let mut count: usize = 0;
    let success = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_ids(
            manager,
            &mut wallet_ids,
            &mut count,
            error,
        )
    };
    assert!(success);
    assert_eq!(count, 1);

    let wallet_id = wallet_ids; // First wallet ID starts at offset 0

    // 6. Derive addresses using wallet manager
    let receive_addr = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_get_receive_address(
            manager,
            wallet_id,
            FFINetworks::Testnet,
            0,
            error,
        )
    };
    assert!(!receive_addr.is_null());

    let change_addr = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_get_change_address(
            manager,
            wallet_id,
            FFINetworks::Testnet,
            0,
            error,
        )
    };
    assert!(!change_addr.is_null());

    // 7. Get balance
    let mut confirmed: u64 = 0;
    let mut unconfirmed: u64 = 0;
    let success = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_balance(
            manager,
            wallet_id,
            &mut confirmed,
            &mut unconfirmed,
            error,
        )
    };
    assert!(success);
    assert_eq!(confirmed, 0);
    assert_eq!(unconfirmed, 0);

    // Clean up
    unsafe {
        key_wallet_ffi::address::address_free(receive_addr);
        key_wallet_ffi::address::address_free(change_addr);
        key_wallet_ffi::wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
        key_wallet_ffi::wallet_manager::wallet_manager_free(manager);
        key_wallet_ffi::mnemonic::mnemonic_free(mnemonic);
    }
}

#[test]
fn test_seed_to_wallet_workflow() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // 1. Convert mnemonic to seed
    let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
    let passphrase = CString::new("test passphrase").unwrap();

    let mut seed = [0u8; 64];
    let mut seed_len: usize = 0;

    let success = unsafe {
        key_wallet_ffi::mnemonic::mnemonic_to_seed(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            seed.as_mut_ptr(),
            &mut seed_len,
            error,
        )
    };
    assert!(success);
    assert_eq!(seed_len, 64);

    // 2. Create wallet from seed
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_seed(
            seed.as_ptr(),
            seed_len,
            FFINetworks::Testnet,
            error,
        )
    };
    assert!(!wallet.is_null());

    // Clean up
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet);
    }
}

#[test]
fn test_derivation_paths() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Test BIP44 paths
    let mut path_buffer = vec![0u8; 256];

    // Account path
    let success = key_wallet_ffi::derivation::derivation_bip44_account_path(
        FFINetworks::Dash,
        0,
        path_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
        path_buffer.len(),
        error,
    );
    assert!(success);

    let path_str = unsafe {
        std::ffi::CStr::from_ptr(path_buffer.as_ptr() as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert_eq!(path_str, "m/44'/5'/0'");

    // Payment path
    path_buffer.fill(0);
    let success = key_wallet_ffi::derivation::derivation_bip44_payment_path(
        FFINetworks::Dash,
        0,
        false,
        5,
        path_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
        path_buffer.len(),
        error,
    );
    assert!(success);

    let path_str = unsafe {
        std::ffi::CStr::from_ptr(path_buffer.as_ptr() as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert_eq!(path_str, "m/44'/5'/0'/0/5");
}

#[test]
fn test_error_handling() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Test various error conditions

    // 1. Invalid mnemonic
    let invalid_mnemonic = CString::new("invalid mnemonic phrase").unwrap();
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            invalid_mnemonic.as_ptr(),
            ptr::null(),
            FFINetworks::Testnet,
            error,
        )
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);

    // 2. Null pointer errors
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            ptr::null(),
            ptr::null(),
            FFINetworks::Testnet,
            error,
        )
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

    // 3. Invalid seed size
    let invalid_seed = [0u8; 10]; // Too small
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_seed(
            invalid_seed.as_ptr(),
            invalid_seed.len(),
            FFINetworks::Testnet,
            error,
        )
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
}
