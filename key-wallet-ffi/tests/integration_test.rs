//! Integration tests for key-wallet-ffi
//!
//! These tests verify the interaction between different FFI modules

use dash_network::ffi::FFINetwork;
use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use std::ffi::CString;
use std::ptr;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_seed_to_wallet_workflow() {
    let mut error = FFIError::default();
    let error = &mut error as *mut FFIError;

    // 1. Convert mnemonic to seed
    let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
    let passphrase = CString::new("").unwrap();

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
            FFINetwork::Testnet,
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
    let mut error = FFIError::default();
    let error = &mut error as *mut FFIError;

    // Test BIP44 paths
    let mut path_buffer = vec![0u8; 256];

    // Account path
    let success = unsafe {
        key_wallet_ffi::derivation::derivation_bip44_account_path(
            FFINetwork::Mainnet,
            0,
            path_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
            path_buffer.len(),
            error,
        )
    };
    assert!(success);

    let path_str = unsafe {
        std::ffi::CStr::from_ptr(path_buffer.as_ptr() as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert_eq!(path_str, "m/44'/5'/0'");

    // Payment path
    path_buffer.fill(0);
    let success = unsafe {
        key_wallet_ffi::derivation::derivation_bip44_payment_path(
            FFINetwork::Mainnet,
            0,
            false,
            5,
            path_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
            path_buffer.len(),
            error,
        )
    };
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
    let mut error = FFIError::default();
    let error = &mut error as *mut FFIError;

    // Test various error conditions

    // 1. Invalid mnemonic
    let invalid_mnemonic = CString::new("invalid mnemonic phrase").unwrap();
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            invalid_mnemonic.as_ptr(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);

    // 2. Null pointer errors
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(ptr::null(), FFINetwork::Testnet, error)
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

    // 3. Invalid seed size
    let invalid_seed = [0u8; 10]; // Too small
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_seed(
            invalid_seed.as_ptr(),
            invalid_seed.len(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
}
