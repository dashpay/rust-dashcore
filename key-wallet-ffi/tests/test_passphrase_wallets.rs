//! Tests for wallet creation with passphrase through FFI
//! These tests demonstrate current issues with passphrase handling in the FFI layer

use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use key_wallet_ffi::types::FFINetwork;
use std::ffi::{CStr, CString};

#[test]
fn test_ffi_wallet_create_from_mnemonic_with_passphrase() {
    // This test shows the issue with creating wallets with passphrases through FFI

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let passphrase = CString::new("my_secure_passphrase").unwrap();

    // Create wallet with passphrase
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            error,
        )
    };

    // Wallet should be created successfully
    assert!(!wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // Try to derive an address from account 0
    // THIS WILL FAIL because account 0 doesn't exist
    let addr = unsafe {
        key_wallet_ffi::address::wallet_derive_receive_address(
            wallet,
            FFINetwork::Testnet,
            0, // account 0
            0, // address index
            error,
        )
    };

    // EXPECTED: This will fail with "Account not found" error
    assert!(addr.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::NotFound);

    if !unsafe { (*error).message.is_null() } {
        let error_msg = unsafe { CStr::from_ptr((*error).message).to_str().unwrap() };
        println!("Expected error: {}", error_msg);
        assert!(error_msg.contains("Account not found") || error_msg.contains("account"));
    }

    // Clean up
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet);
    }
}

#[test]
fn test_ffi_wallet_manager_add_wallet_with_passphrase() {
    // This test shows the issue when adding a wallet with passphrase to the wallet manager

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Create wallet manager
    let manager = unsafe { key_wallet_ffi::wallet_manager::wallet_manager_create(error) };
    assert!(!manager.is_null());

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let passphrase = CString::new("test_passphrase_123").unwrap();

    // Add wallet with passphrase to manager
    let success = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            1, // account_count (ignored)
            error,
        )
    };

    // This should succeed after our previous fix
    assert!(success);
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // Get wallet IDs
    let mut wallet_ids_ptr = std::ptr::null_mut();
    let mut count = 0usize;
    let success = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_ids(
            manager,
            &mut wallet_ids_ptr,
            &mut count,
            error,
        )
    };
    assert!(success);
    assert_eq!(count, 1);

    // Try to get a receive address from the wallet
    // THIS WILL FAIL because the wallet has no accounts
    let addr = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_get_receive_address(
            manager,
            wallet_ids_ptr, // First wallet ID
            FFINetwork::Testnet,
            0, // account_index
            error,
        )
    };

    // EXPECTED: This will fail because the wallet with passphrase has no accounts
    assert!(addr.is_null());

    if !unsafe { (*error).message.is_null() } {
        let error_msg = unsafe { CStr::from_ptr((*error).message).to_str().unwrap() };
        println!("Expected error when getting address: {}", error_msg);
    }

    // Clean up
    unsafe {
        if !wallet_ids_ptr.is_null() && count > 0 {
            key_wallet_ffi::wallet_manager::wallet_manager_free_wallet_ids(wallet_ids_ptr, count);
        }
        key_wallet_ffi::wallet_manager::wallet_manager_free(manager);
    }
}

#[test]
#[ignore] // This test shows what SHOULD work but currently doesn't
fn test_ffi_wallet_with_passphrase_ideal_workflow() {
    // This test demonstrates what the ideal workflow should be for wallets with passphrases

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let passphrase = CString::new("my_passphrase").unwrap();

    // Create wallet with passphrase
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!wallet.is_null());

    // IDEAL: There should be a way to either:
    // 1. Automatically create account 0 with the passphrase during wallet creation
    // 2. Provide a function to add an account with passphrase:
    //    wallet_add_account_with_passphrase(wallet, account_type, network, passphrase, error)
    // 3. Have a callback mechanism to request the passphrase when needed

    // Then we should be able to derive addresses
    let addr = unsafe {
        key_wallet_ffi::address::wallet_derive_receive_address(
            wallet,
            FFINetwork::Testnet,
            0,
            0,
            error,
        )
    };

    // This should work in an ideal implementation
    assert!(!addr.is_null());

    // Clean up
    unsafe {
        if !addr.is_null() {
            key_wallet_ffi::address::address_free(addr);
        }
        key_wallet_ffi::wallet::wallet_free(wallet);
    }
}

#[test]
fn test_demonstrate_passphrase_issue_with_account_creation() {
    // This test clearly demonstrates the core issue with passphrase wallets

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Create two wallets: one without passphrase, one with
    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let empty_passphrase = CString::new("").unwrap();
    let actual_passphrase = CString::new("test123").unwrap();

    // Wallet WITHOUT passphrase
    let wallet_no_pass = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            empty_passphrase.as_ptr(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!wallet_no_pass.is_null());

    // Wallet WITH passphrase
    let wallet_with_pass = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            actual_passphrase.as_ptr(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!wallet_with_pass.is_null());

    // Try to get account count for both wallets
    let count_no_pass = unsafe {
        key_wallet_ffi::account::wallet_get_account_count(
            wallet_no_pass,
            FFINetwork::Testnet,
            error,
        )
    };

    let count_with_pass = unsafe {
        key_wallet_ffi::account::wallet_get_account_count(
            wallet_with_pass,
            FFINetwork::Testnet,
            error,
        )
    };

    println!("Account count without passphrase: {}", count_no_pass);
    println!("Account count with passphrase: {}", count_with_pass);

    // The wallet without passphrase should have account 0 created automatically
    assert!(count_no_pass > 0, "Wallet without passphrase should have at least one account");

    // The wallet with passphrase should have NO accounts
    assert_eq!(count_with_pass, 0, "Wallet with passphrase should have no accounts");

    // This demonstrates the problem: wallets with passphrases can't automatically
    // create accounts because they need the passphrase to derive the account keys

    // Clean up
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet_no_pass);
        key_wallet_ffi::wallet::wallet_free(wallet_with_pass);
    }
}
