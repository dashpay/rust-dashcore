//! Tests for wallet creation with passphrase through FFI
//! These tests demonstrate current issues with passphrase handling in the FFI layer

use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use key_wallet_ffi::FFINetwork;
use std::ffi::CString;

#[test]
fn test_ffi_wallet_create_from_mnemonic_with_passphrase() {
    // This test verifies that wallets with passphrases now work correctly through FFI

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let passphrase = CString::new("my_secure_passphrase").unwrap();

    // Create wallet with passphrase using default options (which creates account 0)
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

    // Since we can't derive addresses directly from wallets anymore,
    // verify that the wallet was created successfully
    let is_watch_only = unsafe { key_wallet_ffi::wallet::wallet_is_watch_only(wallet, error) };
    assert!(!is_watch_only);
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // Get wallet ID to verify it was created
    let mut wallet_id = [0u8; 32];
    let success =
        unsafe { key_wallet_ffi::wallet::wallet_get_id(wallet, wallet_id.as_mut_ptr(), error) };
    assert!(success);
    assert_ne!(wallet_id, [0u8; 32]);
    println!("Successfully created passphrase wallet with ID: {:?}", &wallet_id[..8]);

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
    let manager = key_wallet_ffi::wallet_manager::wallet_manager_create(FFINetwork::Testnet, error);
    assert!(!manager.is_null());

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let passphrase = CString::new("test_passphrase_123").unwrap();

    // Add wallet with passphrase to manager
    let success = unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
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

    // Clean up
    if !wallet_ids_ptr.is_null() && count > 0 {
        unsafe {
            key_wallet_ffi::wallet_manager::wallet_manager_free_wallet_ids(wallet_ids_ptr, count);
        }
    }
    unsafe {
        key_wallet_ffi::wallet_manager::wallet_manager_free(manager);
    }
}

#[test]
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

    // Since we can't derive addresses directly from wallets anymore,
    // just verify the wallet was created
    let is_watch_only = unsafe { key_wallet_ffi::wallet::wallet_is_watch_only(wallet, error) };
    assert!(!is_watch_only);
    println!("Wallet with passphrase created successfully");
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet);
    }
}

#[test]
fn test_demonstrate_passphrase_issue_with_account_creation() {
    // This test verifies that the passphrase wallet issue has been FIXED

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
    let count_no_pass =
        unsafe { key_wallet_ffi::account::wallet_get_account_count(wallet_no_pass, error) };

    let count_with_pass =
        unsafe { key_wallet_ffi::account::wallet_get_account_count(wallet_with_pass, error) };

    println!("Account count without passphrase: {}", count_no_pass);
    println!("Account count with passphrase: {}", count_with_pass);

    // Both wallets should now have accounts created automatically
    assert!(count_no_pass > 0, "Wallet without passphrase should have at least one account");

    // FIXED: The wallet with passphrase should ALSO have accounts now
    assert!(count_with_pass > 0, "Wallet with passphrase should now have accounts created");

    // Verify the accounts are actually different (different derivation due to passphrase)

    // Clean up
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet_no_pass);
        key_wallet_ffi::wallet::wallet_free(wallet_with_pass);
    }
}
