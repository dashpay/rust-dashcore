//! Integration tests for key-wallet-ffi
//!
//! These tests verify the interaction between different FFI modules

use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use key_wallet_ffi::types::FFINetwork;
use std::ffi::CString;
use std::ptr;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_full_wallet_workflow() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // 1. Generate a mnemonic
    let mnemonic = unsafe { key_wallet_ffi::mnemonic::mnemonic_generate(12, error) };
    assert!(!mnemonic.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // 2. Validate the mnemonic
    let is_valid = unsafe { key_wallet_ffi::mnemonic::mnemonic_validate(mnemonic, error) };
    assert!(is_valid);

    // 3. Create wallet from mnemonic
    let passphrase = CString::new("").unwrap();
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            mnemonic,
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!wallet.is_null());

    // 4. Derive addresses
    let receive_addr = unsafe {
        key_wallet_ffi::address::wallet_derive_receive_address(
            wallet,
            FFINetwork::Testnet,
            0,
            0,
            error,
        )
    };
    assert!(!receive_addr.is_null());

    let change_addr = unsafe {
        key_wallet_ffi::address::wallet_derive_change_address(
            wallet,
            FFINetwork::Testnet,
            0,
            0,
            error,
        )
    };
    assert!(!change_addr.is_null());

    // 5. Get balance
    let mut balance = key_wallet_ffi::balance::FFIBalance::default();
    let success = unsafe {
        key_wallet_ffi::balance::wallet_get_balance(
            wallet,
            FFINetwork::Testnet,
            &mut balance,
            error,
        )
    };
    assert!(success);
    assert_eq!(balance.confirmed, 0);

    // 6. Get wallet ID
    let mut id = [0u8; 32];
    let success = unsafe { key_wallet_ffi::wallet::wallet_get_id(wallet, id.as_mut_ptr(), error) };
    assert!(success);
    assert_ne!(id, [0u8; 32]);

    // Clean up
    unsafe {
        key_wallet_ffi::mnemonic::mnemonic_free(mnemonic);
        key_wallet_ffi::address::address_free(receive_addr);
        key_wallet_ffi::address::address_free(change_addr);
        key_wallet_ffi::wallet::wallet_free(wallet);
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
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!wallet.is_null());

    // 3. Derive multiple addresses
    let mut addresses = Vec::new();
    for i in 0..5 {
        let addr = unsafe {
            key_wallet_ffi::address::wallet_derive_receive_address(
                wallet,
                FFINetwork::Testnet,
                0,
                i,
                error,
            )
        };
        assert!(!addr.is_null());

        let addr_str = unsafe { std::ffi::CStr::from_ptr(addr).to_str().unwrap().to_string() };

        // Addresses should be unique
        assert!(!addresses.contains(&addr_str));
        addresses.push(addr_str);

        unsafe {
            key_wallet_ffi::address::address_free(addr);
        }
    }

    assert_eq!(addresses.len(), 5);

    // Clean up
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet);
    }
}

#[test]
fn test_watch_only_wallet() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // 1. Create a regular wallet
    let seed = vec![0x01u8; 64];
    let source_wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_seed(
            seed.as_ptr(),
            seed.len(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!source_wallet.is_null());

    // 2. Get xpub
    let xpub = unsafe {
        key_wallet_ffi::wallet::wallet_get_xpub(source_wallet, FFINetwork::Testnet, 0, error)
    };
    assert!(!xpub.is_null());

    // 3. Create watch-only wallet from xpub
    let watch_wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_xpub(xpub, FFINetwork::Testnet, error)
    };
    assert!(!watch_wallet.is_null());

    // 4. Verify it's watch-only
    let is_watch_only =
        unsafe { key_wallet_ffi::wallet::wallet_is_watch_only(watch_wallet, error) };
    assert!(is_watch_only);

    // 5. Verify regular wallet is not watch-only
    let is_watch_only =
        unsafe { key_wallet_ffi::wallet::wallet_is_watch_only(source_wallet, error) };
    assert!(!is_watch_only);

    // 6. Both wallets should derive the same addresses
    let addr1 = unsafe {
        key_wallet_ffi::address::wallet_derive_receive_address(
            source_wallet,
            FFINetwork::Testnet,
            0,
            0,
            error,
        )
    };
    assert!(!addr1.is_null());

    let addr2 = unsafe {
        key_wallet_ffi::address::wallet_derive_receive_address(
            watch_wallet,
            FFINetwork::Testnet,
            0,
            0,
            error,
        )
    };
    assert!(!addr2.is_null());

    let addr1_str = unsafe { std::ffi::CStr::from_ptr(addr1).to_str().unwrap() };
    let addr2_str = unsafe { std::ffi::CStr::from_ptr(addr2).to_str().unwrap() };

    assert_eq!(addr1_str, addr2_str);

    // Clean up
    unsafe {
        key_wallet_ffi::address::address_free(addr1);
        key_wallet_ffi::address::address_free(addr2);
        key_wallet_ffi::wallet::wallet_free(source_wallet);
        key_wallet_ffi::wallet::wallet_free(watch_wallet);
        key_wallet_ffi::utils::string_free(xpub);
    }
}

#[test]
fn test_derivation_paths() {
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Test BIP44 paths
    let mut path_buffer = vec![0u8; 256];

    // Account path
    let success = unsafe {
        key_wallet_ffi::derivation::derivation_bip44_account_path(
            FFINetwork::Dash,
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
            FFINetwork::Dash,
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
    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Test various error conditions

    // 1. Invalid mnemonic
    let invalid_mnemonic = CString::new("invalid mnemonic phrase").unwrap();
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_mnemonic(
            invalid_mnemonic.as_ptr(),
            ptr::null(),
            FFINetwork::Testnet,
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
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

    // 3. Invalid seed size
    let invalid_seed = vec![0u8; 10]; // Too small
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
