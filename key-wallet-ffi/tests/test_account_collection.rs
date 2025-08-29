//! Integration tests for account collection FFI functions

use key_wallet_ffi::account::account_free;
use key_wallet_ffi::account_collection::*;
use key_wallet_ffi::types::{
    FFIAccountCreationOptionType, FFINetworks, FFIWalletAccountCreationOptions,
};
use key_wallet_ffi::wallet::{wallet_create_from_mnemonic_with_options, wallet_free};
use std::ffi::CString;
use std::ptr;

#[test]
fn test_account_collection_comprehensive() {
    unsafe {
        // Create a test mnemonic
        let mnemonic = CString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        // Create wallet with various account types
        let account_options = FFIWalletAccountCreationOptions {
            option_type: FFIAccountCreationOptionType::AllAccounts,
            bip44_indices: [0, 1, 2].as_ptr(),
            bip44_count: 3,
            bip32_indices: [0].as_ptr(),
            bip32_count: 1,
            coinjoin_indices: [0, 1].as_ptr(),
            coinjoin_count: 2,
            topup_indices: [0, 1, 2].as_ptr(),
            topup_count: 3,
            special_account_types: ptr::null(),
            special_account_types_count: 0,
        };

        let wallet = wallet_create_from_mnemonic_with_options(
            mnemonic.as_ptr(),
            ptr::null(),
            FFINetworks::Testnet,
            &account_options,
            ptr::null_mut(),
        );
        assert!(!wallet.is_null());

        // Get account collection for testnet
        let collection =
            wallet_get_account_collection(wallet, FFINetworks::Testnet, ptr::null_mut());
        assert!(!collection.is_null());

        // Test account count
        let count = account_collection_count(collection);
        assert!(count > 0, "Should have at least some accounts");

        // Test BIP44 accounts
        let mut bip44_indices: *mut u32 = ptr::null_mut();
        let mut bip44_count: usize = 0;
        let success =
            account_collection_get_bip44_indices(collection, &mut bip44_indices, &mut bip44_count);
        assert!(success);
        assert_eq!(bip44_count, 3, "Should have 3 BIP44 accounts");

        // Get each BIP44 account
        for i in 0..3 {
            let account = account_collection_get_bip44_account(collection, i);
            assert!(!account.is_null(), "BIP44 account {} should exist", i);
            account_free(account);
        }

        // Test BIP32 accounts
        let mut bip32_indices: *mut u32 = ptr::null_mut();
        let mut bip32_count: usize = 0;
        let success =
            account_collection_get_bip32_indices(collection, &mut bip32_indices, &mut bip32_count);
        assert!(success);
        assert_eq!(bip32_count, 1, "Should have 1 BIP32 account");

        let bip32_account = account_collection_get_bip32_account(collection, 0);
        assert!(!bip32_account.is_null());
        account_free(bip32_account);

        // Test CoinJoin accounts
        let mut coinjoin_indices: *mut u32 = ptr::null_mut();
        let mut coinjoin_count: usize = 0;
        let success = account_collection_get_coinjoin_indices(
            collection,
            &mut coinjoin_indices,
            &mut coinjoin_count,
        );
        assert!(success);
        assert_eq!(coinjoin_count, 2, "Should have 2 CoinJoin accounts");

        // Test special accounts existence
        assert!(account_collection_has_identity_registration(collection));
        assert!(account_collection_has_identity_invitation(collection));
        assert!(account_collection_has_provider_voting_keys(collection));
        assert!(account_collection_has_provider_owner_keys(collection));

        // Test getting special accounts
        let identity_reg = account_collection_get_identity_registration(collection);
        assert!(!identity_reg.is_null());
        account_free(identity_reg);

        let identity_inv = account_collection_get_identity_invitation(collection);
        assert!(!identity_inv.is_null());
        account_free(identity_inv);

        // Test identity topup accounts
        let mut topup_indices: *mut u32 = ptr::null_mut();
        let mut topup_count: usize = 0;
        let success = account_collection_get_identity_topup_indices(
            collection,
            &mut topup_indices,
            &mut topup_count,
        );
        assert!(success);
        assert_eq!(topup_count, 3, "Should have 3 identity topup accounts");

        // Get each topup account
        for i in 0..3 {
            let topup = account_collection_get_identity_topup(collection, i);
            assert!(!topup.is_null(), "Identity topup {} should exist", i);
            account_free(topup);
        }

        // Clean up arrays
        if !bip44_indices.is_null() {
            free_u32_array(bip44_indices, bip44_count);
        }
        if !bip32_indices.is_null() {
            free_u32_array(bip32_indices, bip32_count);
        }
        if !coinjoin_indices.is_null() {
            free_u32_array(coinjoin_indices, coinjoin_count);
        }
        if !topup_indices.is_null() {
            free_u32_array(topup_indices, topup_count);
        }

        // Clean up
        account_collection_free(collection);
        wallet_free(wallet);
    }
}

#[test]
fn test_account_collection_minimal() {
    unsafe {
        // Create a test mnemonic
        let mnemonic = CString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        // Create wallet with minimal accounts (default)
        let wallet = wallet_create_from_mnemonic_with_options(
            mnemonic.as_ptr(),
            ptr::null(),
            FFINetworks::Testnet,
            ptr::null(), // Use default options
            ptr::null_mut(),
        );
        assert!(!wallet.is_null());

        // Get account collection
        let collection =
            wallet_get_account_collection(wallet, FFINetworks::Testnet, ptr::null_mut());
        assert!(!collection.is_null());

        // Should have at least some default accounts
        let count = account_collection_count(collection);
        assert!(count > 0, "Default wallet should have some accounts");

        // Check for BIP44 account 0 (should exist by default)
        let account0 = account_collection_get_bip44_account(collection, 0);
        assert!(!account0.is_null(), "Default wallet should have BIP44 account 0");
        account_free(account0);

        // Clean up
        account_collection_free(collection);
        wallet_free(wallet);
    }
}

#[test]
fn test_account_collection_null_safety() {
    unsafe {
        // Test null safety of various functions
        assert_eq!(account_collection_count(ptr::null()), 0);
        assert!(!account_collection_has_identity_registration(ptr::null()));
        assert!(!account_collection_has_identity_invitation(ptr::null()));
        assert!(account_collection_get_bip44_account(ptr::null(), 0).is_null());
        assert!(account_collection_get_identity_registration(ptr::null()).is_null());

        // Test free with null (should not crash)
        account_collection_free(ptr::null_mut());
        free_u32_array(ptr::null_mut(), 0);
    }
}
