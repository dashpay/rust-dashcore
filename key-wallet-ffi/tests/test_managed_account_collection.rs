//! Tests for managed account collection FFI bindings

use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use key_wallet_ffi::managed_account_collection::*;
use key_wallet_ffi::types::{
    FFIAccountCreationOptionType, FFINetwork, FFIWalletAccountCreationOptions,
};
use key_wallet_ffi::wallet_manager::{
    wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
    wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
};
use std::ffi::CString;
use std::ptr;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_managed_account_collection_basic() {
    unsafe {
        let mut error = FFIError::success();

        // Create wallet manager
        let manager = wallet_manager_create(&mut error);
        assert!(!manager.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Add a wallet with default accounts
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = wallet_manager_add_wallet_from_mnemonic_with_options(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            ptr::null(), // Use default options
            &mut error,
        );
        assert!(success);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Get wallet IDs
        let mut wallet_ids_out: *mut u8 = ptr::null_mut();
        let mut count_out: usize = 0;

        let success =
            wallet_manager_get_wallet_ids(manager, &mut wallet_ids_out, &mut count_out, &mut error);
        assert!(success);
        assert_eq!(count_out, 1);
        assert!(!wallet_ids_out.is_null());

        // Get the managed account collection
        let collection = managed_wallet_get_account_collection(
            manager,
            wallet_ids_out,
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(!collection.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Check that we have some accounts
        let count = managed_account_collection_count(collection);
        assert!(count > 0);

        // Check BIP44 accounts
        let mut indices: *mut std::os::raw::c_uint = ptr::null_mut();
        let mut indices_count: usize = 0;
        let success = managed_account_collection_get_bip44_indices(
            collection,
            &mut indices,
            &mut indices_count,
        );
        assert!(success);
        assert!(indices_count > 0);

        // Get first BIP44 account
        let account = managed_account_collection_get_bip44_account(collection, manager, 0);
        assert!(!account.is_null());

        // Clean up
        key_wallet_ffi::managed_account::managed_account_free(account);
        if !indices.is_null() {
            key_wallet_ffi::account_collection::free_u32_array(indices, indices_count);
        }
        managed_account_collection_free(collection);
        wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
        wallet_manager_free(manager);
    }
}

#[test]
fn test_managed_account_collection_with_special_accounts() {
    unsafe {
        let mut error = FFIError::success();

        // Create wallet manager
        let manager = wallet_manager_create(&mut error);
        assert!(!manager.is_null());

        // Create wallet with special accounts
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut options = FFIWalletAccountCreationOptions::default_options();
        options.option_type = FFIAccountCreationOptionType::AllAccounts;

        // Add various special accounts
        let special_types = vec![
            key_wallet_ffi::types::FFIAccountType::ProviderVotingKeys,
            key_wallet_ffi::types::FFIAccountType::ProviderOwnerKeys,
            key_wallet_ffi::types::FFIAccountType::IdentityRegistration,
            key_wallet_ffi::types::FFIAccountType::IdentityInvitation,
        ];
        options.special_account_types = special_types.as_ptr();
        options.special_account_types_count = special_types.len();

        // Configure standard accounts
        let bip44_indices = vec![0, 4, 5, 8];
        let bip32_indices = vec![0];
        let coinjoin_indices = vec![0, 1];
        let topup_indices = vec![0, 1, 2];

        options.bip44_indices = bip44_indices.as_ptr();
        options.bip44_count = bip44_indices.len();

        options.bip32_indices = bip32_indices.as_ptr();
        options.bip32_count = bip32_indices.len();

        options.coinjoin_indices = coinjoin_indices.as_ptr();
        options.coinjoin_count = coinjoin_indices.len();

        options.topup_indices = topup_indices.as_ptr();
        options.topup_count = topup_indices.len();

        let success = wallet_manager_add_wallet_from_mnemonic_with_options(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &options,
            &mut error,
        );
        assert!(success);

        // Get wallet IDs
        let mut wallet_ids_out: *mut u8 = ptr::null_mut();
        let mut count_out: usize = 0;

        let success =
            wallet_manager_get_wallet_ids(manager, &mut wallet_ids_out, &mut count_out, &mut error);
        assert!(success);
        assert_eq!(count_out, 1);

        // Get the managed account collection
        let collection = managed_wallet_get_account_collection(
            manager,
            wallet_ids_out,
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(!collection.is_null());

        // Verify BIP44 accounts
        let mut indices: *mut std::os::raw::c_uint = ptr::null_mut();
        let mut indices_count: usize = 0;
        let success = managed_account_collection_get_bip44_indices(
            collection,
            &mut indices,
            &mut indices_count,
        );
        assert!(success);
        assert_eq!(indices_count, 4);
        if !indices.is_null() {
            key_wallet_ffi::account_collection::free_u32_array(indices, indices_count);
        }

        // Verify BIP32 accounts
        let success = managed_account_collection_get_bip32_indices(
            collection,
            &mut indices,
            &mut indices_count,
        );
        assert!(success);
        assert_eq!(indices_count, 1);
        if !indices.is_null() {
            key_wallet_ffi::account_collection::free_u32_array(indices, indices_count);
        }

        // Verify CoinJoin accounts
        let success = managed_account_collection_get_coinjoin_indices(
            collection,
            &mut indices,
            &mut indices_count,
        );
        assert!(success);
        assert_eq!(indices_count, 2);
        if !indices.is_null() {
            key_wallet_ffi::account_collection::free_u32_array(indices, indices_count);
        }

        // Check special accounts existence
        assert!(managed_account_collection_has_identity_registration(collection));
        assert!(managed_account_collection_has_identity_invitation(collection));
        assert!(managed_account_collection_has_provider_voting_keys(collection));
        assert!(managed_account_collection_has_provider_owner_keys(collection));

        // Get specific accounts
        let identity_reg =
            managed_account_collection_get_identity_registration(collection, manager);
        assert!(!identity_reg.is_null());
        key_wallet_ffi::managed_account::managed_account_free(identity_reg);

        let voting_keys = managed_account_collection_get_provider_voting_keys(collection, manager);
        assert!(!voting_keys.is_null());
        key_wallet_ffi::managed_account::managed_account_free(voting_keys);

        // Clean up
        managed_account_collection_free(collection);
        wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
        wallet_manager_free(manager);
    }
}

#[test]
fn test_managed_account_collection_summary() {
    unsafe {
        use std::ffi::CStr;

        let mut error = FFIError::success();

        // Create wallet manager
        let manager = wallet_manager_create(&mut error);
        assert!(!manager.is_null());

        // Create wallet with multiple account types
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut options = FFIWalletAccountCreationOptions::default_options();
        options.option_type = FFIAccountCreationOptionType::AllAccounts;

        // Add various special accounts
        let special_types = vec![
            key_wallet_ffi::types::FFIAccountType::ProviderVotingKeys,
            key_wallet_ffi::types::FFIAccountType::ProviderOwnerKeys,
            key_wallet_ffi::types::FFIAccountType::IdentityRegistration,
        ];
        options.special_account_types = special_types.as_ptr();
        options.special_account_types_count = special_types.len();

        // Configure standard accounts
        let bip44_indices = vec![0, 1, 2];
        let bip32_indices = vec![0];

        options.bip44_indices = bip44_indices.as_ptr();
        options.bip44_count = bip44_indices.len();

        options.bip32_indices = bip32_indices.as_ptr();
        options.bip32_count = bip32_indices.len();

        let success = wallet_manager_add_wallet_from_mnemonic_with_options(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &options,
            &mut error,
        );
        assert!(success);

        // Get wallet IDs
        let mut wallet_ids_out: *mut u8 = ptr::null_mut();
        let mut count_out: usize = 0;

        let success =
            wallet_manager_get_wallet_ids(manager, &mut wallet_ids_out, &mut count_out, &mut error);
        assert!(success);
        assert_eq!(count_out, 1);

        // Get the managed account collection
        let collection = managed_wallet_get_account_collection(
            manager,
            wallet_ids_out,
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(!collection.is_null());

        // Get the summary
        let summary_ptr = managed_account_collection_summary(collection);
        assert!(!summary_ptr.is_null());

        // Convert to Rust string to verify content
        let summary_cstr = CStr::from_ptr(summary_ptr);
        let summary = summary_cstr.to_str().unwrap();

        // Verify the summary contains expected content
        assert!(summary.contains("Managed Account Summary:"));
        assert!(summary.contains("BIP44 Accounts"));
        assert!(summary.contains("BIP32 Accounts"));
        assert!(summary.contains("Identity Registration Account"));
        assert!(summary.contains("Provider Voting Keys Account"));
        assert!(summary.contains("Provider Owner Keys Account"));

        // Clean up
        key_wallet_ffi::utils::string_free(summary_ptr);
        managed_account_collection_free(collection);
        wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
        wallet_manager_free(manager);
    }
}

#[test]
fn test_managed_account_collection_summary_data() {
    unsafe {
        let mut error = FFIError::success();

        // Create wallet manager
        let manager = wallet_manager_create(&mut error);
        assert!(!manager.is_null());

        // Create wallet with various account types
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut options = FFIWalletAccountCreationOptions::default_options();
        options.option_type = FFIAccountCreationOptionType::AllAccounts;

        // Add various special accounts
        let special_types = vec![
            key_wallet_ffi::types::FFIAccountType::IdentityRegistration,
            key_wallet_ffi::types::FFIAccountType::IdentityInvitation,
        ];
        options.special_account_types = special_types.as_ptr();
        options.special_account_types_count = special_types.len();

        // Configure standard accounts
        let bip44_indices = vec![0, 1, 2, 5];
        let bip32_indices = vec![0];
        let coinjoin_indices = vec![0, 1];
        let topup_indices = vec![0, 1, 2];

        options.bip44_indices = bip44_indices.as_ptr();
        options.bip44_count = bip44_indices.len();

        options.bip32_indices = bip32_indices.as_ptr();
        options.bip32_count = bip32_indices.len();

        options.coinjoin_indices = coinjoin_indices.as_ptr();
        options.coinjoin_count = coinjoin_indices.len();

        options.topup_indices = topup_indices.as_ptr();
        options.topup_count = topup_indices.len();

        let success = wallet_manager_add_wallet_from_mnemonic_with_options(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &options,
            &mut error,
        );
        assert!(success);

        // Get wallet IDs
        let mut wallet_ids_out: *mut u8 = ptr::null_mut();
        let mut count_out: usize = 0;

        let success =
            wallet_manager_get_wallet_ids(manager, &mut wallet_ids_out, &mut count_out, &mut error);
        assert!(success);
        assert_eq!(count_out, 1);

        // Get the managed account collection
        let collection = managed_wallet_get_account_collection(
            manager,
            wallet_ids_out,
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(!collection.is_null());

        // Get the summary data
        let summary = managed_account_collection_summary_data(collection);
        assert!(!summary.is_null());

        let summary_ref = &*summary;

        // Verify BIP44 indices
        assert_eq!(summary_ref.bip44_count, 4);
        assert!(!summary_ref.bip44_indices.is_null());
        let bip44_slice =
            std::slice::from_raw_parts(summary_ref.bip44_indices, summary_ref.bip44_count);
        assert_eq!(bip44_slice, &[0, 1, 2, 5]);

        // Verify BIP32 indices
        assert_eq!(summary_ref.bip32_count, 1);
        assert!(!summary_ref.bip32_indices.is_null());

        // Verify CoinJoin indices
        assert_eq!(summary_ref.coinjoin_count, 2);
        assert!(!summary_ref.coinjoin_indices.is_null());

        // Verify identity topup indices
        assert_eq!(summary_ref.identity_topup_count, 3);
        assert!(!summary_ref.identity_topup_indices.is_null());

        // Verify boolean flags
        assert!(summary_ref.has_identity_registration);
        assert!(summary_ref.has_identity_invitation);

        // Clean up
        managed_account_collection_summary_free(summary);
        managed_account_collection_free(collection);
        wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
        wallet_manager_free(manager);
    }
}

#[test]
fn test_managed_account_collection_null_safety() {
    unsafe {
        let mut error = FFIError::success();

        // Test with null manager
        let collection = managed_wallet_get_account_collection(
            ptr::null(),
            ptr::null(),
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(collection.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null collection for various functions
        assert_eq!(managed_account_collection_count(ptr::null()), 0);
        assert!(!managed_account_collection_has_identity_registration(ptr::null()));
        assert!(managed_account_collection_get_bip44_account(ptr::null(), ptr::null(), 0).is_null());
        assert!(managed_account_collection_summary(ptr::null()).is_null());
        assert!(managed_account_collection_summary_data(ptr::null()).is_null());

        // Test free with null (should not crash)
        managed_account_collection_free(ptr::null_mut());
        managed_account_collection_summary_free(ptr::null_mut());
    }
}

#[test]
fn test_managed_account_collection_nonexistent_accounts() {
    unsafe {
        let mut error = FFIError::success();

        // Create wallet manager
        let manager = wallet_manager_create(&mut error);
        assert!(!manager.is_null());

        // Create wallet with minimal accounts
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = wallet_manager_add_wallet_from_mnemonic_with_options(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            ptr::null(), // Default options
            &mut error,
        );
        assert!(success);

        // Get wallet IDs
        let mut wallet_ids_out: *mut u8 = ptr::null_mut();
        let mut count_out: usize = 0;

        let success =
            wallet_manager_get_wallet_ids(manager, &mut wallet_ids_out, &mut count_out, &mut error);
        assert!(success);
        assert_eq!(count_out, 1);

        // Get the managed account collection
        let collection = managed_wallet_get_account_collection(
            manager,
            wallet_ids_out,
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(!collection.is_null());

        // Try to get non-existent accounts
        let account = managed_account_collection_get_bip44_account(collection, manager, 999);
        assert!(account.is_null());

        let account = managed_account_collection_get_bip32_account(collection, manager, 999);
        assert!(account.is_null());

        let account = managed_account_collection_get_coinjoin_account(collection, manager, 999);
        assert!(account.is_null());

        let account = managed_account_collection_get_identity_topup(collection, manager, 999);
        assert!(account.is_null());

        // Clean up
        managed_account_collection_free(collection);
        wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
        wallet_manager_free(manager);
    }
}

#[test]
fn test_managed_account_collection_wrong_network() {
    unsafe {
        let mut error = FFIError::success();

        // Create wallet manager
        let manager = wallet_manager_create(&mut error);
        assert!(!manager.is_null());

        // Create wallet on testnet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = wallet_manager_add_wallet_from_mnemonic_with_options(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            ptr::null(),
            &mut error,
        );
        assert!(success);

        // Get wallet IDs
        let mut wallet_ids_out: *mut u8 = ptr::null_mut();
        let mut count_out: usize = 0;

        let success =
            wallet_manager_get_wallet_ids(manager, &mut wallet_ids_out, &mut count_out, &mut error);
        assert!(success);
        assert_eq!(count_out, 1);

        // Try to get collection for mainnet (should fail or return empty)
        let collection = managed_wallet_get_account_collection(
            manager,
            wallet_ids_out,
            FFINetwork::Dash, // Wrong network (mainnet)
            &mut error,
        );

        // Should either be null or have no accounts
        if !collection.is_null() {
            let count = managed_account_collection_count(collection);
            assert_eq!(count, 0);
            managed_account_collection_free(collection);
        }

        // Clean up
        wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
        wallet_manager_free(manager);
    }
}
