//! Tests for wallet serialization FFI functions

#[cfg(all(test, feature = "bincode"))]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::{FFINetwork, FFIWalletAccountCreationOptions};
    use crate::wallet_manager;
    use std::ffi::CString;
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_create_wallet_return_serialized_bytes_full_wallet() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        // Create a full wallet with private keys
        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,           // birth_height
                ptr::null(), // default account options
                false,       // don't downgrade to pubkey wallet
                false,       // allow_external_signing
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success, "Failed to create wallet");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);

        // Verify wallet ID is not all zeros
        assert!(wallet_id_out.iter().any(|&b| b != 0), "Wallet ID should not be all zeros");

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }
    }

    #[test]
    fn test_create_wallet_return_serialized_bytes_watch_only() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        // Create a watch-only wallet (no private keys)
        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                true,  // downgrade to pubkey wallet
                false, // watch-only
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success, "Failed to create watch-only wallet");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }
    }

    #[test]
    fn test_create_wallet_return_serialized_bytes_externally_signable() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        // Create an externally signable wallet
        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                true, // downgrade to pubkey wallet
                true, // externally signable
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success, "Failed to create externally signable wallet");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }
    }

    #[test]
    fn test_create_wallet_with_passphrase() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("test_passphrase").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        // Create wallet with passphrase
        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                false,
                false,
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success, "Failed to create wallet with passphrase");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }
    }

    #[test]
    fn test_import_serialized_wallet() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut original_wallet_id = [0u8; 32];

        // First create and serialize a wallet
        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                false,
                false,
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                original_wallet_id.as_mut_ptr(),
                error,
            )
        };

        assert!(success);
        assert!(!wallet_bytes_out.is_null());

        // Now import the wallet into a new manager
        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        let mut imported_wallet_id = [0u8; 32];
        let import_success = unsafe {
            wallet_manager::wallet_manager_import_wallet_from_bytes(
                manager,
                wallet_bytes_out,
                wallet_bytes_len_out,
                imported_wallet_id.as_mut_ptr(),
                error,
            )
        };

        assert!(import_success, "Failed to import wallet");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Wallet IDs should match
        assert_eq!(original_wallet_id, imported_wallet_id, "Wallet IDs should match");

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_invalid_mnemonic() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let invalid_mnemonic = CString::new("invalid mnemonic phrase").unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                invalid_mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                false,
                false,
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(!success, "Should fail with invalid mnemonic");
        assert_ne!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(wallet_bytes_out.is_null());
        assert_eq!(wallet_bytes_len_out, 0);
    }

    #[test]
    fn test_null_mnemonic() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                ptr::null(),
                ptr::null(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                false,
                false,
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(!success, "Should fail with null mnemonic");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_create_wallet_with_custom_account_options() {
        use crate::types::FFIAccountCreationOptionType;

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        // Create custom account options (BIP44 accounts only)
        let bip44_indices = vec![0u32, 1u32, 2u32];

        let account_options = FFIWalletAccountCreationOptions {
            option_type: FFIAccountCreationOptionType::BIP44AccountsOnly,
            bip44_indices: bip44_indices.as_ptr(),
            bip44_count: bip44_indices.len(),
            bip32_indices: ptr::null(),
            bip32_count: 0,
            coinjoin_indices: ptr::null(),
            coinjoin_count: 0,
            topup_indices: ptr::null(),
            topup_count: 0,
            special_account_types: ptr::null(),
            special_account_types_count: 0,
        };

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            wallet_manager::create_wallet_from_mnemonic_return_serialized_bytes(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                &account_options,
                false,
                false,
                &mut wallet_bytes_out,
                &mut wallet_bytes_len_out,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success, "Failed to create wallet with custom options");
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }
    }
}
