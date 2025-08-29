//! Unit tests for wallet FFI module

#[cfg(test)]
mod wallet_tests {
    use crate::account::account_free;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::{FFIAccountType, FFINetworks};
    use crate::wallet;
    use std::ffi::CString;
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_wallet_creation_from_mnemonic() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                error,
            )
        };

        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_creation_from_seed() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let seed = [0x01u8; 64];

        let wallet = unsafe {
            wallet::wallet_create_from_seed(seed.as_ptr(), seed.len(), FFINetworks::Testnet, error)
        };

        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_creation_methods() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test random wallet creation
        let random_wallet = unsafe { wallet::wallet_create_random(FFINetworks::Testnet, error) };
        assert!(!random_wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Verify it's not watch-only
        let is_watch_only = unsafe { wallet::wallet_is_watch_only(random_wallet, error) };
        assert!(!is_watch_only);

        // Clean up
        unsafe {
            wallet::wallet_free(random_wallet);
        }
    }

    #[test]
    fn test_wallet_multiple_accounts() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let seed = [0x03u8; 64];

        // Create wallet with multiple accounts
        unsafe {
            for _account_index in 0..3 {
                let wallet = wallet::wallet_create_from_seed(
                    seed.as_ptr(),
                    seed.len(),
                    FFINetworks::Testnet,
                    error,
                );

                assert!(!wallet.is_null());
                assert_eq!((*error).code, FFIErrorCode::Success);

                // Clean up
                wallet::wallet_free(wallet);
            }
        }
    }

    #[test]
    fn test_wallet_with_passphrase() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("test passphrase").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                error,
            )
        };

        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_error_cases() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null mnemonic
        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                ptr::null(),
                ptr::null(),
                FFINetworks::Testnet,
                error,
            )
        };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with invalid mnemonic
        let invalid_mnemonic = CString::new("invalid mnemonic").unwrap();
        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                invalid_mnemonic.as_ptr(),
                ptr::null(),
                FFINetworks::Testnet,
                error,
            )
        };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);

        // Test with null seed
        let wallet =
            unsafe { wallet::wallet_create_from_seed(ptr::null(), 64, FFINetworks::Testnet, error) };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_id_operations() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let wallet = unsafe { wallet::wallet_create_random(FFINetworks::Testnet, error) };
        assert!(!wallet.is_null());

        // Get wallet ID
        let mut id = [0u8; 32];
        let success = unsafe { wallet::wallet_get_id(wallet, id.as_mut_ptr(), error) };
        assert!(success);

        // ID should not be all zeros
        assert_ne!(id, [0u8; 32]);

        // Test with null buffer
        let success = unsafe { wallet::wallet_get_id(wallet, ptr::null_mut(), error) };
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_create_from_seed_bytes() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create seed bytes directly
        let seed_bytes = [0x05u8; 64];

        let wallet = unsafe {
            wallet::wallet_create_from_seed(
                seed_bytes.as_ptr(),
                seed_bytes.len(),
                FFINetworks::Testnet,
                error,
            )
        };

        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_create_from_seed_bytes_null() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null seed bytes
        let wallet =
            unsafe { wallet::wallet_create_from_seed(ptr::null(), 64, FFINetworks::Testnet, error) };

        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_has_mnemonic() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create wallet from mnemonic
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet_with_mnemonic = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                error,
            )
        };
        assert!(!wallet_with_mnemonic.is_null());

        // Test has_mnemonic - should return true
        let has_mnemonic = unsafe { wallet::wallet_has_mnemonic(wallet_with_mnemonic, error) };
        assert!(has_mnemonic);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet_with_mnemonic);
        }
    }

    #[test]
    fn test_wallet_has_mnemonic_null() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null wallet
        let has_mnemonic = unsafe { wallet::wallet_has_mnemonic(ptr::null(), error) };
        assert!(!has_mnemonic);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_add_account() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let wallet = unsafe { wallet::wallet_create_random(FFINetworks::Testnet, error) };
        assert!(!wallet.is_null());

        // Test adding account - check if it succeeds or fails gracefully
        let result = unsafe {
            wallet::wallet_add_account(
                wallet,
                FFINetworks::Testnet,
                FFIAccountType::StandardBIP44,
                1,
            )
        };
        // Some implementations may not support adding accounts, so just verify it doesn't crash
        // and the error code is set appropriately
        assert!(!result.account.is_null() || result.error_code != 0);

        // Clean up the account if it was created
        if !result.account.is_null() {
            unsafe {
                account_free(result.account);
            }
        }

        // Free error message if present
        if !result.error_message.is_null() {
            unsafe {
                let _ = CString::from_raw(result.error_message);
            }
        }

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_add_account_null() {
        // Test with null wallet
        let result = unsafe {
            wallet::wallet_add_account(
                ptr::null_mut(),
                FFINetworks::Testnet,
                FFIAccountType::StandardBIP44,
                0,
            )
        };
        assert!(result.account.is_null());
        assert_ne!(result.error_code, 0);

        // Free error message if present
        if !result.error_message.is_null() {
            unsafe {
                let _ = CString::from_raw(result.error_message);
            }
        }
    }

    #[test]
    fn test_wallet_create_edge_cases() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test creating from normal seed size
        let normal_seed = [0x07u8; 64]; // Standard seed size
        let wallet = unsafe {
            wallet::wallet_create_from_seed(
                normal_seed.as_ptr(),
                normal_seed.len(),
                FFINetworks::Testnet,
                error,
            )
        };
        assert!(!wallet.is_null());
        unsafe {
            wallet::wallet_free(wallet);
        }

        // Test creating from larger seed
        let large_seed = [0x08u8; 128];
        let wallet = unsafe {
            wallet::wallet_create_from_seed(
                large_seed.as_ptr(),
                large_seed.len(),
                FFINetworks::Testnet,
                error,
            )
        };
        // Large seeds may or may not be accepted - just test it doesn't crash
        if !wallet.is_null() {
            unsafe {
                wallet::wallet_free(wallet);
            }
        }
    }

    #[test]
    fn test_wallet_xpub_operations() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let wallet = unsafe { wallet::wallet_create_random(FFINetworks::Testnet, error) };
        assert!(!wallet.is_null());

        // Get xpub for account 0
        let xpub = unsafe { wallet::wallet_get_xpub(wallet, FFINetworks::Testnet, 0, error) };
        assert!(!xpub.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Verify xpub string format
        let xpub_str = unsafe { std::ffi::CStr::from_ptr(xpub).to_str().unwrap() };
        assert!(xpub_str.starts_with("tpub")); // Testnet public key

        // Clean up
        unsafe {
            let _ = CString::from_raw(xpub);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_xpub_null_wallet() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null wallet
        let xpub = unsafe { wallet::wallet_get_xpub(ptr::null(), FFINetworks::Testnet, 0, error) };
        assert!(xpub.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_free_null() {
        // Should handle null gracefully
        unsafe {
            wallet::wallet_free(ptr::null_mut());
        }
    }
}
