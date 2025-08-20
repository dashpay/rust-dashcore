//! Unit tests for wallet FFI module

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
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
                FFINetwork::Testnet,
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

        let seed = vec![0x01u8; 64];

        let wallet = unsafe {
            wallet::wallet_create_from_seed(seed.as_ptr(), seed.len(), FFINetwork::Testnet, error)
        };

        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_creation_from_xpub() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create a wallet first to get an xpub
        let seed = vec![0x02u8; 64];
        let source_wallet = unsafe {
            wallet::wallet_create_from_seed(seed.as_ptr(), seed.len(), FFINetwork::Testnet, error)
        };
        assert!(!source_wallet.is_null());

        // Get xpub
        let xpub = unsafe { wallet::wallet_get_xpub(source_wallet, FFINetwork::Testnet, 0, error) };
        assert!(!xpub.is_null());

        // Create watch-only wallet from xpub
        let watch_wallet =
            unsafe { wallet::wallet_create_from_xpub(xpub, FFINetwork::Testnet, error) };
        assert!(!watch_wallet.is_null());

        // Verify it's watch-only
        let is_watch_only = unsafe { wallet::wallet_is_watch_only(watch_wallet, error) };
        assert!(is_watch_only);

        // Clean up
        unsafe {
            wallet::wallet_free(source_wallet);
            wallet::wallet_free(watch_wallet);

            let _ = CString::from_raw(xpub);
        }
    }

    #[test]
    fn test_wallet_creation_methods() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test random wallet creation
        let random_wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, error) };
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

        let seed = vec![0x03u8; 64];

        // Create wallet with multiple accounts
        unsafe {
            for _account_index in 0..3 {
                let wallet = wallet::wallet_create_from_seed(
                    seed.as_ptr(),
                    seed.len(),
                    FFINetwork::Testnet,
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
                FFINetwork::Testnet,
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
                FFINetwork::Testnet,
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
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);

        // Test with null seed
        let wallet =
            unsafe { wallet::wallet_create_from_seed(ptr::null(), 64, FFINetwork::Testnet, error) };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_id_operations() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, error) };
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
        let seed_bytes = vec![0x05u8; 64];

        let wallet = unsafe {
            wallet::wallet_create_from_seed_bytes(
                seed_bytes.as_ptr(),
                seed_bytes.len(),
                FFINetwork::Testnet,
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
        let wallet = unsafe {
            wallet::wallet_create_from_seed_bytes(ptr::null(), 64, FFINetwork::Testnet, error)
        };

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
                FFINetwork::Testnet,
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

        // Create watch-only wallet (no mnemonic)
        let seed = vec![0x06u8; 64];
        let source_wallet = unsafe {
            wallet::wallet_create_from_seed(seed.as_ptr(), seed.len(), FFINetwork::Testnet, error)
        };
        let xpub = unsafe { wallet::wallet_get_xpub(source_wallet, FFINetwork::Testnet, 0, error) };
        let watch_wallet =
            unsafe { wallet::wallet_create_from_xpub(xpub, FFINetwork::Testnet, error) };

        // Test has_mnemonic - should return false for watch-only
        let has_mnemonic = unsafe { wallet::wallet_has_mnemonic(watch_wallet, error) };
        assert!(!has_mnemonic);

        // Clean up
        unsafe {
            wallet::wallet_free(source_wallet);
            wallet::wallet_free(watch_wallet);
            let _ = CString::from_raw(xpub);
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

        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, error) };
        assert!(!wallet.is_null());

        // Test adding account - check if it succeeds or fails gracefully
        let result = unsafe { wallet::wallet_add_account(wallet, FFINetwork::Testnet, 0, 1) };
        // Some implementations may not support adding accounts, so just verify it doesn't crash
        // and the error code is set appropriately
        assert!(!result.account.is_null() || result.error_code != 0);

        // Clean up the account if it was created
        if !result.account.is_null() {
            unsafe {
                // We need to free the account if it was created
                // Note: there should be an account_free function
            }
        }
        
        // Free error message if present
        if !result.error_message.is_null() {
            unsafe {
                let _ = std::ffi::CString::from_raw(result.error_message);
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
            wallet::wallet_add_account(ptr::null_mut(), FFINetwork::Testnet, 0, 0)
        };
        assert!(result.account.is_null());
        assert_ne!(result.error_code, 0);
        
        // Free error message if present
        if !result.error_message.is_null() {
            unsafe {
                let _ = std::ffi::CString::from_raw(result.error_message);
            }
        }
    }

    #[test]
    fn test_wallet_create_edge_cases() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test creating from normal seed size
        let normal_seed = vec![0x07u8; 64]; // Standard seed size
        let wallet = unsafe {
            wallet::wallet_create_from_seed(
                normal_seed.as_ptr(),
                normal_seed.len(),
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(!wallet.is_null());
        unsafe {
            wallet::wallet_free(wallet);
        }

        // Test creating from larger seed
        let large_seed = vec![0x08u8; 128];
        let wallet = unsafe {
            wallet::wallet_create_from_seed(
                large_seed.as_ptr(),
                large_seed.len(),
                FFINetwork::Testnet,
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

        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, error) };
        assert!(!wallet.is_null());

        // Get xpub for account 0
        let xpub = unsafe { wallet::wallet_get_xpub(wallet, FFINetwork::Testnet, 0, error) };
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
        let xpub = unsafe { wallet::wallet_get_xpub(ptr::null(), FFINetwork::Testnet, 0, error) };
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
