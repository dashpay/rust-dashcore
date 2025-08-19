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
            CString::from_raw(xpub);
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
        for account_index in 0..3 {
            let wallet = unsafe {
                wallet::wallet_create_from_seed(
                    seed.as_ptr(),
                    seed.len(),
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
}
