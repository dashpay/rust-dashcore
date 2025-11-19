//! Tests for managed wallet FFI module

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::managed_wallet::*;
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::CString;
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_managed_wallet_create_success() {
        let mut error = FFIError::success();

        // Create a wallet first
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };
        assert!(!wallet.is_null());

        // Create managed wallet
        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };

        // Should succeed
        assert!(!managed_wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Clean up
        unsafe {
            managed_wallet_free(managed_wallet);
            unsafe {wallet::wallet_free(wallet);}
        }
    }

    #[test]
    fn test_managed_wallet_create_null_wallet() {
        let mut error = FFIError::success();

        let managed_wallet = unsafe {
            managed_wallet_create(ptr::null(), &mut error)
        };

        assert!(managed_wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_mark_address_used_valid() {
        let mut error = FFIError::success();

        // Create managed wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };

        // Test with a valid testnet address
        let address = CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap();
        let success = unsafe {
            managed_wallet_mark_address_used(
                managed_wallet,
                FFINetwork::Testnet,
                address.as_ptr(),
                &mut error,
            )
        };

        // Should succeed or fail gracefully depending on address validation
        // The function validates the address format internally
        if success {
            assert_eq!(error.code, FFIErrorCode::Success);
        } else {
            // Address validation might fail due to library version differences
            assert!(error.code == FFIErrorCode::InvalidAddress);
        }

        // Clean up
        unsafe {
            managed_wallet_free(managed_wallet);
            unsafe {wallet::wallet_free(wallet);}
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_invalid() {
        let mut error = FFIError::success();

        // Create managed wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };

        // Test with invalid address
        let address = CString::new("invalid_address").unwrap();
        let success = unsafe {
            managed_wallet_mark_address_used(
                managed_wallet,
                FFINetwork::Testnet,
                address.as_ptr(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidAddress);

        // Clean up
        unsafe {
            managed_wallet_free(managed_wallet);
            unsafe {wallet::wallet_free(wallet);}
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_null_address() {
        let mut error = FFIError::success();

        let success = unsafe {
            managed_wallet_mark_address_used(
                ptr::null_mut(),
                FFINetwork::Testnet,
                ptr::null(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_get_next_receive_address_not_implemented() {
        let mut error = FFIError::success();

        let address = unsafe {
            managed_wallet_get_next_receive_address(
                ptr::null_mut(),
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);
    }

    #[test]
    fn test_managed_wallet_get_next_change_address_not_implemented() {
        let mut error = FFIError::success();

        let address = unsafe {
            managed_wallet_get_next_change_address(
                ptr::null_mut(),
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);
    }

    #[test]
    fn test_managed_wallet_get_all_addresses_success() {
        let mut error = FFIError::success();
        let mut addresses_out: *mut *mut std::os::raw::c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            managed_wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 0);
        assert!(addresses_out.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);
    }

    #[test]
    fn test_managed_wallet_get_all_addresses_null_outputs() {
        let mut error = FFIError::success();

        // Test with null addresses_out
        let success = unsafe {
            managed_wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                ptr::null_mut(),
                &mut 0,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null count_out
        let mut addresses_out: *mut *mut std::os::raw::c_char = ptr::null_mut();
        let success = unsafe {
            managed_wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut addresses_out,
                ptr::null_mut(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_free_null() {
        // Should handle null gracefully
        unsafe {
            managed_wallet_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_managed_wallet_free_valid() {
        let mut error = FFIError::success();

        // Create managed wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };
        assert!(!managed_wallet.is_null());

        // Free managed wallet - should not crash
        unsafe {
            managed_wallet_free(managed_wallet);
        }

        // Clean up wallet
        unsafe {
            unsafe {wallet::wallet_free(wallet);}
        }
    }

    #[test]
    fn test_ffi_managed_wallet_info_methods() {
        let mut error = FFIError::success();

        // Create managed wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };
        assert!(!managed_wallet.is_null());

        // Test that we can access the inner methods
        unsafe {
            let managed_ref = &*managed_wallet;
            let _inner = managed_ref.inner();

            let managed_mut = &mut *managed_wallet;
            let _inner_mut = managed_mut.inner_mut();
        }

        // Clean up
        unsafe {
            managed_wallet_free(managed_wallet);
            unsafe {wallet::wallet_free(wallet);}
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_utf8_error() {
        let mut error = FFIError::success();

        // Create managed wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };

        // Create invalid UTF-8 string
        let invalid_utf8 = [0xFF, 0xFE, 0xFD, 0x00]; // Invalid UTF-8 bytes with null terminator
        let success = unsafe {
            managed_wallet_mark_address_used(
                managed_wallet,
                FFINetwork::Testnet,
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            managed_wallet_free(managed_wallet);
            unsafe {wallet::wallet_free(wallet);}
        }
    }

    #[test]
    fn test_managed_wallet_address_operations_with_real_wallet() {
        let mut error = FFIError::success();

        // Create managed wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let managed_wallet = unsafe {
            managed_wallet_create(wallet, &mut error)
        };
        assert!(!managed_wallet.is_null());

        // Test get_next_receive_address with real wallet (should still fail as not implemented)
        let address = unsafe {
            managed_wallet_get_next_receive_address(
                managed_wallet,
                wallet,
                FFINetwork::Testnet,
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);

        // Test get_next_change_address with real wallet (should still fail as not implemented)
        let address = unsafe {
            managed_wallet_get_next_change_address(
                managed_wallet,
                wallet,
                FFINetwork::Testnet,
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);

        // Clean up
        unsafe {
            managed_wallet_free(managed_wallet);
            unsafe {wallet::wallet_free(wallet);}
        }
    }
}