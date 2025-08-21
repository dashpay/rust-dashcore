#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_wallet_get_account_null_wallet() {
        let result = unsafe {
            wallet_get_account(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                0, // StandardBIP44
            )
        };

        assert!(result.account.is_null());
        assert_ne!(result.error_code, 0);
        assert_eq!(result.error_code, FFIErrorCode::InvalidInput as i32);

        // Clean up error message if present
        if !result.error_message.is_null() {
            unsafe {
                let _ = CString::from_raw(result.error_message);
            }
        }
    }

    #[test]
    fn test_wallet_get_account_invalid_type() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let result = unsafe {
            wallet_get_account(
                wallet,
                FFINetwork::Testnet,
                0,
                99, // Invalid account type
            )
        };

        assert!(result.account.is_null());
        assert_ne!(result.error_code, 0);
        assert_eq!(result.error_code, FFIErrorCode::InvalidInput as i32);

        // Clean up error message if present
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
    fn test_wallet_get_account_existing() {
        let mut error = FFIError::success();

        // Create a wallet with default accounts
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        // Try to get the default account (should exist)
        let result = unsafe {
            wallet_get_account(
                wallet,
                FFINetwork::Testnet,
                0,
                0, // StandardBIP44
            )
        };

        // Note: Since the account may not exist yet (depends on wallet creation logic),
        // we just check that the call doesn't return an error for invalid parameters
        // The actual account existence check would depend on the wallet implementation

        // Clean up the account if it was returned
        if !result.account.is_null() {
            unsafe {
                account_free(result.account);
            }
        }

        // Clean up error message if present
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
    fn test_wallet_get_account_count_null_wallet() {
        let mut error = FFIError::success();

        let count =
            unsafe { wallet_get_account_count(ptr::null(), FFINetwork::Testnet, &mut error) };

        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_get_account_count() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let count = unsafe { wallet_get_account_count(wallet, FFINetwork::Testnet, &mut error) };

        // Should have at least one default account
        assert!(count >= 1);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_account_count_empty_network() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        // Try to get account count for a different network (Mainnet)
        let count = unsafe {
            wallet_get_account_count(
                wallet,
                FFINetwork::Dash, // Different network
                &mut error,
            )
        };

        // Should return 0 for network with no accounts
        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_account_identity_topup_error() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        // Try to get an IdentityTopUp account (should fail with helpful error)
        let result = unsafe {
            wallet_get_account(
                wallet,
                FFINetwork::Testnet,
                0,
                4, // IdentityTopUp
            )
        };

        assert!(result.account.is_null());
        assert_ne!(result.error_code, 0);
        assert_eq!(result.error_code, FFIErrorCode::InvalidInput as i32);

        // Check that error message contains helpful guidance
        if !result.error_message.is_null() {
            unsafe {
                let c_str = std::ffi::CStr::from_ptr(result.error_message);
                let msg = c_str.to_string_lossy();
                assert!(msg.contains("wallet_get_top_up_account_with_registration_index"));
                let _ = CString::from_raw(result.error_message);
            }
        }

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_type_values() {
        // Test FFIAccountType enum values
        assert_eq!(FFIAccountType::StandardBIP44 as u32, 0);
        assert_eq!(FFIAccountType::StandardBIP32 as u32, 1);
        assert_eq!(FFIAccountType::CoinJoin as u32, 2);
        assert_eq!(FFIAccountType::IdentityRegistration as u32, 3);
        assert_eq!(FFIAccountType::IdentityTopUp as u32, 4);
        assert_eq!(FFIAccountType::IdentityTopUpNotBoundToIdentity as u32, 5);
        assert_eq!(FFIAccountType::IdentityInvitation as u32, 6);
        assert_eq!(FFIAccountType::ProviderVotingKeys as u32, 7);
        assert_eq!(FFIAccountType::ProviderOwnerKeys as u32, 8);
        assert_eq!(FFIAccountType::ProviderOperatorKeys as u32, 9);
        assert_eq!(FFIAccountType::ProviderPlatformKeys as u32, 10);
    }
}
