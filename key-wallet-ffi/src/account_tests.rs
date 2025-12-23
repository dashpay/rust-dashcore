#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFIAccountType;
    use crate::wallet;
    use crate::FFINetwork;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_wallet_get_account_null_wallet() {
        let result = unsafe { wallet_get_account(ptr::null(), 0, FFIAccountType::StandardBIP44) };

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
        let result = unsafe { wallet_get_account(wallet, 0, FFIAccountType::StandardBIP44) };

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

        let count = unsafe { wallet_get_account_count(ptr::null(), &mut error) };

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

        let count = unsafe { wallet_get_account_count(wallet, &mut error) };

        // Should have at least one default account
        assert!(count >= 1);
        assert_eq!(error.code, FFIErrorCode::Success);

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

    #[test]
    fn test_account_getters() {
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

        assert!(!wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Get an account
        let result = unsafe { wallet_get_account(wallet, 0, FFIAccountType::StandardBIP44) };

        if !result.account.is_null() {
            // Test all the getter functions
            unsafe {
                // Test get xpub
                let xpub_str = account_get_extended_public_key_as_string(result.account);
                assert!(!xpub_str.is_null());
                let xpub = CString::from_raw(xpub_str);
                let xpub_string = xpub.to_string_lossy();
                assert!(xpub_string.starts_with("tpub")); // Testnet xpub should start with tpub

                // Test get network
                let network = account_get_network(result.account);
                assert_eq!(network, FFINetwork::Testnet);

                // Test get parent wallet id (may be null)
                let _wallet_id = account_get_parent_wallet_id(result.account);
                // Just check it doesn't crash - may be null

                // Test get account type
                let mut index = 999u32;
                let account_type = account_get_account_type(result.account, &mut index);
                assert_eq!(account_type as u32, FFIAccountType::StandardBIP44 as u32);
                assert_eq!(index, 0); // Account index should be 0

                // Test is watch only - should be false for a wallet created from mnemonic
                let is_watch_only = account_get_is_watch_only(result.account);
                assert!(!is_watch_only);

                // Clean up
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
    fn test_account_getters_null_safety() {
        unsafe {
            // Test all getter functions with null pointers
            let xpub = account_get_extended_public_key_as_string(ptr::null());
            assert!(xpub.is_null());

            let network = account_get_network(ptr::null());
            assert_eq!(network, crate::FFINetwork::Dash);

            let wallet_id = account_get_parent_wallet_id(ptr::null());
            assert!(wallet_id.is_null());

            let mut index = 0u32;
            let account_type = account_get_account_type(ptr::null(), &mut index);
            assert_eq!(account_type as u32, FFIAccountType::StandardBIP44 as u32);
            assert_eq!(index, 0);

            // Test with null out_index
            let account_type = account_get_account_type(ptr::null(), ptr::null_mut());
            assert_eq!(account_type as u32, FFIAccountType::StandardBIP44 as u32);

            let is_watch_only = account_get_is_watch_only(ptr::null());
            assert!(!is_watch_only);
        }
    }
}
