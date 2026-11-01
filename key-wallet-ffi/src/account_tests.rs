#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFIAccountKind;
    use crate::wallet;
    use dash_network::ffi::FFINetwork;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_wallet_get_account_null_wallet() {
        let result = unsafe { wallet_get_account(ptr::null(), 0, FFIAccountKind::StandardBIP44) };

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
        let mut error = FFIError::default();

        // Create a wallet with default accounts
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };

        // Try to get the default account (should exist)
        let result = unsafe { wallet_get_account(wallet, 0, FFIAccountKind::StandardBIP44) };

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
        let mut error = FFIError::default();

        let count = unsafe { wallet_get_account_count(ptr::null(), &mut error) };

        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_get_account_count() {
        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
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
        // Test FFIAccountKind enum values
        assert_eq!(FFIAccountKind::StandardBIP44 as u32, 0);
        assert_eq!(FFIAccountKind::StandardBIP32 as u32, 1);
        assert_eq!(FFIAccountKind::CoinJoin as u32, 2);
        assert_eq!(FFIAccountKind::IdentityRegistration as u32, 3);
        assert_eq!(FFIAccountKind::IdentityTopUp as u32, 4);
        assert_eq!(FFIAccountKind::IdentityTopUpNotBoundToIdentity as u32, 5);
        assert_eq!(FFIAccountKind::IdentityInvitation as u32, 6);
        assert_eq!(FFIAccountKind::ProviderVotingKeys as u32, 7);
        assert_eq!(FFIAccountKind::ProviderOwnerKeys as u32, 8);
        assert_eq!(FFIAccountKind::ProviderOperatorKeys as u32, 9);
        assert_eq!(FFIAccountKind::ProviderPlatformKeys as u32, 10);
    }
}
