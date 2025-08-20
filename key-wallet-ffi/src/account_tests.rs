#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::{FFINetwork, FFIWallet};
    use crate::wallet;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_wallet_get_account_null_wallet() {
        let mut error = FFIError::success();

        let success = wallet_get_account(
            ptr::null_mut(),
            FFINetwork::Testnet,
            0,
            0, // Standard account
            &mut error,
        );

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_get_account_invalid_type() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &mut error,
        );

        let success = wallet_get_account(
            wallet,
            FFINetwork::Testnet,
            0,
            99, // Invalid account type
            &mut error,
        );

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

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

        let wallet = wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &mut error,
        );

        // Try to get the default account (should exist)
        let success = wallet_get_account(
            wallet,
            FFINetwork::Testnet,
            0,
            0, // Standard account
            &mut error,
        );

        assert!(success);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_account_count_null_wallet() {
        let mut error = FFIError::success();

        let count = wallet_get_account_count(ptr::null(), FFINetwork::Testnet, &mut error);

        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_get_account_count() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &mut error,
        );

        let count = wallet_get_account_count(wallet, FFINetwork::Testnet, &mut error);

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

        let wallet = wallet::wallet_create_from_mnemonic(
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            FFINetwork::Testnet,
            &mut error,
        );

        // Try to get account count for a different network (Mainnet)
        let count = wallet_get_account_count(
            wallet,
            FFINetwork::Dash, // Different network
            &mut error,
        );

        // Should return 0 for network with no accounts
        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_type_values() {
        // Test FFIAccountType enum values
        assert_eq!(FFIAccountType::Standard as u32, 0);
        assert_eq!(FFIAccountType::CoinJoin as u32, 1);
        assert_eq!(FFIAccountType::Identity as u32, 2);
    }
}
