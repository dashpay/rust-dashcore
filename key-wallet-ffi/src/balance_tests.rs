//! Unit tests for balance FFI module

#[cfg(test)]
mod tests {
    use crate::balance::{self, FFIBalance};
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ptr;

    fn create_test_wallet() -> (*mut crate::types::FFIWallet, *mut FFIError) {
        let mut error = FFIError::success();
        let error_ptr = &mut error as *mut FFIError;

        let wallet = wallet::wallet_create_random(FFINetwork::Testnet, error_ptr);

        (wallet, error_ptr)
    }

    #[test]
    fn test_balance_retrieval() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        let mut balance = FFIBalance::default();

        let success = balance::wallet_get_balance(wallet, FFINetwork::Testnet, &mut balance, error);

        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Balance should be zero for new wallet
        assert_eq!(balance.confirmed, 0);
        assert_eq!(balance.unconfirmed, 0);
        assert_eq!(balance.total, 0);

        // Clean up
        wallet::wallet_free(wallet);
    }

    #[test]
    fn test_account_balance() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        let mut balance = FFIBalance::default();

        let success = balance::wallet_get_account_balance(
            wallet,
            FFINetwork::Testnet,
            0, // account_index
            &mut balance,
            error,
        );

        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Balance should be zero for new account
        assert_eq!(balance.confirmed, 0);
        assert_eq!(balance.unconfirmed, 0);

        // Test non-existent account
        let success = balance::wallet_get_account_balance(
            wallet,
            FFINetwork::Testnet,
            999, // non-existent account
            &mut balance,
            error,
        );

        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::NotFound);

        // Clean up
        wallet::wallet_free(wallet);
    }

    #[test]
    fn test_balance_for_multiple_networks() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        let networks = [FFINetwork::Dash, FFINetwork::Testnet, FFINetwork::Devnet];

        for network in networks.iter() {
            let mut balance = FFIBalance::default();

            let success = balance::wallet_get_balance(wallet, *network, &mut balance, error);

            assert!(success);
            assert_eq!(balance.confirmed, 0);
            assert_eq!(balance.unconfirmed, 0);
        }

        // Clean up
        wallet::wallet_free(wallet);
    }

    #[test]
    fn test_balance_with_null_wallet() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut balance = FFIBalance::default();

        let success =
            balance::wallet_get_balance(ptr::null(), FFINetwork::Testnet, &mut balance, error);

        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_balance_null_checks() {
        let (wallet, _) = create_test_wallet();
        assert!(!wallet.is_null());

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null balance output
        let success =
            balance::wallet_get_balance(wallet, FFINetwork::Testnet, ptr::null_mut(), error);

        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test account balance with null output
        let success = balance::wallet_get_account_balance(
            wallet,
            FFINetwork::Testnet,
            0,
            ptr::null_mut(),
            error,
        );

        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Clean up
        wallet::wallet_free(wallet);
    }
}
