#[cfg(test)]
#[allow(clippy::module_inception)]
mod transaction_tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::wallet;
    use crate::FFINetwork;
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;

    #[test]
    fn test_build_transaction_with_null_wallet() {
        let mut error = FFIError::success();

        let output = FFITxOutput {
            address: CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap().into_raw(),
            amount: 100000,
        };

        let mut tx_bytes_out: *mut u8 = ptr::null_mut();
        let mut tx_len_out: usize = 0;

        let success = unsafe {
            wallet_build_transaction(
                ptr::null_mut(),
                0,
                &output,
                1,
                1000,
                &mut tx_bytes_out,
                &mut tx_len_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            let _ = CString::from_raw(output.address as *mut c_char);
            error.free_message();
        }
    }

    #[test]
    fn test_build_transaction_with_null_outputs() {
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

        let mut tx_bytes_out: *mut u8 = ptr::null_mut();
        let mut tx_len_out: usize = 0;

        let success = unsafe {
            wallet_build_transaction(
                wallet,
                0,
                ptr::null(),
                0,
                1000,
                &mut tx_bytes_out,
                &mut tx_len_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
            error.free_message();
        }
    }

    #[test]
    fn test_sign_transaction_with_null_wallet() {
        let mut error = FFIError::success();

        let tx_bytes = [0u8; 100];
        let mut signed_tx_out: *mut u8 = ptr::null_mut();
        let mut signed_len_out: usize = 0;

        let success = unsafe {
            wallet_sign_transaction(
                ptr::null(),
                tx_bytes.as_ptr(),
                tx_bytes.len(),
                &mut signed_tx_out,
                &mut signed_len_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe { error.free_message() };
    }

    #[test]
    fn test_sign_transaction_with_null_tx_bytes() {
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

        let mut signed_tx_out: *mut u8 = ptr::null_mut();
        let mut signed_len_out: usize = 0;

        let success = unsafe {
            wallet_sign_transaction(
                wallet,
                ptr::null(),
                0,
                &mut signed_tx_out,
                &mut signed_len_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
            error.free_message();
        }
    }

    #[test]
    fn test_transaction_context_enum() {
        // Test that enum values are as expected
        assert_eq!(FFITransactionContext::Mempool as u32, 0);
        assert_eq!(FFITransactionContext::InBlock as u32, 1);
        assert_eq!(FFITransactionContext::InChainLockedBlock as u32, 2);
    }

    #[test]
    fn test_build_transaction_not_implemented() {
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

        let output = FFITxOutput {
            address: CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap().into_raw(),
            amount: 100000,
        };

        let mut tx_bytes_out: *mut u8 = ptr::null_mut();
        let mut tx_len_out: usize = 0;

        let success = unsafe {
            wallet_build_transaction(
                wallet,
                0,
                &output,
                1,
                1000,
                &mut tx_bytes_out,
                &mut tx_len_out,
                &mut error,
            )
        };

        // Should fail because not implemented
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::WalletError);

        // Clean up
        unsafe {
            let _ = CString::from_raw(output.address as *mut c_char);
            wallet::wallet_free(wallet);
            error.free_message();
        }
    }

    #[test]
    fn test_sign_transaction_not_implemented() {
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

        let tx_bytes = [0u8; 100];
        let mut signed_tx_out: *mut u8 = ptr::null_mut();
        let mut signed_len_out: usize = 0;

        let success = unsafe {
            wallet_sign_transaction(
                wallet,
                tx_bytes.as_ptr(),
                tx_bytes.len(),
                &mut signed_tx_out,
                &mut signed_len_out,
                &mut error,
            )
        };

        // Should fail because not implemented
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::WalletError);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
            error.free_message();
        }
    }
}
