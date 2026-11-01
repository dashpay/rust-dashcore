//! Tests for key derivation FFI functions

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::keys::*;
    use crate::wallet;
    use dash_network::ffi::FFINetwork;
    use std::ffi::{CStr, CString};
    use std::ptr;

    // Note: wallet_get_account_xpriv is not implemented for security reasons
    // The function always returns null to prevent private key extraction
    #[test]
    fn test_wallet_get_account_xpriv_not_implemented() {
        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());

        // Try to get account xpriv - should fail
        let xpriv_str = unsafe { wallet_get_account_xpriv(wallet, 0, &mut error) };

        // Should return null (not implemented for security)
        assert!(xpriv_str.is_null());
        assert_eq!(error.code, FFIErrorCode::InternalError);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_account_xpub() {
        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());

        // Get account xpub
        let xpub_str = unsafe { wallet_get_account_xpub(wallet, 0, &mut error) };

        assert!(!xpub_str.is_null());

        let xpub = unsafe { CStr::from_ptr(xpub_str).to_str().unwrap() };
        assert!(xpub.starts_with("tpub")); // Testnet public key

        // Clean up
        unsafe {
            crate::utils::string_free(xpub_str);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_derive_public_key_as_hex() {
        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Derive public key as hex directly
        let path = CString::new("m/44'/1'/0'/0/0").unwrap();
        let hex_str = unsafe { wallet_derive_public_key_as_hex(wallet, path.as_ptr(), &mut error) };
        assert!(!hex_str.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        let hex = unsafe { CStr::from_ptr(hex_str) }.to_str().unwrap();
        // Public key should start with 02 or 03 (compressed)
        assert!(hex.starts_with("02") || hex.starts_with("03"));
        assert_eq!(hex.len(), 66); // 33 bytes * 2 hex chars

        // Clean up
        unsafe { crate::utils::string_free(hex_str) };
        unsafe { wallet::wallet_free(wallet) };
    }

    #[test]
    fn test_derivation_path_parse() {
        let mut error = FFIError::default();

        // Parse a BIP44 path
        let path = CString::new("m/44'/1'/0'/0/5").unwrap();

        let mut indices_out: *mut u32 = ptr::null_mut();
        let mut hardened_out: *mut bool = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            derivation_path_parse(
                path.as_ptr(),
                &mut indices_out,
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 5);
        assert!(!indices_out.is_null());
        assert!(!hardened_out.is_null());

        // Check the parsed values
        let indices = unsafe { std::slice::from_raw_parts(indices_out, count_out) };
        let hardened = unsafe { std::slice::from_raw_parts(hardened_out, count_out) };

        assert_eq!(indices[0], 44);
        assert!(hardened[0]); // 44'
        assert_eq!(indices[1], 1);
        assert!(hardened[1]); // 1'
        assert_eq!(indices[2], 0);
        assert!(hardened[2]); // 0'
        assert_eq!(indices[3], 0);
        assert!(!hardened[3]); // 0
        assert_eq!(indices[4], 5);
        assert!(!hardened[4]); // 5

        // Clean up
        unsafe {
            derivation_path_free(indices_out, hardened_out, count_out);
        }
    }

    #[test]
    fn test_derivation_path_parse_root() {
        let mut error = FFIError::default();

        // Parse root path
        let path = CString::new("m").unwrap();

        let mut indices_out: *mut u32 = ptr::null_mut();
        let mut hardened_out: *mut bool = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            derivation_path_parse(
                path.as_ptr(),
                &mut indices_out,
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 0); // Root path has no indices

        // Clean up (should handle null pointers gracefully)
        unsafe {
            derivation_path_free(indices_out, hardened_out, count_out);
        }
    }

    #[test]
    fn test_error_handling() {
        let mut error = FFIError::default();

        // Test with null wallet
        let xpriv = unsafe { wallet_get_account_xpriv(ptr::null(), 0, &mut error) };
        assert!(xpriv.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with invalid path
        let invalid_path = CString::new("invalid/path").unwrap();
        let mut indices_out: *mut u32 = ptr::null_mut();
        let mut hardened_out: *mut bool = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            derivation_path_parse(
                invalid_path.as_ptr(),
                &mut indices_out,
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
    }

    #[test]
    fn test_derivation_path_parse_null_inputs() {
        let mut error = FFIError::default();

        // Test with null path
        let mut indices_out: *mut u32 = ptr::null_mut();
        let mut hardened_out: *mut bool = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            derivation_path_parse(
                ptr::null(),
                &mut indices_out,
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null output pointers
        let path = CString::new("m/44'/1'/0'").unwrap();
        let success = unsafe {
            derivation_path_parse(
                path.as_ptr(),
                ptr::null_mut(),
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_path_complex_cases() {
        let mut error = FFIError::default();

        // Test single hardened index
        let path = CString::new("m/44'").unwrap();

        let mut indices_out: *mut u32 = ptr::null_mut();
        let mut hardened_out: *mut bool = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            derivation_path_parse(
                path.as_ptr(),
                &mut indices_out,
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 1);

        let indices = unsafe { std::slice::from_raw_parts(indices_out, count_out) };
        let hardened = unsafe { std::slice::from_raw_parts(hardened_out, count_out) };

        assert_eq!(indices[0], 44);
        assert!(hardened[0]);

        // Clean up
        unsafe {
            derivation_path_free(indices_out, hardened_out, count_out);
        }

        // Test mixed hardened and non-hardened
        let path = CString::new("m/1'/2/3'").unwrap();

        let success = unsafe {
            derivation_path_parse(
                path.as_ptr(),
                &mut indices_out,
                &mut hardened_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(count_out, 3);

        let indices = unsafe { std::slice::from_raw_parts(indices_out, count_out) };
        let hardened = unsafe { std::slice::from_raw_parts(hardened_out, count_out) };

        assert_eq!(indices[0], 1);
        assert!(hardened[0]);
        assert_eq!(indices[1], 2);
        assert!(!hardened[1]);
        assert_eq!(indices[2], 3);
        assert!(hardened[2]);

        // Clean up
        unsafe {
            derivation_path_free(indices_out, hardened_out, count_out);
        }
    }

    #[test]
    fn test_wallet_get_account_xpub_edge_cases() {
        let mut error = FFIError::default();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());

        // Test different account indices
        for account_index in 0..3 {
            let xpub_str = unsafe { wallet_get_account_xpub(wallet, account_index, &mut error) };

            if !xpub_str.is_null() {
                let xpub = unsafe { CStr::from_ptr(xpub_str).to_str().unwrap() };
                assert!(xpub.starts_with("tpub")); // Testnet public key

                // Clean up
                unsafe {
                    crate::utils::string_free(xpub_str);
                }
            }
        }

        // Test with null wallet
        let xpub_str = unsafe { wallet_get_account_xpub(ptr::null(), 0, &mut error) };

        assert!(xpub_str.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_derivation_path_free_edge_cases() {
        // Test freeing null pointers
        unsafe {
            derivation_path_free(ptr::null_mut(), ptr::null_mut(), 0);
        }
    }
}
