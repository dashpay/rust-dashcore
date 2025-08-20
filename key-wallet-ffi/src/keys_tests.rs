//! Tests for key derivation FFI functions

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::keys::*;
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::{CStr, CString};
    use std::ptr;

    // Note: wallet_get_account_xpriv is not implemented for security reasons
    // The function always returns null to prevent private key extraction
    #[test]
    fn test_wallet_get_account_xpriv_not_implemented() {
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

        // Try to get account xpriv - should fail
        let xpriv_str =
            unsafe { wallet_get_account_xpriv(wallet, FFINetwork::Testnet, 0, &mut error) };

        // Should return null (not implemented for security)
        assert!(xpriv_str.is_null());
        assert_eq!(error.code, FFIErrorCode::WalletError);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_account_xpub() {
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

        // Get account xpub
        let xpub_str =
            unsafe { wallet_get_account_xpub(wallet, FFINetwork::Testnet, 0, &mut error) };

        assert!(!xpub_str.is_null());

        let xpub = unsafe { CStr::from_ptr(xpub_str).to_str().unwrap() };
        assert!(xpub.starts_with("tpub")); // Testnet public key

        // Clean up
        unsafe {
            CString::from_raw(xpub_str);
            wallet::wallet_free(wallet);
        }
    }

    // wallet_derive_private_key is now implemented
    #[test]
    fn test_wallet_derive_private_key_now_implemented() {
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

        // Try to derive private key - should now succeed (44'/5'/0'/0/0 for Dash)
        let path = CString::new("m/44'/5'/0'/0/0").unwrap();
        let privkey_ptr = unsafe {
            wallet_derive_private_key(wallet, FFINetwork::Testnet, path.as_ptr(), &mut error)
        };

        // Should succeed and return a valid pointer
        assert!(!privkey_ptr.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Convert to WIF to verify it's valid
        let wif_str = unsafe { private_key_to_wif(privkey_ptr, FFINetwork::Testnet, &mut error) };
        assert!(!wif_str.is_null());

        // Clean up
        unsafe {
            if !wif_str.is_null() {
                let _ = CString::from_raw(wif_str);
            }
            private_key_free(privkey_ptr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_derive_public_key() {
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

        // Ensure wallet was created successfully
        assert!(!wallet.is_null(), "Failed to create wallet");
        assert_eq!(error.code, FFIErrorCode::Success, "Wallet creation error: {:?}", error.code);

        // Derive public key using derivation path (44'/5'/0'/0/0 for Dash)
        let path = CString::new("m/44'/5'/0'/0/0").unwrap();
        let pubkey_ptr = unsafe {
            wallet_derive_public_key(wallet, FFINetwork::Testnet, path.as_ptr(), &mut error)
        };

        if pubkey_ptr.is_null() {
            panic!("pubkey_ptr is null, error: {:?}", error);
        }
        assert_eq!(error.code, FFIErrorCode::Success);

        // Get the hex representation to verify
        let hex_str = unsafe { public_key_to_hex(pubkey_ptr, &mut error) };
        assert!(!hex_str.is_null());

        let hex = unsafe { CStr::from_ptr(hex_str).to_str().unwrap() };
        // Public key should start with 02 or 03 (compressed)
        assert!(hex.starts_with("02") || hex.starts_with("03"));
        assert_eq!(hex.len(), 66); // 33 bytes * 2 hex chars

        // Clean up
        unsafe {
            if !hex_str.is_null() {
                let _ = CString::from_raw(hex_str);
            }
            public_key_free(pubkey_ptr);
        }

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_derivation_path_parse() {
        let mut error = FFIError::success();

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
        let mut error = FFIError::success();

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
        let mut error = FFIError::success();

        // Test with null wallet
        let xpriv =
            unsafe { wallet_get_account_xpriv(ptr::null(), FFINetwork::Testnet, 0, &mut error) };
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
    fn test_wallet_derive_public_key_null_inputs() {
        let mut error = FFIError::success();

        // Test with null wallet (44'/5'/0'/0/0 for Dash)
        let path = CString::new("m/44'/5'/0'/0/0").unwrap();
        let pubkey_ptr = unsafe {
            wallet_derive_public_key(ptr::null(), FFINetwork::Testnet, path.as_ptr(), &mut error)
        };

        assert!(pubkey_ptr.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Create a wallet for subsequent tests
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            crate::wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        // Test with null path
        let pubkey_ptr = unsafe {
            wallet_derive_public_key(wallet, FFINetwork::Testnet, ptr::null(), &mut error)
        };

        assert!(pubkey_ptr.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_derivation_path_parse_null_inputs() {
        let mut error = FFIError::success();

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
        let mut error = FFIError::success();

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
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            crate::wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };
        assert!(!wallet.is_null());

        // Test different account indices
        for account_index in 0..3 {
            let xpub_str = unsafe {
                wallet_get_account_xpub(wallet, FFINetwork::Testnet, account_index, &mut error)
            };

            if !xpub_str.is_null() {
                let xpub = unsafe { CStr::from_ptr(xpub_str).to_str().unwrap() };
                assert!(xpub.starts_with("tpub")); // Testnet public key

                // Clean up
                unsafe {
                    CString::from_raw(xpub_str);
                }
            }
        }

        // Test with null wallet
        let xpub_str =
            unsafe { wallet_get_account_xpub(ptr::null(), FFINetwork::Testnet, 0, &mut error) };

        assert!(xpub_str.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_derive_public_key_different_paths() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            crate::wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        // Test different derivation paths (Dash coin type 5)
        let test_paths = [
            "m/44'/5'/0'/0/0",
            "m/44'/5'/0'/0/1",
            "m/44'/5'/0'/1/0", // Change address
            "m/44'/5'/1'/0/0", // Different account
        ];

        for path_str in test_paths.iter() {
            let path = CString::new(*path_str).unwrap();

            let pubkey_ptr = unsafe {
                wallet_derive_public_key(wallet, FFINetwork::Testnet, path.as_ptr(), &mut error)
            };

            if !pubkey_ptr.is_null() {
                // Get hex representation to verify
                let hex_str = unsafe { public_key_to_hex(pubkey_ptr, &mut error) };
                assert!(!hex_str.is_null());

                let hex = unsafe { CStr::from_ptr(hex_str).to_str().unwrap() };
                // Public key should start with 02 or 03 (compressed)
                assert!(hex.starts_with("02") || hex.starts_with("03"));
                assert_eq!(hex.len(), 66); // 33 bytes * 2 hex chars

                // Clean up
                unsafe {
                    if !hex_str.is_null() {
                        let _ = CString::from_raw(hex_str);
                    }
                    public_key_free(pubkey_ptr);
                }
            }
        }

        // Clean up
        unsafe {
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_derivation_path_free_edge_cases() {
        // Test freeing null pointers
        unsafe {
            derivation_path_free(ptr::null_mut(), ptr::null_mut(), 0);
        }

        // Test freeing with zero count
        let dummy_ptr = 1 as *mut u32;
        let dummy_bool_ptr = 1 as *mut bool;
        unsafe {
            derivation_path_free(dummy_ptr, dummy_bool_ptr, 0);
        }
    }
}
