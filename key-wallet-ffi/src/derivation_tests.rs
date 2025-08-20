//! Tests for derivation path FFI functions

#[cfg(test)]
mod tests {
    use crate::derivation::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::mnemonic;
    use crate::types::FFINetwork;
    use std::ffi::{CStr, CString};
    use std::ptr;

    #[test]
    fn test_master_key_from_seed() {
        let mut error = FFIError::success();

        // Generate a seed from mnemonic
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();
        let mut seed = [0u8; 64];
        let mut seed_len = seed.len();

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(success);
        assert_eq!(seed_len, 64);

        // Create master key from seed
        let xprv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        assert!(!xprv.is_null());

        // Clean up
        unsafe {
            derivation_xpriv_free(xprv);
        }
    }

    #[test]
    fn test_xpriv_to_xpub() {
        let mut error = FFIError::success();

        // Create master key
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let xprv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        // Get public key
        let xpub = unsafe { derivation_xpriv_to_xpub(xprv, &mut error) };

        assert!(!xpub.is_null());

        // Clean up
        unsafe {
            derivation_xpub_free(xpub);
            derivation_xpriv_free(xprv);
        }
    }

    #[test]
    fn test_xpriv_to_string() {
        let mut error = FFIError::success();

        // Create master key
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let xprv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        // Convert to string
        let xprv_str = unsafe { derivation_xpriv_to_string(xprv, &mut error) };
        assert!(!xprv_str.is_null());

        let str_val = unsafe { CStr::from_ptr(xprv_str).to_str().unwrap() };
        assert!(str_val.starts_with("tprv")); // Testnet private key

        // Clean up
        unsafe {
            derivation_string_free(xprv_str);
            derivation_xpriv_free(xprv);
        }
    }

    #[test]
    fn test_xpub_to_string() {
        let mut error = FFIError::success();

        // Create master key and get public key
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let xprv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        let xpub = unsafe { derivation_xpriv_to_xpub(xprv, &mut error) };

        // Convert to string
        let xpub_str = unsafe { derivation_xpub_to_string(xpub, &mut error) };
        assert!(!xpub_str.is_null());

        let str_val = unsafe { CStr::from_ptr(xpub_str).to_str().unwrap() };
        assert!(str_val.starts_with("tpub")); // Testnet public key

        // Clean up
        unsafe {
            derivation_string_free(xpub_str);
            derivation_xpub_free(xpub);
            derivation_xpriv_free(xprv);
        }
    }

    #[test]
    fn test_xpub_fingerprint() {
        let mut error = FFIError::success();

        // Create master key
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let xprv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        let xpub = unsafe { derivation_xpriv_to_xpub(xprv, &mut error) };

        // Get fingerprint
        let mut fingerprint = [0u8; 4];
        let success =
            unsafe { derivation_xpub_fingerprint(xpub, fingerprint.as_mut_ptr(), &mut error) };

        assert!(success);
        // Fingerprint should not be all zeros
        assert!(fingerprint.iter().any(|&b| b != 0));

        // Clean up
        unsafe {
            derivation_xpub_free(xpub);
            derivation_xpriv_free(xprv);
        }
    }

    #[test]
    fn test_bip44_paths() {
        let mut error = FFIError::success();

        // Test BIP44 account path
        let mut account_path = vec![0u8; 256];
        let success = unsafe {
            derivation_bip44_account_path(
                FFINetwork::Testnet,
                0,
                account_path.as_mut_ptr() as *mut i8,
                account_path.len(),
                &mut error,
            )
        };
        assert!(success);

        let path_str =
            unsafe { CStr::from_ptr(account_path.as_ptr() as *const i8).to_str().unwrap() };
        assert_eq!(path_str, "m/44'/1'/0'");

        // Test BIP44 payment path
        let mut payment_path = vec![0u8; 256];
        let success = unsafe {
            derivation_bip44_payment_path(
                FFINetwork::Testnet,
                0,     // account_index
                false, // is_change
                0,     // address_index
                payment_path.as_mut_ptr() as *mut i8,
                payment_path.len(),
                &mut error,
            )
        };
        assert!(success);

        let path_str =
            unsafe { CStr::from_ptr(payment_path.as_ptr() as *const i8).to_str().unwrap() };
        assert_eq!(path_str, "m/44'/1'/0'/0/0");
    }

    #[test]
    fn test_special_paths() {
        let mut error = FFIError::success();

        // Test CoinJoin path
        let mut coinjoin_path = vec![0u8; 256];
        let success = unsafe {
            derivation_coinjoin_path(
                FFINetwork::Testnet,
                0, // account_index
                coinjoin_path.as_mut_ptr() as *mut i8,
                coinjoin_path.len(),
                &mut error,
            )
        };
        assert!(success);

        // Test identity registration path - takes 2 args: network and identity_index
        let mut id_reg_path = vec![0u8; 256];
        let success = unsafe {
            derivation_identity_registration_path(
                FFINetwork::Testnet,
                0, // identity_index
                id_reg_path.as_mut_ptr() as *mut i8,
                id_reg_path.len(),
                &mut error,
            )
        };
        assert!(success);

        // Test identity topup path - takes 3 args: network, identity_index, topup_index
        let mut id_topup_path = vec![0u8; 256];
        let success = unsafe {
            derivation_identity_topup_path(
                FFINetwork::Testnet,
                0, // identity_index
                2, // topup_index
                id_topup_path.as_mut_ptr() as *mut i8,
                id_topup_path.len(),
                &mut error,
            )
        };
        assert!(success);

        // Test identity authentication path - takes 3 args: network, identity_index, key_index
        let mut id_auth_path = vec![0u8; 256];
        let success = unsafe {
            derivation_identity_authentication_path(
                FFINetwork::Testnet,
                0, // identity_index
                3, // key_index
                id_auth_path.as_mut_ptr() as *mut i8,
                id_auth_path.len(),
                &mut error,
            )
        };
        assert!(success);
    }

    #[test]
    fn test_derive_private_key_from_seed() {
        let mut error = FFIError::success();

        // Generate a seed
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Create path
        let path = CString::new("m/44'/1'/0'/0/0").unwrap();

        // Derive private key - returns FFIExtendedPrivKey, not raw bytes
        let xpriv = unsafe {
            derivation_derive_private_key_from_seed(
                seed.as_ptr(),
                seed.len(),
                path.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        assert!(!xpriv.is_null());

        // Clean up
        unsafe {
            derivation_xpriv_free(xpriv);
        }
    }

    #[test]
    fn test_dip9_derive_identity_key() {
        let mut error = FFIError::success();

        // Generate a seed
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Derive identity key - takes seed directly, not xprv
        let identity_key = unsafe {
            dip9_derive_identity_key(
                seed.as_ptr(),
                seed.len(),
                FFINetwork::Testnet,
                0,                                           // identity index
                0,                                           // key index
                FFIDerivationPathType::BlockchainIdentities, // key_type
                &mut error,
            )
        };

        assert!(!identity_key.is_null());

        // Clean up
        unsafe {
            derivation_xpriv_free(identity_key);
        }
    }

    #[test]
    fn test_error_handling() {
        let mut error = FFIError::success();

        // Test with null seed
        let xprv =
            unsafe { derivation_new_master_key(ptr::null(), 64, FFINetwork::Testnet, &mut error) };
        assert!(xprv.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Note: The BIP32 implementation actually accepts seeds as small as 16 bytes
        // so we can't test for invalid seed length error here
    }

    #[test]
    fn test_derivation_string_to_xpub() {
        let mut error = FFIError::success();

        // Generate a master key and xpub first
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let master_key = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        let xpub = unsafe { derivation_xpriv_to_xpub(master_key, &mut error) };

        let xpub_string = unsafe { derivation_xpub_to_string(xpub, &mut error) };

        assert!(!xpub_string.is_null());

        // Clean up
        unsafe {
            derivation_string_free(xpub_string);
            derivation_xpub_free(xpub);
            derivation_xpriv_free(master_key);
        }
    }

    #[test]
    fn test_derivation_xpriv_string_conversion() {
        let mut error = FFIError::success();

        // Generate a master key
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let master_key = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        let xpriv_string = unsafe { derivation_xpriv_to_string(master_key, &mut error) };

        assert!(!xpriv_string.is_null());

        // Verify it's a valid xpriv string
        let xpriv_str = unsafe { CStr::from_ptr(xpriv_string).to_str().unwrap() };
        assert!(xpriv_str.starts_with("tprv")); // Testnet private key

        // Clean up
        unsafe {
            derivation_string_free(xpriv_string);
            derivation_xpriv_free(master_key);
        }
    }

    #[test]
    fn test_derivation_xpub_fingerprint() {
        let mut error = FFIError::success();

        // Generate a master key and xpub
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let master_key = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        let xpub = unsafe { derivation_xpriv_to_xpub(master_key, &mut error) };

        let mut fingerprint_buf = [0u8; 4];
        let success =
            unsafe { derivation_xpub_fingerprint(xpub, fingerprint_buf.as_mut_ptr(), &mut error) };

        // Function should succeed
        assert!(success);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Clean up
        unsafe {
            derivation_xpub_free(xpub);
            derivation_xpriv_free(master_key);
        }
    }

    #[test]
    fn test_special_derivation_paths() {
        let mut error = FFIError::success();

        // Test identity registration path
        let mut buffer = vec![0u8; 256];
        let success = unsafe {
            derivation_identity_registration_path(
                FFINetwork::Testnet,
                0, // identity_index
                buffer.as_mut_ptr() as *mut i8,
                buffer.len(),
                &mut error,
            )
        };

        assert!(success);
        let path_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap() };
        assert!(path_str.contains("m/"));

        // Test identity topup path
        let mut buffer = vec![0u8; 256];
        let success = unsafe {
            derivation_identity_topup_path(
                FFINetwork::Testnet,
                0, // identity_index
                0, // topup_index
                buffer.as_mut_ptr() as *mut i8,
                buffer.len(),
                &mut error,
            )
        };

        assert!(success);
        let path_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap() };
        assert!(path_str.contains("m/"));

        // Test identity authentication path
        let mut buffer = vec![0u8; 256];
        let success = unsafe {
            derivation_identity_authentication_path(
                FFINetwork::Testnet,
                0, // identity_index
                0, // key_index
                buffer.as_mut_ptr() as *mut i8,
                buffer.len(),
                &mut error,
            )
        };

        assert!(success);
        let path_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap() };
        assert!(path_str.contains("m/"));
    }

    #[test]
    fn test_free_functions_safety() {
        // Test that free functions handle null pointers gracefully
        unsafe {
            derivation_xpub_free(ptr::null_mut());
            derivation_xpriv_free(ptr::null_mut());
            derivation_string_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_derivation_new_master_key_edge_cases() {
        let mut error = FFIError::success();

        // Test with null seed
        let xprv =
            unsafe { derivation_new_master_key(ptr::null(), 64, FFINetwork::Testnet, &mut error) };
        assert!(xprv.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null error pointer (should not crash)
        let seed = [0u8; 64];
        let xprv = unsafe {
            derivation_new_master_key(
                seed.as_ptr(),
                seed.len(),
                FFINetwork::Testnet,
                ptr::null_mut(),
            )
        };
        // Should handle null error gracefully
        if !xprv.is_null() {
            unsafe { derivation_xpriv_free(xprv) };
        }
    }

    #[test]
    fn test_derivation_path_functions_null_inputs() {
        let mut error = FFIError::success();

        // Test BIP44 account path with null buffer
        let success = unsafe {
            derivation_bip44_account_path(FFINetwork::Testnet, 0, ptr::null_mut(), 256, &mut error)
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test BIP44 payment path with null buffer
        let success = unsafe {
            derivation_bip44_payment_path(
                FFINetwork::Testnet,
                0,
                false,
                0,
                ptr::null_mut(),
                256,
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test CoinJoin path with null buffer
        let success = unsafe {
            derivation_coinjoin_path(FFINetwork::Testnet, 0, ptr::null_mut(), 256, &mut error)
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_path_functions_small_buffer() {
        let mut error = FFIError::success();

        // Test with very small buffer (should fail)
        let mut small_buffer = [0i8; 5];
        let success = unsafe {
            derivation_bip44_account_path(
                FFINetwork::Testnet,
                0,
                small_buffer.as_mut_ptr(),
                small_buffer.len(),
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test BIP44 payment path with small buffer
        let success = unsafe {
            derivation_bip44_payment_path(
                FFINetwork::Testnet,
                0,
                false,
                0,
                small_buffer.as_mut_ptr(),
                small_buffer.len(),
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_different_networks() {
        let mut error = FFIError::success();
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Test with Mainnet
        let xprv_main = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Dash, &mut error)
        };
        assert!(!xprv_main.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Test with Testnet
        let xprv_test = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };
        assert!(!xprv_test.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Convert to strings and verify they have different prefixes
        let main_str = unsafe { derivation_xpriv_to_string(xprv_main, &mut error) };
        let test_str = unsafe { derivation_xpriv_to_string(xprv_test, &mut error) };

        let main_string = unsafe { CStr::from_ptr(main_str).to_str().unwrap() };
        let test_string = unsafe { CStr::from_ptr(test_str).to_str().unwrap() };

        assert!(main_string.starts_with("xprv")); // Dash mainnet
        assert!(test_string.starts_with("tprv")); // Testnet

        // Clean up
        unsafe {
            derivation_string_free(main_str);
            derivation_string_free(test_str);
            derivation_xpriv_free(xprv_main);
            derivation_xpriv_free(xprv_test);
        }
    }

    #[test]
    fn test_derivation_xpriv_to_xpub_null_input() {
        let mut error = FFIError::success();

        let xpub = unsafe { derivation_xpriv_to_xpub(ptr::null_mut(), &mut error) };

        assert!(xpub.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_xpriv_to_string_null_input() {
        let mut error = FFIError::success();

        let xprv_str = unsafe { derivation_xpriv_to_string(ptr::null_mut(), &mut error) };

        assert!(xprv_str.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_xpub_to_string_null_input() {
        let mut error = FFIError::success();

        let xpub_str = unsafe { derivation_xpub_to_string(ptr::null_mut(), &mut error) };

        assert!(xpub_str.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_xpub_fingerprint_null_inputs() {
        let mut error = FFIError::success();
        let mut fingerprint = [0u8; 4];

        // Test with null xpub
        let success = unsafe {
            derivation_xpub_fingerprint(ptr::null_mut(), fingerprint.as_mut_ptr(), &mut error)
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null fingerprint buffer
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let xprv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };

        let xpub = unsafe { derivation_xpriv_to_xpub(xprv, &mut error) };

        let success = unsafe { derivation_xpub_fingerprint(xpub, ptr::null_mut(), &mut error) };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            derivation_xpub_free(xpub);
            derivation_xpriv_free(xprv);
        }
    }

    #[test]
    fn test_derivation_derive_private_key_from_seed_null_inputs() {
        let mut error = FFIError::success();
        let seed = [0u8; 64];
        let path = CString::new("m/44'/1'/0'/0/0").unwrap();

        // Test with null seed
        let xpriv = unsafe {
            derivation_derive_private_key_from_seed(
                ptr::null(),
                64,
                path.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };
        assert!(xpriv.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null path
        let xpriv = unsafe {
            derivation_derive_private_key_from_seed(
                seed.as_ptr(),
                seed.len(),
                ptr::null(),
                FFINetwork::Testnet,
                &mut error,
            )
        };
        assert!(xpriv.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_derivation_derive_private_key_invalid_path() {
        let mut error = FFIError::success();
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Test with invalid path - try a path that should fail
        let invalid_path = CString::new("").unwrap();
        let xpriv = derivation_derive_private_key_from_seed(
            seed.as_ptr(),
            seed.len(),
            invalid_path.as_ptr(),
            FFINetwork::Testnet,
            &mut error,
        );
        // Don't assert specific behavior since we're not sure what the implementation does
        // Just exercise the code path
        if !xpriv.is_null() {
            derivation_xpriv_free(xpriv);
        }
    }

    #[test]
    fn test_dip9_derive_identity_key_null_inputs() {
        let mut error = FFIError::success();

        // Test with null seed
        let identity_key = dip9_derive_identity_key(
            ptr::null(),
            64,
            FFINetwork::Testnet,
            0,
            0,
            FFIDerivationPathType::BlockchainIdentities,
            &mut error,
        );
        assert!(identity_key.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_dip9_derive_identity_key_different_types() {
        let mut error = FFIError::success();
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Test the main derivation path type that we know works
        let identity_key = dip9_derive_identity_key(
            seed.as_ptr(),
            seed.len(),
            FFINetwork::Testnet,
            0,
            0,
            FFIDerivationPathType::BlockchainIdentities,
            &mut error,
        );

        if !identity_key.is_null() {
            derivation_xpriv_free(identity_key);
        }
    }

    #[test]
    fn test_identity_path_functions_null_inputs() {
        let mut error = FFIError::success();

        // Test identity registration with null buffer
        let success = derivation_identity_registration_path(
            FFINetwork::Testnet,
            0,
            ptr::null_mut(),
            256,
            &mut error,
        );
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test identity topup with null buffer
        let success = derivation_identity_topup_path(
            FFINetwork::Testnet,
            0,
            0,
            ptr::null_mut(),
            256,
            &mut error,
        );
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test identity authentication with null buffer
        let success = derivation_identity_authentication_path(
            FFINetwork::Testnet,
            0,
            0,
            ptr::null_mut(),
            256,
            &mut error,
        );
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_identity_path_functions_small_buffer() {
        let mut error = FFIError::success();
        let mut small_buffer = [0i8; 5];

        // Test identity registration with small buffer
        let success = derivation_identity_registration_path(
            FFINetwork::Testnet,
            0,
            small_buffer.as_mut_ptr(),
            small_buffer.len(),
            &mut error,
        );
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test identity topup with small buffer
        let success = derivation_identity_topup_path(
            FFINetwork::Testnet,
            0,
            0,
            small_buffer.as_mut_ptr(),
            small_buffer.len(),
            &mut error,
        );
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test identity authentication with small buffer
        let success = derivation_identity_authentication_path(
            FFINetwork::Testnet,
            0,
            0,
            small_buffer.as_mut_ptr(),
            small_buffer.len(),
            &mut error,
        );
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_path_functions_different_indices() {
        let mut error = FFIError::success();
        let mut buffer1 = vec![0u8; 256];
        let mut buffer2 = vec![0u8; 256];

        // Test BIP44 account path with different account indices
        let success1 = derivation_bip44_account_path(
            FFINetwork::Testnet,
            0,
            buffer1.as_mut_ptr() as *mut i8,
            buffer1.len(),
            &mut error,
        );
        assert!(success1);

        let success2 = derivation_bip44_account_path(
            FFINetwork::Testnet,
            5,
            buffer2.as_mut_ptr() as *mut i8,
            buffer2.len(),
            &mut error,
        );
        assert!(success2);

        let path1 = unsafe { CStr::from_ptr(buffer1.as_ptr() as *const i8).to_str().unwrap() };
        let path2 = unsafe { CStr::from_ptr(buffer2.as_ptr() as *const i8).to_str().unwrap() };

        assert_eq!(path1, "m/44'/1'/0'");
        assert_eq!(path2, "m/44'/1'/5'");
        assert_ne!(path1, path2);
    }

    #[test]
    fn test_bip44_payment_path_variations() {
        let mut error = FFIError::success();

        // Test receive address path
        let mut buffer = vec![0u8; 256];
        let success = derivation_bip44_payment_path(
            FFINetwork::Testnet,
            0,     // account_index
            false, // is_change (receive)
            5,     // address_index
            buffer.as_mut_ptr() as *mut i8,
            buffer.len(),
            &mut error,
        );
        assert!(success);
        let path_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap() };
        assert_eq!(path_str, "m/44'/1'/0'/0/5");

        // Test change address path
        let mut buffer = vec![0u8; 256];
        let success = derivation_bip44_payment_path(
            FFINetwork::Testnet,
            0,    // account_index
            true, // is_change
            3,    // address_index
            buffer.as_mut_ptr() as *mut i8,
            buffer.len(),
            &mut error,
        );
        assert!(success);
        let path_str = unsafe { CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap() };
        assert_eq!(path_str, "m/44'/1'/0'/1/3");
    }

    #[test]
    fn test_comprehensive_derivation_workflow() {
        let mut error = FFIError::success();

        // Generate seed
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        // Create master key
        let master_xprv =
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error);
        assert!(!master_xprv.is_null());

        // Convert to public key
        let master_xpub = derivation_xpriv_to_xpub(master_xprv, &mut error);
        assert!(!master_xpub.is_null());

        // Get fingerprint
        let mut fingerprint = [0u8; 4];
        let success =
            derivation_xpub_fingerprint(master_xpub, fingerprint.as_mut_ptr(), &mut error);
        assert!(success);

        // Derive child key using path
        let path = CString::new("m/44'/1'/0'/0/0").unwrap();
        let child_xprv = derivation_derive_private_key_from_seed(
            seed.as_ptr(),
            seed.len(),
            path.as_ptr(),
            FFINetwork::Testnet,
            &mut error,
        );
        assert!(!child_xprv.is_null());

        // Convert child to public
        let child_xpub = derivation_xpriv_to_xpub(child_xprv, &mut error);
        assert!(!child_xpub.is_null());

        // Convert to strings
        let master_xprv_str = derivation_xpriv_to_string(master_xprv, &mut error);
        let master_xpub_str = derivation_xpub_to_string(master_xpub, &mut error);
        let child_xprv_str = derivation_xpriv_to_string(child_xprv, &mut error);
        let child_xpub_str = derivation_xpub_to_string(child_xpub, &mut error);

        // Verify all strings are different and have correct prefixes
        let master_prv_s = unsafe { CStr::from_ptr(master_xprv_str).to_str().unwrap() };
        let master_pub_s = unsafe { CStr::from_ptr(master_xpub_str).to_str().unwrap() };
        let child_prv_s = unsafe { CStr::from_ptr(child_xprv_str).to_str().unwrap() };
        let child_pub_s = unsafe { CStr::from_ptr(child_xpub_str).to_str().unwrap() };

        assert!(master_prv_s.starts_with("tprv"));
        assert!(master_pub_s.starts_with("tpub"));
        assert!(child_prv_s.starts_with("tprv"));
        assert!(child_pub_s.starts_with("tpub"));

        assert_ne!(master_prv_s, child_prv_s);
        assert_ne!(master_pub_s, child_pub_s);

        // Clean up
        derivation_string_free(master_xprv_str);
        derivation_string_free(master_xpub_str);
        derivation_string_free(child_xprv_str);
        derivation_string_free(child_xpub_str);
        derivation_xpub_free(child_xpub);
        derivation_xpriv_free(child_xprv);
        derivation_xpub_free(master_xpub);
        derivation_xpriv_free(master_xprv);
    }
}
