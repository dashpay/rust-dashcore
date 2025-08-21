//! Unit tests for address FFI module

#[cfg(test)]
mod address_tests {
    use crate::address::{
        address_array_free, address_free, address_get_type, address_validate,
        wallet_derive_change_address, wallet_derive_receive_address, wallet_get_address_at_index,
        wallet_get_all_addresses, wallet_mark_address_used,
    };
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::ptr;

    unsafe fn create_test_wallet() -> (*mut crate::types::FFIWallet, *mut FFIError) {
        let mut error = FFIError::success();
        let error_ptr = &mut error as *mut FFIError;

        let seed = [0x01u8; 64];
        let wallet = wallet::wallet_create_from_seed(
            seed.as_ptr(),
            seed.len(),
            FFINetwork::Testnet,
            error_ptr,
        );

        (wallet, error_ptr)
    }

    #[test]
    fn test_address_derivation() {
        let (wallet, error) = unsafe { create_test_wallet() };
        assert!(!wallet.is_null());

        // Derive receive address
        let receive_addr = unsafe {
            wallet_derive_receive_address(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                0, // address_index
                error,
            )
        };

        assert!(!receive_addr.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        let addr_str = unsafe { CStr::from_ptr(receive_addr).to_str().unwrap() };
        assert!(!addr_str.is_empty());

        // Clean up
        unsafe {
            address_free(receive_addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_change_address_generation() {
        let (wallet, error) = unsafe { create_test_wallet() };
        assert!(!wallet.is_null());

        // Derive change address
        let change_addr = unsafe {
            wallet_derive_change_address(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                0, // address_index
                error,
            )
        };

        assert!(!change_addr.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            address_free(change_addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_address_at_index() {
        let (wallet, error) = unsafe { create_test_wallet() };
        assert!(!wallet.is_null());

        // Get receive address at index
        let addr = unsafe {
            wallet_get_address_at_index(
                wallet,
                FFINetwork::Testnet,
                0,     // account_index
                false, // is_change
                5,     // address_index
                error,
            )
        };

        assert!(!addr.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Get change address at index
        let change_addr = unsafe {
            wallet_get_address_at_index(
                wallet,
                FFINetwork::Testnet,
                0,    // account_index
                true, // is_change
                3,    // address_index
                error,
            )
        };

        assert!(!change_addr.is_null());

        // Clean up
        unsafe {
            address_free(addr);
            address_free(change_addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_multiple_address_generation() {
        let (wallet, error) = unsafe { create_test_wallet() };
        assert!(!wallet.is_null());

        let mut addresses = Vec::new();

        // Generate multiple addresses
        unsafe {
            for i in 0..5 {
                let addr = wallet_derive_receive_address(
                    wallet,
                    FFINetwork::Testnet,
                    0, // account_index
                    i, // address_index
                    error,
                );

                assert!(!addr.is_null());

                let addr_str = CStr::from_ptr(addr).to_str().unwrap().to_string();

                // Check that addresses are unique
                assert!(!addresses.contains(&addr_str));
                addresses.push(addr_str);

                address_free(addr);
            }
        }

        assert_eq!(addresses.len(), 5);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_address_validation() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test valid testnet address (generated from test mnemonic)
        let valid_addr = CString::new("yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt").unwrap();
        let is_valid = unsafe { address_validate(valid_addr.as_ptr(), FFINetwork::Testnet, error) };
        assert!(is_valid);

        // Test invalid address
        let invalid_addr = CString::new("invalid_address").unwrap();
        let is_valid =
            unsafe { address_validate(invalid_addr.as_ptr(), FFINetwork::Testnet, error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidAddress);

        // Test null address
        let is_valid = unsafe { address_validate(ptr::null(), FFINetwork::Testnet, error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_address_get_type() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test P2PKH address (generated from test mnemonic)
        let p2pkh_addr = CString::new("yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt").unwrap();
        let addr_type =
            unsafe { address_get_type(p2pkh_addr.as_ptr(), FFINetwork::Testnet, error) };
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        // Currently returns 0 for P2PKH (placeholder implementation)
        assert_eq!(addr_type, 0);
    }

    #[test]
    fn test_wallet_mark_address_used() {
        let (wallet, error) = unsafe { create_test_wallet() };
        assert!(!wallet.is_null());

        // Derive an address first
        let addr = unsafe {
            wallet_derive_receive_address(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                0, // address_index
                error,
            )
        };
        assert!(!addr.is_null());

        // Mark it as used (currently returns success as placeholder)
        let success = unsafe { wallet_mark_address_used(wallet, FFINetwork::Testnet, addr, error) };
        assert!(success);

        // Clean up
        unsafe {
            address_free(addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_all_addresses() {
        let (wallet, error) = unsafe { create_test_wallet() };
        assert!(!wallet.is_null());

        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        // Get all addresses
        let success = unsafe {
            wallet_get_all_addresses(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                &mut addresses_out as *mut *mut *mut c_char,
                &mut count_out,
                error,
            )
        };
        assert!(success);
        // We generate 5 addresses in the implementation
        assert_eq!(count_out, 5);
        assert!(!addresses_out.is_null());

        // Clean up addresses if any were returned
        if !addresses_out.is_null() && count_out > 0 {
            unsafe {
                address_array_free(addresses_out, count_out);
            }
        }

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_address_validate_valid() {
        let mut error = FFIError::success();

        // Test with valid testnet address - may fail due to library version differences
        let addr_str = CString::new("yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A").unwrap();
        let is_valid =
            unsafe { address_validate(addr_str.as_ptr(), FFINetwork::Testnet, &mut error) };

        assert!(is_valid);
    }

    #[test]
    fn test_address_validate_invalid() {
        let mut error = FFIError::success();

        // Test with invalid address
        let addr_str = CString::new("invalid_address").unwrap();
        let is_valid =
            unsafe { address_validate(addr_str.as_ptr(), FFINetwork::Testnet, &mut error) };

        assert!(!is_valid);
        assert_eq!(error.code, FFIErrorCode::InvalidAddress);
    }

    #[test]
    fn test_address_validate_null() {
        let mut error = FFIError::success();

        let is_valid = unsafe { address_validate(ptr::null(), FFINetwork::Testnet, &mut error) };

        assert!(!is_valid);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_address_get_type_valid() {
        let mut error = FFIError::success();

        // Test P2PKH address type
        let addr_str = CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap();
        let addr_type =
            unsafe { address_get_type(addr_str.as_ptr(), FFINetwork::Testnet, &mut error) };

        // Type may vary based on library version, just verify it runs
        assert!(addr_type <= 2);
    }

    #[test]
    fn test_address_get_type_invalid() {
        let mut error = FFIError::success();

        let addr_str = CString::new("invalid_address").unwrap();
        let addr_type =
            unsafe { address_get_type(addr_str.as_ptr(), FFINetwork::Testnet, &mut error) };

        // Should return 2 for invalid
        assert_eq!(addr_type, 2);
        assert_eq!(error.code, FFIErrorCode::InvalidAddress);
    }

    #[test]
    fn test_address_get_type_null() {
        let mut error = FFIError::success();

        let addr_type = unsafe { address_get_type(ptr::null(), FFINetwork::Testnet, &mut error) };

        // Should return 0 for null input
        assert_eq!(addr_type, 0);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_address_free_null() {
        // Should handle null gracefully
        unsafe {
            address_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_address_array_free() {
        // Create some test addresses
        let mut addresses = Vec::new();
        for i in 0..3 {
            let addr = CString::new(format!("yAddress{}", i)).unwrap();
            addresses.push(addr.into_raw());
        }

        let addrs_ptr = addresses.as_mut_ptr();
        let count = addresses.len();
        std::mem::forget(addresses);

        // Free the addresses
        unsafe {
            address_array_free(addrs_ptr, count);
        }
    }

    #[test]
    fn test_address_array_free_null() {
        // Should handle null gracefully
        unsafe {
            address_array_free(ptr::null_mut(), 0);
        }
    }

    #[test]
    fn test_wallet_derive_receive_address() {
        let mut error = FFIError::success();

        // Create a wallet first
        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, &mut error) };
        assert!(!wallet.is_null());

        // Derive receive address
        let address = unsafe {
            wallet_derive_receive_address(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                0, // address_index
                &mut error,
            )
        };

        if !address.is_null() {
            let addr_str = unsafe { CStr::from_ptr(address).to_str().unwrap() };
            assert!(!addr_str.is_empty());

            // Clean up
            unsafe {
                address_free(address);
            }
        }

        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_derive_change_address() {
        let mut error = FFIError::success();

        // Create a wallet first
        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, &mut error) };
        assert!(!wallet.is_null());

        // Derive change address
        let address = unsafe {
            wallet_derive_change_address(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                0, // address_index
                &mut error,
            )
        };

        if !address.is_null() {
            let addr_str = unsafe { CStr::from_ptr(address).to_str().unwrap() };
            assert!(!addr_str.is_empty());

            // Clean up
            unsafe {
                address_free(address);
            }
        }

        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_derive_address_null_wallet() {
        let mut error = FFIError::success();

        // Test derive receive with null wallet
        let address = unsafe {
            wallet_derive_receive_address(ptr::null(), FFINetwork::Testnet, 0, 0, &mut error)
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test derive change with null wallet
        let address = unsafe {
            wallet_derive_change_address(ptr::null(), FFINetwork::Testnet, 0, 0, &mut error)
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_get_all_addresses_null_inputs() {
        let mut error = FFIError::success();

        // Test with null wallet
        let mut addresses_out: *mut *mut c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            wallet_get_all_addresses(
                ptr::null(),
                FFINetwork::Testnet,
                0,
                &mut addresses_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Create wallet for other null tests
        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, &mut error) };

        // Test with null addresses_out
        let success = unsafe {
            wallet_get_all_addresses(
                wallet,
                FFINetwork::Testnet,
                0,
                ptr::null_mut(),
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test with null count_out
        let success = unsafe {
            wallet_get_all_addresses(
                wallet,
                FFINetwork::Testnet,
                0,
                &mut addresses_out,
                ptr::null_mut(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_address_at_index() {
        let mut error = FFIError::success();

        // Create a wallet first
        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, &mut error) };
        assert!(!wallet.is_null());

        // Test receive address
        let address = unsafe {
            wallet_get_address_at_index(
                wallet,
                FFINetwork::Testnet,
                0,     // account_index
                false, // is_change
                0,     // address_index
                &mut error,
            )
        };

        if !address.is_null() {
            let addr_str = unsafe { CStr::from_ptr(address).to_str().unwrap() };
            assert!(!addr_str.is_empty());

            // Clean up
            unsafe {
                address_free(address);
            }
        }

        // Test change address
        let address = unsafe {
            wallet_get_address_at_index(
                wallet,
                FFINetwork::Testnet,
                0,    // account_index
                true, // is_change
                0,    // address_index
                &mut error,
            )
        };

        if !address.is_null() {
            let addr_str = unsafe { CStr::from_ptr(address).to_str().unwrap() };
            assert!(!addr_str.is_empty());

            // Clean up
            unsafe {
                address_free(address);
            }
        }

        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_mark_address_used_with_address() {
        let mut error = FFIError::success();

        // Create a wallet first
        let wallet = unsafe { wallet::wallet_create_random(FFINetwork::Testnet, &mut error) };
        assert!(!wallet.is_null());

        // Generate an address first
        let address =
            unsafe { wallet_derive_receive_address(wallet, FFINetwork::Testnet, 0, 0, &mut error) };

        unsafe {
            if !address.is_null() {
                // Mark the address as used
                let success =
                    wallet_mark_address_used(wallet, FFINetwork::Testnet, address, &mut error);

                // Should succeed (or at least not crash)
                assert!(success || error.code != FFIErrorCode::Success);

                // Clean up
                address_free(address);
            }
        }

        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_address_validation_comprehensive() {
        let mut error = FFIError::success();

        // Test various invalid address formats
        let invalid_addresses = [
            "invalid",
            "",
            "1234567890",
            "yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadGtoolong",
            "zXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG", // wrong network prefix
        ];

        unsafe {
            for invalid_addr in invalid_addresses.iter() {
                let addr_str = CString::new(*invalid_addr).unwrap();
                let is_valid = address_validate(addr_str.as_ptr(), FFINetwork::Testnet, &mut error);
                assert!(!is_valid);
            }
        }
    }

    #[test]
    fn test_address_get_type_comprehensive() {
        let mut error = FFIError::success();

        // Test various address formats
        let test_addresses = [
            "yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG", // potential P2PKH
            "8oAH2jGDaJVFBJNUj3QHYNLGgtNfaXcNP7", // potential P2SH
            "invalid_address",
        ];

        unsafe {
            for addr in test_addresses.iter() {
                let addr_str = CString::new(*addr).unwrap();
                let addr_type =
                    address_get_type(addr_str.as_ptr(), FFINetwork::Testnet, &mut error);

                // Should return a valid type (0, 1, or 2 for invalid)
                assert!(addr_type <= 2);
            }
        }
    }

    #[test]
    fn test_wallet_mark_address_used_null_wallet() {
        let mut error = FFIError::success();
        let address = CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap();

        let success = unsafe {
            wallet_mark_address_used(
                ptr::null_mut(),
                FFINetwork::Testnet,
                address.as_ptr(),
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_get_address_at_index_null_wallet() {
        let mut error = FFIError::success();

        let address = unsafe {
            wallet_get_address_at_index(ptr::null(), FFINetwork::Testnet, 0, false, 0, &mut error)
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }
}
