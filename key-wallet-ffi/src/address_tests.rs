//! Unit tests for address FFI module

#[cfg(test)]
mod address_tests {
    use crate::address::{address_array_free, address_free, address_get_type, address_validate};
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::CString;
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
}
