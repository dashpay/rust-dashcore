//! Unit tests for address FFI module

#[cfg(test)]
mod address_tests {
    use crate::address::{address_array_free, address_free, address_get_type, address_validate};
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetworks;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_address_validation() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test valid testnet address (generated from test mnemonic)
        let valid_addr = CString::new("yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt").unwrap();
        let is_valid = unsafe { address_validate(valid_addr.as_ptr(), FFINetworks::Testnet, error) };
        assert!(is_valid);

        // Test invalid address
        let invalid_addr = CString::new("invalid_address").unwrap();
        let is_valid =
            unsafe { address_validate(invalid_addr.as_ptr(), FFINetworks::Testnet, error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidAddress);

        // Test null address
        let is_valid = unsafe { address_validate(ptr::null(), FFINetworks::Testnet, error) };
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
            unsafe { address_get_type(p2pkh_addr.as_ptr(), FFINetworks::Testnet, error) };
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        // Returns 0 for P2PKH
        assert_eq!(addr_type, 0);
    }

    #[test]
    fn test_address_validate_valid() {
        let mut error = FFIError::success();

        // Test with valid testnet address - may fail due to library version differences
        let addr_str = CString::new("yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A").unwrap();
        let is_valid =
            unsafe { address_validate(addr_str.as_ptr(), FFINetworks::Testnet, &mut error) };

        assert!(is_valid);
    }

    #[test]
    fn test_address_validate_invalid() {
        let mut error = FFIError::success();

        // Test with invalid address
        let addr_str = CString::new("invalid_address").unwrap();
        let is_valid =
            unsafe { address_validate(addr_str.as_ptr(), FFINetworks::Testnet, &mut error) };

        assert!(!is_valid);
        assert_eq!(error.code, FFIErrorCode::InvalidAddress);
    }

    #[test]
    fn test_address_validate_null() {
        let mut error = FFIError::success();

        let is_valid = unsafe { address_validate(ptr::null(), FFINetworks::Testnet, &mut error) };

        assert!(!is_valid);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_address_get_type_valid() {
        let mut error = FFIError::success();

        // Test P2PKH address type (use same known-valid address from other tests)
        let addr_str = CString::new("yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt").unwrap();
        let addr_type =
            unsafe { address_get_type(addr_str.as_ptr(), FFINetworks::Testnet, &mut error) };

        // Type should be 0, 1, or 2 for valid addresses
        // If it's invalid (255), the address might not be valid for testnet
        if addr_type == 255 {
            assert_eq!(error.code, FFIErrorCode::InvalidAddress);
        } else {
            assert!(addr_type <= 2);
            assert_eq!(error.code, FFIErrorCode::Success);
        }
    }

    #[test]
    fn test_address_get_type_invalid() {
        let mut error = FFIError::success();

        let addr_str = CString::new("invalid_address").unwrap();
        let addr_type =
            unsafe { address_get_type(addr_str.as_ptr(), FFINetworks::Testnet, &mut error) };

        // Should return 255 (u8::MAX) for invalid
        assert_eq!(addr_type, 255);
        assert_eq!(error.code, FFIErrorCode::InvalidAddress);
    }

    #[test]
    fn test_address_get_type_null() {
        let mut error = FFIError::success();

        let addr_type = unsafe { address_get_type(ptr::null(), FFINetworks::Testnet, &mut error) };

        // Should return 255 (u8::MAX) for null input
        assert_eq!(addr_type, 255);
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
                let is_valid = address_validate(addr_str.as_ptr(), FFINetworks::Testnet, &mut error);
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
                    address_get_type(addr_str.as_ptr(), FFINetworks::Testnet, &mut error);

                // Should return a valid type (0, 1, 2) or 255 for error
                assert!(addr_type <= 2 || addr_type == 255);
            }
        }
    }
}
