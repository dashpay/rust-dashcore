//! Unit tests for address FFI module

#[cfg(test)]
mod tests {
    use crate::address;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::{CStr, CString};
    use std::ptr;

    fn create_test_wallet() -> (*mut crate::types::FFIWallet, *mut FFIError) {
        let mut error = FFIError::success();
        let error_ptr = &mut error as *mut FFIError;

        let seed = vec![0x01u8; 64];
        let wallet = unsafe {
            wallet::wallet_create_from_seed(
                seed.as_ptr(),
                seed.len(),
                FFINetwork::Testnet,
                error_ptr,
            )
        };

        (wallet, error_ptr)
    }

    #[test]
    fn test_address_derivation() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        // Derive receive address
        let receive_addr = unsafe {
            address::wallet_derive_receive_address(
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
            address::address_free(receive_addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_change_address_generation() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        // Derive change address
        let change_addr = unsafe {
            address::wallet_derive_change_address(
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
            address::address_free(change_addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_address_at_index() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        // Get receive address at index
        let addr = unsafe {
            address::wallet_get_address_at_index(
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
            address::wallet_get_address_at_index(
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
            address::address_free(addr);
            address::address_free(change_addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_multiple_address_generation() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        let mut addresses = Vec::new();

        // Generate multiple addresses
        for i in 0..5 {
            let addr = unsafe {
                address::wallet_derive_receive_address(
                    wallet,
                    FFINetwork::Testnet,
                    0, // account_index
                    i, // address_index
                    error,
                )
            };

            assert!(!addr.is_null());

            let addr_str = unsafe { CStr::from_ptr(addr).to_str().unwrap().to_string() };

            // Check that addresses are unique
            assert!(!addresses.contains(&addr_str));
            addresses.push(addr_str);

            unsafe {
                address::address_free(addr);
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

        // Test valid testnet address
        let valid_addr = CString::new("yTw7Kn5CrQvpBQy5dNMT8A3PQnU3kEj7jJ").unwrap();
        let is_valid =
            unsafe { address::address_validate(valid_addr.as_ptr(), FFINetwork::Testnet, error) };
        assert!(is_valid);

        // Test invalid address
        let invalid_addr = CString::new("invalid_address").unwrap();
        let is_valid =
            unsafe { address::address_validate(invalid_addr.as_ptr(), FFINetwork::Testnet, error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidAddress);

        // Test null address
        let is_valid =
            unsafe { address::address_validate(ptr::null(), FFINetwork::Testnet, error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_address_get_type() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test P2PKH address
        let p2pkh_addr = CString::new("yTw7Kn5CrQvpBQy5dNMT8A3PQnU3kEj7jJ").unwrap();
        let addr_type =
            unsafe { address::address_get_type(p2pkh_addr.as_ptr(), FFINetwork::Testnet, error) };
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        // Currently returns 0 for P2PKH (placeholder implementation)
        assert_eq!(addr_type, 0);
    }

    #[test]
    fn test_wallet_mark_address_used() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        // Derive an address first
        let addr = unsafe {
            address::wallet_derive_receive_address(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                0, // address_index
                error,
            )
        };
        assert!(!addr.is_null());

        // Mark it as used (currently returns success as placeholder)
        let success =
            unsafe { address::wallet_mark_address_used(wallet, FFINetwork::Testnet, addr, error) };
        assert!(success);

        // Clean up
        unsafe {
            address::address_free(addr);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_all_addresses() {
        let (wallet, error) = create_test_wallet();
        assert!(!wallet.is_null());

        let mut addresses_out: *mut *mut std::os::raw::c_char = ptr::null_mut();
        let mut count_out: usize = 0;

        // Get all addresses (currently returns empty list as placeholder)
        let success = unsafe {
            address::wallet_get_all_addresses(
                wallet,
                FFINetwork::Testnet,
                0, // account_index
                addresses_out,
                &mut count_out,
                error,
            )
        };
        assert!(success);
        assert_eq!(count_out, 0);
        assert!(addresses_out.is_null());

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }
}
