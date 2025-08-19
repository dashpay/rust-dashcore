//! Unit tests for wallet_manager FFI module

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet_manager;
    use std::ffi::{CStr, CString};
    use std::ptr;
    use std::slice;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_wallet_manager_creation() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create a wallet manager
        let manager = unsafe { wallet_manager::wallet_manager_create(error) };

        assert!(!manager.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Verify initial state
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(manager, error) };
        assert_eq!(count, 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_add_wallet_from_mnemonic() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Add a wallet from mnemonic
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                3, // Create 3 accounts
                error,
            )
        };

        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Verify wallet was added
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(manager, error) };
        assert_eq!(count, 1);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_get_wallet_ids() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Add multiple wallets
        for i in 0..3 {
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new(format!("pass{}", i)).unwrap();

            let success = unsafe {
                wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                    manager,
                    mnemonic.as_ptr(),
                    passphrase.as_ptr(),
                    FFINetwork::Testnet,
                    1,
                    error,
                )
            };
            assert!(success);
        }

        // Get wallet IDs
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids,
                &mut count,
                error,
            )
        };

        assert!(success);
        assert_eq!(count, 3);
        assert!(!wallet_ids.is_null());

        // Verify IDs are unique
        let ids = unsafe {
            let mut unique_ids = Vec::new();
            for i in 0..count {
                let id_ptr = wallet_ids.add(i * 32);
                let id = slice::from_raw_parts(id_ptr, 32);
                unique_ids.push(id.to_vec());
            }
            unique_ids
        };

        // Check all IDs are different
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_get_receive_address() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Add a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                1,
                error,
            )
        };
        assert!(success);

        // Get wallet ID
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids,
                &mut count,
                error,
            )
        };
        assert!(success);
        assert_eq!(count, 1);

        // Get receive address
        let address = unsafe {
            wallet_manager::wallet_manager_get_receive_address(
                manager,
                wallet_ids,
                FFINetwork::Testnet,
                0, // account_index
                error,
            )
        };

        assert!(!address.is_null());

        let addr_str = unsafe { CStr::from_ptr(address).to_str().unwrap() };
        assert!(!addr_str.is_empty());

        // Get another address - should be different
        let address2 = unsafe {
            wallet_manager::wallet_manager_get_receive_address(
                manager,
                wallet_ids,
                FFINetwork::Testnet,
                0,
                error,
            )
        };

        let addr_str2 = unsafe { CStr::from_ptr(address2).to_str().unwrap() };

        // Addresses should be different (auto-incremented)
        assert_ne!(addr_str, addr_str2);

        // Clean up
        unsafe {
            CString::from_raw(address);
            CString::from_raw(address2);
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_get_change_address() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Add a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
                1,
                error,
            )
        };
        assert!(success);

        // Get wallet ID
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids,
                &mut count,
                error,
            )
        };
        assert!(success);

        // Get change address
        let address = unsafe {
            wallet_manager::wallet_manager_get_change_address(
                manager,
                wallet_ids,
                FFINetwork::Testnet,
                0,
                error,
            )
        };

        assert!(!address.is_null());

        // Clean up
        unsafe {
            CString::from_raw(address);
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_balance() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Add a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
                1,
                error,
            )
        };
        assert!(success);

        // Get wallet ID
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids,
                &mut count,
                error,
            )
        };
        assert!(success);

        // Get wallet balance
        let mut confirmed: std::os::raw::c_ulong = 0;
        let mut unconfirmed: std::os::raw::c_ulong = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                manager,
                wallet_ids,
                &mut confirmed,
                &mut unconfirmed,
                error,
            )
        };

        assert!(success);
        assert_eq!(confirmed, 0); // New wallet has no balance
        assert_eq!(unconfirmed, 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_total_balance() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Get initial total balance
        let balance = unsafe { wallet_manager::wallet_manager_get_total_balance(manager, error) };
        assert_eq!(balance, 0);

        // Add wallets
        for _ in 0..2 {
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let success = unsafe {
                wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                    manager,
                    mnemonic.as_ptr(),
                    ptr::null(),
                    FFINetwork::Testnet,
                    1,
                    error,
                )
            };
            assert!(success);
        }

        // Total balance should still be 0 (no transactions)
        let balance = unsafe { wallet_manager::wallet_manager_get_total_balance(manager, error) };
        assert_eq!(balance, 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_monitored_addresses() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Initially no monitored addresses
        let mut addresses: *mut *mut std::os::raw::c_char = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_monitored_addresses(
                manager,
                FFINetwork::Testnet,
                addresses,
                &mut count,
                error,
            )
        };

        assert!(success);
        assert_eq!(count, 0);
        assert!(addresses.is_null());

        // Add a wallet and generate addresses
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
                1,
                error,
            )
        };
        assert!(success);

        // Get wallet ID and generate some addresses
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut wallet_count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids,
                &mut wallet_count,
                error,
            )
        };
        assert!(success);

        // Generate a few addresses
        for _ in 0..3 {
            let addr = unsafe {
                wallet_manager::wallet_manager_get_receive_address(
                    manager,
                    wallet_ids,
                    FFINetwork::Testnet,
                    0,
                    error,
                )
            };
            assert!(!addr.is_null());
            unsafe {
                CString::from_raw(addr);
            }
        }

        // Now check monitored addresses
        let success = unsafe {
            wallet_manager::wallet_manager_get_monitored_addresses(
                manager,
                FFINetwork::Testnet,
                addresses,
                &mut count,
                error,
            )
        };

        assert!(success);
        // Should have some monitored addresses now
        if count > 0 {
            assert!(!addresses.is_null());

            // Clean up addresses
            unsafe {
                wallet_manager::wallet_manager_free_addresses(addresses, count);
            }
        }

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, wallet_count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_height_management() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Get initial height
        let height = unsafe {
            wallet_manager::wallet_manager_current_height(manager, FFINetwork::Testnet, error)
        };
        assert_eq!(height, 0);

        // Update height
        let success = unsafe {
            wallet_manager::wallet_manager_update_height(
                manager,
                FFINetwork::Testnet,
                100000,
                error,
            )
        };
        assert!(success);

        // Verify height was updated
        let height = unsafe {
            wallet_manager::wallet_manager_current_height(manager, FFINetwork::Testnet, error)
        };
        assert_eq!(height, 100000);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_error_handling() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null manager
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(ptr::null(), error) };
        assert_eq!(count, 0);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with invalid mnemonic
        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        let invalid_mnemonic = CString::new("invalid mnemonic").unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                invalid_mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
                1,
                error,
            )
        };
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_multiple_wallets_management() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = unsafe { wallet_manager::wallet_manager_create(error) };
        assert!(!manager.is_null());

        // Add multiple wallets with different passphrases
        let wallet_count = 5;
        for i in 0..wallet_count {
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new(format!("passphrase_{}", i)).unwrap();

            let success = unsafe {
                wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                    manager,
                    mnemonic.as_ptr(),
                    passphrase.as_ptr(),
                    FFINetwork::Testnet,
                    2, // 2 accounts per wallet
                    error,
                )
            };
            assert!(success);
        }

        // Verify wallet count
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(manager, error) };
        assert_eq!(count, wallet_count);

        // Get all wallet IDs
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut id_count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids,
                &mut id_count,
                error,
            )
        };
        assert!(success);
        assert_eq!(id_count, wallet_count);

        // Generate addresses for each wallet
        for i in 0..id_count {
            let wallet_id = unsafe { wallet_ids.add(i * 32) };

            let addr = unsafe {
                wallet_manager::wallet_manager_get_receive_address(
                    manager,
                    wallet_id,
                    FFINetwork::Testnet,
                    0,
                    error,
                )
            };
            assert!(!addr.is_null());

            unsafe {
                CString::from_raw(addr);
            }
        }

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
            wallet_manager::wallet_manager_free(manager);
        }
    }
}
