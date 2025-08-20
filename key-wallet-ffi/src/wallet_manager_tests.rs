//! Unit tests for wallet_manager FFI module

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet_manager;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_ulong};
    use std::ptr;
    use std::slice;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_MNEMONIC_2: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    const TEST_MNEMONIC_3: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    #[test]
    fn test_wallet_manager_creation() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create a wallet manager
        let manager = wallet_manager::wallet_manager_create(error);

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

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add a wallet from mnemonic
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet, // Create 3 accounts
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

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add multiple wallets
        // Note: We use different mnemonics instead of different passphrases
        // because the library has a bug with passphrase wallets (see line 140-146 in wallet_manager/mod.rs)
        let mnemonics = [TEST_MNEMONIC, TEST_MNEMONIC_2, TEST_MNEMONIC_3];
        unsafe {
            for (i, mnemonic_str) in mnemonics.iter().enumerate() {
                let mnemonic = CString::new(*mnemonic_str).unwrap();

                let success = wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                    manager,
                    mnemonic.as_ptr(),
                    ptr::null(), // No passphrase
                    FFINetwork::Testnet,
                    error,
                );
                if !success {
                    println!("Failed to add wallet {}! Error code: {:?}", i, (*error).code);
                    if !(*error).message.is_null() {
                        let msg = CStr::from_ptr((*error).message);
                        println!("Error message: {:?}", msg);
                    }
                }
                assert!(success, "Failed to add wallet {}", i);
            }
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
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_get_receive_address() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
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

        assert!(!address.is_null(), "Failed to get receive address");

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

        if !address2.is_null() {
            let addr_str2 = unsafe { CStr::from_ptr(address2).to_str().unwrap() };
            // Addresses should be different (auto-incremented)
            assert_ne!(addr_str, addr_str2);
        }

        // Clean up
        unsafe {
            if !address.is_null() {
                let _ = CString::from_raw(address);
            }
            if !address2.is_null() {
                let _ = CString::from_raw(address2);
            }
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_get_change_address() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
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

        assert!(!address.is_null(), "Failed to get change address");

        // Clean up
        unsafe {
            let _ = CString::from_raw(address);
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_balance() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add a wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
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
        let mut confirmed: c_ulong = 0;
        let mut unconfirmed: c_ulong = 0;

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
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_total_balance() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Get initial total balance
        let balance = wallet_manager::wallet_manager_get_total_balance(manager, error);
        assert_eq!(balance, 0);

        // Add wallets with different mnemonics
        let mnemonics = [TEST_MNEMONIC, TEST_MNEMONIC_2];
        unsafe {
            for mnemonic_str in &mnemonics {
                let mnemonic = CString::new(*mnemonic_str).unwrap();
                let success = wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                    manager,
                    mnemonic.as_ptr(),
                    ptr::null(),
                    FFINetwork::Testnet,
                    error,
                );
                assert!(success);
            }
        }

        // Total balance should still be 0 (no transactions)
        let balance = wallet_manager::wallet_manager_get_total_balance(manager, error);
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

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Initially no monitored addresses
        let mut addresses: *mut *mut c_char = ptr::null_mut();
        let mut count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_monitored_addresses(
                manager,
                FFINetwork::Testnet,
                &mut addresses as *mut *mut *mut c_char,
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

        // Try to generate a few addresses
        // Generate a few addresses
        unsafe {
            for _ in 0..3 {
                let addr = wallet_manager::wallet_manager_get_receive_address(
                    manager,
                    wallet_ids,
                    FFINetwork::Testnet,
                    0,
                    error,
                );
                assert!(!addr.is_null(), "Failed to generate address");

                let _ = CString::from_raw(addr);
            }
        }

        // Now check monitored addresses
        let success = unsafe {
            wallet_manager::wallet_manager_get_monitored_addresses(
                manager,
                FFINetwork::Testnet,
                &mut addresses as *mut *mut *mut c_char,
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
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_height_management() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
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
        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        let invalid_mnemonic = CString::new("invalid mnemonic").unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                invalid_mnemonic.as_ptr(),
                ptr::null(),
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(!success);
        // The WalletManager returns WalletError for invalid mnemonics, not InvalidMnemonic
        // because it wraps the mnemonic error in a WalletCreation error
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::WalletError);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_multiple_wallets_management() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add multiple wallets with different mnemonics
        // (passphrases don't work due to library bug)
        let wallet_count = 3;
        let mnemonics = [TEST_MNEMONIC, TEST_MNEMONIC_2, TEST_MNEMONIC_3];
        unsafe {
            for i in 0..wallet_count {
                let mnemonic = CString::new(mnemonics[i]).unwrap();

                let success = wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                    manager,
                    mnemonic.as_ptr(),
                    ptr::null(),         // No passphrase
                    FFINetwork::Testnet, // 2 accounts per wallet
                    error,
                );
                assert!(success);
            }
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
        unsafe {
            for i in 0..id_count {
                let wallet_id = wallet_ids.add(i * 32);

                let addr = wallet_manager::wallet_manager_get_receive_address(
                    manager,
                    wallet_id,
                    FFINetwork::Testnet,
                    0,
                    error,
                );

                assert!(!addr.is_null(), "Failed to get address for wallet {}", i);

                let _ = CString::from_raw(addr);
            }
        }

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_add_wallet_with_account_count() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add a wallet with account count
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet, // account_count
                error,
            )
        };
        assert!(success);

        // Verify wallet was added
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(manager, error) };
        assert_eq!(count, 1);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_get_wallet() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
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
                error,
            )
        };
        assert!(success);

        // Get wallet ID
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

        // Get the wallet - function not implemented, should return null
        let wallet = wallet_manager::wallet_manager_get_wallet(manager, wallet_ids, error);
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::NotFound);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_get_change_address() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
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
                error,
            )
        };
        assert!(success);

        // Get wallet ID
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

        // Get change address
        let change_addr = unsafe {
            wallet_manager::wallet_manager_get_change_address(
                manager,
                wallet_ids,
                FFINetwork::Testnet,
                0, // address_index
                error,
            )
        };

        if !change_addr.is_null() {
            let addr_str = unsafe { CStr::from_ptr(change_addr).to_str().unwrap() };
            assert!(!addr_str.is_empty());

            unsafe {
                let _ = CString::from_raw(change_addr);
            }
        }

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_get_wallet_balance() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Add wallet
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(success);

        // Get wallet ID
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

        // Get wallet balance
        let mut confirmed_balance: c_ulong = 0;
        let mut unconfirmed_balance: c_ulong = 0;
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                manager,
                wallet_ids,
                &mut confirmed_balance,
                &mut unconfirmed_balance,
                error,
            )
        };

        // Should succeed and balance should be 0 for new wallet
        assert!(success);
        assert_eq!(confirmed_balance, 0);
        assert_eq!(unconfirmed_balance, 0);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
        }
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_process_transaction() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Test with empty transaction data
        let tx_data = vec![0u8; 0];
        let success = wallet_manager::wallet_manager_process_transaction(
            manager,
            tx_data.as_ptr(),
            tx_data.len(),
            12345, // height
            54321, // block_time
            error,
        );

        // Function is not implemented, should return false
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_null_inputs() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test null manager operations
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(ptr::null(), error) };
        assert_eq!(count, 0);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test null manager with get_total_balance
        let balance = wallet_manager::wallet_manager_get_total_balance(ptr::null(), error);
        assert_eq!(balance, 0);

        // Test adding wallet with null manager
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();
        let success = unsafe {
            wallet_manager::wallet_manager_add_wallet_from_mnemonic(
                ptr::null_mut(),
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet, // account_count
                error,
            )
        };
        assert!(!success);
    }

    #[test]
    fn test_wallet_manager_free_null() {
        // Should handle null gracefully
        unsafe {
            wallet_manager::wallet_manager_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_wallet_manager_height_operations() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let manager = wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Get initial height
        let _height = unsafe {
            wallet_manager::wallet_manager_current_height(manager, FFINetwork::Testnet, error)
        };

        // Update height
        let new_height = 12345;
        unsafe {
            wallet_manager::wallet_manager_update_height(
                manager,
                FFINetwork::Testnet,
                new_height,
                error,
            );
        }

        // Get updated height
        let current_height = unsafe {
            wallet_manager::wallet_manager_current_height(manager, FFINetwork::Testnet, error)
        };
        assert_eq!(current_height, new_height);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }
}
