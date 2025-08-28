//! Unit tests for wallet_manager FFI module

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::{wallet, wallet_manager};
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
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
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;

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

        // Get the wallet - now implemented, should return a valid wallet
        let wallet =
            unsafe { wallet_manager::wallet_manager_get_wallet(manager, wallet_ids, error) };
        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up the wallet (cast from const to mut for free)
        unsafe {
            wallet::wallet_free(wallet as *mut _);
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
        let mut confirmed_balance: u64 = 0;
        let mut unconfirmed_balance: u64 = 0;
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

    // Removed old test_wallet_manager_process_transaction - see updated version below

    #[test]
    fn test_wallet_manager_null_inputs() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test null manager operations
        let count = unsafe { wallet_manager::wallet_manager_wallet_count(ptr::null(), error) };
        assert_eq!(count, 0);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test null manager with get_wallet_balance
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        let null_wallet_id = [0u8; 32];
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                ptr::null_mut(),
                null_wallet_id.as_ptr(),
                &mut confirmed,
                &mut unconfirmed,
                error,
            )
        };
        assert!(!success);

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

    #[test]
    fn test_wallet_manager_get_wallet_balance_implementation() {
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
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(success);

        // Get wallet IDs to test balance retrieval
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut id_count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids as *mut *mut u8,
                &mut id_count as *mut usize,
                error,
            )
        };
        assert!(success);
        assert_eq!(id_count, 1);
        assert!(!wallet_ids.is_null());

        // Get the wallet balance (should be 0 for a new wallet)
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;

        let wallet_id_slice = unsafe { slice::from_raw_parts(wallet_ids, 32) };
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                manager,
                wallet_id_slice.as_ptr(),
                &mut confirmed,
                &mut unconfirmed,
                error,
            )
        };
        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // New wallet should have 0 balance
        assert_eq!(confirmed, 0);
        assert_eq!(unconfirmed, 0);

        // Test with null manager
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                ptr::null(),
                wallet_id_slice.as_ptr(),
                &mut confirmed,
                &mut unconfirmed,
                error,
            )
        };
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with null wallet_id
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                manager,
                ptr::null(),
                &mut confirmed,
                &mut unconfirmed,
                error,
            )
        };
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with null output pointers
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                manager,
                wallet_id_slice.as_ptr(),
                ptr::null_mut(),
                &mut unconfirmed,
                error,
            )
        };
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with invalid wallet ID (all zeros which won't match any wallet)
        let invalid_wallet_id = vec![0u8; 32];
        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_balance(
                manager,
                invalid_wallet_id.as_ptr(),
                &mut confirmed,
                &mut unconfirmed,
                error,
            )
        };
        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::WalletError);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_process_transaction() {
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
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(success);

        // Create a sample transaction bytes (this is a minimal valid transaction structure)
        // This is a simplified transaction for testing - in real use you'd have actual transaction data
        let tx_bytes = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x00, // input count
            0x00, // output count
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        // Create transaction contexts for testing
        let mempool_context = crate::types::FFITransactionContextDetails {
            context_type: crate::types::FFITransactionContext::Mempool,
            height: 0,
            block_hash: ptr::null(),
            timestamp: 0,
        };

        let block_context = crate::types::FFITransactionContextDetails {
            context_type: crate::types::FFITransactionContext::InBlock,
            height: 100000,
            block_hash: ptr::null(),
            timestamp: 1234567890,
        };

        // Test processing a mempool transaction
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                manager,
                tx_bytes.as_ptr(),
                tx_bytes.len(),
                FFINetwork::Testnet,
                &mempool_context,
                false,
                error,
            )
        };

        // The transaction is invalid (simplified format), so deserialization will fail
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test processing a block transaction
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                manager,
                tx_bytes.as_ptr(),
                tx_bytes.len(),
                FFINetwork::Testnet,
                &block_context,
                false,
                error,
            )
        };
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test processing a chain-locked block transaction
        let chain_locked_context = crate::types::FFITransactionContextDetails {
            context_type: crate::types::FFITransactionContext::InChainLockedBlock,
            height: 100000,
            block_hash: ptr::null(),
            timestamp: 1234567890,
        };
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                manager,
                tx_bytes.as_ptr(),
                tx_bytes.len(),
                FFINetwork::Testnet,
                &chain_locked_context,
                true,
                error,
            )
        };
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with null manager
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                ptr::null_mut(),
                tx_bytes.as_ptr(),
                tx_bytes.len(),
                FFINetwork::Testnet,
                &mempool_context,
                false,
                error,
            )
        };
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with null transaction bytes
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                manager,
                ptr::null(),
                10,
                FFINetwork::Testnet,
                &mempool_context,
                false,
                error,
            )
        };
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with zero length
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                manager,
                tx_bytes.as_ptr(),
                0,
                FFINetwork::Testnet,
                &mempool_context,
                false,
                error,
            )
        };
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with invalid transaction bytes
        let invalid_tx = vec![0xFF, 0xFF, 0xFF];
        let processed = unsafe {
            wallet_manager::wallet_manager_process_transaction(
                manager,
                invalid_tx.as_ptr(),
                invalid_tx.len(),
                FFINetwork::Testnet,
                &mempool_context,
                false,
                error,
            )
        };
        assert!(!processed);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_wallet_manager_get_wallet_and_info() {
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
                FFINetwork::Testnet,
                error,
            )
        };
        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Get wallet IDs
        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut id_count: usize = 0;

        let success = unsafe {
            wallet_manager::wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids as *mut *mut u8,
                &mut id_count as *mut usize,
                error,
            )
        };
        assert!(success);
        assert_eq!(id_count, 1);
        assert!(!wallet_ids.is_null());

        let wallet_id_slice = unsafe { slice::from_raw_parts(wallet_ids, 32) };

        // Test getting the wallet
        let wallet = unsafe {
            wallet_manager::wallet_manager_get_wallet(manager, wallet_id_slice.as_ptr(), error)
        };
        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Test getting the managed wallet info
        let wallet_info = unsafe {
            wallet_manager::wallet_manager_get_managed_wallet_info(
                manager,
                wallet_id_slice.as_ptr(),
                error,
            )
        };
        assert!(!wallet_info.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Test with invalid wallet ID (all zeros)
        let invalid_wallet_id = vec![0u8; 32];

        let wallet = unsafe {
            wallet_manager::wallet_manager_get_wallet(manager, invalid_wallet_id.as_ptr(), error)
        };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::NotFound);

        let wallet_info = unsafe {
            wallet_manager::wallet_manager_get_managed_wallet_info(
                manager,
                invalid_wallet_id.as_ptr(),
                error,
            )
        };
        assert!(wallet_info.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::NotFound);

        // Test with null manager
        let wallet = unsafe {
            wallet_manager::wallet_manager_get_wallet(ptr::null(), wallet_id_slice.as_ptr(), error)
        };
        assert!(wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        let wallet_info = unsafe {
            wallet_manager::wallet_manager_get_managed_wallet_info(
                ptr::null(),
                wallet_id_slice.as_ptr(),
                error,
            )
        };
        assert!(wallet_info.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            // Free the wallet (cast from const to mut for free)
            wallet::wallet_free(wallet as *mut _);
            // Free the managed wallet info
            crate::managed_wallet::managed_wallet_info_free(wallet_info);
            // Free the wallet IDs
            wallet_manager::wallet_manager_free_wallet_ids(wallet_ids, id_count);
            // Free the manager
            wallet_manager::wallet_manager_free(manager);
        }
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn test_create_wallet_from_mnemonic_return_serialized_bytes() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create a wallet manager
        let manager = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager.is_null());

        // Test basic wallet creation and serialization
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            crate::wallet_manager::wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,           // birth_height
                ptr::null(), // default account options
                false,       // don't downgrade to pubkey wallet
                false,       // allow_external_signing
                &mut wallet_bytes_out as *mut *mut u8,
                &mut wallet_bytes_len_out as *mut usize,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);
        assert_ne!(wallet_id_out, [0u8; 32]);

        // Store the wallet ID for comparison
        let original_wallet_id = wallet_id_out;

        // Clean up the serialized bytes
        unsafe {
            crate::wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }

        // Test with downgrade to watch-only wallet (create new manager to avoid duplicate wallet ID)
        let manager2 = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager2.is_null());

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            crate::wallet_manager::wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
                manager2,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                true,  // downgrade to pubkey wallet
                false, // watch-only, not externally signable
                &mut wallet_bytes_out as *mut *mut u8,
                &mut wallet_bytes_len_out as *mut usize,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        if !success {
            let error_msg = if unsafe { (*error).message.is_null() } {
                "No error message".to_string()
            } else {
                unsafe { std::ffi::CStr::from_ptr((*error).message).to_string_lossy().to_string() }
            };
            panic!("Function failed with error: {:?} - {}", unsafe { (*error).code }, error_msg);
        }
        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);
        // The wallet ID should be the same since it's derived from the same mnemonic
        assert_eq!(wallet_id_out, original_wallet_id);

        // Import the watch-only wallet to verify it works (create third manager for import)
        let manager3 = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager3.is_null());

        let wallet_bytes_slice =
            unsafe { slice::from_raw_parts(wallet_bytes_out, wallet_bytes_len_out) };
        let mut import_wallet_id_out = [0u8; 32];

        let import_success = unsafe {
            crate::wallet_manager::wallet_manager_import_wallet_from_bytes(
                manager3,
                wallet_bytes_slice.as_ptr(),
                wallet_bytes_slice.len(),
                import_wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(import_success);
        assert_eq!(import_wallet_id_out, original_wallet_id);

        // Clean up
        unsafe {
            crate::wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
            wallet_manager::wallet_manager_free(manager2);
            wallet_manager::wallet_manager_free(manager3);
        }

        // Test with externally signable wallet (create fourth manager)
        let manager4 = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager4.is_null());

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            crate::wallet_manager::wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
                manager4,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                true, // downgrade to pubkey wallet
                true, // externally signable
                &mut wallet_bytes_out as *mut *mut u8,
                &mut wallet_bytes_len_out as *mut usize,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);
        assert_eq!(wallet_id_out, original_wallet_id);

        // Clean up
        unsafe {
            crate::wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
        }

        // Test with invalid mnemonic (create fifth manager)
        let manager5 = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager5.is_null());

        let invalid_mnemonic = CString::new("invalid mnemonic phrase").unwrap();
        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        let success = unsafe {
            crate::wallet_manager::wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
                manager5,
                invalid_mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                0,
                ptr::null(),
                false,
                false,
                &mut wallet_bytes_out as *mut *mut u8,
                &mut wallet_bytes_len_out as *mut usize,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(!success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);
        assert!(wallet_bytes_out.is_null());
        assert_eq!(wallet_bytes_len_out, 0);

        // Clean up all managers
        unsafe {
            crate::wallet_manager::wallet_manager_free(manager);
            crate::wallet_manager::wallet_manager_free(manager4);
            crate::wallet_manager::wallet_manager_free(manager5);
        }
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn test_serialized_wallet_across_managers() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Create first wallet manager
        let manager1 = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager1.is_null());

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut wallet_bytes_out: *mut u8 = ptr::null_mut();
        let mut wallet_bytes_len_out: usize = 0;
        let mut wallet_id_out = [0u8; 32];

        // Create and serialize a wallet with the first manager
        let success = unsafe {
            crate::wallet_manager::wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
                manager1,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                100,         // birth_height
                ptr::null(), // default account options
                false,       // don't downgrade to pubkey wallet
                false,       // allow_external_signing
                &mut wallet_bytes_out as *mut *mut u8,
                &mut wallet_bytes_len_out as *mut usize,
                wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert!(!wallet_bytes_out.is_null());
        assert!(wallet_bytes_len_out > 0);

        // Store the wallet ID for comparison
        let original_wallet_id = wallet_id_out;

        // Create a copy of the serialized bytes before freeing the manager
        let wallet_bytes_copy = unsafe {
            let mut copy = Vec::with_capacity(wallet_bytes_len_out);
            ptr::copy_nonoverlapping(wallet_bytes_out, copy.as_mut_ptr(), wallet_bytes_len_out);
            copy.set_len(wallet_bytes_len_out);
            copy
        };

        // Clean up the first manager
        unsafe {
            crate::wallet_manager::wallet_manager_free(manager1);
        }

        // Create a completely new wallet manager
        let manager2 = crate::wallet_manager::wallet_manager_create(error);
        assert!(!manager2.is_null());

        // Import the wallet using the serialized bytes in the new manager
        let mut import_wallet_id_out = [0u8; 32];
        let import_success = unsafe {
            crate::wallet_manager::wallet_manager_import_wallet_from_bytes(
                manager2,
                wallet_bytes_copy.as_ptr(),
                wallet_bytes_copy.len(),
                import_wallet_id_out.as_mut_ptr(),
                error,
            )
        };

        assert!(import_success);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert_eq!(
            import_wallet_id_out, original_wallet_id,
            "Wallet ID should be the same after import"
        );

        // Verify we can get the wallet from the new manager
        let wallet = unsafe {
            crate::wallet_manager::wallet_manager_get_wallet(
                manager2,
                import_wallet_id_out.as_ptr(),
                error,
            )
        };
        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Clean up
        unsafe {
            crate::wallet_manager::wallet_manager_free_wallet_bytes(
                wallet_bytes_out,
                wallet_bytes_len_out,
            );
            crate::wallet_manager::wallet_manager_free(manager2);
        }
    }
}
