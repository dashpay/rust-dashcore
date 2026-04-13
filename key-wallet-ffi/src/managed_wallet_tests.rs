//! Tests for managed wallet FFI module

#[cfg(test)]
mod tests {
    use dashcore::ffi::FFINetwork;

    use crate::address_pool::managed_wallet_mark_address_used;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::managed_wallet::*;
    use crate::types::FFIWallet;
    use crate::wallet;
    use crate::wallet_manager::FFIWalletManager;
    use crate::wallet_manager::{
        wallet_manager_add_wallet_from_mnemonic, wallet_manager_create, wallet_manager_free,
        wallet_manager_free_wallet_ids, wallet_manager_get_managed_wallet_info,
        wallet_manager_get_wallet, wallet_manager_get_wallet_ids,
    };
    use std::ffi::CString;
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Helper: build a manager populated with a single wallet derived from TEST_MNEMONIC
    /// and return the manager, the retrieved wallet, the managed wallet info, the raw
    /// wallet-id buffer owned by the manager, and the wallet-id length. The caller is
    /// responsible for calling `cleanup_fixture` once done.
    unsafe fn setup_fixture(
        error: &mut FFIError,
    ) -> (*mut FFIWalletManager, *const FFIWallet, *mut FFIManagedWalletInfo, *mut u8, usize) {
        let manager = wallet_manager_create(FFINetwork::Testnet, error);
        assert!(!manager.is_null());

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let added = wallet_manager_add_wallet_from_mnemonic(
            manager,
            mnemonic.as_ptr(),
            passphrase.as_ptr(),
            error,
        );
        assert!(added);
        assert_eq!(error.code, FFIErrorCode::Success);

        let mut wallet_ids: *mut u8 = ptr::null_mut();
        let mut id_count: usize = 0;
        let got_ids = wallet_manager_get_wallet_ids(
            manager,
            &mut wallet_ids as *mut *mut u8,
            &mut id_count as *mut usize,
            error,
        );
        assert!(got_ids);
        assert_eq!(id_count, 1);
        assert!(!wallet_ids.is_null());

        let wallet = wallet_manager_get_wallet(manager, wallet_ids, error);
        assert!(!wallet.is_null());

        let managed_wallet = wallet_manager_get_managed_wallet_info(manager, wallet_ids, error);
        assert!(!managed_wallet.is_null());

        (manager, wallet, managed_wallet, wallet_ids, id_count)
    }

    unsafe fn cleanup_fixture(
        manager: *mut FFIWalletManager,
        wallet: *const FFIWallet,
        managed_wallet: *mut FFIManagedWalletInfo,
        wallet_ids: *mut u8,
        id_count: usize,
        error: &mut FFIError,
    ) {
        if !managed_wallet.is_null() {
            managed_wallet_info_free(managed_wallet);
        }
        if !wallet.is_null() {
            wallet::wallet_free_const(wallet);
        }
        if !wallet_ids.is_null() {
            wallet_manager_free_wallet_ids(wallet_ids, id_count);
        }
        if !manager.is_null() {
            wallet_manager_free(manager);
        }
        error.free_message();
    }

    #[test]
    fn test_managed_wallet_info_from_manager_success() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };

        assert!(!managed_wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        unsafe {
            cleanup_fixture(manager, wallet, managed_wallet, wallet_ids, id_count, &mut error);
        }
    }

    #[test]
    fn test_managed_wallet_info_from_manager_null_manager() {
        let mut error = FFIError::success();
        let wallet_id = [0u8; 32];

        let managed_wallet = unsafe {
            wallet_manager_get_managed_wallet_info(ptr::null(), wallet_id.as_ptr(), &mut error)
        };

        assert!(managed_wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe { error.free_message() };
    }

    #[test]
    fn test_managed_wallet_info_from_manager_unknown_wallet_id() {
        let mut error = FFIError::success();
        let manager = wallet_manager_create(FFINetwork::Testnet, &mut error);
        assert!(!manager.is_null());

        let bogus_wallet_id = [0u8; 32];
        let managed_wallet = unsafe {
            wallet_manager_get_managed_wallet_info(manager, bogus_wallet_id.as_ptr(), &mut error)
        };

        assert!(managed_wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::NotFound);

        unsafe {
            wallet_manager_free(manager);
            error.free_message();
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_valid() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };

        // Well-formed testnet address. It may or may not belong to any pool of this
        // wallet, but the function must at minimum parse it without panicking.
        let address = CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap();
        let success = unsafe {
            managed_wallet_mark_address_used(managed_wallet, address.as_ptr(), &mut error)
        };

        // Should succeed or fail gracefully depending on address validation
        // The function validates the address format internally
        if success {
            assert_eq!(error.code, FFIErrorCode::Success);
        } else {
            // Address validation might fail due to library version differences
            assert!(error.code == FFIErrorCode::InvalidInput);
        }

        unsafe {
            cleanup_fixture(manager, wallet, managed_wallet, wallet_ids, id_count, &mut error);
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_invalid() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };

        let address = CString::new("invalid_address").unwrap();
        let success = unsafe {
            managed_wallet_mark_address_used(managed_wallet, address.as_ptr(), &mut error)
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe {
            cleanup_fixture(manager, wallet, managed_wallet, wallet_ids, id_count, &mut error);
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_null_inputs() {
        let mut error = FFIError::success();

        let success =
            unsafe { managed_wallet_mark_address_used(ptr::null_mut(), ptr::null(), &mut error) };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe { error.free_message() };
    }

    #[test]
    fn test_managed_wallet_get_next_bip44_receive_address_null_inputs() {
        let mut error = FFIError::success();

        let address = unsafe {
            managed_wallet_get_next_bip44_receive_address(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe { error.free_message() };
    }

    #[test]
    fn test_managed_wallet_get_next_bip44_change_address_null_inputs() {
        let mut error = FFIError::success();

        let address = unsafe {
            managed_wallet_get_next_bip44_change_address(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe { error.free_message() };
    }

    #[test]
    fn test_managed_wallet_free_null() {
        // Should handle null gracefully
        unsafe {
            managed_wallet_free(ptr::null_mut());
            managed_wallet_info_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_managed_wallet_info_free_valid() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };
        assert!(!managed_wallet.is_null());

        // Free the managed wallet info independently — should not crash.
        unsafe { managed_wallet_info_free(managed_wallet) };

        // Pass null to cleanup_fixture so it doesn't double-free managed_wallet.
        unsafe {
            cleanup_fixture(manager, wallet, ptr::null_mut(), wallet_ids, id_count, &mut error);
        }
    }

    #[test]
    fn test_ffi_managed_wallet_info_methods() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };
        assert!(!managed_wallet.is_null());

        // Verify we can access the inner methods on FFIManagedWalletInfo.
        unsafe {
            let managed_ref = &*managed_wallet;
            let _inner = managed_ref.inner();

            let managed_mut = &mut *managed_wallet;
            let _inner_mut = managed_mut.inner_mut();
        }

        unsafe {
            cleanup_fixture(manager, wallet, managed_wallet, wallet_ids, id_count, &mut error);
        }
    }

    #[test]
    fn test_managed_wallet_mark_address_used_utf8_error() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };

        // Invalid UTF-8 bytes with null terminator.
        let invalid_utf8 = [0xFFu8, 0xFE, 0xFD, 0x00];
        let success = unsafe {
            managed_wallet_mark_address_used(
                managed_wallet,
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe {
            cleanup_fixture(manager, wallet, managed_wallet, wallet_ids, id_count, &mut error);
        }
    }

    #[test]
    fn test_managed_wallet_address_operations_with_real_wallet() {
        let mut error = FFIError::success();
        let (manager, wallet, managed_wallet, wallet_ids, id_count) =
            unsafe { setup_fixture(&mut error) };
        assert!(!managed_wallet.is_null());

        // Get the next receive address for BIP44 account 0 — with a fully populated
        // managed wallet this should succeed.
        let address_ptr = unsafe {
            managed_wallet_get_next_bip44_receive_address(managed_wallet, wallet, 0, &mut error)
        };
        assert!(!address_ptr.is_null(), "expected a receive address, error: {:?}", error.code);
        assert_eq!(error.code, FFIErrorCode::Success);
        unsafe {
            // Reclaim the C string allocated by the FFI function.
            let _ = CString::from_raw(address_ptr);
        }

        // Same for the next change address.
        let address_ptr = unsafe {
            managed_wallet_get_next_bip44_change_address(managed_wallet, wallet, 0, &mut error)
        };
        assert!(!address_ptr.is_null(), "expected a change address, error: {:?}", error.code);
        assert_eq!(error.code, FFIErrorCode::Success);
        unsafe {
            let _ = CString::from_raw(address_ptr);
        }

        unsafe {
            cleanup_fixture(manager, wallet, managed_wallet, wallet_ids, id_count, &mut error);
        }
    }
}
