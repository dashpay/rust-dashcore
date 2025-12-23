//! Test for wallet import from bytes via FFI

#[cfg(feature = "bincode")]
#[cfg(test)]
mod tests {
    use key_wallet_ffi::error::{FFIError, FFIErrorCode};
    use key_wallet_ffi::wallet_manager::*;
    use key_wallet_ffi::FFINetwork;
    use std::os::raw::c_char;
    use std::ptr;

    #[test]
    fn test_import_wallet_from_bytes() {
        unsafe {
            // Create a wallet manager
            let mut error = FFIError::success();
            let manager = wallet_manager_create(&mut error);
            assert_eq!(error.code, FFIErrorCode::Success);
            assert!(!manager.is_null());

            // First, create a wallet from mnemonic
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\0";
            let passphrase = "\0";

            let success = wallet_manager_add_wallet_from_mnemonic(
                manager,
                mnemonic.as_ptr() as *const c_char,
                passphrase.as_ptr() as *const c_char,
                FFINetwork::Dash,
                &mut error,
            );
            assert!(success);
            assert_eq!(error.code, FFIErrorCode::Success);

            // Get the wallet for serialization
            let mut wallet_ids_ptr: *mut u8 = ptr::null_mut();
            let mut count: usize = 0;
            let success =
                wallet_manager_get_wallet_ids(manager, &mut wallet_ids_ptr, &mut count, &mut error);
            assert!(success);
            assert_eq!(count, 1);
            assert!(!wallet_ids_ptr.is_null());

            // Get the wallet
            let wallet_ptr = wallet_manager_get_wallet(manager, wallet_ids_ptr, &mut error);
            assert!(!wallet_ptr.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Now we would serialize the wallet to bytes here if we had that functionality exposed
            // For now, we'll just test that the import function exists and compiles

            // Create a second manager to test import
            let manager2 = wallet_manager_create(&mut error);
            assert_eq!(error.code, FFIErrorCode::Success);
            assert!(!manager2.is_null());

            // Test with invalid input (null bytes)
            let mut imported_wallet_id = [0u8; 32];
            let success = wallet_manager_import_wallet_from_bytes(
                manager2,
                ptr::null(),
                0,
                imported_wallet_id.as_mut_ptr(),
                &mut error,
            );
            assert!(!success);
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Clean up
            wallet_manager_free_wallet_ids(wallet_ids_ptr, count);
            wallet_manager_free(manager);
            wallet_manager_free(manager2);
        }
    }
}
