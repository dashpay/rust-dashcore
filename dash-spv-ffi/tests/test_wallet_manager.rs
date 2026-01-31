#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_ffi::{
        wallet_manager::{
            wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
            wallet_manager_import_wallet_from_bytes, wallet_manager_wallet_count,
        },
        FFIError, FFINetwork, FFIWalletManager,
    };
    use key_wallet_manager::wallet_manager::WalletManager;
    use std::ffi::{CStr, CString};
    use tempfile::TempDir;

    #[test]
    fn test_get_wallet_manager() {
        unsafe {
            // Create a config
            let config = dash_spv_ffi_config_testnet();
            assert!(!config.is_null());

            let temp_dir = TempDir::new().unwrap();
            dash_spv_ffi_config_set_data_dir(
                config,
                CString::new(temp_dir.path().to_str().unwrap()).unwrap().as_ptr(),
            );

            // Create a client
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Get wallet manager
            let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
            assert!(!wallet_manager.is_null());
            let wallet_manager_ptr = wallet_manager as *mut FFIWalletManager;
            assert_eq!((*wallet_manager_ptr).network(), FFINetwork::Testnet);

            // Get wallet count (should be 0 initially)
            let mut error = FFIError::success();
            let count = wallet_manager_wallet_count(
                wallet_manager as *const FFIWalletManager,
                &mut error as *mut FFIError,
            );
            assert_eq!(count, 0);

            // Clean up
            dash_spv_ffi_wallet_manager_free(wallet_manager);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    fn test_wallet_manager_shared_via_client_imports_wallet() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();
            assert!(!config.is_null());

            let temp_dir = TempDir::new().unwrap();
            dash_spv_ffi_config_set_data_dir(
                config,
                CString::new(temp_dir.path().to_str().unwrap()).unwrap().as_ptr(),
            );

            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
            assert!(!wallet_manager.is_null());
            let wallet_manager_ptr = wallet_manager as *mut key_wallet_ffi::FFIWalletManager;
            assert_eq!((*wallet_manager_ptr).network(), FFINetwork::Testnet);

            // Prepare a serialized wallet using the native manager so we can import it
            let mut native_manager =
                WalletManager::<ManagedWalletInfo>::new((*config).get_inner().network);
            let (serialized_wallet, expected_wallet_id) = native_manager
                .create_wallet_from_mnemonic_return_serialized_bytes(
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                    "",
                    0,
                    WalletAccountCreationOptions::Default,
                    false,
                    false,
                )
                .expect("wallet serialization should succeed");

            // Import the serialized wallet through the FFI pointer we retrieved from the client
            let mut error = FFIError::success();
            let mut imported_wallet_id = [0u8; 32];
            let import_ok = wallet_manager_import_wallet_from_bytes(
                wallet_manager_ptr,
                serialized_wallet.as_ptr(),
                serialized_wallet.len(),
                imported_wallet_id.as_mut_ptr(),
                &mut error as *mut FFIError,
            );
            assert!(import_ok, "import should succeed: {:?}", error);
            assert_eq!(imported_wallet_id, expected_wallet_id);

            // Fetch wallet IDs through FFI to confirm the manager sees the new wallet
            let mut ids_ptr: *mut u8 = std::ptr::null_mut();
            let mut id_count: usize = 0;
            let ids_ok = wallet_manager_get_wallet_ids(
                wallet_manager_ptr as *const FFIWalletManager,
                &mut ids_ptr,
                &mut id_count,
                &mut error as *mut FFIError,
            );
            assert!(ids_ok, "get_wallet_ids should succeed: {:?}", error);
            assert_eq!(id_count, 1);
            assert!(!ids_ptr.is_null());

            let ids_slice = std::slice::from_raw_parts(ids_ptr, id_count * 32);
            assert_eq!(&ids_slice[..32], &expected_wallet_id);
            wallet_manager_free_wallet_ids(ids_ptr, id_count);

            // Call the describe helper through FFI to ensure the shared instance reports correctly
            let mut description_error = FFIError::success();
            let description_ptr = key_wallet_ffi::wallet_manager_describe(
                wallet_manager_ptr as *const FFIWalletManager,
                &mut description_error as *mut FFIError,
            );
            assert!(!description_ptr.is_null(), "describe should succeed: {:?}", description_error);
            let description = CStr::from_ptr(description_ptr).to_string_lossy().into_owned();
            key_wallet_ffi::wallet_manager_free_string(description_ptr);
            assert!(
                description.contains("WalletManager: 1 wallet"),
                "description should mention the imported wallet, got: {}",
                description
            );

            dash_spv_ffi_wallet_manager_free(wallet_manager);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
