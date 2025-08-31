#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::{
        wallet_manager::{wallet_manager_free, wallet_manager_wallet_count},
        FFIError, FFIWalletManager,
    };

    #[test]
    fn test_get_wallet_manager() {
        unsafe {
            // Create a config
            let config = dash_spv_ffi_config_testnet();
            assert!(!config.is_null());

            // Create a client
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Get wallet manager
            let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
            assert!(!wallet_manager.is_null());

            // Get wallet count (should be 0 initially)
            let mut error = FFIError::success();
            let count = wallet_manager_wallet_count(
                wallet_manager as *const FFIWalletManager,
                &mut error as *mut FFIError,
            );
            assert_eq!(count, 0);

            // Clean up
            wallet_manager_free(wallet_manager as *mut FFIWalletManager);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
