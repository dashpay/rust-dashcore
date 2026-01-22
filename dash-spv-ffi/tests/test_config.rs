#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;

    #[test]
    #[serial]
    fn test_config_creation() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);
            assert!(!config.is_null());

            let network = dash_spv_ffi_config_get_network(config);
            assert_eq!(network as i32, FFINetwork::Testnet as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_mainnet() {
        unsafe {
            let config = dash_spv_ffi_config_mainnet();
            assert!(!config.is_null());

            let network = dash_spv_ffi_config_get_network(config);
            assert_eq!(network as i32, FFINetwork::Dash as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_testnet() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();
            assert!(!config.is_null());

            let network = dash_spv_ffi_config_get_network(config);
            assert_eq!(network as i32, FFINetwork::Testnet as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_set_data_dir() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);

            let path = CString::new("/tmp/dash-spv-test").unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_null_checks() {
        unsafe {
            let result = dash_spv_ffi_config_set_data_dir(std::ptr::null_mut(), std::ptr::null());
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);
            let result = dash_spv_ffi_config_set_data_dir(config, std::ptr::null());
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_peers() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);

            let peer_addr = CString::new("127.0.0.1:9999").unwrap();
            let result = dash_spv_ffi_config_add_peer(config, peer_addr.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            let invalid_addr = CString::new("not-an-address").unwrap();
            let result = dash_spv_ffi_config_add_peer(config, invalid_addr.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_user_agent() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);

            let agent = CString::new("TestAgent/1.0").unwrap();
            let result = dash_spv_ffi_config_set_user_agent(config, agent.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }
}
