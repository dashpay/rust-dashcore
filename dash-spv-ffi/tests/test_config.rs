#[cfg(test)]
mod tests {
    use dash_network::ffi::FFINetwork;
    use dash_spv_ffi::*;
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
            assert_eq!(network as i32, FFINetwork::Mainnet as i32);

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

    #[test]
    #[serial]
    fn test_config_broadcast_holdout_setters() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);

            let result = dash_spv_ffi_config_set_broadcast_holdout_count(config, 2);
            assert_eq!(result, FFIErrorCode::Success as i32);
            assert_eq!(
                (*config).get_inner().broadcast_holdout,
                dash_spv::BroadcastHoldout::Count(2)
            );

            let result = dash_spv_ffi_config_set_broadcast_holdout_half(config);
            assert_eq!(result, FFIErrorCode::Success as i32);
            assert_eq!((*config).get_inner().broadcast_holdout, dash_spv::BroadcastHoldout::Half);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_broadcast_acceptance_threshold() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);

            // Zero is rejected and leaves the default intact
            let default_threshold = (*config).get_inner().broadcast_acceptance_threshold;
            let result = dash_spv_ffi_config_set_broadcast_acceptance_threshold(config, 0);
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);
            assert_eq!(
                (*config).get_inner().broadcast_acceptance_threshold,
                default_threshold,
                "rejected value must not modify the config"
            );

            // Nonzero maps to the ClientConfig field
            let result = dash_spv_ffi_config_set_broadcast_acceptance_threshold(config, 3);
            assert_eq!(result, FFIErrorCode::Success as i32);
            assert_eq!((*config).get_inner().broadcast_acceptance_threshold, 3);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_broadcast_acceptance_timeout() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Testnet);

            // Zero is rejected and leaves the default intact
            let default_timeout = (*config).get_inner().broadcast_acceptance_timeout;
            let result = dash_spv_ffi_config_set_broadcast_acceptance_timeout_secs(config, 0);
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);
            assert_eq!(
                (*config).get_inner().broadcast_acceptance_timeout,
                default_timeout,
                "rejected value must not modify the config"
            );

            // Nonzero maps to the ClientConfig field
            let result = dash_spv_ffi_config_set_broadcast_acceptance_timeout_secs(config, 90);
            assert_eq!(result, FFIErrorCode::Success as i32);
            assert_eq!(
                (*config).get_inner().broadcast_acceptance_timeout,
                std::time::Duration::from_secs(90)
            );

            dash_spv_ffi_config_destroy(config);
        }
    }
}
