#[cfg(test)]
mod tests {
    use crate::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;

    #[test]
    #[serial]
    fn test_config_with_invalid_network() {
        unsafe {
            // Test creating config with each valid network
            let networks =
                [FFINetwork::Dash, FFINetwork::Testnet, FFINetwork::Regtest, FFINetwork::Devnet];
            for net in networks {
                let config = dash_spv_ffi_config_new(net);
                assert!(!config.is_null());
                let retrieved_net = dash_spv_ffi_config_get_network(config);
                assert_eq!(retrieved_net as i32, net as i32);
                dash_spv_ffi_config_destroy(config);
            }
        }
    }

    #[test]
    #[serial]
    fn test_extremely_long_paths() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();

            // Test with very long path (near filesystem limits)
            let long_path = format!("/tmp/{}", "x".repeat(4000));
            let c_path = CString::new(long_path.clone()).unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_invalid_peer_addresses() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();

            // Test various invalid addresses
            let invalid_addrs = [
                "",                     // empty string
                "256.256.256.256:9999", // invalid IP octets
                "127.0.0.1:99999",      // port too high
                "127.0.0.1:-1",         // negative port
                ":9999",                // missing hostname
                "localhost:",           // missing port
                ":",                    // missing hostname and port
                ":::",                  // invalid IPv6
                "localhost:abc",        // non-numeric port
            ];

            for addr in &invalid_addrs {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_config_add_peer(config, c_addr.as_ptr());
                assert_eq!(
                    result,
                    FFIErrorCode::InvalidArgument as i32,
                    "Expected '{}' to be invalid",
                    addr
                );

                // Check error message
                let error_ptr = dash_spv_ffi_get_last_error();
                assert!(!error_ptr.is_null());
            }

            // Test valid addresses including IP-only forms (port inferred from network)
            let valid_addrs = [
                "127.0.0.1:9999",
                "192.168.1.1:8333",
                "[::1]:9999",
                "[2001:db8::1]:8333",
                "127.0.0.1",      // IP-only v4
                "2001:db8::1",    // IP-only v6
                "localhost:9999", // Hostname with port
                "localhost",      // Hostname without port (uses default)
            ];

            for addr in &valid_addrs {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_config_add_peer(config, c_addr.as_ptr());
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_adding_maximum_peers() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();

            // Add many peers
            for i in 0..1000 {
                let addr = format!("192.168.1.{}:9999", (i % 254) + 1);
                let c_addr = CString::new(addr).unwrap();
                let result = dash_spv_ffi_config_add_peer(config, c_addr.as_ptr());
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_with_special_characters_in_paths() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();

            // Test paths with spaces
            let path_with_spaces = "/tmp/path with spaces/dash spv";
            let c_path = CString::new(path_with_spaces).unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test paths with unicode
            let unicode_path = "/tmp/путь/目录/dossier";
            let c_path = CString::new(unicode_path).unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_relative_vs_absolute_paths() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();

            // Test relative path
            let rel_path = "./data/dash-spv";
            let c_path = CString::new(rel_path).unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test absolute path
            let abs_path = "/tmp/dash-spv-test";
            let c_path = CString::new(abs_path).unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test home directory expansion (won't actually expand in FFI)
            let home_path = "~/dash-spv";
            let c_path = CString::new(home_path).unwrap();
            let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_all_settings() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);

            // Set all possible configuration options
            let data_dir = CString::new("/tmp/test-dash-spv").unwrap();
            assert_eq!(
                dash_spv_ffi_config_set_data_dir(config, data_dir.as_ptr()),
                FFIErrorCode::Success as i32
            );

            let peer = CString::new("127.0.0.1:9999").unwrap();
            assert_eq!(
                dash_spv_ffi_config_add_peer(config, peer.as_ptr()),
                FFIErrorCode::Success as i32
            );

            let user_agent = CString::new("TestAgent/1.0").unwrap();
            assert_eq!(
                dash_spv_ffi_config_set_user_agent(config, user_agent.as_ptr()),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_set_restrict_to_configured_peers(config, true),
                FFIErrorCode::Success as i32
            );

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_null_handling() {
        unsafe {
            // Test all functions with null config
            assert_eq!(
                dash_spv_ffi_config_set_data_dir(std::ptr::null_mut(), std::ptr::null()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_add_peer(std::ptr::null_mut(), std::ptr::null()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_set_user_agent(std::ptr::null_mut(), std::ptr::null()),
                FFIErrorCode::NullPointer as i32
            );

            // Test getters with null
            let net = dash_spv_ffi_config_get_network(std::ptr::null());
            assert_eq!(net as i32, FFINetwork::Dash as i32); // Returns default

            // Test destroy with null (should be safe)
            dash_spv_ffi_config_destroy(std::ptr::null_mut());
        }
    }

    #[test]
    #[serial]
    fn test_config_edge_case_values() {
        unsafe {
            let config = dash_spv_ffi_config_testnet();

            // Test empty strings
            let empty = CString::new("").unwrap();
            assert_eq!(
                dash_spv_ffi_config_set_data_dir(config, empty.as_ptr()),
                FFIErrorCode::Success as i32
            );

            dash_spv_ffi_config_destroy(config);
        }
    }
}
