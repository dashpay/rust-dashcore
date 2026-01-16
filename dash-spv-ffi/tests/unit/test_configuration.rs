#[cfg(test)]
mod tests {
    use crate::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::{CStr, CString};

    #[test]
    #[serial]
    fn test_extremely_long_paths() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test with very long path (near filesystem limits)
            let long_path = format!("/tmp/{}", "x".repeat(4000));
            let c_path = CString::new(long_path.clone()).unwrap();
            let result = dash_spv_ffi_config_builder_set_storage_path(builder, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Verify it was set
            let config = dash_spv_ffi_config_builder_build(builder);
            assert!(config.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_invalid_peer_addresses() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();
            let config = dash_spv_ffi_config_builder_build(builder);

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
            let builder = dash_spv_ffi_config_builder_testnet();
            let config = dash_spv_ffi_config_builder_build(builder);

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
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test paths with spaces
            let path_with_spaces = "/tmp/path with spaces/dash spv";
            let c_path = CString::new(path_with_spaces).unwrap();
            let result = dash_spv_ffi_config_builder_set_storage_path(builder, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test paths with unicode
            let unicode_path = "/tmp/путь/目录/dossier";
            let c_path = CString::new(unicode_path).unwrap();
            let result = dash_spv_ffi_config_builder_set_storage_path(builder, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            let config = dash_spv_ffi_config_builder_build(builder);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_relative_vs_absolute_paths() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test relative path
            let rel_path = "./data/dash-spv";
            let c_path = CString::new(rel_path).unwrap();
            let result = dash_spv_ffi_config_builder_set_storage_path(builder, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test absolute path
            let abs_path = "/tmp/dash-spv-test";
            let c_path = CString::new(abs_path).unwrap();
            let result = dash_spv_ffi_config_builder_set_storage_path(builder, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test home directory expansion (won't actually expand in FFI)
            let home_path = "~/dash-spv";
            let c_path = CString::new(home_path).unwrap();
            let result = dash_spv_ffi_config_builder_set_storage_path(builder, c_path.as_ptr());
            assert_eq!(result, FFIErrorCode::Success as i32);

            let config = dash_spv_ffi_config_builder_build(builder);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_all_settings() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_regtest();

            // Set all possible configuration options
            let data_dir = CString::new("/tmp/test-dash-spv").unwrap();
            assert_eq!(
                dash_spv_ffi_config_builder_set_storage_path(builder, data_dir.as_ptr()),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::Full),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_max_peers(builder, 50),
                FFIErrorCode::Success as i32
            );

            let user_agent = CString::new("TestAgent/1.0").unwrap();
            assert_eq!(
                dash_spv_ffi_config_builder_set_user_agent(builder, user_agent.as_ptr()),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_relay_transactions(builder, true),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_filter_load(builder, true),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_restrict_to_configured_peers(builder, true),
                FFIErrorCode::Success as i32
            );

            let config = dash_spv_ffi_config_builder_build(builder);

            let peer = CString::new("127.0.0.1:9999").unwrap();
            assert_eq!(
                dash_spv_ffi_config_add_peer(config, peer.as_ptr()),
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
                dash_spv_ffi_config_builder_set_storage_path(
                    std::ptr::null_mut(),
                    std::ptr::null()
                ),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_validation_mode(
                    std::ptr::null_mut(),
                    FFIValidationMode::Basic
                ),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_max_peers(std::ptr::null_mut(), 10),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_add_peer(std::ptr::null_mut(), std::ptr::null()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_user_agent(std::ptr::null_mut(), std::ptr::null()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_relay_transactions(std::ptr::null_mut(), false),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_filter_load(std::ptr::null_mut(), false),
                FFIErrorCode::NullPointer as i32
            );

            // Test getters with null
            let net = dash_spv_ffi_config_get_network(std::ptr::null());
            assert_eq!(net as i32, FFINetwork::Dash as i32); // Returns default

            let dir = dash_spv_ffi_config_get_storage_path(std::ptr::null());
            assert!(dir.ptr.is_null());

            // Test destroy with null (should be safe)
            dash_spv_ffi_config_destroy(std::ptr::null_mut());
        }
    }

    #[test]
    #[serial]
    fn test_config_validation_modes() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test all validation modes
            let modes =
                [FFIValidationMode::None, FFIValidationMode::Basic, FFIValidationMode::Full];
            for mode in modes {
                let result = dash_spv_ffi_config_builder_set_validation_mode(builder, mode);
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            let config = dash_spv_ffi_config_builder_build(builder);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_config_edge_case_values() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test max peers with edge values
            assert_eq!(
                dash_spv_ffi_config_builder_set_max_peers(builder, 0),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_max_peers(builder, 1),
                FFIErrorCode::Success as i32
            );

            assert_eq!(
                dash_spv_ffi_config_builder_set_max_peers(builder, u32::MAX),
                FFIErrorCode::Success as i32
            );

            // Test empty strings
            let empty = CString::new("").unwrap();
            assert_eq!(
                dash_spv_ffi_config_builder_set_storage_path(builder, empty.as_ptr()),
                FFIErrorCode::Success as i32
            );

            let config = dash_spv_ffi_config_builder_build(builder);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_worker_threads_configuration() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test setting worker threads to 0 (auto mode)
            let result = dash_spv_ffi_config_builder_set_worker_threads(builder, 0);
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test setting specific worker thread counts
            let thread_counts = [1, 2, 4, 8, 16, 32];
            for &count in &thread_counts {
                let result = dash_spv_ffi_config_builder_set_worker_threads(builder, count);
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            // Test large worker thread count
            let result = dash_spv_ffi_config_builder_set_worker_threads(builder, 1000);
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test maximum value
            let result = dash_spv_ffi_config_builder_set_worker_threads(builder, u32::MAX);
            assert_eq!(result, FFIErrorCode::Success as i32);

            let config = dash_spv_ffi_config_builder_build(builder);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_worker_threads_with_null_config() {
        unsafe {
            // Test with null config pointer
            let result = dash_spv_ffi_config_builder_set_worker_threads(std::ptr::null_mut(), 4);
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            // Check error was set
            let error_ptr = dash_spv_ffi_get_last_error();
            assert!(!error_ptr.is_null());
            let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
            assert!(
                error_str.contains("Null")
                    || error_str.contains("null")
                    || error_str.contains("invalid")
            );
        }
    }

    #[test]
    #[serial]
    fn test_worker_threads_persistence() {
        unsafe {
            // Test that worker thread setting is preserved
            for &thread_count in &[0, 1, 4, 8] {
                let builder = dash_spv_ffi_config_builder_testnet();

                // Set worker threads
                let result = dash_spv_ffi_config_builder_set_worker_threads(builder, thread_count);
                assert_eq!(result, FFIErrorCode::Success as i32);

                // Create client with this config (this tests that the setting is used)
                let temp_dir = tempfile::TempDir::new().unwrap();
                let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
                dash_spv_ffi_config_builder_set_storage_path(builder, path.as_ptr());
                dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::None);

                let config = dash_spv_ffi_config_builder_build(builder);

                let client = dash_spv_ffi_client_new(config);
                // Client creation should succeed regardless of worker thread count
                assert!(
                    !client.is_null(),
                    "Failed to create client with {} worker threads",
                    thread_count
                );

                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }
        }
    }

    #[test]
    #[serial]
    fn test_worker_threads_multiple_configs() {
        unsafe {
            // Test that different configs can have different worker thread counts
            let builders = [
                (dash_spv_ffi_config_builder_testnet(), 1),
                (dash_spv_ffi_config_builder_mainnet(), 4),
                (dash_spv_ffi_config_builder_regtest(), 8),
            ];

            for (builder, thread_count) in builders {
                let result = dash_spv_ffi_config_builder_set_worker_threads(builder, thread_count);
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            // Clean up all configs
            for (builder, _) in builders {
                let config = dash_spv_ffi_config_builder_build(builder);
                dash_spv_ffi_config_destroy(config);
            }
        }
    }

    #[test]
    #[serial]
    fn test_worker_threads_edge_cases() {
        unsafe {
            let builder = dash_spv_ffi_config_builder_testnet();

            // Test repeated setting of worker threads
            for _ in 0..10 {
                let result = dash_spv_ffi_config_builder_set_worker_threads(builder, 4);
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            // Test setting different values in sequence
            let sequence = [0, 1, 0, 8, 0, 16, 0];
            for &count in &sequence {
                let result = dash_spv_ffi_config_builder_set_worker_threads(builder, count);
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            let config = dash_spv_ffi_config_builder_build(builder);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
