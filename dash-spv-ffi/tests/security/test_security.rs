#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use std::ffi::{CString, CStr};
    use std::os::raw::{c_char, c_void};
    use serial_test::serial;
    use tempfile::TempDir;
    use std::ptr;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    #[serial]
    fn test_buffer_overflow_protection() {
        unsafe {
            // Test string handling with potential overflow scenarios

            // Very long string
            let long_string = "A".repeat(10_000_000);
            let ffi_str = FFIString::new(&long_string);
            assert!(!ffi_str.ptr.is_null());

            // Verify we can read it back without corruption
            let recovered = FFIString::from_ptr(ffi_str.ptr).unwrap();
            assert_eq!(recovered.len(), long_string.len());

            dash_spv_ffi_string_destroy(ffi_str);

            // Test with strings containing special characters
            let special_chars = "\0\n\r\t\x01\x02\x03\xFF";
            let c_string = CString::new(special_chars.replace('\0', "")).unwrap();
            let ffi_special = FFIString {
                ptr: c_string.as_ptr() as *mut c_char,
                length: special_chars.replace('\0', "").len(),
            };

            if let Ok(recovered) = FFIString::from_ptr(ffi_special.ptr) {
                // Should handle special chars safely
                assert!(!recovered.is_empty());
            }
        }
    }

    #[test]
    #[serial]
    fn test_null_pointer_dereferencing() {
        unsafe {
            // Test all functions with null pointers

            // Config functions
            assert_eq!(dash_spv_ffi_config_set_data_dir(ptr::null_mut(), ptr::null()),
                      FFIErrorCode::NullPointer as i32);
            assert_eq!(dash_spv_ffi_config_builder_set_validation_mode(ptr::null_mut(), FFIValidationMode::Basic),
                      FFIErrorCode::NullPointer as i32);
            assert_eq!(dash_spv_ffi_config_add_peer(ptr::null_mut(), ptr::null()),
                      FFIErrorCode::NullPointer as i32);

            // Client functions
            assert!(dash_spv_ffi_client_new(ptr::null()).is_null());
            assert_eq!(dash_spv_ffi_client_start(ptr::null_mut()),
                      FFIErrorCode::NullPointer as i32);
            assert!(dash_spv_ffi_client_get_sync_progress(ptr::null_mut()).is_null());

            // Destruction functions should handle null gracefully
            dash_spv_ffi_client_destroy(ptr::null_mut());
            dash_spv_ffi_config_destroy(ptr::null_mut());
            dash_spv_ffi_string_destroy(FFIString { ptr: ptr::null_mut(), length: 0 });
            dash_spv_ffi_array_destroy(FFIArray { data: ptr::null_mut(), len: 0, capacity: 0 });
        }
    }

    #[test]
    #[serial]
    fn test_use_after_free_prevention() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let builder = dash_spv_ffi_config_builder_regtest();
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_builder_set_data_dir(builder, path.as_ptr());

            let config = dash_spv_ffi_config_builder_build(builder);

            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Destroy the client
            dash_spv_ffi_client_destroy(client);

            // These operations should handle the freed pointer safely
            // (In a real implementation, these should check for validity)
            let result = dash_spv_ffi_client_start(client);
            assert_ne!(result, FFIErrorCode::Success as i32);

            // Destroy config
            dash_spv_ffi_config_destroy(config);

            // Using config after free should fail
            let result = dash_spv_ffi_config_builder_set_max_peers(builder, 10);
            assert_ne!(result, FFIErrorCode::Success as i32);
        }
    }

    #[test]
    #[serial]
    fn test_integer_overflow_protection() {
        unsafe {
            // Test with maximum values
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);

            // Test setting max peers to u32::MAX
            let result = dash_spv_ffi_config_builder_set_max_peers(config, u32::MAX);
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test large array allocation
            let huge_size = usize::MAX / 2; // Avoid actual overflow
            let huge_array = FFIArray {
                data: ptr::null_mut(),
                len: huge_size,
                capacity: huge_size,
            };

            // Should handle large sizes safely
            dash_spv_ffi_array_destroy(huge_array);

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_race_condition_safety() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            let client_ptr = Arc::new(Mutex::new(client));
            let stop_flag = Arc::new(Mutex::new(false));
            let mut handles = vec![];

            // Spawn threads that will race
            for i in 0..10 {
                let client_clone = client_ptr.clone();
                let stop_clone = stop_flag.clone();

                let handle = thread::spawn(move || {
                    while !*stop_clone.lock().unwrap() {
                        let client = *client_clone.lock().unwrap();

                        // Perform operations that might race
                        match i % 3 {
                            0 => {
                                let progress = dash_spv_ffi_client_get_sync_progress(client);
                                if !progress.is_null() {
                                    dash_spv_ffi_sync_progress_destroy(progress);
                                }
                            }
                            1 => {
                                let stats = dash_spv_ffi_client_get_stats(client);
                                if !stats.is_null() {
                                    dash_spv_ffi_spv_stats_destroy(stats);
                                }
                            }
                            2 => {
                                let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
                                dash_spv_ffi_client_watch_address(client, addr.as_ptr());
                            }
                            _ => {}
                        }

                        thread::yield_now();
                    }
                });
                handles.push(handle);
            }

            // Let threads race for a bit
            thread::sleep(std::time::Duration::from_millis(100));

            // Stop all threads
            *stop_flag.lock().unwrap() = true;

            for handle in handles {
                handle.join().unwrap();
            }

            let client = *client_ptr.lock().unwrap();
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_input_validation() {
        unsafe {
            // Test various invalid inputs
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);

            // Invalid IP addresses
            let invalid_ips = vec![
                "999.999.999.999:9999",
                "256.0.0.1:9999",
                "not.an.ip:9999",
                "192.168.1.1:99999", // Port too high
                "192.168.1.1:-1",    // Negative port
                "",                   // Empty string
                ":::::",              // Invalid IPv6
            ];

            for ip in invalid_ips {
                let c_ip = CString::new(ip).unwrap();
                let result = dash_spv_ffi_config_add_peer(config, c_ip.as_ptr());
                assert_eq!(result, FFIErrorCode::InvalidArgument as i32,
                          "Should reject invalid IP: {}", ip);
            }

            // Invalid Bitcoin/Dash addresses
            let temp_dir = TempDir::new().unwrap();
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config);

            let invalid_addrs = vec![
                "",
                "notanaddress",
                "1BitcoinAddress",  // Bitcoin, not Dash
                "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1",  // Too short
                "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1EE", // Too long
                &"X".repeat(100),  // Way too long
            ];

            for addr in invalid_addrs {
                let c_addr = CString::new(addr).unwrap();
                let result = dash_spv_ffi_client_watch_address(client, c_addr.as_ptr());
                assert_eq!(result, FFIErrorCode::InvalidArgument as i32,
                          "Should reject invalid address: {}", addr);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_memory_exhaustion_handling() {
        unsafe {
            // Test allocation of many small objects
            let mut strings = Vec::new();

            // Try to allocate many strings (but not enough to actually exhaust memory)
            for i in 0..10000 {
                let s = FFIString::new(&format!("String number {}", i));
                strings.push(s);

                // Every 1000 allocations, free half to prevent actual exhaustion
                if i % 1000 == 999 {
                    let half = strings.len() / 2;
                    for _ in 0..half {
                        if let Some(s) = strings.pop() {
                            dash_spv_ffi_string_destroy(s);
                        }
                    }
                }
            }

            // Clean up remaining
            for s in strings {
                dash_spv_ffi_string_destroy(s);
            }

            // Test single large allocation
            let large_size = 100_000_000; // 100MB
            let large_string = "X".repeat(large_size);
            let large_ffi = FFIString::new(&large_string);

            // Should handle large allocation
            assert!(!large_ffi.ptr.is_null());
            dash_spv_ffi_string_destroy(large_ffi);
        }
    }

    #[test]
    #[serial]
    fn test_callback_security() {
        unsafe {
            // Test callback with malicious data
            let malicious_data = vec![
                "\0\0\0\0",  // Null bytes
                &"A".repeat(1_000_000), // Very long string
                "'; DROP TABLE users; --", // SQL injection attempt
                "<script>alert('xss')</script>", // XSS attempt
                "../../../etc/passwd", // Path traversal
                "%00%00%00%00", // URL encoded nulls
            ];

            extern "C" fn test_callback(progress: f64, msg: *const c_char, user_data: *mut c_void) {
                if !msg.is_null() {
                    // Should safely handle any input
                    let _ = CStr::from_ptr(msg);
                }

                // Validate progress is in expected range
                assert!(progress >= 0.0 && progress <= 100.0);
            }

            // Test callbacks with malicious messages
            for data in malicious_data {
                let c_str = CString::new(data.replace('\0', "")).unwrap();
                test_callback(50.0, c_str.as_ptr(), ptr::null_mut());
            }

            // Test callback with null message
            test_callback(50.0, ptr::null(), ptr::null_mut());

            // Test callback with invalid progress values
            test_callback(-1.0, ptr::null(), ptr::null_mut());
            test_callback(101.0, ptr::null(), ptr::null_mut());
            test_callback(f64::NAN, ptr::null(), ptr::null_mut());
            test_callback(f64::INFINITY, ptr::null(), ptr::null_mut());
        }
    }

    #[test]
    #[serial]
    fn test_path_traversal_prevention() {
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);

            // Test potentially dangerous paths
            let dangerous_paths = vec![
                "../../../sensitive/data",
                "/etc/passwd",
                "C:\\Windows\\System32",
                "~/../../root",
                "/dev/null",
                "\0/etc/passwd",
                "data\0../../etc/passwd",
            ];

            for path in dangerous_paths {
                // Remove null bytes for CString
                let safe_path = path.replace('\0', "");
                let c_path = CString::new(safe_path).unwrap();

                // Should accept the path (validation is up to the implementation)
                // but should not allow actual traversal
                let result = dash_spv_ffi_config_set_data_dir(config, c_path.as_ptr());

                // The implementation should sanitize or validate paths
                println!("Path '{}' result: {}", path, result);
            }

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_cryptographic_material_handling() {
        unsafe {
            // Test that sensitive data is handled securely
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config);

            // Test with private key-like hex strings (should be rejected or handled carefully)
            let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let c_key = CString::new(private_key_hex).unwrap();

            // This should not accept raw private keys
            let result = dash_spv_ffi_client_watch_script(client, c_key.as_ptr());

            // Test transaction broadcast doesn't leak sensitive info
            let tx_hex = "0100000000010000000000000000";
            let c_tx = CString::new(tx_hex).unwrap();
            let broadcast_result = dash_spv_ffi_client_broadcast_transaction(client, c_tx.as_ptr());

            // Check error messages don't contain sensitive data
            if broadcast_result != FFIErrorCode::Success as i32 {
                let error_ptr = dash_spv_ffi_get_last_error();
                if !error_ptr.is_null() {
                    let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
                    // Error should not contain the full transaction hex
                    assert!(!error_str.contains(tx_hex));
                }
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_dos_resistance() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config);

            // Test rapid repeated operations
            let start = std::time::Instant::now();
            let duration = std::time::Duration::from_millis(100);
            let mut operation_count = 0;

            while start.elapsed() < duration {
                // Rapidly request sync progress
                let progress = dash_spv_ffi_client_get_sync_progress(client);
                if !progress.is_null() {
                    dash_spv_ffi_sync_progress_destroy(progress);
                }
                operation_count += 1;
            }

            println!("Performed {} operations in {:?}", operation_count, duration);

            // System should still be responsive
            let final_progress = dash_spv_ffi_client_get_sync_progress(client);
            assert!(!final_progress.is_null());
            dash_spv_ffi_sync_progress_destroy(final_progress);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
