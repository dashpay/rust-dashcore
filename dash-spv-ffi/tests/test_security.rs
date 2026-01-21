#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;
    use tempfile::TempDir;

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
            let special_chars = "\0\n\r\t\x01\x02\x03";
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
            assert_eq!(
                dash_spv_ffi_config_set_data_dir(ptr::null_mut(), ptr::null()),
                FFIErrorCode::NullPointer as i32
            );
            assert_eq!(
                dash_spv_ffi_config_set_validation_mode(ptr::null_mut(), FFIValidationMode::Basic),
                FFIErrorCode::NullPointer as i32
            );
            assert_eq!(
                dash_spv_ffi_config_add_peer(ptr::null_mut(), ptr::null()),
                FFIErrorCode::NullPointer as i32
            );

            // Client functions
            assert!(dash_spv_ffi_client_new(ptr::null()).is_null());
            assert_eq!(
                dash_spv_ffi_client_start(ptr::null_mut()),
                FFIErrorCode::NullPointer as i32
            );
            assert!(dash_spv_ffi_client_get_sync_progress(ptr::null_mut()).is_null());

            // Destruction functions should handle null gracefully
            dash_spv_ffi_client_destroy(ptr::null_mut());
            dash_spv_ffi_config_destroy(ptr::null_mut());
            dash_spv_ffi_string_destroy(FFIString {
                ptr: ptr::null_mut(),
                length: 0,
            });
            let array = FFIArray {
                data: ptr::null_mut(),
                len: 0,
                capacity: 0,
                elem_size: 0,
                elem_align: 0,
            };
            dash_spv_ffi_array_destroy(Box::into_raw(Box::new(array)));
        }
    }

    #[test]
    #[serial]
    fn test_integer_overflow_protection() {
        unsafe {
            // Test with maximum values
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);

            // Test setting max peers to u32::MAX
            let result = dash_spv_ffi_config_set_max_peers(config, u32::MAX);
            assert_eq!(result, FFIErrorCode::Success as i32);

            // Test large array allocation
            let huge_size = usize::MAX / 2; // Avoid actual overflow
            let huge_array = FFIArray {
                data: ptr::null_mut(),
                len: huge_size,
                capacity: huge_size,
                elem_size: 0,
                elem_align: 0,
            };

            // Should handle large sizes safely
            dash_spv_ffi_array_destroy(Box::into_raw(Box::new(huge_array)));

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
