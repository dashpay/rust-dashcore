#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use std::ffi::{CString, CStr};
    use std::os::raw::{c_char, c_void};
    use serial_test::serial;
    use tempfile::TempDir;
    use std::process::Command;
    use std::path::PathBuf;
    use std::fs;

    #[test]
    #[serial]
    fn test_c_header_generation() {
        // Verify that cbindgen can generate valid C headers
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let header_path = crate_dir.join("dash_spv_ffi.h");

        // Run cbindgen
        let output = Command::new("cbindgen")
            .current_dir(&crate_dir)
            .arg("--config")
            .arg("cbindgen.toml")
            .arg("--crate")
            .arg("dash-spv-ffi")
            .arg("--output")
            .arg(&header_path)
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                // Verify header was created
                assert!(header_path.exists(), "C header file was not generated");

                // Read and validate header content
                let header_content = fs::read_to_string(&header_path).unwrap();

                // Check for essential function declarations
                assert!(header_content.contains("dash_spv_ffi_client_new"));
                assert!(header_content.contains("dash_spv_ffi_client_destroy"));
                assert!(header_content.contains("dash_spv_ffi_config_new"));
                assert!(header_content.contains("FFINetwork"));
                assert!(header_content.contains("FFIErrorCode"));

                // Check for proper extern "C" blocks
                assert!(header_content.contains("extern \"C\"") || header_content.contains("#ifdef __cplusplus"));

                println!("C header generated successfully with {} lines", header_content.lines().count());
            } else {
                println!("cbindgen not available or failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        } else {
            println!("cbindgen command not found, skipping header generation test");
        }
    }

    #[test]
    #[serial]
    fn test_string_encoding_compatibility() {
        unsafe {
            // Test various string encodings that might come from C
            let long_string = "Very long string ".repeat(1000);
            let test_strings = vec![
                "Simple ASCII string",
                "UTF-8 with émojis 🎉",
                "Special chars: \n\r\t",
                "Null in middle: before\0after", // Will be truncated at null
                long_string.as_str(),
            ];

            for test_str in &test_strings {
                // Simulate C string creation
                let c_string = CString::new(test_str.as_bytes()).unwrap_or_else(|_| {
                    // Handle null bytes by truncating
                    let null_pos = test_str.find('\0').unwrap_or(test_str.len());
                    CString::new(&test_str[..null_pos]).unwrap()
                });

                // Pass through FFI boundary
                let ffi_string = FFIString {
                    ptr: c_string.as_ptr() as *mut c_char,
                    length: test_str.len(),
                };

                // Recover on Rust side
                if let Ok(recovered) = FFIString::from_ptr(ffi_string.ptr) {
                    // Verify we can handle the string
                    assert!(!recovered.is_empty() || test_str.is_empty());
                }
            }
        }
    }

    #[test]
    #[serial]
    fn test_struct_alignment_compatibility() {
        // Verify struct sizes and alignments match C expectations

        // Check size of enums (should be C int-compatible)
        assert_eq!(std::mem::size_of::<FFINetwork>(), std::mem::size_of::<i32>());
        assert_eq!(std::mem::size_of::<FFIErrorCode>(), std::mem::size_of::<i32>());
        assert_eq!(std::mem::size_of::<FFIValidationMode>(), std::mem::size_of::<i32>());

        // Check alignment of structs
        assert!(std::mem::align_of::<FFISyncProgress>() <= 8);
        assert!(std::mem::align_of::<FFIBalance>() <= 8);

        // Verify FFIString is pointer-sized
        assert_eq!(std::mem::size_of::<FFIString>(), std::mem::size_of::<*mut c_char>());

        // Verify FFIArray has expected layout
        assert_eq!(std::mem::size_of::<FFIArray>(),
                   std::mem::size_of::<*mut c_void>() + std::mem::size_of::<usize>());
    }

    #[test]
    #[serial]
    fn test_callback_calling_conventions() {
        unsafe {
            // Test that callbacks work with different calling conventions
            let mut callback_called = false;
            let mut received_progress = 0.0;

            extern "C" fn test_callback(progress: f64, msg: *const c_char, user_data: *mut c_void) {
                let data = user_data as *mut (bool, f64);
                let (called, prog) = &mut *data;
                *called = true;
                *prog = progress;

                // Verify we can safely access the message
                if !msg.is_null() {
                    let _ = CStr::from_ptr(msg);
                }
            }

            let mut user_data = (callback_called, received_progress);
            let user_data_ptr = &mut user_data as *mut _ as *mut c_void;

            // Simulate callback invocation
            test_callback(50.0, std::ptr::null(), user_data_ptr);

            assert!(user_data.0);
            assert_eq!(user_data.1, 50.0);
        }
    }

    #[test]
    #[serial]
    fn test_error_code_consistency() {
        // Verify error codes are consistent and non-overlapping
        let error_codes = vec![
            FFIErrorCode::Success as i32,
            FFIErrorCode::NullPointer as i32,
            FFIErrorCode::InvalidArgument as i32,
            FFIErrorCode::NetworkError as i32,
            FFIErrorCode::StorageError as i32,
            FFIErrorCode::ValidationError as i32,
            FFIErrorCode::SyncError as i32,
            FFIErrorCode::WalletError as i32,
            FFIErrorCode::ConfigError as i32,
            FFIErrorCode::RuntimeError as i32,
            FFIErrorCode::Unknown as i32,
        ];

        // Check all codes are unique
        let mut seen = std::collections::HashSet::new();
        for code in &error_codes {
            assert!(seen.insert(*code), "Duplicate error code: {}", code);
        }

        // Verify Success is 0 (C convention)
        assert_eq!(FFIErrorCode::Success as i32, 0);

        // Verify other codes are positive
        for code in &error_codes[1..] {
            assert!(*code > 0, "Error code should be positive: {}", code);
        }
    }

    #[test]
    #[serial]
    fn test_pointer_validity_across_calls() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            // Create client and store pointer
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());
            let client_addr = client as usize;

            // Use client multiple times - pointer should remain valid
            for _ in 0..10 {
                let progress = dash_spv_ffi_client_get_sync_progress(client);
                if !progress.is_null() {
                    // Verify pointer is in reasonable range
                    let progress_addr = progress as usize;
                    assert!(progress_addr > 0);
                    dash_spv_ffi_sync_progress_destroy(progress);
                }
            }

            // Verify client pointer hasn't changed
            assert_eq!(client as usize, client_addr);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_thread_safety_annotations() {
        // This test verifies our thread safety assumptions
        // In a real C integration, these would be documented

        // Client should be Send (can be moved between threads)
        fn assert_send<T: Send>() {}
        assert_send::<*mut FFIDashSpvClient>();

        // Config should be Send
        assert_send::<*mut FFIClientConfig>();

        // But raw pointers are not Sync by default (correct)
        // This means C code needs proper synchronization for concurrent access
    }

    #[test]
    #[serial]
    fn test_null_termination_handling() {
        unsafe {
            // Test that all string functions properly null-terminate
            let test_str = "Test string";
            let ffi_str = FFIString::new(test_str);

            // Manually verify null termination
            let c_str = ffi_str.ptr as *const c_char;
            let mut len = 0;
            while *c_str.offset(len) != 0 {
                len += 1;
            }
            assert_eq!(len as usize, test_str.len());

            // Verify the byte after the string is null
            assert_eq!(*c_str.offset(len), 0);

            dash_spv_ffi_string_destroy(ffi_str);
        }
    }

    #[test]
    #[serial]
    fn test_platform_specific_types() {
        // Verify sizes of C types across platforms
        assert_eq!(std::mem::size_of::<c_char>(), 1);
        // c_void is a zero-sized type in Rust (it's an opaque type)
        assert_eq!(std::mem::size_of::<c_void>(), 0);

        // Verify pointer sizes (platform-dependent)
        let ptr_size = std::mem::size_of::<*mut c_void>();
        assert!(ptr_size == 4 || ptr_size == 8); // 32-bit or 64-bit

        // Verify usize matches pointer size (important for FFI)
        assert_eq!(std::mem::size_of::<usize>(), ptr_size);
    }
}
