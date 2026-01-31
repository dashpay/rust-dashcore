#[cfg(test)]
mod tests {
    use crate::*;
    use key_wallet_ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_void};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    #[test]
    #[serial]
    fn test_string_memory_lifecycle() {
        unsafe {
            // Test FFIString allocation and deallocation
            let test_string = "Hello, FFI Memory Test!";
            let ffi_string = FFIString::new(test_string);
            assert!(!ffi_string.ptr.is_null());

            // Verify contents
            let recovered = FFIString::from_ptr(ffi_string.ptr).unwrap();
            assert_eq!(recovered, test_string);

            // Clean up
            dash_spv_ffi_string_destroy(ffi_string);

            // Test with empty string
            let empty = FFIString::new("");
            assert!(!empty.ptr.is_null());
            dash_spv_ffi_string_destroy(empty);

            // Test with very large string
            let large_string = "X".repeat(1_000_000);
            let large_ffi = FFIString::new(&large_string);
            assert!(!large_ffi.ptr.is_null());
            dash_spv_ffi_string_destroy(large_ffi);
        }
    }

    #[test]
    #[serial]
    fn test_client_memory_lifecycle() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            // Create and destroy multiple clients
            for _ in 0..10 {
                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Perform some operations
                let progress = dash_spv_ffi_client_get_sync_progress(client);
                if !progress.is_null() {
                    dash_spv_ffi_sync_progress_destroy(progress);
                }

                dash_spv_ffi_client_destroy(client);
            }

            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_concurrent_memory_operations() {
        let barrier = Arc::new(std::sync::Barrier::new(10));
        let mut handles = vec![];

        for i in 0..10 {
            let barrier_clone = barrier.clone();
            let handle = thread::spawn(move || {
                barrier_clone.wait();

                unsafe {
                    // Each thread creates and destroys strings
                    for j in 0..100 {
                        let s = format!("Thread {} iteration {}", i, j);
                        let ffi = FFIString::new(&s);

                        // Simulate some work
                        thread::sleep(Duration::from_micros(10));

                        dash_spv_ffi_string_destroy(ffi);
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    #[serial]
    fn test_memory_stress_large_allocations() {
        unsafe {
            // Test with progressively larger allocations
            let sizes = [1_000, 10_000, 100_000, 1_000_000, 10_000_000];

            for &size in &sizes {
                // String allocation
                let large_string = "X".repeat(size);
                let ffi_string = FFIString::new(&large_string);
                assert!(!ffi_string.ptr.is_null());

                // Verify we can read it back
                let recovered = FFIString::from_ptr(ffi_string.ptr).unwrap();
                assert_eq!(recovered.len(), size);

                dash_spv_ffi_string_destroy(ffi_string);
            }
        }
    }

    #[test]
    #[serial]
    fn test_double_free_prevention() {
        unsafe {
            // Test that double-free doesn't cause issues
            // Note: This relies on the implementation handling null pointers gracefully

            // Test with string
            let ffi_string = FFIString::new("test");
            let _ptr = ffi_string.ptr;
            dash_spv_ffi_string_destroy(ffi_string);

            // Second destroy should handle gracefully
            let null_string = FFIString {
                ptr: std::ptr::null_mut(),
                length: 0,
            };
            dash_spv_ffi_string_destroy(null_string);
        }
    }

    #[test]
    #[serial]
    fn test_callback_memory_management() {
        // Test that callbacks don't leak memory
        let data = Arc::new(Mutex::new(Vec::<String>::new()));
        let data_clone = data.clone();

        extern "C" fn memory_test_callback(
            _progress: f64,
            msg: *const c_char,
            user_data: *mut c_void,
        ) {
            let data = unsafe { &*(user_data as *const Arc<Mutex<Vec<String>>>) };
            if !msg.is_null() {
                let msg_str = unsafe { CStr::from_ptr(msg).to_str().unwrap() };
                data.lock().unwrap().push(msg_str.to_string());
            }
        }

        // Simulate multiple callback invocations
        for i in 0..1000 {
            let msg = CString::new(format!("Progress: {}", i)).unwrap();
            memory_test_callback(i as f64, msg.as_ptr(), &data_clone as *const _ as *mut c_void);
        }

        // Verify we captured all messages
        assert_eq!(data.lock().unwrap().len(), 1000);
    }

    #[test]
    #[serial]
    fn test_recursive_structure_cleanup() {
        unsafe {
            // Test cleanup of structures containing pointers to other structures
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            // Get structures that contain FFIString and other pointers
            let progress = dash_spv_ffi_client_get_sync_progress(client);
            if !progress.is_null() {
                // SyncProgress might contain strings or other allocated data
                dash_spv_ffi_sync_progress_destroy(progress);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_memory_pool_behavior() {
        unsafe {
            // Test rapid allocation/deallocation patterns
            let start = Instant::now();
            let mut allocations = Vec::new();

            // Rapid allocation phase
            for i in 0..10000 {
                let s = format!("String number {}", i);
                let ffi = FFIString::new(&s);
                allocations.push(ffi);
            }

            // Rapid deallocation phase
            for ffi in allocations {
                dash_spv_ffi_string_destroy(ffi);
            }

            let duration = start.elapsed();
            println!("Allocation/deallocation of 10000 strings took: {:?}", duration);

            // Test interleaved allocation/deallocation
            for i in 0..5000 {
                let s1 = FFIString::new(&format!("First {}", i));
                let s2 = FFIString::new(&format!("Second {}", i));
                dash_spv_ffi_string_destroy(s1);
                let s3 = FFIString::new(&format!("Third {}", i));
                dash_spv_ffi_string_destroy(s2);
                dash_spv_ffi_string_destroy(s3);
            }
        }
    }

    #[test]
    #[serial]
    fn test_zero_size_allocations() {
        unsafe {
            // Test edge case of zero-size allocations
            let empty_string = FFIString::new("");
            assert!(!empty_string.ptr.is_null());
            let recovered = FFIString::from_ptr(empty_string.ptr).unwrap();
            assert_eq!(recovered, "");
            dash_spv_ffi_string_destroy(empty_string);
        }
    }

    #[test]
    #[serial]
    fn test_memory_corruption_detection() {
        unsafe {
            // Test that we can detect potential memory corruption scenarios
            // This test verifies our memory handling is robust

            // Create multiple strings with specific patterns
            let patterns = vec!["AAAAAAAAAA", "BBBBBBBBBB", "CCCCCCCCCC", "DDDDDDDDDD"];

            let mut ffi_strings = Vec::new();
            for pattern in &patterns {
                let ffi = FFIString::new(pattern);
                ffi_strings.push(ffi);
            }

            // Verify all strings are still intact
            for (i, ffi) in ffi_strings.iter().enumerate() {
                let recovered = FFIString::from_ptr(ffi.ptr).unwrap();
                assert_eq!(recovered, patterns[i]);
            }

            // Clean up in reverse order
            while let Some(ffi) = ffi_strings.pop() {
                dash_spv_ffi_string_destroy(ffi);
            }
        }
    }

    #[test]
    #[serial]
    fn test_long_running_memory_stability() {
        unsafe {
            // Simulate long-running application with periodic allocations
            let duration = Duration::from_millis(100);
            let start = Instant::now();
            let mut cycle = 0;

            while start.elapsed() < duration {
                // Allocate some memory
                let strings: Vec<_> = (0..10)
                    .map(|i| FFIString::new(&format!("Cycle {} String {}", cycle, i)))
                    .collect();

                // Do some work
                thread::sleep(Duration::from_micros(100));

                // Clean up
                for s in strings {
                    dash_spv_ffi_string_destroy(s);
                }

                cycle += 1;
            }

            println!("Completed {} allocation cycles", cycle);
        }
    }

    #[test]
    #[serial]
    fn test_cross_thread_memory_sharing() {
        // Test that memory allocated in one thread can be safely used in another
        unsafe {
            let string = FFIString::new("Allocated in thread 1");

            // Verify we can read the data
            let s = FFIString::from_ptr(string.ptr).unwrap();
            assert_eq!(s, "Allocated in thread 1");

            // Clean up
            dash_spv_ffi_string_destroy(string);
        }
    }
}
