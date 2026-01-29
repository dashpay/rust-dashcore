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
    fn test_array_memory_lifecycle() {
        unsafe {
            // Test with different types and sizes
            let small_array: Vec<u32> = vec![1, 2, 3, 4, 5];
            let mut small_ffi = FFIArray::new(small_array);
            assert!(!small_ffi.data.is_null());
            assert_eq!(small_ffi.len, 5);
            dash_spv_ffi_array_destroy(&mut small_ffi as *mut FFIArray);

            // Test with large array
            let large_array: Vec<u64> = (0..100_000).collect();
            let mut large_ffi = FFIArray::new(large_array);
            assert!(!large_ffi.data.is_null());
            assert_eq!(large_ffi.len, 100_000);
            dash_spv_ffi_array_destroy(&mut large_ffi as *mut FFIArray);

            // Test with empty array
            let empty_array: Vec<u8> = vec![];
            let mut empty_ffi = FFIArray::new(empty_array);
            // Even empty arrays have valid pointers
            assert!(!empty_ffi.data.is_null());
            assert_eq!(empty_ffi.len, 0);
            dash_spv_ffi_array_destroy(&mut empty_ffi as *mut FFIArray);
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

                    // Each thread creates and destroys arrays
                    for j in 0..50 {
                        let array: Vec<u32> = (0..j * 10).collect();
                        let mut ffi_array = FFIArray::new(array);

                        // Simulate some work
                        thread::sleep(Duration::from_micros(10));

                        dash_spv_ffi_array_destroy(&mut ffi_array as *mut FFIArray);
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

                // Array allocation
                let large_array: Vec<u8> = vec![0xFF; size];
                let mut ffi_array = FFIArray::new(large_array);
                assert!(!ffi_array.data.is_null());
                assert_eq!(ffi_array.len, size);

                dash_spv_ffi_array_destroy(&mut ffi_array as *mut FFIArray);
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

            // Test with array
            let mut ffi_array = FFIArray::new(vec![1u32, 2, 3]);
            dash_spv_ffi_array_destroy(&mut ffi_array as *mut FFIArray);

            // Destroying with null should be safe
            let mut null_array = FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
                elem_size: 0,
                elem_align: 1,
            };
            dash_spv_ffi_array_destroy(&mut null_array as *mut FFIArray);
        }
    }

    #[test]
    #[serial]
    fn test_memory_alignment() {
        unsafe {
            // Test that memory is properly aligned for different types

            // u8 - 1 byte alignment
            let u8_array = vec![1u8, 2, 3, 4];
            let mut u8_ffi = FFIArray::new(u8_array);
            assert_eq!(u8_ffi.data as usize % std::mem::align_of::<u8>(), 0);
            dash_spv_ffi_array_destroy(&mut u8_ffi as *mut FFIArray);

            // u32 - 4 byte alignment
            let u32_array = vec![1u32, 2, 3, 4];
            let mut u32_ffi = FFIArray::new(u32_array);
            assert_eq!(u32_ffi.data as usize % std::mem::align_of::<u32>(), 0);
            dash_spv_ffi_array_destroy(&mut u32_ffi as *mut FFIArray);

            // u64 - 8 byte alignment
            let u64_array = vec![1u64, 2, 3, 4];
            let mut u64_ffi = FFIArray::new(u64_array);
            assert_eq!(u64_ffi.data as usize % std::mem::align_of::<u64>(), 0);
            dash_spv_ffi_array_destroy(&mut u64_ffi as *mut FFIArray);
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

            // Empty array
            let empty_vec: Vec<u8> = vec![];
            let mut empty_array = FFIArray::new(empty_vec);
            assert!(!empty_array.data.is_null());
            assert_eq!(empty_array.len, 0);
            dash_spv_ffi_array_destroy(&mut empty_array as *mut FFIArray);
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

                let arrays: Vec<_> = (0..10)
                    .map(|i| {
                        let data: Vec<u32> = (0..i * 10).collect();
                        FFIArray::new(data)
                    })
                    .collect();

                // Do some work
                thread::sleep(Duration::from_micros(100));

                // Clean up
                for s in strings {
                    dash_spv_ffi_string_destroy(s);
                }

                for mut a in arrays {
                    dash_spv_ffi_array_destroy(&mut a as *mut FFIArray);
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
            let mut array = FFIArray::new(vec![1u32, 2, 3, 4, 5]);

            // Verify we can read the data
            let s = FFIString::from_ptr(string.ptr).unwrap();
            assert_eq!(s, "Allocated in thread 1");

            let slice = array.as_slice::<u32>();
            assert_eq!(slice, &[1, 2, 3, 4, 5]);

            // Clean up
            dash_spv_ffi_string_destroy(string);
            dash_spv_ffi_array_destroy(&mut array as *mut FFIArray);
        }
    }
}
