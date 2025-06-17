#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use std::ffi::{CString, CStr};
    use std::os::raw::{c_char, c_void};
    use serial_test::serial;
    use tempfile::TempDir;
    use std::time::{Duration, Instant};
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    struct BenchmarkResult {
        name: String,
        iterations: u64,
        total_time: Duration,
        min_time: Duration,
        max_time: Duration,
        avg_time: Duration,
        ops_per_second: f64,
    }
    
    impl BenchmarkResult {
        fn new(name: &str, times: Vec<Duration>) -> Self {
            let iterations = times.len() as u64;
            let total_time = times.iter().sum();
            let min_time = *times.iter().min().unwrap();
            let max_time = *times.iter().max().unwrap();
            let avg_time = total_time / iterations as u32;
            let ops_per_second = iterations as f64 / total_time.as_secs_f64();
            
            BenchmarkResult {
                name: name.to_string(),
                iterations,
                total_time,
                min_time,
                max_time,
                avg_time,
                ops_per_second,
            }
        }
        
        fn print(&self) {
            println!("\nBenchmark: {}", self.name);
            println!("  Iterations: {}", self.iterations);
            println!("  Total time: {:?}", self.total_time);
            println!("  Min time: {:?}", self.min_time);
            println!("  Max time: {:?}", self.max_time);
            println!("  Avg time: {:?}", self.avg_time);
            println!("  Ops/second: {:.2}", self.ops_per_second);
        }
    }
    
    #[test]
    #[serial]
    fn bench_string_allocation() {
        unsafe {
            let test_strings = vec![
                "short",
                "medium length string with some content",
                &"x".repeat(1000),
                &"very long string ".repeat(1000),
            ];
            
            for test_str in &test_strings {
                let mut times = Vec::new();
                let iterations = 10000;
                
                for _ in 0..iterations {
                    let start = Instant::now();
                    let ffi_str = FFIString::new(test_str);
                    dash_spv_ffi_string_destroy(ffi_str);
                    times.push(start.elapsed());
                }
                
                let result = BenchmarkResult::new(
                    &format!("String allocation (len={})", test_str.len()),
                    times
                );
                result.print();
            }
        }
    }
    
    #[test]
    #[serial]
    fn bench_array_allocation() {
        unsafe {
            let sizes = vec![10, 100, 1000, 10000, 100000];
            
            for size in sizes {
                let mut times = Vec::new();
                let iterations = 1000;
                
                for _ in 0..iterations {
                    let data: Vec<u32> = (0..size).collect();
                    let start = Instant::now();
                    let ffi_array = FFIArray::new(data);
                    dash_spv_ffi_array_destroy(ffi_array);
                    times.push(start.elapsed());
                }
                
                let result = BenchmarkResult::new(
                    &format!("Array allocation (size={})", size),
                    times
                );
                result.print();
            }
        }
    }
    
    #[test]
    #[serial]
    fn bench_client_creation() {
        unsafe {
            let mut times = Vec::new();
            let iterations = 100;
            
            for _ in 0..iterations {
                let temp_dir = TempDir::new().unwrap();
                let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
                let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
                dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
                
                let start = Instant::now();
                let client = dash_spv_ffi_client_new(config);
                let creation_time = start.elapsed();
                
                times.push(creation_time);
                
                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }
            
            let result = BenchmarkResult::new("Client creation", times);
            result.print();
        }
    }
    
    #[test]
    #[serial]
    fn bench_address_validation() {
        unsafe {
            let addresses = vec![
                "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E",
                "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN",
                "invalid_address",
                "1BitcoinAddress",
                "XpAy3DUNod14KdJJh3XUjtkAiUkD2kd4JT",
            ];
            
            let mut times = Vec::new();
            let iterations = 10000;
            
            for _ in 0..iterations {
                for addr in &addresses {
                    let c_addr = CString::new(*addr).unwrap();
                    let start = Instant::now();
                    let _ = dash_spv_ffi_validate_address(c_addr.as_ptr(), FFINetwork::Dash);
                    times.push(start.elapsed());
                }
            }
            
            let result = BenchmarkResult::new("Address validation", times);
            result.print();
        }
    }
    
    #[test]
    #[serial]
    fn bench_concurrent_operations() {
        unsafe {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
            
            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());
            
            let client_ptr = Arc::new(Mutex::new(client));
            let thread_count = 4;
            let ops_per_thread = 1000;
            
            let start = Instant::now();
            let mut handles = vec![];
            
            for _ in 0..thread_count {
                let client_clone = client_ptr.clone();
                let handle = thread::spawn(move || {
                    let mut times = Vec::new();
                    
                    for _ in 0..ops_per_thread {
                        let client = *client_clone.lock().unwrap();
                        let op_start = Instant::now();
                        
                        // Perform various operations
                        let progress = dash_spv_ffi_client_get_sync_progress(client);
                        if !progress.is_null() {
                            dash_spv_ffi_sync_progress_destroy(progress);
                        }
                        
                        times.push(op_start.elapsed());
                    }
                    
                    times
                });
                handles.push(handle);
            }
            
            let mut all_times = Vec::new();
            for handle in handles {
                all_times.extend(handle.join().unwrap());
            }
            
            let total_elapsed = start.elapsed();
            
            let result = BenchmarkResult::new("Concurrent operations", all_times);
            result.print();
            
            println!("Total concurrent execution time: {:?}", total_elapsed);
            println!("Total operations: {}", thread_count * ops_per_thread);
            println!("Overall throughput: {:.2} ops/sec", 
                     (thread_count * ops_per_thread) as f64 / total_elapsed.as_secs_f64());
            
            let client = *client_ptr.lock().unwrap();
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
    
    #[test]
    #[serial]
    fn bench_callback_overhead() {
        unsafe {
            let iterations = 100000;
            let mut times = Vec::new();
            
            // Minimal callback that does nothing
            extern "C" fn noop_callback(_: f64, _: *const c_char, _: *mut c_void) {}
            
            // Callback that does some work
            extern "C" fn work_callback(progress: f64, msg: *const c_char, user_data: *mut c_void) {
                if !user_data.is_null() {
                    let counter = user_data as *mut u64;
                    *counter += 1;
                }
                if !msg.is_null() {
                    let _ = CStr::from_ptr(msg);
                }
            }
            
            // Benchmark noop callback
            for _ in 0..iterations {
                let start = Instant::now();
                noop_callback(50.0, std::ptr::null(), std::ptr::null_mut());
                times.push(start.elapsed());
            }
            
            let noop_result = BenchmarkResult::new("Noop callback", times.clone());
            noop_result.print();
            
            // Benchmark work callback
            times.clear();
            let mut counter = 0u64;
            let msg = CString::new("Progress update").unwrap();
            
            for _ in 0..iterations {
                let start = Instant::now();
                work_callback(50.0, msg.as_ptr(), &mut counter as *mut _ as *mut c_void);
                times.push(start.elapsed());
            }
            
            let work_result = BenchmarkResult::new("Work callback", times);
            work_result.print();
            
            assert_eq!(counter, iterations);
        }
    }
    
    #[test]
    #[serial]
    fn bench_memory_churn() {
        unsafe {
            // Test rapid allocation/deallocation patterns
            let patterns = vec![
                ("Sequential", false),
                ("Interleaved", true),
            ];
            
            for (pattern_name, interleaved) in patterns {
                let mut times = Vec::new();
                let iterations = 1000;
                let allocations_per_iteration = 100;
                
                let start = Instant::now();
                
                for _ in 0..iterations {
                    let iter_start = Instant::now();
                    
                    if interleaved {
                        // Interleaved allocation/deallocation
                        for i in 0..allocations_per_iteration {
                            let s1 = FFIString::new(&format!("String {}", i));
                            let s2 = FFIString::new(&format!("Another {}", i));
                            dash_spv_ffi_string_destroy(s1);
                            let s3 = FFIString::new(&format!("Third {}", i));
                            dash_spv_ffi_string_destroy(s2);
                            dash_spv_ffi_string_destroy(s3);
                        }
                    } else {
                        // Sequential allocation then deallocation
                        let mut strings = Vec::new();
                        for i in 0..allocations_per_iteration {
                            strings.push(FFIString::new(&format!("String {}", i)));
                        }
                        for s in strings {
                            dash_spv_ffi_string_destroy(s);
                        }
                    }
                    
                    times.push(iter_start.elapsed());
                }
                
                let total_elapsed = start.elapsed();
                
                let result = BenchmarkResult::new(
                    &format!("Memory churn - {}", pattern_name),
                    times
                );
                result.print();
                
                println!("Total allocations: {}", iterations * allocations_per_iteration * 3);
                println!("Allocations/sec: {:.2}", 
                         (iterations * allocations_per_iteration * 3) as f64 / total_elapsed.as_secs_f64());
            }
        }
    }
    
    #[test]
    #[serial]
    fn bench_error_handling() {
        unsafe {
            let iterations = 100000;
            let mut times = Vec::new();
            
            // Benchmark error setting and retrieval
            for i in 0..iterations {
                let error_msg = format!("Error number {}", i);
                
                let start = Instant::now();
                set_last_error(&error_msg);
                let error_ptr = dash_spv_ffi_get_last_error();
                if !error_ptr.is_null() {
                    let _ = CStr::from_ptr(error_ptr);
                }
                dash_spv_ffi_clear_error();
                times.push(start.elapsed());
            }
            
            let result = BenchmarkResult::new("Error handling cycle", times);
            result.print();
        }
    }
    
    #[test]
    #[serial]
    fn bench_type_conversions() {
        let iterations = 100000;
        let mut times = Vec::new();
        
        // Benchmark various type conversions
        for _ in 0..iterations {
            let start = Instant::now();
            
            // Network enum conversions
            let net: dashcore::Network = FFINetwork::Dash.into();
            let _ffi_net: FFINetwork = net.into();
            
            // Create and convert complex types
            let progress = dash_spv::SyncProgress {
                header_height: 12345,
                filter_header_height: 12340,
                masternode_height: 12300,
                peer_count: 8,
                headers_synced: true,
                filter_headers_synced: true,
                masternodes_synced: false,
                filters_downloaded: 1000,
                last_synced_filter_height: Some(12000),
                sync_start: std::time::SystemTime::now(),
                last_update: std::time::SystemTime::now(),
            };
            
            let _ffi_progress = FFISyncProgress::from(progress);
            
            times.push(start.elapsed());
        }
        
        let result = BenchmarkResult::new("Type conversions", times);
        result.print();
    }
    
    #[test]
    #[serial]
    fn bench_large_data_handling() {
        unsafe {
            // Test performance with large data sets
            let sizes = vec![1_000, 10_000, 100_000, 1_000_000];
            
            for size in sizes {
                // Large string handling
                let large_string = "X".repeat(size);
                let string_start = Instant::now();
                let ffi_str = FFIString::new(&large_string);
                let string_alloc_time = string_start.elapsed();
                
                let read_start = Instant::now();
                let recovered = FFIString::from_ptr(ffi_str.ptr).unwrap();
                let read_time = read_start.elapsed();
                assert_eq!(recovered.len(), size);
                
                let destroy_start = Instant::now();
                dash_spv_ffi_string_destroy(ffi_str);
                let destroy_time = destroy_start.elapsed();
                
                println!("\nLarge string (size={}):", size);
                println!("  Allocation: {:?}", string_alloc_time);
                println!("  Read: {:?}", read_time);
                println!("  Destruction: {:?}", destroy_time);
                println!("  MB/sec alloc: {:.2}", 
                         (size as f64 / 1_000_000.0) / string_alloc_time.as_secs_f64());
                
                // Large array handling
                let large_array: Vec<u64> = (0..size as u64).collect();
                let array_start = Instant::now();
                let ffi_array = FFIArray::new(large_array);
                let array_alloc_time = array_start.elapsed();
                
                let array_destroy_start = Instant::now();
                dash_spv_ffi_array_destroy(ffi_array);
                let array_destroy_time = array_destroy_start.elapsed();
                
                println!("Large array (size={}):", size);
                println!("  Allocation: {:?}", array_alloc_time);
                println!("  Destruction: {:?}", array_destroy_time);
                println!("  Million elements/sec: {:.2}", 
                         (size as f64 / 1_000_000.0) / array_alloc_time.as_secs_f64());
            }
        }
    }
}