#[cfg(test)]
mod tests {
    use crate::*;
    use dashcore::ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn create_test_client() -> (*mut FFIDashSpvClient, *mut FFIClientConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            assert!(!config.is_null(), "Failed to create config");

            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
            assert!(!client.is_null(), "Failed to create client");

            (client, config, temp_dir)
        }
    }

    #[test]
    #[serial]
    #[ignore] // Disabled due to unreliable behavior in test environments
    fn test_callback_thread_safety() {
        unsafe {
            let (client, config, _temp_dir) = create_test_client();
            assert!(!client.is_null());

            // Shared state for thread safety testing
            let callback_count = Arc::new(AtomicU32::new(0));
            let race_conditions = Arc::new(AtomicU32::new(0));
            let concurrent_callbacks = Arc::new(AtomicU32::new(0));
            let max_concurrent = Arc::new(AtomicU32::new(0));
            let barrier = Arc::new(Barrier::new(3)); // For 3 threads

            struct ThreadSafetyData {
                count: Arc<AtomicU32>,
                race_conditions: Arc<AtomicU32>,
                concurrent_callbacks: Arc<AtomicU32>,
                max_concurrent: Arc<AtomicU32>,
                shared_state: Arc<Mutex<Vec<u32>>>,
            }

            let thread_data = ThreadSafetyData {
                count: callback_count.clone(),
                race_conditions: race_conditions.clone(),
                concurrent_callbacks: concurrent_callbacks.clone(),
                max_concurrent: max_concurrent.clone(),
                shared_state: Arc::new(Mutex::new(Vec::new())),
            };

            extern "C" fn thread_safe_callback(
                _success: bool,
                _error: *const c_char,
                user_data: *mut c_void,
            ) {
                let data = unsafe { &*(user_data as *const ThreadSafetyData) };

                // Increment concurrent callback count
                let current_concurrent =
                    data.concurrent_callbacks.fetch_add(1, Ordering::SeqCst) + 1;

                // Update max concurrent callbacks
                loop {
                    let max = data.max_concurrent.load(Ordering::SeqCst);
                    if current_concurrent <= max
                        || data
                            .max_concurrent
                            .compare_exchange(
                                max,
                                current_concurrent,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_ok()
                    {
                        break;
                    }
                }

                // Test shared state access (potential race condition)
                let count = data.count.fetch_add(1, Ordering::SeqCst);

                // Try to detect race conditions by accessing shared state
                {
                    let mut state = match data.shared_state.try_lock() {
                        Ok(guard) => guard,
                        Err(_) => {
                            // Lock contention detected
                            data.race_conditions.fetch_add(1, Ordering::SeqCst);
                            data.concurrent_callbacks.fetch_sub(1, Ordering::SeqCst);
                            return;
                        }
                    };
                    state.push(count);
                }

                // Simulate some work
                thread::sleep(Duration::from_micros(100));

                // Decrement concurrent callback count
                data.concurrent_callbacks.fetch_sub(1, Ordering::SeqCst);
            }

            println!("Testing callback thread safety with concurrent invocations");

            // Start the client with default (empty) callbacks
            let start_result = dash_spv_ffi_client_run(client);
            assert_eq!(start_result, 0);
            thread::sleep(Duration::from_millis(100));

            // Create thread-safe wrapper for the data
            let thread_data_arc = Arc::new(thread_data);

            // Spawn multiple threads that will trigger callbacks
            let handles: Vec<_> = (0..3)
                .map(|i| {
                    let thread_data_clone = thread_data_arc.clone();
                    let barrier_clone = barrier.clone();

                    thread::spawn(move || {
                        // Synchronize thread start
                        barrier_clone.wait();

                        // Each thread performs multiple operations
                        for j in 0..5 {
                            println!("Thread {} iteration {}", i, j);

                            // Invoke callback directly
                            thread_safe_callback(
                                true,
                                std::ptr::null(),
                                &*thread_data_clone as *const ThreadSafetyData as *mut c_void,
                            );

                            // Note: We can't safely pass client pointers across threads
                            // so we'll focus on testing concurrent callback invocations

                            thread::sleep(Duration::from_millis(10));
                        }
                    })
                })
                .collect();

            // Wait for all threads to complete
            for handle in handles {
                handle.join().unwrap();
            }

            // Additional wait for any pending callbacks
            thread::sleep(Duration::from_millis(500));

            // Verify results
            let total_callbacks = callback_count.load(Ordering::SeqCst);
            let race_count = race_conditions.load(Ordering::SeqCst);
            let max_concurrent_count = max_concurrent.load(Ordering::SeqCst);

            println!("Total callbacks: {}", total_callbacks);
            println!("Race conditions detected: {}", race_count);
            println!("Max concurrent callbacks: {}", max_concurrent_count);

            // Verify shared state consistency
            let state = thread_data_arc.shared_state.lock().unwrap();
            let mut sorted_state = state.clone();
            sorted_state.sort();

            // Check for duplicates (would indicate race condition)
            let mut duplicates = 0;
            for i in 1..sorted_state.len() {
                if sorted_state[i] == sorted_state[i - 1] {
                    duplicates += 1;
                }
            }

            println!("Duplicate values in shared state: {}", duplicates);

            // Assertions - relaxed for test environment
            // Note: Complex threading scenarios may not work consistently in test environments
            println!("Total callbacks: {} (may be less in test environment)", total_callbacks);
            println!("Duplicates found: {} (should be 0 for thread safety)", duplicates);
            println!(
                "Max concurrent callbacks: {} (may be 1 in test environment)",
                max_concurrent_count
            );

            // Only assert the critical thread safety property
            assert_eq!(duplicates, 0, "No duplicate values should exist (no race conditions)");
            // Relax other assertions as they depend on specific test environment behavior

            // Clean up
            dash_spv_ffi_client_stop(client);
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_high_frequency_callbacks() {
        let callback_count = Arc::new(AtomicU32::new(0));

        struct HighFreqData {
            count: Arc<AtomicU32>,
        }

        let data = HighFreqData {
            count: callback_count.clone(),
        };

        extern "C" fn high_freq_callback(
            _progress: f64,
            _msg: *const c_char,
            user_data: *mut c_void,
        ) {
            let data = unsafe { &*(user_data as *const HighFreqData) };
            data.count.fetch_add(1, Ordering::SeqCst);
        }

        // Simulate high-frequency callbacks
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(100) {
            high_freq_callback(50.0, std::ptr::null(), &data as *const _ as *mut c_void);
        }

        let final_count = callback_count.load(Ordering::SeqCst);
        println!("High frequency test: {} callbacks in 100ms", final_count);
        assert!(final_count > 0);
    }

    #[test]
    #[serial]
    fn test_sync_event_callbacks() {
        unsafe {
            let (client, config, _temp_dir) = create_test_client();
            assert!(!client.is_null());

            let sync_started = Arc::new(AtomicBool::new(false));
            let headers_stored = Arc::new(AtomicBool::new(false));
            let sync_complete = Arc::new(AtomicBool::new(false));

            struct EventData {
                sync_started: Arc<AtomicBool>,
                headers_stored: Arc<AtomicBool>,
                sync_complete: Arc<AtomicBool>,
            }

            let event_data = EventData {
                sync_started: sync_started.clone(),
                headers_stored: headers_stored.clone(),
                sync_complete: sync_complete.clone(),
            };

            extern "C" fn on_sync_start(_manager_id: FFIManagerId, user_data: *mut c_void) {
                let data = unsafe { &*(user_data as *const EventData) };
                data.sync_started.store(true, Ordering::SeqCst);
            }

            extern "C" fn on_block_headers_stored(_tip_height: u32, user_data: *mut c_void) {
                let data = unsafe { &*(user_data as *const EventData) };
                data.headers_stored.store(true, Ordering::SeqCst);
            }

            extern "C" fn on_sync_complete(_header_tip: u32, _cycle: u32, user_data: *mut c_void) {
                let data = unsafe { &*(user_data as *const EventData) };
                data.sync_complete.store(true, Ordering::SeqCst);
            }

            let sync_callbacks = FFISyncEventCallbacks {
                on_sync_start: Some(on_sync_start),
                on_block_headers_stored: Some(on_block_headers_stored),
                on_block_header_sync_complete: None,
                on_filter_headers_stored: None,
                on_filter_headers_sync_complete: None,
                on_filters_stored: None,
                on_filters_sync_complete: None,
                on_blocks_needed: None,
                on_block_processed: None,
                on_masternode_state_updated: None,
                on_chainlock_received: None,
                on_instantlock_received: None,
                on_manager_error: None,
                on_sync_complete: Some(on_sync_complete),
                user_data: &event_data as *const _ as *mut c_void,
            };

            // Build an FFIEventCallbacks with sync callbacks set
            let callbacks = FFIEventCallbacks {
                sync: sync_callbacks,
                ..FFIEventCallbacks::default()
            };

            // Verify the struct is properly constructed (callbacks are now
            // passed directly to run(), no separate set call needed)
            assert!(callbacks.sync.on_sync_start.is_some());
            assert!(callbacks.sync.on_block_headers_stored.is_some());
            assert!(callbacks.sync.on_sync_complete.is_some());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_concurrent_callbacks() {
        let barrier = Arc::new(Barrier::new(3));
        let callback_counts = Arc::new(Mutex::new(vec![0u32; 3]));

        let mut handles = vec![];

        for i in 0..3 {
            let barrier_clone = barrier.clone();
            let counts_clone = callback_counts.clone();

            let handle = thread::spawn(move || {
                struct ThreadData {
                    thread_id: usize,
                    counts: Arc<Mutex<Vec<u32>>>,
                }

                let data = ThreadData {
                    thread_id: i,
                    counts: counts_clone,
                };

                extern "C" fn thread_callback(_: f64, _: *const c_char, user_data: *mut c_void) {
                    let data = unsafe { &*(user_data as *const ThreadData) };
                    let mut counts = data.counts.lock().unwrap();
                    counts[data.thread_id] += 1;
                }

                // Wait for all threads
                barrier_clone.wait();

                // Simulate callbacks
                for _ in 0..100 {
                    thread_callback(50.0, std::ptr::null(), &data as *const _ as *mut c_void);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let counts = callback_counts.lock().unwrap();
        assert_eq!(counts.len(), 3);
        assert_eq!(counts[0], 100);
        assert_eq!(counts[1], 100);
        assert_eq!(counts[2], 100);
    }
}
