#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use std::ffi::{CString, CStr};
    use std::os::raw::{c_char, c_void};
    use serial_test::serial;
    use tempfile::TempDir;
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU32, Ordering}};
    use std::thread;
    use std::time::{Duration, Instant};

    struct IntegrationTestContext {
        client: *mut FFIDashSpvClient,
        config: *mut FFIClientConfig,
        _temp_dir: TempDir,
        sync_completed: Arc<AtomicBool>,
        errors: Arc<Mutex<Vec<String>>>,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl IntegrationTestContext {
        unsafe fn new(network: FFINetwork) -> Self {
            let temp_dir = TempDir::new().unwrap();
            let config = dash_spv_ffi_config_new(network);

            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
            dash_spv_ffi_config_builder_set_validation_mode(config, FFIValidationMode::Basic);
            dash_spv_ffi_config_builder_set_max_peers(config, 8);

            // Add some test peers if available
            let test_peers = [
                "127.0.0.1:19999",
                "127.0.0.1:19998",
            ];

            for peer in &test_peers {
                let c_peer = CString::new(*peer).unwrap();
                dash_spv_ffi_config_add_peer(config, c_peer.as_ptr());
            }

            let client = dash_spv_ffi_client_new(config);
            assert!(!client.is_null());

            IntegrationTestContext {
                client,
                config,
                _temp_dir: temp_dir,
                sync_completed: Arc::new(AtomicBool::new(false)),
                errors: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        unsafe fn cleanup(self) {
            dash_spv_ffi_client_destroy(self.client);
            dash_spv_ffi_config_destroy(self.config);
        }
    }

    #[test]
    #[serial]
    fn test_complete_sync_workflow() {
        unsafe {
            let mut ctx = IntegrationTestContext::new(FFINetwork::Regtest);

            // Set up callbacks
            let sync_completed = ctx.sync_completed.clone();
            let errors = ctx.errors.clone();

            extern "C" fn on_sync_progress(progress: f64, msg: *const c_char, user_data: *mut c_void) {
                let ctx = unsafe { &*(user_data as *const IntegrationTestContext) };
                if progress >= 100.0 {
                    ctx.sync_completed.store(true, Ordering::SeqCst);
                }

                if !msg.is_null() {
                    let msg_str = unsafe { CStr::from_ptr(msg).to_str().unwrap() };
                    ctx.events.lock().unwrap().push(format!("Progress {:.1}%: {}", progress, msg_str));
                }
            }

            extern "C" fn on_sync_complete(success: bool, error: *const c_char, user_data: *mut c_void) {
                let ctx = unsafe { &*(user_data as *const IntegrationTestContext) };
                ctx.sync_completed.store(true, Ordering::SeqCst);

                if !success && !error.is_null() {
                    let error_str = unsafe { CStr::from_ptr(error).to_str().unwrap() };
                    ctx.errors.lock().unwrap().push(error_str.to_string());
                }
            }

            let callbacks = FFICallbacks {
                on_progress: Some(on_sync_progress),
                on_completion: Some(on_sync_complete),
                on_data: None,
                user_data: &ctx as *const _ as *mut c_void,
            };

            // Start the client
            let result = dash_spv_ffi_client_start(ctx.client);

            // Wait for sync to complete or timeout
            let start = Instant::now();
            let timeout = Duration::from_secs(10);

            while !ctx.sync_completed.load(Ordering::SeqCst) && start.elapsed() < timeout {
                thread::sleep(Duration::from_millis(100));

                // Check sync progress
                let progress = dash_spv_ffi_client_get_sync_progress(ctx.client);
                if !progress.is_null() {
                    let p = &*progress;
                    println!("Sync progress: headers={}, filters={}, masternodes={}",
                             p.header_height, p.filter_header_height, p.masternode_height);
                    dash_spv_ffi_sync_progress_destroy(progress);
                }
            }

            // Stop the client
            dash_spv_ffi_client_stop(ctx.client);

            // Check results
            let errors_vec = ctx.errors.lock().unwrap();
            if !errors_vec.is_empty() {
                println!("Sync errors: {:?}", errors_vec);
            }

            let events_vec = ctx.events.lock().unwrap();
            println!("Sync events: {} total", events_vec.len());

            ctx.cleanup();
        }
    }

    #[test]
    #[serial]
    fn test_wallet_monitoring_workflow() {
        unsafe {
            let mut ctx = IntegrationTestContext::new(FFINetwork::Regtest);

            // Add addresses to watch
            let test_addresses = [
                "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E",
                "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN",
                "XpAy3DUNod14KdJJh3XUjtkAiUkD2kd4JT",
            ];

            for addr in &test_addresses {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_client_watch_address(ctx.client, c_addr.as_ptr());
                assert_eq!(result, FFIErrorCode::Success as i32);
            }

            // Set up event callbacks
            let events = ctx.events.clone();

            extern "C" fn on_block(height: u32, hash: *const c_char, user_data: *mut c_void) {
                let ctx = unsafe { &*(user_data as *const IntegrationTestContext) };
                let hash_str = if hash.is_null() {
                    "null".to_string()
                } else {
                    unsafe { CStr::from_ptr(hash).to_str().unwrap().to_string() }
                };
                ctx.events.lock().unwrap().push(format!("New block at height {}: {}", height, hash_str));
            }

            extern "C" fn on_transaction(txid: *const c_char, confirmed: bool, user_data: *mut c_void) {
                let ctx = unsafe { &*(user_data as *const IntegrationTestContext) };
                let txid_str = if txid.is_null() {
                    "null".to_string()
                } else {
                    unsafe { CStr::from_ptr(txid).to_str().unwrap().to_string() }
                };
                ctx.events.lock().unwrap().push(
                    format!("Transaction {}: confirmed={}", txid_str, confirmed)
                );
            }

            extern "C" fn on_balance(confirmed: u64, unconfirmed: u64, user_data: *mut c_void) {
                let ctx = unsafe { &*(user_data as *const IntegrationTestContext) };
                ctx.events.lock().unwrap().push(
                    format!("Balance update: confirmed={}, unconfirmed={}", confirmed, unconfirmed)
                );
            }

            let event_callbacks = FFIEventCallbacks {
                on_block: Some(on_block),
                on_transaction: Some(on_transaction),
                on_balance_update: Some(on_balance),
                on_mempool_transaction_added: None,
                on_mempool_transaction_confirmed: None,
                on_mempool_transaction_removed: None,
                on_compact_filter_matched: None,
                on_wallet_transaction: None,
                user_data: &ctx as *const _ as *mut c_void,
            };

            dash_spv_ffi_client_set_event_callbacks(ctx.client, event_callbacks);

            // Start monitoring
            dash_spv_ffi_client_start(ctx.client);

            // Monitor for a while
            let monitor_duration = Duration::from_secs(5);
            let start = Instant::now();

            while start.elapsed() < monitor_duration {
                // Check balances
                for addr in &test_addresses {
                    let c_addr = CString::new(*addr).unwrap();
                    let balance = dash_spv_ffi_client_get_address_balance(ctx.client, c_addr.as_ptr());

                    if !balance.is_null() {
                        let bal = &*balance;
                        if bal.confirmed > 0 || bal.pending > 0 {
                            println!("Address {} has balance: confirmed={}, pending={}",
                                     addr, bal.confirmed, bal.pending);
                        }
                        dash_spv_ffi_balance_destroy(balance);
                    }
                }

                thread::sleep(Duration::from_secs(1));
            }

            dash_spv_ffi_client_stop(ctx.client);

            // Check events
            let events_vec = ctx.events.lock().unwrap();
            println!("Wallet monitoring events: {} total", events_vec.len());
            for event in events_vec.iter().take(10) {
                println!("  {}", event);
            }

            ctx.cleanup();
        }
    }

    #[test]
    #[serial]
    fn test_transaction_broadcast_workflow() {
        unsafe {
            let mut ctx = IntegrationTestContext::new(FFINetwork::Regtest);

            // Start the client
            dash_spv_ffi_client_start(ctx.client);

            // Create a test transaction (this would normally come from wallet)
            // For testing, we'll use a minimal transaction hex
            let test_tx_hex = "01000000000100000000000000001976a914000000000000000000000000000000000000000088ac00000000";
            let c_tx = CString::new(test_tx_hex).unwrap();

            // Set up broadcast tracking
            let broadcast_result = Arc::new(Mutex::new(None));
            let result_clone = broadcast_result.clone();

            extern "C" fn on_broadcast_complete(success: bool, error: *const c_char, user_data: *mut c_void) {
                let result = unsafe { &*(user_data as *const Arc<Mutex<Option<(bool, String)>>>) };
                let error_str = if error.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(error).to_str().unwrap().to_string() }
                };
                *result.lock().unwrap() = Some((success, error_str));
            }

            let callbacks = FFICallbacks {
                on_progress: None,
                on_completion: Some(on_broadcast_complete),
                on_data: None,
                user_data: &result_clone as *const _ as *mut c_void,
            };

            // Broadcast transaction
            let result = dash_spv_ffi_client_broadcast_transaction(ctx.client, c_tx.as_ptr());

            // In a real test, we'd wait for the broadcast result
            thread::sleep(Duration::from_secs(2));

            // Check result
            if let Some((success, error)) = &*broadcast_result.lock().unwrap() {
                println!("Broadcast result: success={}, error={}", success, error);
            }

            dash_spv_ffi_client_stop(ctx.client);
            ctx.cleanup();
        }
    }

    #[test]
    #[serial]
    fn test_concurrent_operations_workflow() {
        unsafe {
            let mut ctx = IntegrationTestContext::new(FFINetwork::Regtest);

            dash_spv_ffi_client_start(ctx.client);

            let client_ptr = Arc::new(Mutex::new(ctx.client));
            let mut handles = vec![];

            // Spawn multiple threads doing different operations
            for i in 0..5 {
                let client_clone = client_ptr.clone();
                let handle = thread::spawn(move || {
                    let client = *client_clone.lock().unwrap();

                    match i % 5 {
                        0 => {
                            // Thread 1: Monitor sync progress
                            for _ in 0..10 {
                                let progress = dash_spv_ffi_client_get_sync_progress(client);
                                if !progress.is_null() {
                                    dash_spv_ffi_sync_progress_destroy(progress);
                                }
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                        1 => {
                            // Thread 2: Check stats
                            for _ in 0..10 {
                                let stats = dash_spv_ffi_client_get_stats(client);
                                if !stats.is_null() {
                                    dash_spv_ffi_spv_stats_destroy(stats);
                                }
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                        2 => {
                            // Thread 3: Add/remove addresses
                            for j in 0..5 {
                                let addr = format!("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R{:02}", j);
                                let c_addr = CString::new(addr).unwrap();
                                dash_spv_ffi_client_watch_address(client, c_addr.as_ptr());
                                thread::sleep(Duration::from_millis(200));
                                dash_spv_ffi_client_unwatch_address(client, c_addr.as_ptr());
                            }
                        }
                        3 => {
                            // Thread 4: Check balances
                            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
                            for _ in 0..10 {
                                let balance = dash_spv_ffi_client_get_address_balance(client, addr.as_ptr());
                                if !balance.is_null() {
                                    dash_spv_ffi_balance_destroy(balance);
                                }
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                        4 => {
                            // Thread 5: Get watched addresses
                            for _ in 0..10 {
                                let addresses = dash_spv_ffi_client_get_watched_addresses(client);
                                if !addresses.is_null() {
                                    dash_spv_ffi_array_destroy(addresses);
                                }
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                        _ => {}
                    }
                });
                handles.push(handle);
            }

            // Wait for all threads
            for handle in handles {
                handle.join().unwrap();
            }

            let client = *client_ptr.lock().unwrap();
            dash_spv_ffi_client_stop(client);

            // Can't use cleanup() because client_ptr owns the client
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(ctx.config);
        }
    }

    #[test]
    #[serial]
    fn test_error_recovery_workflow() {
        unsafe {
            let mut ctx = IntegrationTestContext::new(FFINetwork::Regtest);

            // Test recovery from various error conditions

            // 1. Start without peers
            let result = dash_spv_ffi_client_start(ctx.client);

            // 2. Add invalid address
            let invalid_addr = CString::new("invalid_address").unwrap();
            let watch_result = dash_spv_ffi_client_watch_address(ctx.client, invalid_addr.as_ptr());
            assert_eq!(watch_result, FFIErrorCode::InvalidArgument as i32);

            // Check error was set
            let error_ptr = dash_spv_ffi_get_last_error();
            if !error_ptr.is_null() {
                let error_str = CStr::from_ptr(error_ptr).to_str().unwrap();
                println!("Expected error: {}", error_str);
            }

            // 4. Clear error and continue with valid operations
            dash_spv_ffi_clear_error();

            let valid_addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let watch_result = dash_spv_ffi_client_watch_address(ctx.client, valid_addr.as_ptr());
            assert_eq!(watch_result, FFIErrorCode::Success as i32);

            // 5. Test graceful shutdown
            dash_spv_ffi_client_stop(ctx.client);

            ctx.cleanup();
        }
    }

    #[test]
    #[serial]
    fn test_persistence_workflow() {
        let temp_dir = TempDir::new().unwrap();
        let data_path = temp_dir.path().to_str().unwrap();

        unsafe {
            // Phase 1: Create client, add data, and shut down
            {
                let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
                let path = CString::new(data_path).unwrap();
                dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Add some watched addresses
                let addresses = [
                    "XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E",
                    "XuQQkwA4FYkq2XERzMY2CiAZhJTEkgZ6uN",
                ];

                for addr in &addresses {
                    let c_addr = CString::new(*addr).unwrap();
                    dash_spv_ffi_client_watch_address(client, c_addr.as_ptr());
                }

                // Perform some sync
                dash_spv_ffi_client_start(client);
                thread::sleep(Duration::from_secs(2));

                // Get current state
                let progress1 = dash_spv_ffi_client_get_sync_progress(client);
                let height1 = if progress1.is_null() { 0 } else { (*progress1).header_height };
                if !progress1.is_null() {
                    dash_spv_ffi_sync_progress_destroy(progress1);
                }

                dash_spv_ffi_client_stop(client);
                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);

                println!("Phase 1 complete, height: {}", height1);
            }

            // Phase 2: Create new client with same data directory
            {
                let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
                let path = CString::new(data_path).unwrap();
                dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Check if state was persisted
                let progress2 = dash_spv_ffi_client_get_sync_progress(client);
                if !progress2.is_null() {
                    let height2 = (*progress2).header_height;
                    println!("Phase 2 loaded, height: {}", height2);
                    dash_spv_ffi_sync_progress_destroy(progress2);
                }

                // Check if watched addresses were persisted
                let watched = dash_spv_ffi_client_get_watched_addresses(client);
                if !watched.is_null() {
                    println!("Watched addresses persisted: {} addresses", (*watched).len);
                    dash_spv_ffi_array_destroy(*watched);
                }

                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }
        }
    }

    #[test]
    #[serial]
    fn test_network_resilience_workflow() {
        unsafe {
            let mut ctx = IntegrationTestContext::new(FFINetwork::Regtest);

            // Add unreachable peers to test timeout handling
            let unreachable_peers = [
                "192.0.2.1:9999",  // TEST-NET-1 (unreachable)
                "198.51.100.1:9999", // TEST-NET-2 (unreachable)
            ];

            for peer in &unreachable_peers {
                let c_peer = CString::new(*peer).unwrap();
                dash_spv_ffi_config_add_peer(ctx.config, c_peer.as_ptr());
            }

            // Start with network issues
            let start_result = dash_spv_ffi_client_start(ctx.client);

            // Should handle timeouts gracefully
            thread::sleep(Duration::from_secs(3));

            // Check client is still responsive
            let stats = dash_spv_ffi_client_get_stats(ctx.client);
            if !stats.is_null() {
                println!("Client still responsive after network issues");
                dash_spv_ffi_spv_stats_destroy(stats);
            }

            dash_spv_ffi_client_stop(ctx.client);
            ctx.cleanup();
        }
    }
}
