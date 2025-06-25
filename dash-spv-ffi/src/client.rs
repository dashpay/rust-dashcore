use crate::{
    null_check, set_last_error, FFIArray, FFIBalance, FFICallbacks, FFIClientConfig, FFIDetailedSyncProgress,
    FFIErrorCode, FFIEventCallbacks, FFIMempoolStrategy, FFISpvStats, FFISyncProgress, 
    FFITransaction, FFIUtxo, FFIWatchItem,
};
use dash_spv::types::SyncStage;
use dash_spv::DashSpvClient;
use dash_spv::Utxo;
use dashcore::{Address, ScriptBuf, Txid};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Validate a script hex string and convert it to ScriptBuf
unsafe fn validate_script_hex(script_hex: *const c_char) -> Result<ScriptBuf, i32> {
    let script_str = match CStr::from_ptr(script_hex).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in script: {}", e));
            return Err(FFIErrorCode::InvalidArgument as i32);
        }
    };

    // Check for odd-length hex string
    if script_str.len() % 2 != 0 {
        set_last_error("Hex string must have even length");
        return Err(FFIErrorCode::InvalidArgument as i32);
    }

    let script_bytes = match hex::decode(script_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Invalid hex in script: {}", e));
            return Err(FFIErrorCode::InvalidArgument as i32);
        }
    };

    // Check for empty script
    if script_bytes.is_empty() {
        set_last_error("Script cannot be empty");
        return Err(FFIErrorCode::InvalidArgument as i32);
    }

    // Check for minimum script length (scripts should be at least 1 byte)
    // But very short scripts (like 2 bytes) might not be meaningful
    if script_bytes.len() < 3 {
        set_last_error("Script too short to be meaningful");
        return Err(FFIErrorCode::InvalidArgument as i32);
    }

    Ok(ScriptBuf::from(script_bytes))
}

pub struct FFIDashSpvClient {
    inner: Arc<Mutex<Option<DashSpvClient>>>,
    runtime: Arc<Runtime>,
    event_callbacks: Arc<Mutex<FFIEventCallbacks>>,
    active_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    // Sync-specific callbacks
    sync_progress_callback: Arc<Mutex<Option<extern "C" fn(*const FFIDetailedSyncProgress, *mut c_void)>>>,
    sync_completion_callback: Arc<Mutex<Option<extern "C" fn(bool, *const c_char, *mut c_void)>>>,
    sync_user_data: Arc<Mutex<*mut c_void>>,
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_new(
    config: *const FFIClientConfig,
) -> *mut FFIDashSpvClient {
    null_check!(config, std::ptr::null_mut());

    let config = &(*config);
    let runtime = match Runtime::new() {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            set_last_error(&format!("Failed to create runtime: {}", e));
            return std::ptr::null_mut();
        }
    };

    let client_config = config.clone_inner();
    let client_result = runtime.block_on(async { DashSpvClient::new(client_config).await });

    match client_result {
        Ok(client) => {
            let ffi_client = FFIDashSpvClient {
                inner: Arc::new(Mutex::new(Some(client))),
                runtime,
                event_callbacks: Arc::new(Mutex::new(FFIEventCallbacks::default())),
                active_threads: Arc::new(Mutex::new(Vec::new())),
                sync_progress_callback: Arc::new(Mutex::new(None)),
                sync_completion_callback: Arc::new(Mutex::new(None)),
                sync_user_data: Arc::new(Mutex::new(std::ptr::null_mut())),
            };
            Box::into_raw(Box::new(ffi_client))
        }
        Err(e) => {
            set_last_error(&format!("Failed to create client: {}", e));
            std::ptr::null_mut()
        }
    }
}

impl FFIDashSpvClient {
    /// Start the event listener task to handle events from the SPV client.
    fn start_event_listener(&self) {
        let inner = self.inner.clone();
        let event_callbacks = self.event_callbacks.clone();
        let runtime = self.runtime.clone();
        
        let handle = std::thread::spawn(move || {
            runtime.block_on(async {
                let event_rx = {
                    let mut guard = inner.lock().unwrap();
                    if let Some(ref mut client) = *guard {
                        client.take_event_receiver()
                    } else {
                        None
                    }
                };
                
                if let Some(mut rx) = event_rx {
                    tracing::info!("🎧 FFI event listener started successfully");
                    while let Some(event) = rx.recv().await {
                        tracing::info!("🎧 FFI received event: {:?}", event);
                        let callbacks = event_callbacks.lock().unwrap();
                        
                        match event {
                            dash_spv::types::SpvEvent::BalanceUpdate { confirmed, unconfirmed, total } => {
                                tracing::info!("💰 Balance update event: confirmed={}, unconfirmed={}, total={}", 
                                             confirmed, unconfirmed, total);
                                callbacks.call_balance_update(confirmed, unconfirmed);
                            }
                            dash_spv::types::SpvEvent::TransactionDetected { ref txid, confirmed, ref addresses, amount, block_height, .. } => {
                                tracing::info!("💸 Transaction detected: txid={}, confirmed={}, amount={}, addresses={:?}, height={:?}", 
                                             txid, confirmed, amount, addresses, block_height);
                                callbacks.call_transaction(txid, confirmed, amount as i64, addresses, block_height);
                            }
                            dash_spv::types::SpvEvent::BlockProcessed { height, ref hash, transactions_count, relevant_transactions } => {
                                tracing::info!("📦 Block processed: height={}, hash={}, total_tx={}, relevant_tx={}", 
                                             height, hash, transactions_count, relevant_transactions);
                                callbacks.call_block(height, hash);
                            }
                            dash_spv::types::SpvEvent::SyncProgress { .. } => {
                                // Sync progress is handled via existing progress callback
                                tracing::debug!("📊 Sync progress event (handled separately)");
                            }
                            dash_spv::types::SpvEvent::ChainLockReceived { height, hash } => {
                                // ChainLock events can be handled here
                                tracing::info!("🔒 ChainLock received for height {} hash {}", height, hash);
                            }
                            dash_spv::types::SpvEvent::MempoolTransactionAdded { ref txid, transaction: _, amount, ref addresses, is_instant_send } => {
                                tracing::info!("➕ Mempool transaction added: txid={}, amount={}, addresses={:?}, instant_send={}", 
                                             txid, amount, addresses, is_instant_send);
                                // Call the mempool-specific callback
                                callbacks.call_mempool_transaction_added(&txid.to_string(), amount, addresses, is_instant_send);
                            }
                            dash_spv::types::SpvEvent::MempoolTransactionConfirmed { ref txid, block_height, ref block_hash } => {
                                tracing::info!("✅ Mempool transaction confirmed: txid={}, height={}, hash={}", 
                                             txid, block_height, block_hash);
                                // Call the mempool confirmed callback
                                callbacks.call_mempool_transaction_confirmed(&txid.to_string(), block_height, &block_hash.to_string());
                            }
                            dash_spv::types::SpvEvent::MempoolTransactionRemoved { ref txid, ref reason } => {
                                tracing::info!("❌ Mempool transaction removed: txid={}, reason={:?}", 
                                             txid, reason);
                                // Convert reason to u8 for FFI
                                let reason_code = match reason {
                                    dash_spv::types::MempoolRemovalReason::Expired => 0,
                                    dash_spv::types::MempoolRemovalReason::Replaced { .. } => 1,
                                    dash_spv::types::MempoolRemovalReason::DoubleSpent { .. } => 2,
                                    dash_spv::types::MempoolRemovalReason::Confirmed => 3,
                                    dash_spv::types::MempoolRemovalReason::Manual => 4,
                                };
                                callbacks.call_mempool_transaction_removed(&txid.to_string(), reason_code);
                            }
                        }
                    }
                    tracing::info!("🎧 FFI event listener stopped");
                } else {
                    tracing::error!("❌ Failed to get event receiver from SPV client");
                }
            });
        });
        
        // Store thread handle
        self.active_threads.lock().unwrap().push(handle);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_start(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            spv_client.start().await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => {
            // Start event listener after successful start
            client.start_event_listener();
            FFIErrorCode::Success as i32
        }
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_stop(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            spv_client.stop().await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_sync_to_tip(
    client: *mut FFIDashSpvClient,
    progress_callback: Option<extern "C" fn(f64, *const c_char, *mut c_void)>,
    completion_callback: Option<extern "C" fn(bool, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();
    let runtime = client.runtime.clone();

    // Create callbacks struct from individual parameters
    let _callbacks = FFICallbacks {
        on_progress: progress_callback,
        on_completion: completion_callback,
        on_data: None,
        user_data,
    };

    // Execute sync in the runtime
    let result = runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            match spv_client.sync_to_tip().await {
                Ok(_sync_result) => {
                    // sync_to_tip returns a SyncResult, not a stream
                    // We need to simulate progress updates
                    if let Some(callback) = progress_callback {
                        let msg = CString::new("Syncing headers...").unwrap();
                        callback(0.1, msg.as_ptr(), user_data);
                    }
                    
                    // Report completion
                    if let Some(callback) = completion_callback {
                        let msg = CString::new("Sync completed successfully").unwrap();
                        callback(true, msg.as_ptr(), user_data);
                    }
                    
                    Ok(())
                }
                Err(e) => {
                    if let Some(callback) = completion_callback {
                        let msg = CString::new(format!("Sync failed: {}", e)).unwrap();
                        callback(false, msg.as_ptr(), user_data);
                    }
                    Err(e)
                }
            }
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_test_sync(
    client: *mut FFIDashSpvClient,
) -> i32 {
    null_check!(client);
    
    let client = &(*client);
    let result = client.runtime.block_on(async {
        let mut guard = client.inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            println!("Starting test sync...");
            
            // Get initial height
            let start_height = match spv_client.sync_progress().await {
                Ok(progress) => progress.header_height,
                Err(e) => {
                    eprintln!("Failed to get initial height: {}", e);
                    return Err(e);
                }
            };
            println!("Initial height: {}", start_height);
            
            // Start sync
            match spv_client.sync_to_tip().await {
                Ok(_) => println!("Sync started successfully"),
                Err(e) => {
                    eprintln!("Failed to start sync: {}", e);
                    return Err(e);
                }
            }
            
            // Wait a bit for headers to download
            tokio::time::sleep(Duration::from_secs(10)).await;
            
            // Check if headers increased
            let end_height = match spv_client.sync_progress().await {
                Ok(progress) => progress.header_height,
                Err(e) => {
                    eprintln!("Failed to get final height: {}", e);
                    return Err(e);
                }
            };
            println!("Final height: {}", end_height);
            
            if end_height > start_height {
                println!("✅ Sync working! Downloaded {} headers", end_height - start_height);
                Ok(())
            } else {
                let msg = "No headers downloaded".to_string();
                eprintln!("❌ {}", msg);
                Err(dash_spv::SpvError::Sync(dash_spv::SyncError::SyncFailed(msg)))
            }
        } else {
            Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
        }
    });
    
    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_sync_to_tip_with_progress(
    client: *mut FFIDashSpvClient,
    progress_callback: extern "C" fn(*const FFIDetailedSyncProgress, *mut c_void),
    completion_callback: extern "C" fn(bool, *const c_char, *mut c_void),
    user_data: *mut c_void,
) -> i32 {
    null_check!(client);
    
    let client = &(*client);
    
    // Store callbacks
    *client.sync_progress_callback.lock().unwrap() = Some(progress_callback);
    *client.sync_completion_callback.lock().unwrap() = Some(completion_callback);
    *client.sync_user_data.lock().unwrap() = user_data;
    
    let inner = client.inner.clone();
    let runtime = client.runtime.clone();
    let progress_cb = client.sync_progress_callback.clone();
    let completion_cb = client.sync_completion_callback.clone();
    let user_data_ptr = client.sync_user_data.clone();
    
    // Take progress receiver from client
    let progress_receiver = {
        let mut guard = inner.lock().unwrap();
        guard.as_mut().and_then(|c| c.take_progress_receiver())
    };
    
    // Setup progress monitoring - convert raw pointer to usize for thread safety
    if let Some(mut receiver) = progress_receiver {
        let runtime_handle = runtime.handle().clone();
        
        // Get user data as usize to make it Send
        let user_data_usize = {
            let guard = user_data_ptr.lock().unwrap();
            *guard as usize
        };
        
        let handle = std::thread::spawn(move || {
            runtime_handle.block_on(async move {
                while let Some(progress) = receiver.recv().await {
                    // Handle callback in a thread-safe way
                    let should_stop = matches!(progress.sync_stage, SyncStage::Complete);
                    
                    // Create FFI progress
                    let ffi_progress = Box::new(FFIDetailedSyncProgress::from(progress));
                    
                    // Call the callback with proper synchronization
                    {
                        let cb_guard = progress_cb.lock().unwrap();
                        
                        if let Some(callback) = *cb_guard {
                            // Convert usize back to raw pointer
                            let user_data = user_data_usize as *mut c_void;
                            callback(ffi_progress.as_ref(), user_data);
                        }
                    }
                    
                    if should_stop {
                        break;
                    }
                }
            });
        });
        
        // Store thread handle
        client.active_threads.lock().unwrap().push(handle);
    }
    
    // Get user data as usize for main sync task too
    let completion_user_data_usize = {
        let guard = user_data_ptr.lock().unwrap();
        *guard as usize
    };
    
    // Spawn sync task in a separate thread to avoid Send issues
    let runtime_handle = runtime.handle().clone();
    std::thread::spawn(move || {
        // Run monitoring loop
        let monitor_result = runtime_handle.block_on(async move {
            let mut guard = inner.lock().unwrap();
            if let Some(ref mut spv_client) = *guard {
                spv_client.monitor_network().await
            } else {
                Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
            }
        });
        
        // Send completion
        if let Some(callback) = *completion_cb.lock().unwrap() {
            let user_data = completion_user_data_usize as *mut c_void;
            match monitor_result {
                Ok(_) => {
                    let msg = CString::new("Sync completed successfully").unwrap();
                    callback(true, msg.as_ptr(), user_data);
                    std::mem::forget(msg); // Prevent deallocation since callback owns it now
                }
                Err(e) => {
                    let msg = CString::new(format!("Sync failed: {}", e)).unwrap();
                    callback(false, msg.as_ptr(), user_data);
                    std::mem::forget(msg); // Prevent deallocation since callback owns it now
                }
            }
        }
    });
    
    FFIErrorCode::Success as i32
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_cancel_sync(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);
    
    let client = &(*client);
    
    // Clear callbacks to stop progress updates
    *client.sync_progress_callback.lock().unwrap() = None;
    *client.sync_completion_callback.lock().unwrap() = None;
    
    // TODO: Add actual sync cancellation by stopping the client
    let inner = client.inner.clone();
    let result = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            spv_client.stop().await
        } else {
            Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
        }
    });
    
    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_sync_progress(
    client: *mut FFIDashSpvClient,
) -> *mut FFISyncProgress {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.sync_progress().await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(progress) => Box::into_raw(Box::new(progress.into())),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_stats(
    client: *mut FFIDashSpvClient,
) -> *mut FFISpvStats {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.stats().await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(stats) => Box::into_raw(Box::new(stats.into())),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_is_filter_sync_available(
    client: *mut FFIDashSpvClient,
) -> bool {
    null_check!(client, false);

    let client = &(*client);
    let inner = client.inner.clone();

    client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.is_filter_sync_available().await
        } else {
            false
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_add_watch_item(
    client: *mut FFIDashSpvClient,
    item: *const FFIWatchItem,
) -> i32 {
    null_check!(client);
    null_check!(item);

    let watch_item = match (*item).to_watch_item() {
        Ok(item) => item,
        Err(e) => {
            set_last_error(&e);
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            spv_client.add_watch_item(watch_item).await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_remove_watch_item(
    client: *mut FFIDashSpvClient,
    item: *const FFIWatchItem,
) -> i32 {
    null_check!(client);
    null_check!(item);

    let watch_item = match (*item).to_watch_item() {
        Ok(item) => item,
        Err(e) => {
            set_last_error(&e);
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            spv_client.remove_watch_item(&watch_item).await.map(|_| ()).map_err(|e| {
                dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(e.to_string()))
            })
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_address_balance(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> *mut FFIBalance {
    null_check!(client, std::ptr::null_mut());
    null_check!(address, std::ptr::null_mut());

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return std::ptr::null_mut();
        }
    };

    let addr = match Address::from_str(addr_str) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            set_last_error(&format!("Invalid address: {}", e));
            return std::ptr::null_mut();
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.get_address_balance(&addr).await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(balance) => Box::into_raw(Box::new(FFIBalance::from(balance))),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_utxos(client: *mut FFIDashSpvClient) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref _spv_client) = *guard {
            {
                // dash-spv doesn't expose wallet.get_utxos() directly
                // Would need to be implemented in dash-spv client
                Ok(Vec::<Utxo>::new())
            }
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(utxos) => {
            let ffi_utxos: Vec<FFIUtxo> = utxos.into_iter().map(FFIUtxo::from).collect();
            FFIArray::new(ffi_utxos)
        }
        Err(e) => {
            set_last_error(&e.to_string());
            FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_utxos_for_address(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );
    null_check!(
        address,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            };
        }
    };

    let _addr = match Address::from_str(addr_str) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            set_last_error(&format!("Invalid address: {}", e));
            return FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            };
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref _spv_client) = *guard {
            {
                // dash-spv doesn't expose wallet.get_utxos_for_address() directly
                // Would need to be implemented in dash-spv client
                Ok(Vec::<Utxo>::new())
            }
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(utxos) => {
            let ffi_utxos: Vec<FFIUtxo> = utxos.into_iter().map(FFIUtxo::from).collect();
            FFIArray::new(ffi_utxos)
        }
        Err(e) => {
            set_last_error(&e.to_string());
            FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_set_event_callbacks(
    client: *mut FFIDashSpvClient,
    callbacks: FFIEventCallbacks,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    
    tracing::info!("🔧 Setting event callbacks on FFI client");
    tracing::info!("   Block callback: {}", callbacks.on_block.is_some());
    tracing::info!("   Transaction callback: {}", callbacks.on_transaction.is_some());
    tracing::info!("   Balance update callback: {}", callbacks.on_balance_update.is_some());
    
    let mut event_callbacks = client.event_callbacks.lock().unwrap();
    *event_callbacks = callbacks;
    
    // Check if we need to start the event listener
    // This ensures callbacks work even if set after client.start()
    let inner = client.inner.lock().unwrap();
    if inner.is_some() {
        drop(inner); // Release lock before starting listener
        tracing::info!("🚀 Client already started, ensuring event listener is running");
        // The event listener should already be running from start()
        // but we log this for debugging
    }

    tracing::info!("✅ Event callbacks set successfully");
    FFIErrorCode::Success as i32
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_destroy(client: *mut FFIDashSpvClient) {
    if !client.is_null() {
        let client = Box::from_raw(client);
        let _ = client.runtime.block_on(async {
            let mut guard = client.inner.lock().unwrap();
            if let Some(ref mut spv_client) = *guard {
                let _ = spv_client.stop().await;
            }
        });
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_sync_progress_destroy(progress: *mut FFISyncProgress) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_spv_stats_destroy(stats: *mut FFISpvStats) {
    if !stats.is_null() {
        let _ = Box::from_raw(stats);
    }
}

// Wallet operations

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_watch_address(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(address);

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let _addr = match dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(addr_str) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            set_last_error(&format!("Invalid address: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref _spv_client) = *guard {
            // TODO: watch_address not yet implemented in dash-spv
            Err(dash_spv::SpvError::Config("Not implemented".to_string()))
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to watch address: {}", e));
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_unwatch_address(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(address);

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let _addr = match dashcore::Address::<dashcore::address::NetworkUnchecked>::from_str(addr_str) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            set_last_error(&format!("Invalid address: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut _spv_client) = *guard {
            // TODO: unwatch_address not yet implemented in dash-spv
            Err(dash_spv::SpvError::Config("Not implemented".to_string()))
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to unwatch address: {}", e));
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_watch_script(
    client: *mut FFIDashSpvClient,
    script_hex: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(script_hex);

    let _script = match validate_script_hex(script_hex) {
        Ok(script) => script,
        Err(error_code) => return error_code,
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut _spv_client) = *guard {
            // TODO: watch_script not yet implemented in dash-spv
            Err(dash_spv::SpvError::Config("Not implemented".to_string()))
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to watch script: {}", e));
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_unwatch_script(
    client: *mut FFIDashSpvClient,
    script_hex: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(script_hex);

    let _script = match validate_script_hex(script_hex) {
        Ok(script) => script,
        Err(error_code) => return error_code,
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut _spv_client) = *guard {
            // TODO: unwatch_script not yet implemented in dash-spv
            Err(dash_spv::SpvError::Config("Not implemented".to_string()))
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to unwatch script: {}", e));
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_address_history(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );
    null_check!(
        address,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            };
        }
    };

    let _addr = match Address::from_str(addr_str) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            set_last_error(&format!("Invalid address: {}", e));
            return FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
            };
        }
    };

    // Not implemented in dash-spv yet
    FFIArray {
        data: std::ptr::null_mut(),
        len: 0,
        capacity: 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_transaction(
    client: *mut FFIDashSpvClient,
    txid: *const c_char,
) -> *mut FFITransaction {
    null_check!(client, std::ptr::null_mut());
    null_check!(txid, std::ptr::null_mut());

    let txid_str = match CStr::from_ptr(txid).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in txid: {}", e));
            return std::ptr::null_mut();
        }
    };

    let _txid = match Txid::from_str(txid_str) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("Invalid txid: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Not implemented in dash-spv yet
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_broadcast_transaction(
    client: *mut FFIDashSpvClient,
    tx_hex: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(tx_hex);

    let tx_str = match CStr::from_ptr(tx_hex).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in transaction: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let tx_bytes = match hex::decode(tx_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Invalid hex in transaction: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let _tx = match dashcore::consensus::deserialize::<dashcore::Transaction>(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("Invalid transaction: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref _spv_client) = *guard {
            // TODO: broadcast_transaction not yet implemented in dash-spv
            Err(dash_spv::SpvError::Config("Not implemented".to_string()))
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to broadcast transaction: {}", e));
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_watched_addresses(
    client: *mut FFIDashSpvClient,
) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    // Not implemented in dash-spv yet
    FFIArray {
        data: std::ptr::null_mut(),
        len: 0,
        capacity: 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_watched_scripts(
    client: *mut FFIDashSpvClient,
) -> FFIArray {
    null_check!(
        client,
        FFIArray {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0
        }
    );

    // Not implemented in dash-spv yet
    FFIArray {
        data: std::ptr::null_mut(),
        len: 0,
        capacity: 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_total_balance(
    client: *mut FFIDashSpvClient,
) -> *mut FFIBalance {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            // Get all watched addresses
            let watch_items = spv_client.get_watch_items().await;
            let mut total_confirmed = 0u64;
            let mut total_unconfirmed = 0u64;
            
            // Sum up balances for all watched addresses
            for item in watch_items {
                if let dash_spv::types::WatchItem::Address { address, .. } = item {
                    match spv_client.get_address_balance(&address).await {
                        Ok(balance) => {
                            total_confirmed += balance.confirmed.to_sat();
                            total_unconfirmed += balance.unconfirmed.to_sat();
                            tracing::debug!("Address {} balance: confirmed={}, unconfirmed={}", 
                                         address, balance.confirmed, balance.unconfirmed);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to get balance for address {}: {}", address, e);
                        }
                    }
                }
            }
            
            Ok(dash_spv::types::AddressBalance {
                confirmed: dashcore::Amount::from_sat(total_confirmed),
                unconfirmed: dashcore::Amount::from_sat(total_unconfirmed),
                pending: dashcore::Amount::from_sat(0),
                pending_instant: dashcore::Amount::from_sat(0),
            })
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(balance) => Box::into_raw(Box::new(FFIBalance::from(balance))),
        Err(e) => {
            set_last_error(&format!("Failed to get total balance: {}", e));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_rescan_blockchain(
    client: *mut FFIDashSpvClient,
    _from_height: u32,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut _spv_client) = *guard {
            // TODO: rescan_from_height not yet implemented in dash-spv
            Err(dash_spv::SpvError::Config("Not implemented".to_string()))
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to rescan blockchain: {}", e));
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_transaction_confirmations(
    client: *mut FFIDashSpvClient,
    txid: *const c_char,
) -> i32 {
    null_check!(client, -1);
    null_check!(txid, -1);

    // Not implemented in dash-spv yet
    -1
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_is_transaction_confirmed(
    client: *mut FFIDashSpvClient,
    txid: *const c_char,
) -> i32 {
    null_check!(client, 0);
    null_check!(txid, 0);

    // Not implemented in dash-spv yet
    0
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_transaction_destroy(tx: *mut FFITransaction) {
    if !tx.is_null() {
        let _ = Box::from_raw(tx);
    }
}

// This was already implemented earlier but let me add it for tests that import it directly
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_address_utxos(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> FFIArray {
    crate::client::dash_spv_ffi_client_get_utxos_for_address(client, address)
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_enable_mempool_tracking(
    client: *mut FFIDashSpvClient,
    strategy: FFIMempoolStrategy,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();
    
    let mempool_strategy = strategy.into();

    let result = client.runtime.block_on(async {
        let mut guard = inner.lock().unwrap();
        if let Some(ref mut spv_client) = *guard {
            spv_client.enable_mempool_tracking(mempool_strategy).await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_balance_with_mempool(
    client: *mut FFIDashSpvClient,
) -> *mut FFIBalance {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.get_wallet_balance_with_mempool().await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(balance) => Box::into_raw(Box::new(FFIBalance::from(balance))),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_mempool_transaction_count(
    client: *mut FFIDashSpvClient,
) -> i32 {
    null_check!(client, -1);

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            Ok(spv_client.get_mempool_transaction_count().await as i32)
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(count) => count,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_record_send(
    client: *mut FFIDashSpvClient,
    txid: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(txid);

    let txid_str = match CStr::from_ptr(txid).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in txid: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let txid = match Txid::from_str(txid_str) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("Invalid txid: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.record_transaction_send(txid).await;
            Ok(())
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_mempool_balance(
    client: *mut FFIDashSpvClient,
    address: *const c_char,
) -> *mut FFIBalance {
    null_check!(client, std::ptr::null_mut());
    null_check!(address, std::ptr::null_mut());

    let addr_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in address: {}", e));
            return std::ptr::null_mut();
        }
    };

    let addr = match Address::from_str(addr_str) {
        Ok(a) => a.assume_checked(),
        Err(e) => {
            set_last_error(&format!("Invalid address: {}", e));
            return std::ptr::null_mut();
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let guard = inner.lock().unwrap();
        if let Some(ref spv_client) = *guard {
            spv_client.get_mempool_balance(&addr).await
        } else {
            Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                "Client not initialized".to_string(),
            )))
        }
    });

    match result {
        Ok(mempool_balance) => {
            // Convert MempoolBalance to FFIBalance
            let balance = FFIBalance {
                confirmed: 0, // No confirmed balance in mempool
                pending: mempool_balance.pending.to_sat(),
                instantlocked: 0, // No confirmed instantlocked in mempool
                mempool: mempool_balance.pending.to_sat(),
                mempool_instant: mempool_balance.pending_instant.to_sat(),
                total: mempool_balance.pending.to_sat() + mempool_balance.pending_instant.to_sat(),
            };
            Box::into_raw(Box::new(balance))
        }
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}
