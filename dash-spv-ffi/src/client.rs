use crate::{
    null_check, set_last_error, FFIClientConfig, FFIDetailedSyncProgress, FFIErrorCode,
    FFIEventCallbacks, FFISpvStats, FFISyncProgress, FFIWalletManager,
};
// Import wallet types from key-wallet-ffi
use key_wallet_ffi::FFIWalletManager as KeyWalletFFIWalletManager;

use dash_spv::storage::DiskStorageManager;
use dash_spv::types::SyncStage;
use dash_spv::DashSpvClient;
use dash_spv::Hash;
use dashcore::Txid;

use futures::future::{AbortHandle, Abortable};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{error::TryRecvError, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

/// Global callback registry for thread-safe callback management
static CALLBACK_REGISTRY: Lazy<Arc<Mutex<CallbackRegistry>>> =
    Lazy::new(|| Arc::new(Mutex::new(CallbackRegistry::new())));

/// Atomic counter for generating unique callback IDs
static CALLBACK_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Thread-safe callback registry
struct CallbackRegistry {
    callbacks: HashMap<u64, CallbackInfo>,
}

/// Information stored for each callback
enum CallbackInfo {
    /// Detailed progress callbacks (used by sync_to_tip_with_progress)
    Detailed {
        progress_callback: Option<extern "C" fn(*const FFIDetailedSyncProgress, *mut c_void)>,
        completion_callback: Option<extern "C" fn(bool, *const c_char, *mut c_void)>,
        user_data: *mut c_void,
    },
}

/// # Safety
///
/// `CallbackInfo` is only `Send` if the following conditions are met:
/// - All callback functions must be safe to call from any thread
/// - The `user_data` pointer must either:
///   - Point to thread-safe data (i.e., data that implements `Send`)
///   - Be properly synchronized by the caller (e.g., using mutexes)
///   - Be null
///
/// The caller is responsible for ensuring these conditions are met. Violating
/// these requirements will result in undefined behavior.
unsafe impl Send for CallbackInfo {}

/// # Safety
///
/// `CallbackInfo` is only `Sync` if the following conditions are met:
/// - All callback functions must be safe to call concurrently from multiple threads
/// - The `user_data` pointer must either:
///   - Point to thread-safe data (i.e., data that implements `Sync`)
///   - Be properly synchronized by the caller (e.g., using mutexes)
///   - Be null
///
/// The caller is responsible for ensuring these conditions are met. Violating
/// these requirements will result in undefined behavior.
unsafe impl Sync for CallbackInfo {}

impl CallbackRegistry {
    fn new() -> Self {
        Self {
            callbacks: HashMap::new(),
        }
    }

    fn register(&mut self, info: CallbackInfo) -> u64 {
        let id = CALLBACK_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.callbacks.insert(id, info);
        id
    }

    fn get(&self, id: u64) -> Option<&CallbackInfo> {
        self.callbacks.get(&id)
    }

    fn unregister(&mut self, id: u64) -> Option<CallbackInfo> {
        self.callbacks.remove(&id)
    }
}

/// Sync callback data that uses callback IDs instead of raw pointers
struct SyncCallbackData {
    callback_id: u64,
    _marker: std::marker::PhantomData<()>,
}

/// FFIDashSpvClient structure
type InnerClient = DashSpvClient<
    key_wallet_manager::wallet_manager::WalletManager<
        key_wallet::wallet::managed_wallet_info::ManagedWalletInfo,
    >,
    dash_spv::network::PeerNetworkManager,
    DiskStorageManager,
>;
type SharedClient = Arc<Mutex<Option<InnerClient>>>;

pub struct FFIDashSpvClient {
    pub(crate) inner: SharedClient,
    pub(crate) runtime: Arc<Runtime>,
    event_callbacks: Arc<Mutex<FFIEventCallbacks>>,
    active_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    sync_callbacks: Arc<Mutex<Option<SyncCallbackData>>>,
    shutdown_token: CancellationToken,
    // Stored event receiver for pull-based draining (no background thread by default)
    event_rx: Arc<Mutex<Option<UnboundedReceiver<dash_spv::types::SpvEvent>>>>,
}

/// Create a new SPV client and return an opaque pointer.
///
/// # Safety
/// - `config` must be a valid, non-null pointer for the duration of the call.
/// - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_new(
    config: *const FFIClientConfig,
) -> *mut FFIDashSpvClient {
    null_check!(config, std::ptr::null_mut());

    let config = &(*config);
    // Build runtime with configurable worker threads (0 => auto)
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.thread_name("dash-spv-worker").enable_all();
    if config.worker_threads > 0 {
        builder.worker_threads(config.worker_threads as usize);
    }
    let runtime = match builder.build() {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            set_last_error(&format!("Failed to create runtime: {}", e));
            return std::ptr::null_mut();
        }
    };

    let client_config = config.clone_inner();

    let client_result = runtime.block_on(async move {
        // Construct concrete implementations for generics
        let network = dash_spv::network::PeerNetworkManager::new(&client_config).await;
        let storage = DiskStorageManager::new(&client_config).await;
        let wallet = key_wallet_manager::wallet_manager::WalletManager::<
            key_wallet::wallet::managed_wallet_info::ManagedWalletInfo,
        >::new(client_config.network);
        let wallet = std::sync::Arc::new(tokio::sync::RwLock::new(wallet));

        match (network, storage) {
            (Ok(network), Ok(storage)) => {
                DashSpvClient::new(client_config, network, storage, wallet).await
            }
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(dash_spv::SpvError::Storage(e)),
        }
    });

    match client_result {
        Ok(client) => {
            let ffi_client = FFIDashSpvClient {
                inner: Arc::new(Mutex::new(Some(client))),
                runtime,
                event_callbacks: Arc::new(Mutex::new(FFIEventCallbacks::default())),
                active_threads: Arc::new(Mutex::new(Vec::new())),
                sync_callbacks: Arc::new(Mutex::new(None)),
                shutdown_token: CancellationToken::new(),
                event_rx: Arc::new(Mutex::new(None)),
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
    /// Helper method to run async code using the client's runtime
    pub fn run_async<F, Fut, T>(&self, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        self.runtime.block_on(f())
    }

    fn join_active_threads(&self) {
        let handles = {
            let mut guard = self.active_threads.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        for handle in handles {
            if let Err(e) = handle.join() {
                tracing::error!("Failed to join active thread during cleanup: {:?}", e);
            }
        }
    }

    /// Drain pending events and invoke configured callbacks (non-blocking).
    fn drain_events_internal(&self) {
        let mut rx_guard = self.event_rx.lock().unwrap();
        let Some(rx) = rx_guard.as_mut() else {
            return;
        };
        let callbacks = self.event_callbacks.lock().unwrap();
        // Prevent flooding the UI/main thread by limiting events per drain call.
        // Remaining events stay queued and will be drained on the next tick.
        let max_events_per_call: usize = 500;
        let mut processed: usize = 0;
        loop {
            if processed >= max_events_per_call {
                break;
            }
            match rx.try_recv() {
                Ok(event) => match event {
                    dash_spv::types::SpvEvent::BalanceUpdate {
                        confirmed,
                        unconfirmed,
                        ..
                    } => {
                        callbacks.call_balance_update(confirmed, unconfirmed);
                    }
                    dash_spv::types::SpvEvent::TransactionDetected {
                        ref txid,
                        confirmed,
                        ref addresses,
                        amount,
                        block_height,
                        ..
                    } => {
                        if let Ok(txid_parsed) = txid.parse::<dashcore::Txid>() {
                            callbacks.call_transaction(
                                &txid_parsed,
                                confirmed,
                                amount,
                                addresses,
                                block_height,
                            );
                            let wallet_id_hex = "unknown";
                            let account_index = 0;
                            let block_height = block_height.unwrap_or(0);
                            let is_ours = amount != 0;
                            callbacks.call_wallet_transaction(
                                wallet_id_hex,
                                account_index,
                                &txid_parsed,
                                confirmed,
                                amount,
                                addresses,
                                block_height,
                                is_ours,
                            );
                        }
                    }
                    dash_spv::types::SpvEvent::BlockProcessed {
                        height,
                        ref hash,
                        ..
                    } => {
                        if let Ok(hash_parsed) = hash.parse::<dashcore::BlockHash>() {
                            callbacks.call_block(height, &hash_parsed);
                        }
                    }
                    dash_spv::types::SpvEvent::SyncProgress {
                        ..
                    } => {}
                    dash_spv::types::SpvEvent::ChainLockReceived {
                        ..
                    } => {}
                    dash_spv::types::SpvEvent::InstantLockReceived {
                        ..
                    } => {
                        // InstantLock received and validated
                        // TODO: Add FFI callback if needed for instant lock notifications
                    }
                    dash_spv::types::SpvEvent::MempoolTransactionAdded {
                        ref txid,
                        amount,
                        ref addresses,
                        is_instant_send,
                        ..
                    } => {
                        callbacks.call_mempool_transaction_added(
                            txid,
                            amount,
                            addresses,
                            is_instant_send,
                        );
                    }
                    dash_spv::types::SpvEvent::MempoolTransactionConfirmed {
                        ref txid,
                        block_height,
                        ref block_hash,
                    } => {
                        callbacks.call_mempool_transaction_confirmed(
                            txid,
                            block_height,
                            block_hash,
                        );
                    }
                    dash_spv::types::SpvEvent::MempoolTransactionRemoved {
                        ref txid,
                        ref reason,
                    } => {
                        let ffi_reason: crate::types::FFIMempoolRemovalReason =
                            reason.clone().into();
                        let reason_code = ffi_reason as u8;
                        callbacks.call_mempool_transaction_removed(txid, reason_code);
                    }
                    dash_spv::types::SpvEvent::CompactFilterMatched {
                        hash,
                    } => {
                        if let Ok(block_hash_parsed) = hash.parse::<dashcore::BlockHash>() {
                            callbacks.call_compact_filter_matched(
                                &block_hash_parsed,
                                &[],
                                "unknown",
                            );
                        }
                    }
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    *rx_guard = None;
                    break;
                }
            }
            processed += 1;
        }
    }
}

/// Drain pending events and invoke configured callbacks (non-blocking).
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_drain_events(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);
    let client = &*client;
    client.drain_events_internal();
    FFIErrorCode::Success as i32
}

fn stop_client_internal(client: &mut FFIDashSpvClient) -> Result<(), dash_spv::SpvError> {
    client.shutdown_token.cancel();

    // Ensure callbacks are cleared so no further progress/completion notifications fire.
    {
        let mut cb_guard = client.sync_callbacks.lock().unwrap();
        if let Some(ref callback_data) = *cb_guard {
            CALLBACK_REGISTRY.lock().unwrap().unregister(callback_data.callback_id);
        }
        *cb_guard = None;
    }

    client.join_active_threads();

    let inner = client.inner.clone();
    let result = client.runtime.block_on(async {
        let mut spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                        "Client not initialized".to_string(),
                    )))
                }
            }
        };
        let res = spv_client.stop().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    client.shutdown_token = CancellationToken::new();

    result
}

/// Update the running client's configuration.
///
/// # Safety
/// - `client` must be a valid pointer to an `FFIDashSpvClient`.
/// - `config` must be a valid pointer to an `FFIClientConfig`.
/// - The network in `config` must match the client's network; changing networks at runtime is not supported.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_update_config(
    client: *mut FFIDashSpvClient,
    config: *const FFIClientConfig,
) -> i32 {
    null_check!(client);
    null_check!(config);

    let client = &(*client);
    let new_config = (&*config).clone_inner();

    let result = client.runtime.block_on(async {
        // Take client without holding the lock across await
        let mut spv_client = {
            let mut guard = client.inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
                }
            }
        };

        let res = spv_client.update_config(new_config).await;

        // Put client back
        let mut guard = client.inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Start the SPV client.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to a created client.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_start(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let mut spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                        "Client not initialized".to_string(),
                    )))
                }
            }
        };
        let res = spv_client.start().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(()) => {
            // After successful start, take event receiver for pull-based draining
            let mut guard = client.inner.lock().unwrap();
            if let Some(ref mut spv_client) = *guard {
                match spv_client.take_event_receiver() {
                    Some(rx) => {
                        *client.event_rx.lock().unwrap() = Some(rx);
                        tracing::debug!("Replaced FFI event receiver after client start");
                    }
                    None => {
                        tracing::debug!(
                            "No new event receiver returned after client start; keeping existing receiver"
                        );
                    }
                }
            }
            FFIErrorCode::Success as i32
        }
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Stop the SPV client.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to a created client.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_stop(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &mut (*client);
    match stop_client_internal(client) {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Performs a test synchronization of the SPV client
///
/// # Parameters
/// - `client`: Pointer to an FFIDashSpvClient instance
///
/// # Returns
/// - `0` on success
/// - Negative error code on failure
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the client pointer is valid.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_test_sync(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);
    let result = client.runtime.block_on(async {
        let spv_client = {
            let mut guard = client.inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
                }
            }
        };
        tracing::info!("Starting test sync...");

        // Get initial height
        let start_height = match spv_client.sync_progress().await {
            Ok(progress) => progress.header_height,
            Err(e) => {
                tracing::error!("Failed to get initial height: {}", e);
                return Err(e);
            }
        };
        tracing::info!("Initial height: {}", start_height);

        // Wait a bit for headers to download
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Check if headers increased
        let end_height = match spv_client.sync_progress().await {
            Ok(progress) => progress.header_height,
            Err(e) => {
                tracing::error!("Failed to get final height: {}", e);
                let mut guard = client.inner.lock().unwrap();
                *guard = Some(spv_client);
                return Err(e);
            }
        };
        tracing::info!("Final height: {}", end_height);

        let result = if end_height > start_height {
            tracing::info!("✅ Sync working! Downloaded {} headers", end_height - start_height);
            Ok(())
        } else {
            let msg = "No headers downloaded".to_string();
            tracing::error!("❌ {}", msg);
            Err(dash_spv::SpvError::Sync(dash_spv::SyncError::Network(msg)))
        };

        // put client back
        let mut guard = client.inner.lock().unwrap();
        *guard = Some(spv_client);
        result
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Sync the SPV client to the chain tip with detailed progress updates.
///
/// # Safety
///
/// This function is unsafe because:
/// - `client` must be a valid pointer to an initialized `FFIDashSpvClient`
/// - `user_data` must satisfy thread safety requirements:
///   - If non-null, it must point to data that is safe to access from multiple threads
///   - The caller must ensure proper synchronization if the data is mutable
///   - The data must remain valid for the entire duration of the sync operation
/// - Both `progress_callback` and `completion_callback` must be thread-safe and can be called from any thread
///
/// # Parameters
///
/// - `client`: Pointer to the SPV client
/// - `progress_callback`: Optional callback invoked periodically with sync progress
/// - `completion_callback`: Optional callback invoked on completion
/// - `user_data`: Optional user data pointer passed to all callbacks
///
/// # Returns
///
/// 0 on success, error code on failure
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_sync_to_tip_with_progress(
    client: *mut FFIDashSpvClient,
    progress_callback: Option<extern "C" fn(*const FFIDetailedSyncProgress, *mut c_void)>,
    completion_callback: Option<extern "C" fn(bool, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) -> i32 {
    null_check!(client);

    let client = &(*client);

    // Register callbacks in the global registry
    let callback_info = CallbackInfo::Detailed {
        progress_callback,
        completion_callback,
        user_data,
    };
    let callback_id = CALLBACK_REGISTRY.lock().unwrap().register(callback_info);

    // Store callback ID in the client
    let callback_data = SyncCallbackData {
        callback_id,
        _marker: std::marker::PhantomData,
    };
    *client.sync_callbacks.lock().unwrap() = Some(callback_data);

    let inner = client.inner.clone();
    let runtime = client.runtime.clone();
    let sync_callbacks = client.sync_callbacks.clone();

    // Take progress receiver from client
    let progress_receiver = {
        let mut guard = inner.lock().unwrap();
        guard.as_mut().and_then(|c| c.take_progress_receiver())
    };

    // Setup progress monitoring with safe callback access
    if let Some(mut receiver) = progress_receiver {
        let runtime_handle = runtime.handle().clone();
        let sync_callbacks_clone = sync_callbacks.clone();
        let shutdown_token_monitor = client.shutdown_token.clone();

        let handle = std::thread::spawn(move || {
            runtime_handle.block_on(async move {
                loop {
                    tokio::select! {
                        maybe_progress = receiver.recv() => {
                            match maybe_progress {
                                Some(progress) => {
                                    // Handle callback in a thread-safe way
                                    let should_stop = matches!(
                                        progress.sync_stage,
                                        SyncStage::Complete | SyncStage::Failed(_)
                                    );

                                    // Create FFI progress (stack-allocated to avoid double-free issues)
                                    let mut ffi_progress = FFIDetailedSyncProgress::from(progress);

                                    // Call the callback using the registry
                                    {
                                        let cb_guard = sync_callbacks_clone.lock().unwrap();

                                        if let Some(ref callback_data) = *cb_guard {
                                            let registry = CALLBACK_REGISTRY.lock().unwrap();
                                            if let Some(CallbackInfo::Detailed {
                                                progress_callback: Some(callback),
                                                user_data,
                                                ..
                                            }) = registry.get(callback_data.callback_id)
                                            {
                                                // SAFETY: The callback and user_data are safely stored in the registry
                                                // and accessed through thread-safe mechanisms. The registry ensures
                                                // proper lifetime management without raw pointer passing across threads.
                                                callback(&ffi_progress, *user_data);

                                                // Free any heap-allocated strings inside the progress struct
                                                // to avoid leaking per-callback allocations (e.g., stage_message).
                                                // Move stage_message out of the struct to avoid double-free.
                                                unsafe {
                                                    // Move stage_message out of the struct (not using ptr::read to avoid double-free)
                                                    let stage_message = std::mem::replace(
                                                        &mut ffi_progress.stage_message,
                                                        crate::types::FFIString {
                                                            ptr: std::ptr::null_mut(),
                                                            length: 0,
                                                        },
                                                    );
                                                    // Destroy stage_message allocated in FFIDetailedSyncProgress::from
                                                    crate::types::dash_spv_ffi_string_destroy(stage_message);
                                                    // ffi_progress will be dropped normally here; no Drop impl exists
                                                }
                                            }
                                        }
                                    }

                                    if should_stop {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = shutdown_token_monitor.cancelled() => {
                            break;
                        }
                    }
                }
            });
        });

        // Store thread handle
        client.active_threads.lock().unwrap().push(handle);
    }

    // Spawn sync task in a separate thread with safe callback access
    let runtime_handle = runtime.handle().clone();
    let sync_callbacks_clone = sync_callbacks.clone();
    let shutdown_token_sync = client.shutdown_token.clone();
    let sync_handle = std::thread::spawn(move || {
        let shutdown_token_callback = shutdown_token_sync.clone();
        // Run monitoring loop
        let monitor_result = runtime_handle.block_on({
            let inner = inner.clone();
            async move {
                let mut spv_client = {
                    let mut guard = inner.lock().unwrap();
                    match guard.take() {
                        Some(client) => client,
                        None => {
                            return Err(dash_spv::SpvError::Config(
                                "Client not initialized".to_string(),
                            ))
                        }
                    }
                };
                let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
                let run_token = shutdown_token_sync.clone();
                let (abort_handle, abort_registration) = AbortHandle::new_pair();
                let mut monitor_future = Box::pin(Abortable::new(
                    spv_client.monitor_network(command_receiver, run_token),
                    abort_registration,
                ));
                let result = tokio::select! {
                    res = &mut monitor_future => match res {
                        Ok(inner) => inner,
                        Err(_) => Ok(()),
                    },
                    _ = shutdown_token_sync.cancelled() => {
                        abort_handle.abort();
                        match monitor_future.as_mut().await {
                            Ok(inner) => inner,
                            Err(_) => Ok(()),
                        }
                    }
                };
                drop(monitor_future);
                let mut guard = inner.lock().unwrap();
                *guard = Some(spv_client);
                result
            }
        });

        // Send completion callback and cleanup
        {
            let mut cb_guard = sync_callbacks_clone.lock().unwrap();
            if let Some(ref callback_data) = *cb_guard {
                let mut registry = CALLBACK_REGISTRY.lock().unwrap();
                if let Some(CallbackInfo::Detailed {
                    completion_callback: Some(callback),
                    user_data,
                    ..
                }) = registry.unregister(callback_data.callback_id)
                {
                    if shutdown_token_callback.is_cancelled() {
                        let msg = CString::new("Sync stopped by request").unwrap_or_else(|_| {
                            CString::new("Sync stopped").expect("hardcoded string is safe")
                        });
                        callback(false, msg.as_ptr(), user_data);
                    } else {
                        match monitor_result {
                            Ok(_) => {
                                let msg = CString::new("Sync completed successfully")
                                    .unwrap_or_else(|_| {
                                        CString::new("Sync completed")
                                            .expect("hardcoded string is safe")
                                    });
                                callback(true, msg.as_ptr(), user_data);
                            }
                            Err(e) => {
                                let msg = match CString::new(format!("Sync failed: {}", e)) {
                                    Ok(s) => s,
                                    Err(_) => CString::new("Sync failed")
                                        .expect("hardcoded string is safe"),
                                };
                                callback(false, msg.as_ptr(), user_data);
                            }
                        }
                    }
                }
            }
            // Clear the callbacks after completion
            *cb_guard = None;
        }
    });

    // Store thread handle
    client.active_threads.lock().unwrap().push(sync_handle);

    FFIErrorCode::Success as i32
}

// Filter header progress updates are included in the detailed sync progress callback.

/// Cancels the sync operation.
///
/// This stops the SPV client, clears callbacks, and joins active threads so the sync
/// operation halts immediately.
///
/// # Safety
/// The client pointer must be valid and non-null.
///
/// # Returns
/// Returns 0 on success, or an error code on failure.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_cancel_sync(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &mut (*client);

    match stop_client_internal(client) {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Get the current sync progress snapshot.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_sync_progress(
    client: *mut FFIDashSpvClient,
) -> *mut FFISyncProgress {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(c) => c,
                None => {
                    return Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                        "Client not initialized".to_string(),
                    )))
                }
            }
        };
        let res = spv_client.sync_progress().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(progress) => Box::into_raw(Box::new(progress.into())),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Get current runtime statistics for the SPV client.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_stats(
    client: *mut FFIDashSpvClient,
) -> *mut FFISpvStats {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                        "Client not initialized".to_string(),
                    )))
                }
            }
        };
        let res = spv_client.stats().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(stats) => Box::into_raw(Box::new(stats.into())),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Get the current chain tip hash (32 bytes) if available.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
/// - `out_hash` must be a valid pointer to a 32-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_tip_hash(
    client: *mut FFIDashSpvClient,
    out_hash: *mut u8,
) -> i32 {
    null_check!(client);
    if out_hash.is_null() {
        set_last_error("Null out_hash pointer");
        return FFIErrorCode::NullPointer as i32;
    }

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(c) => c,
                None => {
                    return Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
                }
            }
        };
        let tip = spv_client.tip_hash().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        Ok(tip)
    });

    match result {
        Ok(Some(hash)) => {
            let bytes = hash.to_byte_array();
            // SAFETY: out_hash points to a buffer with at least 32 bytes
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_hash, 32);
            FFIErrorCode::Success as i32
        }
        Ok(None) => {
            set_last_error("No tip hash available");
            FFIErrorCode::StorageError as i32
        }
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Get the current chain tip height (absolute).
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
/// - `out_height` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_tip_height(
    client: *mut FFIDashSpvClient,
    out_height: *mut u32,
) -> i32 {
    null_check!(client);
    if out_height.is_null() {
        set_last_error("Null out_height pointer");
        return FFIErrorCode::NullPointer as i32;
    }

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(c) => c,
                None => {
                    return Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
                }
            }
        };
        let height = spv_client.tip_height().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        Ok(height)
    });

    match result {
        Ok(height) => {
            *out_height = height;
            FFIErrorCode::Success as i32
        }
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Clear all persisted SPV storage (headers, filters, metadata, sync state).
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_clear_storage(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();

    let result = client.runtime.block_on(async {
        let mut spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(c) => c,
                None => {
                    return Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
                }
            }
        };

        // Try to stop before clearing to ensure no in-flight writes race the wipe.
        if let Err(e) = spv_client.stop().await {
            tracing::warn!("Failed to stop client before clearing storage: {}", e);
        }

        let res = spv_client.clear_storage().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Check if compact filter sync is currently available.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_is_filter_sync_available(
    client: *mut FFIDashSpvClient,
) -> bool {
    null_check!(client, false);

    let client = &(*client);
    let inner = client.inner.clone();

    client.runtime.block_on(async {
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => return false,
            }
        };
        let res = spv_client.is_filter_sync_available().await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    })
}

/// Set event callbacks for the client.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_set_event_callbacks(
    client: *mut FFIDashSpvClient,
    callbacks: FFIEventCallbacks,
) -> i32 {
    null_check!(client);

    let client = &(*client);

    tracing::debug!("Setting event callbacks on FFI client");
    tracing::debug!("   Block callback: {}", callbacks.on_block.is_some());
    tracing::debug!("   Transaction callback: {}", callbacks.on_transaction.is_some());
    tracing::debug!("   Balance update callback: {}", callbacks.on_balance_update.is_some());

    let mut event_callbacks = client.event_callbacks.lock().unwrap();
    *event_callbacks = callbacks;

    tracing::debug!("Event callbacks set successfully");
    FFIErrorCode::Success as i32
}

/// Destroy the client and free associated resources.
///
/// # Safety
/// - `client` must be either null or a pointer obtained from `dash_spv_ffi_client_new`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_destroy(client: *mut FFIDashSpvClient) {
    if !client.is_null() {
        let client = Box::from_raw(client);

        // Cancel shutdown token to stop all threads
        client.shutdown_token.cancel();

        // Clean up any registered callbacks
        if let Some(ref callback_data) = *client.sync_callbacks.lock().unwrap() {
            CALLBACK_REGISTRY.lock().unwrap().unregister(callback_data.callback_id);
        }

        // Stop the SPV client
        client.runtime.block_on(async {
            if let Some(mut spv_client) = {
                let mut guard = client.inner.lock().unwrap();
                guard.take()
            } {
                let _ = spv_client.stop().await;
                let mut guard = client.inner.lock().unwrap();
                *guard = Some(spv_client);
            }
        });

        // Join all active threads to ensure clean shutdown
        let threads = {
            let mut threads_guard = client.active_threads.lock().unwrap();
            std::mem::take(&mut *threads_guard)
        };

        for handle in threads {
            if let Err(e) = handle.join() {
                tracing::error!("Failed to join thread during cleanup: {:?}", e);
            }
        }

        tracing::info!("✅ FFI client destroyed and all threads cleaned up");
    }
}

/// Destroy a `FFISyncProgress` object returned by this crate.
///
/// # Safety
/// - `progress` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_sync_progress_destroy(progress: *mut FFISyncProgress) {
    if !progress.is_null() {
        let _ = Box::from_raw(progress);
    }
}

/// Destroy an `FFISpvStats` object returned by this crate.
///
/// # Safety
/// - `stats` must be a pointer returned from this crate, or null.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_spv_stats_destroy(stats: *mut FFISpvStats) {
    if !stats.is_null() {
        let _ = Box::from_raw(stats);
    }
}

// Wallet operations

/// Request a rescan of the blockchain from a given height (not yet implemented).
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
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

/// Record that we attempted to send a transaction by its txid.
///
/// # Safety
/// - `client` and `txid` must be valid, non-null pointers.
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
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                        "Client not initialized".to_string(),
                    )))
                }
            }
        };
        let res = spv_client.record_send(txid).await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Get the wallet manager from the SPV client
///
/// Returns a pointer to an `FFIWalletManager` wrapper that clones the underlying
/// `Arc<RwLock<WalletManager>>`. This allows direct interaction with the wallet
/// manager without going back through the client for each call.
///
/// # Safety
///
/// The caller must ensure that:
/// - The client pointer is valid
/// - The returned pointer is released exactly once using
///   `dash_spv_ffi_wallet_manager_free`
///
/// # Returns
///
/// A pointer to the wallet manager wrapper, or NULL if the client is not initialized.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_wallet_manager(
    client: *mut FFIDashSpvClient,
) -> *mut FFIWalletManager {
    null_check!(client, std::ptr::null_mut());

    let client = &*client;
    let inner = client.inner.lock().unwrap();

    if let Some(ref spv_client) = *inner {
        // Clone the Arc to the wallet manager
        let wallet_arc = spv_client.wallet().clone();
        let runtime = client.runtime.clone();

        // Create the FFIWalletManager with the cloned Arc
        let manager = KeyWalletFFIWalletManager::from_arc(wallet_arc, runtime);

        Box::into_raw(Box::new(manager)) as *mut FFIWalletManager
    } else {
        set_last_error("Client not initialized");
        std::ptr::null_mut()
    }
}

/// Release a wallet manager obtained from `dash_spv_ffi_client_get_wallet_manager`.
///
/// This simply forwards to `wallet_manager_free` in key-wallet-ffi so that
/// lifetime management is consistent between direct key-wallet usage and the
/// SPV client pathway.
///
/// # Safety
/// - `manager` must either be null or a pointer previously returned by
///   `dash_spv_ffi_client_get_wallet_manager`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_wallet_manager_free(manager: *mut FFIWalletManager) {
    if manager.is_null() {
        return;
    }

    key_wallet_ffi::wallet_manager::wallet_manager_free(manager as *mut KeyWalletFFIWalletManager);
}
