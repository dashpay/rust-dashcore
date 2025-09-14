use crate::{
    null_check, set_last_error, FFIClientConfig, FFIDetailedSyncProgress, FFIErrorCode,
    FFIEventCallbacks, FFIMempoolStrategy, FFISpvStats, FFISyncProgress,
};
// Import wallet types from key-wallet-ffi
use key_wallet_ffi::FFIWalletManager;

use dash_spv::types::SyncStage;
use dash_spv::DashSpvClient;
use dashcore::Txid;

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;

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
    /// Simple progress callbacks (used by sync_to_tip)
    Simple {
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
    dash_spv::network::MultiPeerNetworkManager,
    dash_spv::storage::MemoryStorageManager,
>;
type SharedClient = Arc<Mutex<Option<InnerClient>>>;

pub struct FFIDashSpvClient {
    pub(crate) inner: SharedClient,
    pub(crate) runtime: Arc<Runtime>,
    event_callbacks: Arc<Mutex<FFIEventCallbacks>>,
    active_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    sync_callbacks: Arc<Mutex<Option<SyncCallbackData>>>,
    shutdown_signal: Arc<AtomicBool>,
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
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .thread_name("dash-spv-worker")
        .worker_threads(4) // Use 4 threads for better performance on iOS
        .enable_all()
        .build()
    {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            set_last_error(&format!("Failed to create runtime: {}", e));
            return std::ptr::null_mut();
        }
    };

    let client_config = config.clone_inner();
    let client_result = runtime.block_on(async {
        // Construct concrete implementations for generics
        let network = dash_spv::network::MultiPeerNetworkManager::new(&client_config).await;
        let storage = dash_spv::storage::MemoryStorageManager::new().await;
        let wallet = key_wallet_manager::wallet_manager::WalletManager::<
            key_wallet::wallet::managed_wallet_info::ManagedWalletInfo,
        >::new();
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
                shutdown_signal: Arc::new(AtomicBool::new(false)),
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

    /// Start the event listener task to handle events from the SPV client.
    fn start_event_listener(&self) {
        let inner = self.inner.clone();
        let event_callbacks = self.event_callbacks.clone();
        let runtime = self.runtime.clone();
        let shutdown_signal = self.shutdown_signal.clone();

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
                    loop {
                        // Check shutdown signal
                        if shutdown_signal.load(Ordering::Relaxed) {
                            tracing::info!("🛑 FFI event listener received shutdown signal");
                            break;
                        }

                        // Use recv with timeout to periodically check shutdown signal
                        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                            Ok(Some(event)) => {
                                tracing::info!("🎧 FFI received event: {:?}", event);
                                let callbacks = event_callbacks.lock().unwrap();
                        match event {
                            dash_spv::types::SpvEvent::BalanceUpdate { confirmed, unconfirmed, total } => {
                                tracing::info!("💰 Balance update event: confirmed={}, unconfirmed={}, total={}", 
                                             confirmed, unconfirmed, total);
                                callbacks.call_balance_update(confirmed, unconfirmed);
                            }
                            dash_spv::types::SpvEvent::FilterHeadersProgress { filter_header_height, header_height, percentage } => {
                                tracing::info!("📊 Filter headers progress event: filter={}, header={}, pct={:.2}",
                                               filter_header_height, header_height, percentage);
                                callbacks
                                    .call_filter_headers_progress(
                                        filter_header_height,
                                        header_height,
                                        percentage,
                                    );
                            }
                            dash_spv::types::SpvEvent::TransactionDetected { ref txid, confirmed, ref addresses, amount, block_height, .. } => {
                                tracing::info!("💸 Transaction detected: txid={}, confirmed={}, amount={}, addresses={:?}, height={:?}",
                                             txid, confirmed, amount, addresses, block_height);
                                // Parse the txid string to a Txid type
                                if let Ok(txid_parsed) = txid.parse::<dashcore::Txid>() {
                            // Call the general transaction callback
                            callbacks.call_transaction(&txid_parsed, confirmed, amount, addresses, block_height);

                                    // Also try to provide wallet-specific context
                                    // Note: For now, we provide basic wallet context.
                                    // In a more advanced implementation, we could enhance this
                                    // to look up the actual wallet/account that owns this transaction.
                                    let wallet_id_hex = "unknown"; // Placeholder - would need wallet lookup
                                    let account_index = 0; // Default account index
                                    let block_height = block_height.unwrap_or(0);
                                    let is_ours = amount != 0; // Simple heuristic

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
                                } else {
                                    tracing::error!("Failed to parse transaction ID: {}", txid);
                                }
                            }
                            dash_spv::types::SpvEvent::BlockProcessed { height, ref hash, transactions_count, relevant_transactions } => {
                                tracing::info!("📦 Block processed: height={}, hash={}, total_tx={}, relevant_tx={}", 
                                             height, hash, transactions_count, relevant_transactions);
                                // Parse the block hash string to a BlockHash type
                                if let Ok(hash_parsed) = hash.parse::<dashcore::BlockHash>() {
                                    callbacks.call_block(height, &hash_parsed);
                                } else {
                                    tracing::error!("Failed to parse block hash: {}", hash);
                                }
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
                                callbacks.call_mempool_transaction_added(txid, amount, addresses, is_instant_send);
                            }
                            dash_spv::types::SpvEvent::MempoolTransactionConfirmed { ref txid, block_height, ref block_hash } => {
                                tracing::info!("✅ Mempool transaction confirmed: txid={}, height={}, hash={}", 
                                             txid, block_height, block_hash);
                                // Call the mempool confirmed callback
                                callbacks.call_mempool_transaction_confirmed(txid, block_height, block_hash);
                            }
                            dash_spv::types::SpvEvent::MempoolTransactionRemoved { ref txid, ref reason } => {
                                tracing::info!("❌ Mempool transaction removed: txid={}, reason={:?}", 
                                             txid, reason);
                                // Convert reason to u8 for FFI using existing conversion
                                let ffi_reason: crate::types::FFIMempoolRemovalReason = reason.clone().into();
                                let reason_code = ffi_reason as u8;
                                callbacks.call_mempool_transaction_removed(txid, reason_code);
                            }
                            dash_spv::types::SpvEvent::CompactFilterMatched { hash } => {
                                tracing::info!("📄 Compact filter matched: block={}", hash);

                                // Try to provide richer information by looking up which wallet matched
                                // Since we don't have direct access to filter details, we'll provide basic info
                                if let Ok(block_hash_parsed) = hash.parse::<dashcore::BlockHash>() {
                                    // For now, we'll call with empty matched scripts and unknown wallet
                                    // In a more advanced implementation, we could enhance the SpvEvent to include this info
                                    callbacks.call_compact_filter_matched(
                                        &block_hash_parsed,
                                        &[], // matched_scripts - empty for now
                                        "unknown", // wallet_id - unknown for now
                                    );
                                } else {
                                    tracing::error!("Failed to parse compact filter block hash: {}", hash);
                                }
                            }
                        }
                            }
                            Ok(None) => {
                                // Channel closed, exit loop
                                tracing::info!("🎧 FFI event channel closed");
                                break;
                            }
                            Err(_) => {
                                // Timeout, continue to check shutdown signal
                                continue;
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

/// Stop the SPV client.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to a created client.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_stop(client: *mut FFIDashSpvClient) -> i32 {
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
        let res = spv_client.stop().await;
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

/// Sync the SPV client to the chain tip.
///
/// # Safety
///
/// This function is unsafe because:
/// - `client` must be a valid pointer to an initialized `FFIDashSpvClient`
/// - `user_data` must satisfy thread safety requirements:
///   - If non-null, it must point to data that is safe to access from multiple threads
///   - The caller must ensure proper synchronization if the data is mutable
///   - The data must remain valid for the entire duration of the sync operation
/// - `completion_callback` must be thread-safe and can be called from any thread
///
/// # Parameters
///
/// - `client`: Pointer to the SPV client
/// - `completion_callback`: Optional callback invoked on completion
/// - `user_data`: Optional user data pointer passed to callbacks
///
/// # Returns
///
/// 0 on success, error code on failure
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_sync_to_tip(
    client: *mut FFIDashSpvClient,
    completion_callback: Option<extern "C" fn(bool, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    let inner = client.inner.clone();
    let runtime = client.runtime.clone();

    // Register callbacks in the global registry for safe lifetime management
    let callback_info = CallbackInfo::Simple {
        completion_callback,
        user_data,
    };
    let callback_id = CALLBACK_REGISTRY.lock().unwrap().register(callback_info);

    // Execute sync in the runtime
    let result = runtime.block_on(async {
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
        match spv_client.sync_to_tip().await {
            Ok(_sync_result) => {
                // sync_to_tip returns a SyncResult, not a stream
                // Progress callbacks removed as sync_to_tip doesn't provide real progress updates

                // Report completion and unregister callbacks
                let mut registry = CALLBACK_REGISTRY.lock().unwrap();
                if let Some(CallbackInfo::Simple {
                    completion_callback: Some(callback),
                    user_data,
                }) = registry.unregister(callback_id)
                {
                    let msg = CString::new("Sync completed successfully").unwrap_or_else(|_| {
                        CString::new("Sync completed").expect("hardcoded string is safe")
                    });
                    callback(true, msg.as_ptr(), user_data);
                }

                // Put client back
                let mut guard = inner.lock().unwrap();
                *guard = Some(spv_client);

                Ok(())
            }
            Err(e) => {
                // Report error and unregister callbacks
                let mut registry = CALLBACK_REGISTRY.lock().unwrap();
                if let Some(CallbackInfo::Simple {
                    completion_callback: Some(callback),
                    user_data,
                }) = registry.unregister(callback_id)
                {
                    let msg = match CString::new(format!("Sync failed: {}", e)) {
                        Ok(s) => s,
                        Err(_) => CString::new("Sync failed").expect("hardcoded string is safe"),
                    };
                    callback(false, msg.as_ptr(), user_data);
                }

                // Put client back
                let mut guard = inner.lock().unwrap();
                *guard = Some(spv_client);
                Err(e)
            }
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
        let mut spv_client = {
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

        // Start sync
        match spv_client.sync_to_tip().await {
            Ok(_) => tracing::info!("Sync started successfully"),
            Err(e) => {
                tracing::error!("Failed to start sync: {}", e);
                // put back before returning
                let mut guard = client.inner.lock().unwrap();
                *guard = Some(spv_client);
                return Err(e);
            }
        }

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
    // Shared flag to coordinate internal threads during sync
    let sync_running = Arc::new(AtomicBool::new(true));

    // Take progress receiver from client
    let progress_receiver = {
        let mut guard = inner.lock().unwrap();
        guard.as_mut().and_then(|c| c.take_progress_receiver())
    };

    // Setup progress monitoring with safe callback access
    if let Some(mut receiver) = progress_receiver {
        let runtime_handle = runtime.handle().clone();
        let sync_callbacks_clone = sync_callbacks.clone();

        let handle = std::thread::spawn(move || {
            runtime_handle.block_on(async move {
                while let Some(progress) = receiver.recv().await {
                    // Handle callback in a thread-safe way
                    let should_stop = matches!(progress.sync_stage, SyncStage::Complete);

                    // Create FFI progress
                    let ffi_progress = Box::new(FFIDetailedSyncProgress::from(progress));

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
                                callback(ffi_progress.as_ref(), *user_data);
                            }
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

    // Spawn sync task in a separate thread with safe callback access
    let runtime_handle = runtime.handle().clone();
    let sync_callbacks_clone = sync_callbacks.clone();
    let sync_running_for_join = sync_running.clone();
    let sync_handle = std::thread::spawn(move || {
        // Run monitoring loop
        let monitor_result = runtime_handle.block_on(async move {
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
            let res = spv_client.monitor_network().await;
            let mut guard = inner.lock().unwrap();
            *guard = Some(spv_client);
            res
        });

        // Signal background handlers to stop
        sync_running_for_join.store(false, Ordering::Relaxed);

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
                    match monitor_result {
                        Ok(_) => {
                            let msg =
                                CString::new("Sync completed successfully").unwrap_or_else(|_| {
                                    CString::new("Sync completed")
                                        .expect("hardcoded string is safe")
                                });
                            // SAFETY: The callback and user_data are safely managed through the registry.
                            // The registry ensures proper lifetime management and thread safety.
                            // The string pointer is only valid for the duration of the callback.
                            callback(true, msg.as_ptr(), user_data);
                            // CString is automatically dropped here, which is safe because the callback
                            // should not store or use the pointer after it returns
                        }
                        Err(e) => {
                            let msg = match CString::new(format!("Sync failed: {}", e)) {
                                Ok(s) => s,
                                Err(_) => {
                                    CString::new("Sync failed").expect("hardcoded string is safe")
                                }
                            };
                            // SAFETY: Same as above
                            callback(false, msg.as_ptr(), user_data);
                            // CString is automatically dropped here, which is safe because the callback
                            // should not store or use the pointer after it returns
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

// Note: filter headers progress is forwarded via FFIEventCallbacks.on_filter_headers_progress

/// Cancels the sync operation.
///
/// **Note**: This function currently only stops the SPV client and clears sync callbacks,
/// but does not fully abort the ongoing sync process. The sync operation may continue
/// running in the background until it completes naturally. Full sync cancellation with
/// proper task abortion is not yet implemented.
///
/// # Safety
/// The client pointer must be valid and non-null.
///
/// # Returns
/// Returns 0 on success, or an error code on failure.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_cancel_sync(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);

    // Clear callbacks to stop progress updates and unregister from the registry
    let mut cb_guard = client.sync_callbacks.lock().unwrap();
    if let Some(ref callback_data) = *cb_guard {
        CALLBACK_REGISTRY.lock().unwrap().unregister(callback_data.callback_id);
    }
    *cb_guard = None;

    // TODO: Implement proper sync task cancellation using cancellation tokens or abort handles.
    // Currently, this only stops the client, but the sync task may continue running in the background.
    let inner = client.inner.clone();
    let result = client.runtime.block_on(async {
        let mut spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Config("Client not initialized".to_string()))
                }
            }
        };
        let res = spv_client.stop().await;
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

    tracing::info!("🔧 Setting event callbacks on FFI client");
    tracing::info!("   Block callback: {}", callbacks.on_block.is_some());
    tracing::info!("   Transaction callback: {}", callbacks.on_transaction.is_some());
    tracing::info!("   Balance update callback: {}", callbacks.on_balance_update.is_some());
    tracing::info!(
        "   Filter headers progress callback: {}",
        callbacks.on_filter_headers_progress.is_some()
    );

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

/// Destroy the client and free associated resources.
///
/// # Safety
/// - `client` must be either null or a pointer obtained from `dash_spv_ffi_client_new`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_destroy(client: *mut FFIDashSpvClient) {
    if !client.is_null() {
        let client = Box::from_raw(client);

        // Set shutdown signal to stop all threads
        client.shutdown_signal.store(true, Ordering::Relaxed);

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

/// Enable mempool tracking with a given strategy.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
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
        let res = spv_client.enable_mempool_tracking(mempool_strategy).await;
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
        spv_client.record_transaction_send(txid).await;
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        Ok(())
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
/// Returns an opaque pointer to FFIWalletManager that contains a cloned Arc reference to the wallet manager.
/// This allows direct interaction with the wallet manager without going through the client.
///
/// # Safety
///
/// The caller must ensure that:
/// - The client pointer is valid
/// - The returned pointer is freed using `wallet_manager_free` from key-wallet-ffi
///
/// # Returns
///
/// An opaque pointer (void*) to the wallet manager, or NULL if the client is not initialized.
/// Swift should treat this as an OpaquePointer.
/// Get a handle to the wallet manager owned by this client.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_wallet_manager(
    client: *mut FFIDashSpvClient,
) -> *mut c_void {
    null_check!(client, std::ptr::null_mut());

    let client = &*client;
    let inner = client.inner.lock().unwrap();

    if let Some(ref spv_client) = *inner {
        // Clone the Arc to the wallet manager
        let wallet_arc = spv_client.wallet().clone();
        let runtime = client.runtime.clone();

        // Create the FFIWalletManager with the cloned Arc
        let manager = FFIWalletManager::from_arc(wallet_arc, runtime);

        Box::into_raw(Box::new(manager)) as *mut c_void
    } else {
        set_last_error("Client not initialized");
        std::ptr::null_mut()
    }
}
