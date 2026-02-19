use crate::{
    null_check, set_last_error, FFIClientConfig, FFIErrorCode, FFINetworkEventCallbacks,
    FFIProgressCallback, FFISyncEventCallbacks, FFISyncProgress, FFIWalletEventCallbacks,
    FFIWalletManager,
};
// Import wallet types from key-wallet-ffi
use key_wallet_ffi::FFIWalletManager as KeyWalletFFIWalletManager;

use dash_spv::storage::DiskStorageManager;
use dash_spv::DashSpvClient;

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tokio::runtime::Handle;
use tokio::runtime::Runtime;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

/// Spawns a monitoring thread for broadcast-based events (sync, network, wallet).
///
/// Returns a thread handle that monitors the receiver and dispatches events to callbacks.
fn spawn_broadcast_monitor<E, C, F>(
    name: &'static str,
    receiver: broadcast::Receiver<E>,
    callbacks: Arc<Mutex<Option<C>>>,
    shutdown: CancellationToken,
    rt: Handle,
    dispatch_fn: F,
) -> JoinHandle<()>
where
    E: Clone + Send + 'static,
    C: Send + 'static,
    F: Fn(&C, &E) + Send + 'static,
{
    let mut receiver = receiver;
    std::thread::spawn(move || {
        rt.block_on(async move {
            tracing::debug!("{} monitoring thread started", name);
            loop {
                tokio::select! {
                    result = receiver.recv() => {
                        match result {
                            Ok(event) => {
                                let guard = callbacks.lock().unwrap();
                                if let Some(ref cb) = *guard {
                                    dispatch_fn(cb, &event);
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        }
                    }
                    _ = shutdown.cancelled() => break,
                }
            }
            tracing::debug!("{} monitoring thread exiting", name);
        });
    })
}

/// Spawns a monitoring thread for watch-based progress updates.
///
/// Sends the initial progress value, then monitors for changes.
fn spawn_progress_monitor<P, C, F>(
    receiver: watch::Receiver<P>,
    callbacks: Arc<Mutex<Option<C>>>,
    shutdown: CancellationToken,
    rt: Handle,
    dispatch_fn: F,
) -> JoinHandle<()>
where
    P: Clone + Send + Sync + 'static,
    C: Send + 'static,
    F: Fn(&C, &P) + Send + 'static,
{
    let mut receiver = receiver;
    std::thread::spawn(move || {
        rt.block_on(async move {
            tracing::debug!("Progress monitoring thread started");

            // Send initial progress
            {
                let progress = receiver.borrow_and_update().clone();
                let guard = callbacks.lock().unwrap();
                if let Some(ref cb) = *guard {
                    dispatch_fn(cb, &progress);
                }
            }

            loop {
                tokio::select! {
                    result = receiver.changed() => {
                        match result {
                            Ok(()) => {
                                let progress = receiver.borrow_and_update().clone();
                                let guard = callbacks.lock().unwrap();
                                if let Some(ref cb) = *guard {
                                    dispatch_fn(cb, &progress);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = shutdown.cancelled() => break,
                }
            }
            tracing::debug!("Progress monitoring thread exiting");
        });
    })
}

/// FFI wrapper around `DashSpvClient`.
type InnerClient = DashSpvClient<
    key_wallet_manager::wallet_manager::WalletManager<
        key_wallet::wallet::managed_wallet_info::ManagedWalletInfo,
    >,
    dash_spv::network::PeerNetworkManager,
    DiskStorageManager,
>;

pub struct FFIDashSpvClient {
    pub(crate) inner: InnerClient,
    pub(crate) runtime: Arc<Runtime>,
    active_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    shutdown_token: CancellationToken,
    sync_event_callbacks: Arc<Mutex<Option<FFISyncEventCallbacks>>>,
    network_event_callbacks: Arc<Mutex<Option<FFINetworkEventCallbacks>>>,
    wallet_event_callbacks: Arc<Mutex<Option<FFIWalletEventCallbacks>>>,
    progress_callback: Arc<Mutex<Option<FFIProgressCallback>>>,
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
                inner: client,
                runtime,
                active_threads: Arc::new(Mutex::new(Vec::new())),
                shutdown_token: CancellationToken::new(),
                sync_event_callbacks: Arc::new(Mutex::new(None)),
                network_event_callbacks: Arc::new(Mutex::new(None)),
                wallet_event_callbacks: Arc::new(Mutex::new(None)),
                progress_callback: Arc::new(Mutex::new(None)),
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
}

fn stop_client_internal(client: &mut FFIDashSpvClient) -> Result<(), dash_spv::SpvError> {
    client.shutdown_token.cancel();

    client.join_active_threads();

    let result = client.runtime.block_on(async { client.inner.stop().await });

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

    let result = client.runtime.block_on(async { client.inner.update_config(new_config).await });

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

    let result = client.runtime.block_on(async { client.inner.start().await });

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
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

/// Start the SPV client and begin syncing in the background.
///
/// This is the streamlined entry point that combines `start()` and continuous monitoring
/// into a single non-blocking call. Use event callbacks (set via `set_sync_event_callbacks`,
/// `set_network_event_callbacks`, `set_wallet_event_callbacks`) to receive notifications
/// about sync progress, peer connections, and wallet activity.
///
/// Workflow:
/// 1. Configure event callbacks before calling `run()`
/// 2. Call `run()` - it returns immediately after spawning background sync threads
/// 3. Receive notifications via callbacks as sync progresses
/// 4. Call `stop()` when done
///
/// # Safety
/// - `client` must be a valid, non-null pointer to a created client.
///
/// # Returns
/// 0 on success, error code on failure.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_run(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);

    tracing::info!("dash_spv_ffi_client_run: starting client");

    // Start the client first
    let start_result = client.runtime.block_on(async { client.inner.start().await });

    if let Err(e) = start_result {
        tracing::error!("dash_spv_ffi_client_run: start failed: {}", e);
        set_last_error(&e.to_string());
        return FFIErrorCode::from(e) as i32;
    }

    tracing::info!("dash_spv_ffi_client_run: client started, setting up event monitoring");

    let runtime_handle = client.runtime.handle().clone();
    let shutdown_token = client.shutdown_token.clone();

    // Subscribe to events before spawning the sync thread
    let (sync_event_rx, network_event_rx, progress_rx, wallet_event_rx) =
        client.runtime.block_on(async {
            let wallet_rx = client.inner.wallet().read().await.subscribe_events();
            (
                client.inner.subscribe_sync_events().await,
                client.inner.subscribe_network_events().await,
                client.inner.subscribe_progress().await,
                wallet_rx,
            )
        });

    // Spawn event monitoring threads for each callback type that is set
    let rt = client.runtime.handle().clone();

    if client.sync_event_callbacks.lock().unwrap().is_some() {
        let handle = spawn_broadcast_monitor(
            "Sync event",
            sync_event_rx.resubscribe(),
            client.sync_event_callbacks.clone(),
            shutdown_token.clone(),
            rt.clone(),
            |cb, event| cb.dispatch(event),
        );
        client.active_threads.lock().unwrap().push(handle);
    }

    if client.network_event_callbacks.lock().unwrap().is_some() {
        let handle = spawn_broadcast_monitor(
            "Network event",
            network_event_rx.resubscribe(),
            client.network_event_callbacks.clone(),
            shutdown_token.clone(),
            rt.clone(),
            |cb, event| cb.dispatch(event),
        );
        client.active_threads.lock().unwrap().push(handle);
    }

    if client.progress_callback.lock().unwrap().is_some() {
        let handle = spawn_progress_monitor(
            progress_rx.clone(),
            client.progress_callback.clone(),
            shutdown_token.clone(),
            rt.clone(),
            |cb, progress| cb.dispatch(progress),
        );
        client.active_threads.lock().unwrap().push(handle);
    }

    if client.wallet_event_callbacks.lock().unwrap().is_some() {
        let handle = spawn_broadcast_monitor(
            "Wallet event",
            wallet_event_rx.resubscribe(),
            client.wallet_event_callbacks.clone(),
            shutdown_token.clone(),
            rt.clone(),
            |cb, event| cb.dispatch(event),
        );
        client.active_threads.lock().unwrap().push(handle);
    }

    tracing::info!("dash_spv_ffi_client_run: spawning sync thread");

    let spv_client = client.inner.clone();

    let sync_handle = std::thread::spawn(move || {
        runtime_handle.block_on(async move {
            tracing::debug!("Sync thread: starting monitor_network");

            if let Err(e) = spv_client.monitor_network(shutdown_token).await {
                tracing::error!("Sync thread: sync error: {}", e);
            }

            tracing::debug!("Sync thread: exiting");
        });
    });

    // Store thread handle for cleanup
    client.active_threads.lock().unwrap().push(sync_handle);

    tracing::info!("dash_spv_ffi_client_run: sync thread spawned, returning");

    FFIErrorCode::Success as i32
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

    let progress = client.runtime.block_on(async { client.inner.sync_progress().await });

    Box::into_raw(Box::new(FFISyncProgress::from(progress)))
}

/// Get the current manager-based sync progress.
///
/// Returns the new parallel sync system's progress with per-manager details.
/// Use `dash_spv_ffi_manager_sync_progress_destroy` to free the returned struct.
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_get_manager_sync_progress(
    client: *mut FFIDashSpvClient,
) -> *mut FFISyncProgress {
    null_check!(client, std::ptr::null_mut());

    let client = &(*client);

    let progress = client.runtime.block_on(async { client.inner.progress().await });

    Box::into_raw(Box::new(FFISyncProgress::from(progress)))
}

/// Clear all persisted SPV storage (headers, filters, metadata, sync state).
///
/// # Safety
/// - `client` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_clear_storage(client: *mut FFIDashSpvClient) -> i32 {
    null_check!(client);

    let client = &(*client);

    let result = client.runtime.block_on(async {
        // Try to stop before clearing to ensure no in-flight writes race the wipe.
        if let Err(e) = client.inner.stop().await {
            tracing::warn!("Failed to stop client before clearing storage: {}", e);
        }

        client.inner.clear_storage().await
    });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
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

        // Stop the SPV client
        client.runtime.block_on(async {
            let _ = client.inner.stop().await;
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

// Wallet operations

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

    // Clone the Arc to the wallet manager
    let wallet_arc = client.inner.wallet().clone();
    let runtime = client.runtime.clone();

    // Create the FFIWalletManager with the cloned Arc
    let manager = KeyWalletFFIWalletManager::from_arc(wallet_arc, runtime);

    Box::into_raw(Box::new(manager)) as *mut FFIWalletManager
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

// ============================================================================
// Event Callback Functions
// ============================================================================

/// Set sync event callbacks for push-based event notifications.
///
/// The monitoring thread is spawned when `dash_spv_ffi_client_run` is called.
/// Call this before calling run().
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
/// - The `callbacks` struct and its `user_data` must remain valid until callbacks are cleared.
/// - Callbacks must be thread-safe as they may be called from a background thread.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_set_sync_event_callbacks(
    client: *mut FFIDashSpvClient,
    callbacks: FFISyncEventCallbacks,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.sync_event_callbacks.lock().unwrap() = Some(callbacks);

    FFIErrorCode::Success as i32
}

/// Clear sync event callbacks.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_clear_sync_event_callbacks(
    client: *mut FFIDashSpvClient,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.sync_event_callbacks.lock().unwrap() = None;

    FFIErrorCode::Success as i32
}

/// Set network event callbacks for push-based event notifications.
///
/// The monitoring thread is spawned when `dash_spv_ffi_client_run` is called.
/// Call this before calling run().
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
/// - The `callbacks` struct and its `user_data` must remain valid until callbacks are cleared.
/// - Callbacks must be thread-safe as they may be called from a background thread.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_set_network_event_callbacks(
    client: *mut FFIDashSpvClient,
    callbacks: FFINetworkEventCallbacks,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.network_event_callbacks.lock().unwrap() = Some(callbacks);

    FFIErrorCode::Success as i32
}

/// Clear network event callbacks.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_clear_network_event_callbacks(
    client: *mut FFIDashSpvClient,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.network_event_callbacks.lock().unwrap() = None;

    FFIErrorCode::Success as i32
}

/// Set wallet event callbacks for push-based event notifications.
///
/// The monitoring thread is spawned when `dash_spv_ffi_client_run` is called.
/// Call this before calling run().
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
/// - The `callbacks` struct and its `user_data` must remain valid until callbacks are cleared.
/// - Callbacks must be thread-safe as they may be called from a background thread.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_set_wallet_event_callbacks(
    client: *mut FFIDashSpvClient,
    callbacks: FFIWalletEventCallbacks,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.wallet_event_callbacks.lock().unwrap() = Some(callbacks);

    FFIErrorCode::Success as i32
}

/// Clear wallet event callbacks.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_clear_wallet_event_callbacks(
    client: *mut FFIDashSpvClient,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.wallet_event_callbacks.lock().unwrap() = None;

    FFIErrorCode::Success as i32
}

/// Set progress callback for sync progress updates.
///
/// The monitoring thread is spawned when `dash_spv_ffi_client_run` is called.
/// Call this before calling run().
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
/// - The `callback` struct and its `user_data` must remain valid until the callback is cleared.
/// - The callback must be thread-safe as it may be called from a background thread.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_set_progress_callback(
    client: *mut FFIDashSpvClient,
    callback: crate::FFIProgressCallback,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.progress_callback.lock().unwrap() = Some(callback);

    FFIErrorCode::Success as i32
}

/// Clear progress callback.
///
/// # Safety
/// - `client` must be a valid, non-null pointer to an `FFIDashSpvClient`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_clear_progress_callback(
    client: *mut FFIDashSpvClient,
) -> i32 {
    null_check!(client);

    let client = &(*client);
    *client.progress_callback.lock().unwrap() = None;

    FFIErrorCode::Success as i32
}
