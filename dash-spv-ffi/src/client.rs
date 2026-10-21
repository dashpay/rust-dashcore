use crate::{
    null_check, set_last_error, FFIClientConfig, FFIErrorCode, FFIEventCallbacks, FFISyncProgress,
    FFIWalletManager,
};
// Import wallet types from key-wallet-ffi
use key_wallet_ffi::FFIWalletManager as KeyWalletFFIWalletManager;

use dash_spv::storage::DiskStorageManager;
use dash_spv::DashSpvClient;
use tracing::dispatcher::{get_default, set_default};

use std::mem::forget;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

/// FFI wrapper around `DashSpvClient`.
type InnerClient = DashSpvClient<
    key_wallet_manager::WalletManager<key_wallet::wallet::managed_wallet_info::ManagedWalletInfo>,
    dash_spv::network::PeerNetworkManager,
    DiskStorageManager,
>;

pub struct FFIDashSpvClient {
    pub(crate) inner: InnerClient,
    pub(crate) runtime: Arc<Runtime>,
    run_task: Mutex<Option<JoinHandle<()>>>,
}

impl FFIDashSpvClient {
    /// Returns the shared masternode list engine, if initialized.
    pub fn masternode_list_engine(
        &self,
    ) -> Option<Arc<tokio::sync::RwLock<dash_spv::MasternodeListEngine>>> {
        self.inner.masternode_list_engine().ok()
    }
}

/// Create a new SPV client and return an opaque pointer.
///
/// # Safety
/// - `config` must be a valid, non-null pointer for the duration of the call.
/// - `callbacks` is taken by value (function pointers and `user_data` pointers
///   are copied internally). The struct itself may be dropped after the call,
///   but all `user_data` pointer targets must remain valid until
///   `dash_spv_ffi_client_stop` or `dash_spv_ffi_client_destroy` is called.
/// - Callback functions and `user_data` pointees must be safe to use from
///   background threads; different callback groups may be invoked concurrently.
/// - The returned pointer must be freed with `dash_spv_ffi_client_destroy`.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_new(
    config: *const FFIClientConfig,
    callbacks: FFIEventCallbacks,
) -> *mut FFIDashSpvClient {
    null_check!(config, std::ptr::null_mut());

    let config = &(*config);
    // Build runtime with configurable worker threads (0 => auto)
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.thread_name("dash-spv-worker").enable_all();
    if config.worker_threads > 0 {
        builder.worker_threads(config.worker_threads as usize);
    }

    // Propagate the caller's tracing subscriber to worker threads so that
    // thread-local subscribers (used by tests for per-test log isolation)
    // capture logs from spawned async tasks.
    let dispatch = get_default(|d| d.clone());
    builder.on_thread_start(move || {
        let guard = set_default(&dispatch);
        forget(guard);
    });
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
        let wallet = key_wallet_manager::WalletManager::<
            key_wallet::wallet::managed_wallet_info::ManagedWalletInfo,
        >::new(client_config.network);
        let wallet = std::sync::Arc::new(tokio::sync::RwLock::new(wallet));

        match (network, storage) {
            (Ok(network), Ok(storage)) => {
                DashSpvClient::new(
                    client_config,
                    network,
                    storage,
                    wallet,
                    vec![Arc::new(callbacks)],
                )
                .await
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
                run_task: Mutex::new(None),
            };
            Box::into_raw(Box::new(ffi_client))
        }
        Err(e) => {
            set_last_error(&format!("Failed to create client: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Maximum time to wait for the run task to exit cooperatively before aborting.
const RUN_TASK_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl FFIDashSpvClient {
    /// Wait for the run task to finish cooperatively, aborting only on timeout.
    ///
    /// `DashSpvClient::stop()` must have been called first (it flips the client's
    /// internal running state, which makes `run()` exit its loop and clean up
    /// monitor tasks). This only falls back to `abort()` if the task doesn't
    /// exit within the timeout.
    fn wait_for_run_task(&self) {
        let task = self.run_task.lock().unwrap().take();
        if let Some(mut task) = task {
            let finished = self.runtime.block_on(async {
                tokio::time::timeout(RUN_TASK_SHUTDOWN_TIMEOUT, &mut task).await
            });
            match finished {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("Run task exited with join error: {}", e),
                Err(_) => {
                    tracing::warn!(
                        "Run task did not exit within {:?}, aborting",
                        RUN_TASK_SHUTDOWN_TIMEOUT,
                    );
                    task.abort();
                    let _ = self.runtime.block_on(task);
                }
            }
        }
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

    let result = client.runtime.block_on(async { client.inner.update_config(new_config).await });

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

    let client = &(*client);

    // `stop()` flips the client's internal running state, making `run()` break
    // out of its loop. Wait for the spawned run task only after that.
    let result = client.runtime.block_on(async { client.inner.stop().await });
    client.wait_for_run_task();

    match result {
        Ok(()) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&e.to_string());
            FFIErrorCode::from(e) as i32
        }
    }
}

/// Start the SPV client and begin syncing in the background.
///
/// Uses the event callbacks provided at client creation time. Returns
/// immediately after spawning the sync task.
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

    tracing::info!("dash_spv_ffi_client_run: starting sync");

    let spv_client = client.inner.clone();

    let task = client.runtime.spawn(async move {
        tracing::debug!("Sync task: starting run");

        if let Err(e) = spv_client.run().await {
            tracing::error!("Sync task: error: {}", e);
        }

        tracing::debug!("Sync task: exiting");
    });

    *client.run_task.lock().unwrap() = Some(task);

    tracing::info!("dash_spv_ffi_client_run: background task spawned, returning");

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
/// Use `dash_spv_ffi_sync_progress_destroy` to free the returned struct.
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

/// Broadcasts a transaction to the Dash network via connected peers.
///
/// # Safety
///
/// - `client` must be a valid, non-null pointer to an initialized FFIDashSpvClient
/// - `tx_bytes` must be a valid, non-null pointer to the transaction data
/// - `length` must be the length of the transaction data in bytes
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_broadcast_transaction(
    client: *mut FFIDashSpvClient,
    tx_bytes: *const u8,
    length: usize,
) -> i32 {
    null_check!(client);
    null_check!(tx_bytes);

    let tx_bytes = std::slice::from_raw_parts(tx_bytes, length);

    let tx = match dashcore::consensus::deserialize::<dashcore::Transaction>(tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("Invalid transaction: {}", e));
            return FFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);

    let spv_client = client.inner.clone();

    let result = client.runtime.block_on(async { spv_client.broadcast_transaction(&tx).await });

    match result {
        Ok(_) => FFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to broadcast transaction: {}", e));
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

        // Stop the SPV client (run() calls stop() internally, but this
        // handles the case where run() was never called or was aborted).
        client.runtime.block_on(async {
            let _ = client.inner.stop().await;
        });

        // Wait for the run task to finish (cooperative, with timeout fallback)
        client.wait_for_run_task();

        tracing::info!("FFI client destroyed and all tasks cleaned up");
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
