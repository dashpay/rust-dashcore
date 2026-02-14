//! FFI test context for integration tests.

use std::ffi::{CStr, CString};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::*;
use key_wallet_ffi::FFINetwork;
use tempfile::TempDir;

use super::callbacks::{create_minimal_sync_callbacks, CallbackTracker};

// ============================================================================
// FFI Test Context
// ============================================================================

/// Shared FFI test context used by both sync and callback tests.
pub struct FFITestContext {
    pub client: *mut FFIDashSpvClient,
    pub config: *mut FFIClientConfig,
    pub wallet_manager: *mut FFIWalletManager,
    pub _temp_dir: TempDir,
    pub tracker: Arc<CallbackTracker>,
}

// Safety: Raw FFI pointers are only accessed from the test thread that created them.
// The Send/Sync impls are needed because Arc<CallbackTracker> requires them, and
// tests are single-threaded with respect to FFI resource access.
unsafe impl Send for FFITestContext {}
unsafe impl Sync for FFITestContext {}

impl FFITestContext {
    /// Create a new FFI test context connected to the given peer.
    ///
    /// # Safety
    /// Calls FFI functions. Must be called in an unsafe block.
    pub unsafe fn new(peer_addr: std::net::SocketAddr) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
        assert!(!config.is_null(), "Failed to create FFI config");

        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        let result = dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
        assert_eq!(result, 0, "Failed to set data dir");

        let result = dash_spv_ffi_config_set_masternode_sync_enabled(config, false);
        assert_eq!(result, 0, "Failed to disable masternode sync");

        let peer_str = CString::new(format!("{}:{}", peer_addr.ip(), peer_addr.port())).unwrap();
        let result = dash_spv_ffi_config_add_peer(config, peer_str.as_ptr());
        assert_eq!(result, 0, "Failed to add peer");

        let result = dash_spv_ffi_config_set_restrict_to_configured_peers(config, true);
        assert_eq!(result, 0, "Failed to restrict peers");

        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null(), "Failed to create FFI client");

        let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
        assert!(!wallet_manager.is_null(), "Failed to get wallet manager");

        FFITestContext {
            client,
            config,
            wallet_manager,
            _temp_dir: temp_dir,
            tracker: Arc::new(CallbackTracker::default()),
        }
    }

    /// Add a wallet from mnemonic via FFI.
    ///
    /// # Safety
    /// Calls FFI functions.
    pub unsafe fn add_wallet(&self, mnemonic: &str) -> Vec<u8> {
        let mnemonic_c = CString::new(mnemonic).unwrap();
        let passphrase = CString::new("").unwrap();
        let mut error = key_wallet_ffi::FFIError::success();

        let success = key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic(
            self.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager,
            mnemonic_c.as_ptr(),
            passphrase.as_ptr(),
            &mut error,
        );
        if !success {
            let error_msg = if !error.message.is_null() {
                CStr::from_ptr(error.message).to_str().unwrap_or("Unknown error")
            } else {
                "No error message"
            };
            panic!("Failed to add wallet from mnemonic: code={:?}, msg={}", error.code, error_msg);
        }

        let mut wallet_ids_ptr: *mut u8 = std::ptr::null_mut();
        let mut wallet_count: usize = 0;
        let success = key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_ids(
            self.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager,
            &mut wallet_ids_ptr,
            &mut wallet_count,
            &mut error,
        );
        assert!(success && wallet_count > 0, "Failed to get wallet IDs");

        let wallet_id = std::slice::from_raw_parts(wallet_ids_ptr, 32).to_vec();
        key_wallet_ffi::wallet_manager::wallet_manager_free_wallet_ids(
            wallet_ids_ptr,
            wallet_count,
        );
        wallet_id
    }

    /// Get wallet balance via FFI. Returns (confirmed, unconfirmed).
    ///
    /// # Safety
    /// Calls FFI functions.
    pub unsafe fn get_wallet_balance(&self, wallet_id: &[u8]) -> (u64, u64) {
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        let mut error = key_wallet_ffi::FFIError::success();

        let success = key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_balance(
            self.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager,
            wallet_id.as_ptr(),
            &mut confirmed,
            &mut unconfirmed,
            &mut error,
        );
        assert!(success, "Failed to get wallet balance");
        (confirmed, unconfirmed)
    }

    /// Set up sync event callbacks and run the client.
    ///
    /// # Safety
    /// Calls FFI functions.
    pub unsafe fn run_with_sync_callbacks(&self) {
        let sync_callbacks = create_minimal_sync_callbacks(&self.tracker);
        let result = dash_spv_ffi_client_set_sync_event_callbacks(self.client, sync_callbacks);
        assert_eq!(result, 0, "Failed to set sync event callbacks");

        let result = dash_spv_ffi_client_run(self.client);
        assert_eq!(result, 0, "Failed to run FFI client");
    }

    /// Wait for sync completion, polling with the given timeout.
    pub fn wait_for_sync(&self, expected_height: u32, timeout_secs: u64) {
        let timeout_duration = Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();

        while !self.tracker.sync_completed.load(Ordering::SeqCst)
            && start.elapsed() < timeout_duration
        {
            std::thread::sleep(Duration::from_millis(500));

            let current_header = self.tracker.last_header_tip.load(Ordering::SeqCst);
            let current_filter = self.tracker.last_filter_tip.load(Ordering::SeqCst);

            if current_header > 0 {
                tracing::info!(
                    "Sync progress: headers={}/{}, filters={}/{}",
                    current_header,
                    expected_height,
                    current_filter,
                    expected_height
                );
            }
        }

        assert!(
            self.tracker.sync_completed.load(Ordering::SeqCst),
            "Sync did not complete within timeout"
        );
    }

    /// Get a receive address for the given wallet via FFI.
    ///
    /// # Safety
    /// Calls FFI functions.
    pub unsafe fn get_receive_address(&self, wallet_id: &[u8]) -> String {
        let mut error = key_wallet_ffi::FFIError::success();
        let wm = self.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager;

        let ffi_wallet = key_wallet_ffi::wallet_manager::wallet_manager_get_wallet(
            wm,
            wallet_id.as_ptr(),
            &mut error,
        );
        assert!(!ffi_wallet.is_null(), "Failed to get FFI wallet");

        let ffi_info = key_wallet_ffi::wallet_manager::wallet_manager_get_managed_wallet_info(
            wm,
            wallet_id.as_ptr(),
            &mut error,
        );
        assert!(!ffi_info.is_null(), "Failed to get FFI managed wallet info");

        let addr_ptr =
            key_wallet_ffi::managed_wallet::managed_wallet_get_next_bip44_receive_address(
                ffi_info, ffi_wallet, 0, &mut error,
            );
        assert!(!addr_ptr.is_null(), "Failed to get receive address");

        let address = CStr::from_ptr(addr_ptr).to_str().unwrap().to_string();
        key_wallet_ffi::wallet_manager::wallet_manager_free_string(addr_ptr);

        // Free FFI objects
        key_wallet_ffi::managed_wallet::managed_wallet_info_free(ffi_info);
        key_wallet_ffi::wallet::wallet_free_const(ffi_wallet);

        address
    }

    /// Wait for the next sync completion after the current count.
    ///
    /// Captures the current `sync_complete_count` and polls until it increments.
    /// Works for both initial and incremental syncs since the coordinator emits
    /// `SyncComplete` on every not-synced -> synced transition.
    pub fn wait_for_next_sync(&self, timeout_secs: u64) {
        let current_count = self.tracker.sync_complete_count.load(Ordering::SeqCst);
        let target = current_count + 1;
        let timeout_duration = Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();

        while self.tracker.sync_complete_count.load(Ordering::SeqCst) < target
            && start.elapsed() < timeout_duration
        {
            std::thread::sleep(Duration::from_millis(500));

            let header = self.tracker.last_header_tip.load(Ordering::SeqCst);
            let filter = self.tracker.last_filter_tip.load(Ordering::SeqCst);
            tracing::info!(
                "Waiting for next sync: headers={}, filters={}, sync_count={}/{}",
                header,
                filter,
                self.tracker.sync_complete_count.load(Ordering::SeqCst),
                target
            );
        }

        let count = self.tracker.sync_complete_count.load(Ordering::SeqCst);
        assert!(
            count >= target,
            "Sync complete count {} did not reach target {} within timeout",
            count,
            target
        );
    }

    /// Stop the client and recreate it with the same config and storage.
    ///
    /// Resets the tracker and returns the new context. The wallet must be
    /// re-added after calling this.
    ///
    /// # Safety
    /// Calls FFI functions.
    pub unsafe fn restart(self) -> Self {
        dash_spv_ffi_wallet_manager_free(self.wallet_manager);
        dash_spv_ffi_client_stop(self.client);
        dash_spv_ffi_client_destroy(self.client);

        // Recreate client from same config (same storage dir and peers)
        let client = dash_spv_ffi_client_new(self.config);
        assert!(!client.is_null(), "Failed to recreate FFI client");

        let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
        assert!(!wallet_manager.is_null(), "Failed to get wallet manager after restart");

        FFITestContext {
            client,
            config: self.config,
            wallet_manager,
            _temp_dir: self._temp_dir,
            tracker: Arc::new(CallbackTracker::default()),
        }
    }

    /// Clean up FFI resources.
    ///
    /// # Safety
    /// Calls FFI functions. Must be called exactly once.
    pub unsafe fn cleanup(self) {
        dash_spv_ffi_wallet_manager_free(self.wallet_manager);
        dash_spv_ffi_client_stop(self.client);
        dash_spv_ffi_client_destroy(self.client);
        dash_spv_ffi_config_destroy(self.config);
    }
}
