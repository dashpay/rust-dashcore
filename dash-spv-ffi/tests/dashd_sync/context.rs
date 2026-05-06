//! FFI test context for integration tests.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use super::callbacks::{
    create_network_callbacks, create_sync_callbacks, create_wallet_callbacks, CallbackTracker,
};
use dash_network::ffi::FFINetwork;
use dash_spv::logging::{LogFileConfig, LoggingConfig, LoggingGuard};
use dash_spv::test_utils::{retain_test_dir, SYNC_TIMEOUT};
use dash_spv_ffi::client::{
    dash_spv_ffi_client_destroy, dash_spv_ffi_client_get_wallet_manager, dash_spv_ffi_client_new,
    dash_spv_ffi_client_run, dash_spv_ffi_client_stop, dash_spv_ffi_wallet_manager_free,
    FFIDashSpvClient,
};
use dash_spv_ffi::config::{
    dash_spv_ffi_config_add_peer, dash_spv_ffi_config_destroy, dash_spv_ffi_config_new,
    dash_spv_ffi_config_set_data_dir, dash_spv_ffi_config_set_masternode_sync_enabled,
    dash_spv_ffi_config_set_restrict_to_configured_peers, FFIClientConfig,
};
use dash_spv_ffi::types::FFIWalletManager as FFIWalletManagerOpaque;
use dash_spv_ffi::FFIEventCallbacks;
use dashcore::hashes::Hash;
use dashcore::{Address, Txid};
use key_wallet_ffi::managed_account::{
    managed_core_account_free, managed_core_account_free_transactions,
    managed_core_account_get_transaction_count, managed_core_account_get_transactions,
    managed_wallet_get_account, FFIManagedCoreAccount, FFITransactionRecord,
};
use key_wallet_ffi::managed_wallet::{
    managed_wallet_get_next_bip44_receive_address, managed_wallet_info_free,
};
use key_wallet_ffi::types::FFIAccountKind;
use key_wallet_ffi::wallet::wallet_free_const;
use key_wallet_ffi::wallet_manager::{
    wallet_manager_add_wallet_from_mnemonic, wallet_manager_get_managed_wallet_info,
};
use key_wallet_ffi::{
    wallet_manager_free_string, wallet_manager_free_wallet_ids, wallet_manager_get_wallet,
    wallet_manager_get_wallet_balance, wallet_manager_get_wallet_ids, FFIError, FFIWalletManager,
};
use tempfile::TempDir;

/// State that stays fixed across client restarts (temp dir, logging, config).
struct FixedState {
    _temp_dir: TempDir,
    _log_guard: LoggingGuard,
    storage_dir: PathBuf,
    config: *mut FFIClientConfig,
}

impl Drop for FixedState {
    fn drop(&mut self) {
        retain_test_dir(&self.storage_dir, "spv");
        unsafe {
            dash_spv_ffi_config_destroy(self.config);
        }
    }
}

/// Per-session FFI state (client, wallet_manager, tracker). Recreated on restart.
struct SessionState {
    client: *mut FFIDashSpvClient,
    wallet_manager: *mut FFIWalletManagerOpaque,
    tracker: Arc<CallbackTracker>,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        unsafe {
            dash_spv_ffi_client_stop(self.client);
            dash_spv_ffi_wallet_manager_free(self.wallet_manager);
            dash_spv_ffi_client_destroy(self.client);
        }
    }
}

/// Shared FFI test context.
///
/// Split into `FixedState` (stays fixed across restarts) and `SessionState`
/// (recreated on restart).
pub(super) struct FFITestContext {
    fixed: FixedState,
    session: SessionState,
}

impl FFITestContext {
    /// Create a new FFI test context connected to the given peer.
    ///
    /// # Safety
    ///
    /// Calls FFI functions that allocate and configure opaque pointers.
    pub(super) unsafe fn new(peer_addr: std::net::SocketAddr) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage_dir = temp_dir.path().to_path_buf();
        let log_dir = storage_dir.join("logs");

        let log_guard = dash_spv::init_logging(LoggingConfig {
            level: Some(dash_spv::LevelFilter::DEBUG),
            console: std::env::var("DASHD_TEST_LOG").is_ok(),
            file: Some(LogFileConfig {
                log_dir,
                max_files: 1,
            }),
            thread_local: true,
        })
        .expect("Failed to initialize test logging");

        let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
        assert!(!config.is_null(), "Failed to create FFI config");

        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        let result = dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
        assert_eq!(result, 0, "Failed to set data dir");

        let result = dash_spv_ffi_config_set_masternode_sync_enabled(config, false);
        assert_eq!(result, 0, "Failed to disable masternode sync");

        let peer_str = CString::new(peer_addr.to_string()).unwrap();
        let result = dash_spv_ffi_config_add_peer(config, peer_str.as_ptr());
        assert_eq!(result, 0, "Failed to add peer");

        let result = dash_spv_ffi_config_set_restrict_to_configured_peers(config, true);
        assert_eq!(result, 0, "Failed to restrict peers");

        let tracker = Arc::new(CallbackTracker::default());
        let callbacks = FFIEventCallbacks {
            sync: create_sync_callbacks(&tracker),
            network: create_network_callbacks(&tracker),
            wallet: create_wallet_callbacks(&tracker),
            ..FFIEventCallbacks::default()
        };

        let client = dash_spv_ffi_client_new(config, callbacks);
        assert!(!client.is_null(), "Failed to create FFI client");

        let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
        assert!(!wallet_manager.is_null(), "Failed to get wallet manager");

        FFITestContext {
            fixed: FixedState {
                _temp_dir: temp_dir,
                _log_guard: log_guard,
                storage_dir,
                config,
            },
            session: SessionState {
                client,
                wallet_manager,
                tracker,
            },
        }
    }

    /// The callback tracker.
    pub(super) fn tracker(&self) -> &Arc<CallbackTracker> {
        &self.session.tracker
    }

    /// Add a wallet from mnemonic via FFI.
    ///
    /// # Safety
    ///
    /// Calls FFI wallet functions through raw pointers held by the context.
    pub(super) unsafe fn add_wallet(&self, mnemonic: &str) -> Vec<u8> {
        let mnemonic_c = CString::new(mnemonic).unwrap();
        let passphrase = CString::new("").unwrap();
        let mut error = FFIError::default();
        let wm = self.session.wallet_manager as *mut FFIWalletManager;

        let success = wallet_manager_add_wallet_from_mnemonic(
            wm,
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
        let success =
            wallet_manager_get_wallet_ids(wm, &mut wallet_ids_ptr, &mut wallet_count, &mut error);
        assert!(success && wallet_count > 0, "Failed to get wallet IDs");

        let wallet_id = std::slice::from_raw_parts(wallet_ids_ptr, 32).to_vec();
        wallet_manager_free_wallet_ids(wallet_ids_ptr, wallet_count);
        wallet_id
    }

    /// Get wallet balance via FFI. Returns (confirmed, unconfirmed).
    ///
    /// # Safety
    ///
    /// Calls FFI wallet functions through raw pointers held by the context.
    pub(super) unsafe fn get_wallet_balance(&self, wallet_id: &[u8]) -> (u64, u64) {
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        let mut error = FFIError::default();
        let wm = self.session.wallet_manager as *mut FFIWalletManager;

        let success = wallet_manager_get_wallet_balance(
            wm,
            wallet_id.as_ptr(),
            &mut confirmed,
            &mut unconfirmed,
            &mut error,
        );
        assert!(success, "Failed to get wallet balance");
        (confirmed, unconfirmed)
    }

    /// Run the client (callbacks were registered at creation time).
    ///
    /// # Safety
    ///
    /// Calls FFI client functions through raw pointers held by the context.
    pub(super) unsafe fn run(&self) {
        self.snapshot_sync_baseline();
        let result = dash_spv_ffi_client_run(self.session.client);
        assert_eq!(result, 0, "Failed to run FFI client");
    }

    /// Captures the current `sync_complete_count` as the baseline for the next
    /// `wait_for_sync` call. Called automatically by the `run_*` methods before
    /// starting the client, and by `wait_for_sync` after each successful wait.
    fn snapshot_sync_baseline(&self) {
        let current = self.session.tracker.sync_complete_count.load(Ordering::SeqCst);
        self.session.tracker.sync_count_baseline.store(current, Ordering::SeqCst);
    }

    /// Polls until a new `SyncComplete` event fires with both header and filter
    /// tips at or above `expected_height`.
    pub(super) fn wait_for_sync(&self, expected_height: u32) {
        let baseline = self.session.tracker.sync_count_baseline.load(Ordering::SeqCst);
        let start = std::time::Instant::now();

        loop {
            let sync_fired =
                self.session.tracker.sync_complete_count.load(Ordering::SeqCst) > baseline;
            let current_header = self.session.tracker.last_header_tip.load(Ordering::SeqCst);
            let current_filter = self.session.tracker.last_filter_tip.load(Ordering::SeqCst);

            if sync_fired && current_header >= expected_height && current_filter >= expected_height
            {
                self.snapshot_sync_baseline();
                break;
            }

            assert!(
                start.elapsed() < SYNC_TIMEOUT,
                "Sync did not complete within {:?} (headers={}/{}, filters={}/{})",
                SYNC_TIMEOUT,
                current_header,
                expected_height,
                current_filter,
                expected_height,
            );

            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Get a receive address for the given wallet via FFI.
    ///
    /// # Safety
    ///
    /// Calls FFI wallet functions through raw pointers held by the context.
    pub(super) unsafe fn get_receive_address(&self, wallet_id: &[u8]) -> Address {
        let mut error = FFIError::default();
        let wm = self.session.wallet_manager as *mut FFIWalletManager;

        let ffi_wallet = wallet_manager_get_wallet(wm, wallet_id.as_ptr(), &mut error);
        assert!(!ffi_wallet.is_null(), "Failed to get FFI wallet");

        let ffi_info = wallet_manager_get_managed_wallet_info(wm, wallet_id.as_ptr(), &mut error);
        assert!(!ffi_info.is_null(), "Failed to get FFI managed wallet info");

        let addr_ptr =
            managed_wallet_get_next_bip44_receive_address(ffi_info, ffi_wallet, 0, &mut error);
        assert!(!addr_ptr.is_null(), "Failed to get receive address");

        let addr_str = CStr::from_ptr(addr_ptr).to_str().unwrap();
        let address = addr_str.parse::<Address<_>>().unwrap().assume_checked();
        wallet_manager_free_string(addr_ptr);

        managed_wallet_info_free(ffi_info);
        wallet_free_const(ffi_wallet);

        address
    }

    /// Get the BIP44 account 0 for a wallet, call the provided closure, then free the account.
    ///
    /// # Safety
    ///
    /// Calls FFI managed account functions through raw pointers.
    unsafe fn with_bip44_account<T>(
        &self,
        wallet_id: &[u8],
        f: impl FnOnce(*const FFIManagedCoreAccount) -> T,
    ) -> T {
        let wm = self.session.wallet_manager as *const FFIWalletManager;
        let result =
            managed_wallet_get_account(wm, wallet_id.as_ptr(), 0, FFIAccountKind::StandardBIP44);
        assert!(
            result.error_code == 0 && !result.account.is_null(),
            "Failed to get BIP44 account 0"
        );
        let value = f(result.account);
        managed_core_account_free(result.account);
        value
    }

    /// Get the number of transactions in the BIP44 account 0 for a wallet.
    ///
    /// # Safety
    ///
    /// Calls FFI managed account functions through raw pointers.
    pub(super) unsafe fn transaction_count(&self, wallet_id: &[u8]) -> usize {
        self.with_bip44_account(wallet_id, |account| {
            managed_core_account_get_transaction_count(account) as usize
        })
    }

    /// Check whether the BIP44 account 0 contains a specific transaction.
    ///
    /// # Safety
    ///
    /// Calls FFI managed account functions through raw pointers.
    pub(super) unsafe fn has_transaction(&self, wallet_id: &[u8], txid: &Txid) -> bool {
        self.with_bip44_account(wallet_id, |account| {
            let mut txs_ptr: *mut FFITransactionRecord = std::ptr::null_mut();
            let mut count: usize = 0;
            let ok = managed_core_account_get_transactions(account, &mut txs_ptr, &mut count);
            assert!(ok, "Failed to get transactions");

            let found = if count > 0 && !txs_ptr.is_null() {
                let txs = std::slice::from_raw_parts(txs_ptr, count);
                let target = txid.to_byte_array();
                txs.iter().any(|t| t.txid == target)
            } else {
                false
            };

            managed_core_account_free_transactions(txs_ptr, count);
            found
        })
    }

    /// Collect all transaction IDs from BIP44 account 0 as hex strings (display order).
    ///
    /// # Safety
    ///
    /// Calls FFI managed account functions through raw pointers.
    pub(super) unsafe fn wallet_txids(&self, wallet_id: &[u8]) -> HashSet<String> {
        self.with_bip44_account(wallet_id, |account| {
            let mut txs_ptr: *mut FFITransactionRecord = std::ptr::null_mut();
            let mut count: usize = 0;
            let ok = managed_core_account_get_transactions(account, &mut txs_ptr, &mut count);
            assert!(ok, "Failed to get transactions");

            let mut txids = HashSet::new();
            if count > 0 && !txs_ptr.is_null() {
                let txs = std::slice::from_raw_parts(txs_ptr, count);
                for t in txs {
                    // Reverse bytes for display order (internal is little-endian)
                    let txid = Txid::from_byte_array(t.txid);
                    txids.insert(txid.to_string());
                }
            }

            managed_core_account_free_transactions(txs_ptr, count);
            txids
        })
    }

    /// Stop the client and recreate it with the same config and storage.
    ///
    /// Resets the tracker and returns the new context. The wallet must be
    /// re-added after calling this.
    ///
    /// # Safety
    ///
    /// Calls FFI client functions through raw pointers held by the context.
    pub(super) unsafe fn restart(self) -> Self {
        let fixed = self.fixed;
        // Drop the session (stops client, frees wallet manager, destroys client)
        drop(self.session);

        // Recreate client from same config (same storage dir and peers)
        let tracker = Arc::new(CallbackTracker::default());
        let callbacks = FFIEventCallbacks {
            sync: create_sync_callbacks(&tracker),
            network: create_network_callbacks(&tracker),
            wallet: create_wallet_callbacks(&tracker),
            ..FFIEventCallbacks::default()
        };

        let client = dash_spv_ffi_client_new(fixed.config, callbacks);
        assert!(!client.is_null(), "Failed to recreate FFI client");

        let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
        assert!(!wallet_manager.is_null(), "Failed to get wallet manager after restart");

        FFITestContext {
            fixed,
            session: SessionState {
                client,
                wallet_manager,
                tracker,
            },
        }
    }
}
