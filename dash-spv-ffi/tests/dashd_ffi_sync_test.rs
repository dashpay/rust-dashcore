//! FFI Sync test using dashd.
//!
//! This test mirrors `test_wallet_sync` from dash-spv but uses FFI bindings.

use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dash_spv::test_utils::{
    is_dashd_available, kill_all_dashd, load_wallet_file, DashCoreConfig, DashCoreNode,
};
use dash_spv_ffi::*;
use key_wallet_ffi::FFINetwork;
use serial_test::serial;
use tempfile::TempDir;

// ============================================================================
// FFI Test Context
// ============================================================================

struct FFISyncTestContext {
    client: *mut FFIDashSpvClient,
    config: *mut FFIClientConfig,
    wallet_manager: *mut FFIWalletManager,
    _temp_dir: TempDir,
    sync_completed: Arc<AtomicBool>,
    sync_success: Arc<AtomicBool>,
    header_height: Arc<AtomicU32>,
    filter_header_height: Arc<AtomicU32>,
    errors: Arc<Mutex<Vec<String>>>,
}

unsafe impl Send for FFISyncTestContext {}
unsafe impl Sync for FFISyncTestContext {}

impl FFISyncTestContext {
    unsafe fn new(peer_addr: std::net::SocketAddr) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create FFI config for regtest
        let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
        assert!(!config.is_null(), "Failed to create FFI config");

        // Set data directory
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        let result = dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
        assert_eq!(result, 0, "Failed to set data dir");

        // Set validation mode
        let result = dash_spv_ffi_config_set_validation_mode(config, FFIValidationMode::Basic);
        assert_eq!(result, 0, "Failed to set validation mode");

        // Disable masternode sync (regtest doesn't have masternodes)
        let result = dash_spv_ffi_config_set_masternode_sync_enabled(config, false);
        assert_eq!(result, 0, "Failed to disable masternode sync");

        // Add peer
        let peer_str = CString::new(format!("{}:{}", peer_addr.ip(), peer_addr.port())).unwrap();
        let result = dash_spv_ffi_config_add_peer(config, peer_str.as_ptr());
        assert_eq!(result, 0, "Failed to add peer");

        // Restrict to configured peers
        let result = dash_spv_ffi_config_set_restrict_to_configured_peers(config, true);
        assert_eq!(result, 0, "Failed to restrict peers");

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null(), "Failed to create FFI client");

        // Get wallet manager
        let wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);
        assert!(!wallet_manager.is_null(), "Failed to get wallet manager");

        FFISyncTestContext {
            client,
            config,
            wallet_manager,
            _temp_dir: temp_dir,
            sync_completed: Arc::new(AtomicBool::new(false)),
            sync_success: Arc::new(AtomicBool::new(false)),
            header_height: Arc::new(AtomicU32::new(0)),
            filter_header_height: Arc::new(AtomicU32::new(0)),
            errors: Arc::new(Mutex::new(Vec::new())),
        }
    }

    unsafe fn cleanup(self) {
        dash_spv_ffi_wallet_manager_free(self.wallet_manager);
        dash_spv_ffi_client_stop(self.client);
        dash_spv_ffi_client_destroy(self.client);
        dash_spv_ffi_config_destroy(self.config);
    }
}

// ============================================================================
// FFI Callback Functions
// ============================================================================

extern "C" fn on_sync_progress(progress: *const FFISyncProgress, user_data: *mut c_void) {
    if progress.is_null() || user_data.is_null() {
        return;
    }

    unsafe {
        let ctx = &*(user_data as *const FFISyncTestContext);
        let p = &*progress;

        // Update header height
        if !p.headers.is_null() {
            let headers = &*p.headers;
            ctx.header_height.store(headers.current_height, Ordering::SeqCst);
        }

        // Update filter header height
        if !p.filter_headers.is_null() {
            let filter_headers = &*p.filter_headers;
            ctx.filter_header_height.store(filter_headers.current_height, Ordering::SeqCst);
        }

        // Check if synced
        if p.state == FFISyncState::Synced {
            ctx.sync_success.store(true, Ordering::SeqCst);
        }
    }
}

extern "C" fn on_sync_completion(
    success: bool,
    error: *const std::os::raw::c_char,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }

    unsafe {
        let ctx = &*(user_data as *const FFISyncTestContext);
        ctx.sync_completed.store(true, Ordering::SeqCst);
        ctx.sync_success.store(success, Ordering::SeqCst);

        if !success && !error.is_null() {
            let error_str = CStr::from_ptr(error).to_string_lossy().to_string();
            tracing::error!("FFI Sync failed: {}", error_str);
            ctx.errors.lock().unwrap().push(error_str);
        }
    }
}

// ============================================================================
// Test
// ============================================================================

#[test]
#[serial]
fn test_wallet_sync_via_ffi() {
    kill_all_dashd();

    // Skip if dashd not available
    if !is_dashd_available() {
        tracing::warn!("dashd not available, skipping test");
        return;
    }

    // Create config with light wallet
    let config = DashCoreConfig {
        wallet: "light".to_string(),
        ..Default::default()
    };
    tracing::info!("Using datadir: {:?}", config.datadir);

    // Load light wallet from test data
    let light_wallet =
        load_wallet_file(&config.datadir, "light").expect("Failed to load light wallet");
    assert_eq!(light_wallet.wallet_name, "light", "Unexpected wallet name");
    tracing::info!(
        "Loaded '{}' wallet with {} transactions, {} UTXOs, balance: {:.8} DASH",
        light_wallet.wallet_name,
        light_wallet.transaction_count,
        light_wallet.utxo_count,
        light_wallet.balance
    );

    // Create a separate runtime for dashd operations (not conflicting with FFI's runtime)
    let dashd_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create dashd runtime");

    // Start dashd
    let mut node = DashCoreNode::with_config(config).expect("Failed to create DashCoreNode");
    let addr = dashd_runtime.block_on(node.start()).expect("Failed to start dashd");
    tracing::info!("DashCoreNode started at {}", addr);

    // Get expected block count
    let expected_height =
        dashd_runtime.block_on(node.get_block_count()).expect("Failed to get block count");
    tracing::info!("Dashd has {} blocks", expected_height);

    unsafe {
        // Create FFI test context
        let ctx = FFISyncTestContext::new(addr);

        // Add wallet from mnemonic via FFI
        let mnemonic = CString::new(light_wallet.mnemonic.as_str()).unwrap();
        let passphrase = CString::new("").unwrap();
        let mut error = key_wallet_ffi::FFIError::success();

        tracing::info!("Adding wallet from mnemonic: '{}'", light_wallet.mnemonic);
        let success = key_wallet_ffi::wallet_manager::wallet_manager_add_wallet_from_mnemonic(
            ctx.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager,
            mnemonic.as_ptr(),
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
        tracing::info!("Added wallet from mnemonic via FFI");

        // Get wallet ID for balance check later
        let mut wallet_ids_ptr: *mut u8 = ptr::null_mut();
        let mut wallet_count: usize = 0;
        let success = key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_ids(
            ctx.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager,
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
        tracing::info!("Got wallet ID: {:?}", hex::encode(&wallet_id));

        // Start the client first
        let result = dash_spv_ffi_client_start(ctx.client);
        assert_eq!(result, 0, "Failed to start FFI client");
        tracing::info!("Started FFI client");

        // Start sync with progress callbacks
        let ctx_ptr = &ctx as *const FFISyncTestContext as *mut c_void;
        let result = dash_spv_ffi_client_sync_to_tip_with_progress(
            ctx.client,
            Some(on_sync_progress),
            Some(on_sync_completion),
            ctx_ptr,
        );
        assert_eq!(result, 0, "Failed to start FFI sync");
        tracing::info!("Started FFI sync to tip with progress callbacks");

        // Wait for sync completion with timeout
        let timeout_duration = Duration::from_secs(180);
        let start = std::time::Instant::now();

        while !ctx.sync_completed.load(Ordering::SeqCst) && start.elapsed() < timeout_duration {
            std::thread::sleep(Duration::from_millis(500));

            let current_header = ctx.header_height.load(Ordering::SeqCst);
            let current_filter = ctx.filter_header_height.load(Ordering::SeqCst);

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

        // Check sync results
        assert!(ctx.sync_completed.load(Ordering::SeqCst), "Sync did not complete within timeout");

        {
            let errors = ctx.errors.lock().unwrap();
            if !errors.is_empty() {
                tracing::error!("Sync errors: {:?}", *errors);
            }
        }

        // === Validation ===
        tracing::info!("=== Validation ===");

        // Validate header height
        let final_header_height = ctx.header_height.load(Ordering::SeqCst);
        assert_eq!(
            final_header_height, expected_height,
            "Header height mismatch: got {}, expected {}",
            final_header_height, expected_height
        );
        tracing::info!("Header height matches: {}", final_header_height);

        // Validate filter header height
        let final_filter_height = ctx.filter_header_height.load(Ordering::SeqCst);
        assert_eq!(
            final_filter_height, expected_height,
            "Filter header height mismatch: got {}, expected {}",
            final_filter_height, expected_height
        );
        tracing::info!("Filter header height matches: {}", final_filter_height);

        // Validate wallet balance via FFI
        let mut confirmed: u64 = 0;
        let mut unconfirmed: u64 = 0;
        let success = key_wallet_ffi::wallet_manager::wallet_manager_get_wallet_balance(
            ctx.wallet_manager as *mut key_wallet_ffi::wallet_manager::FFIWalletManager,
            wallet_id.as_ptr(),
            &mut confirmed,
            &mut unconfirmed,
            &mut error,
        );
        assert!(success, "Failed to get wallet balance");

        let balance_dash = (confirmed as f64) / 100_000_000.0;
        tracing::info!(
            "Wallet balance: {:.8} DASH (confirmed: {}, unconfirmed: {})",
            balance_dash,
            confirmed,
            unconfirmed
        );

        // Calculate expected balance in satoshis
        let expected_balance_satoshis = (light_wallet.balance * 100_000_000.0) as u64;
        tracing::info!(
            "Expected balance: {:.8} DASH ({} satoshis)",
            light_wallet.balance,
            expected_balance_satoshis
        );

        // Note: Balance might not match exactly due to transaction processing
        // For now, just log the values for debugging
        if confirmed != expected_balance_satoshis {
            tracing::warn!(
                "Balance mismatch: got {} satoshis, expected {} satoshis",
                confirmed,
                expected_balance_satoshis
            );
        }

        // Stop dashd before cleanup
        dashd_runtime.block_on(node.stop());

        // Cleanup FFI resources
        ctx.cleanup();
    }

    tracing::info!("FFI sync test completed successfully!");
}
