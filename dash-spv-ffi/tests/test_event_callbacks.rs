use dash_spv_ffi::callbacks::FFIEventCallbacks;
use dash_spv_ffi::*;
use serial_test::serial;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

// Test data tracking
struct TestEventData {
    block_received: AtomicBool,
    block_height: AtomicU32,
    transaction_received: AtomicBool,
    balance_updated: AtomicBool,
    confirmed_balance: AtomicU64,
    unconfirmed_balance: AtomicU64,
    compact_filter_matched: AtomicBool,
    compact_filter_block_hash: std::sync::Mutex<String>,
    compact_filter_scripts: std::sync::Mutex<String>,
    wallet_transaction_received: AtomicBool,
    wallet_transaction_wallet_id: std::sync::Mutex<String>,
    wallet_transaction_account_index: AtomicU32,
    wallet_transaction_txid: std::sync::Mutex<String>,
}

impl TestEventData {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            block_received: AtomicBool::new(false),
            block_height: AtomicU32::new(0),
            transaction_received: AtomicBool::new(false),
            balance_updated: AtomicBool::new(false),
            confirmed_balance: AtomicU64::new(0),
            unconfirmed_balance: AtomicU64::new(0),
            compact_filter_matched: AtomicBool::new(false),
            compact_filter_block_hash: std::sync::Mutex::new(String::new()),
            compact_filter_scripts: std::sync::Mutex::new(String::new()),
            wallet_transaction_received: AtomicBool::new(false),
            wallet_transaction_wallet_id: std::sync::Mutex::new(String::new()),
            wallet_transaction_account_index: AtomicU32::new(0),
            wallet_transaction_txid: std::sync::Mutex::new(String::new()),
        })
    }
}

extern "C" fn test_block_callback(height: u32, _hash: *const [u8; 32], user_data: *mut c_void) {
    println!("Test block callback called: height={}", height);
    let data = unsafe { &*(user_data as *const TestEventData) };
    data.block_received.store(true, Ordering::SeqCst);
    data.block_height.store(height, Ordering::SeqCst);
}

extern "C" fn test_transaction_callback(
    _txid: *const [u8; 32],
    _confirmed: bool,
    _amount: i64,
    _addresses: *const c_char,
    _block_height: u32,
    user_data: *mut c_void,
) {
    println!("Test transaction callback called");
    let data = unsafe { &*(user_data as *const TestEventData) };
    data.transaction_received.store(true, Ordering::SeqCst);
}

extern "C" fn test_compact_filter_matched_callback(
    block_hash: *const [u8; 32],
    matched_scripts: *const c_char,
    wallet_id: *const c_char,
    user_data: *mut c_void,
) {
    println!("Test compact filter matched callback called");
    let data = unsafe { &*(user_data as *const TestEventData) };

    // Convert block hash to hex string
    let hash_bytes = unsafe { &*block_hash };
    let hash_hex = hex::encode(hash_bytes);

    // Convert matched scripts to string
    let scripts_str = if matched_scripts.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(matched_scripts).to_string_lossy().into_owned() }
    };

    // Convert wallet ID to string
    let _wallet_id_str = if wallet_id.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(wallet_id).to_string_lossy().into_owned() }
    };

    *data.compact_filter_block_hash.lock().unwrap() = hash_hex;
    *data.compact_filter_scripts.lock().unwrap() = scripts_str;
    data.compact_filter_matched.store(true, Ordering::SeqCst);
}

extern "C" fn test_wallet_transaction_callback(
    wallet_id: *const c_char,
    account_index: u32,
    txid: *const [u8; 32],
    confirmed: bool,
    amount: i64,
    _addresses: *const c_char,
    _block_height: u32,
    is_ours: bool,
    user_data: *mut c_void,
) {
    println!("Test wallet transaction callback called: wallet={}, account={}, confirmed={}, amount={}, is_ours={}",
             unsafe { CStr::from_ptr(wallet_id).to_string_lossy() }, account_index, confirmed, amount, is_ours);
    let data = unsafe { &*(user_data as *const TestEventData) };

    // Convert wallet ID to string
    let wallet_id_str = unsafe { CStr::from_ptr(wallet_id).to_string_lossy().into_owned() };

    // Convert txid to hex string
    let txid_bytes = unsafe { &*txid };
    let txid_hex = hex::encode(txid_bytes);

    *data.wallet_transaction_wallet_id.lock().unwrap() = wallet_id_str;
    data.wallet_transaction_account_index.store(account_index, Ordering::SeqCst);
    *data.wallet_transaction_txid.lock().unwrap() = txid_hex;
    data.wallet_transaction_received.store(true, Ordering::SeqCst);
}

extern "C" fn test_balance_callback(confirmed: u64, unconfirmed: u64, user_data: *mut c_void) {
    println!("Test balance callback called: confirmed={}, unconfirmed={}", confirmed, unconfirmed);
    let data = unsafe { &*(user_data as *const TestEventData) };
    data.balance_updated.store(true, Ordering::SeqCst);
    data.confirmed_balance.store(confirmed, Ordering::SeqCst);
    data.unconfirmed_balance.store(unconfirmed, Ordering::SeqCst);
}

#[test]
fn test_event_callbacks_setup() {
    // Initialize logging
    unsafe {
        dash_spv_ffi_init_logging(c"debug".as_ptr(), true, std::ptr::null(), 0);
    }

    // Create test data
    let test_data = TestEventData::new();
    let user_data = Arc::as_ptr(&test_data) as *mut c_void;

    // Create temp directory for test data
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        // Create config
        let builder = dash_spv_ffi_config_builder_testnet();
        assert!(!builder.is_null());

        // Set data directory to temp directory
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        dash_spv_ffi_config_builder_set_storage_path(builder, path.as_ptr());

        // Set validation mode to basic for faster testing
        dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::Basic);

        let config = dash_spv_ffi_config_builder_build(builder);

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Set event callbacks before starting
        let callbacks = FFIEventCallbacks {
            on_block: Some(test_block_callback),
            on_transaction: Some(test_transaction_callback),
            on_balance_update: Some(test_balance_callback),
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_compact_filter_matched: None,
            on_wallet_transaction: None,
            user_data,
        };

        let result = dash_spv_ffi_client_set_event_callbacks(client, callbacks);
        assert_eq!(result, 0, "Failed to set event callbacks");

        // Start client
        let start_result = dash_spv_ffi_client_start(client);
        assert_eq!(start_result, 0, "Failed to start client");

        println!("Client started, waiting for events...");

        // Wait a bit for events to be processed
        thread::sleep(Duration::from_secs(5));

        // Check if we received any events
        if test_data.block_received.load(Ordering::SeqCst) {
            let height = test_data.block_height.load(Ordering::SeqCst);
            println!("✅ Block event received! Height: {}", height);
        } else {
            println!("⚠️ No block events received");
        }

        if test_data.transaction_received.load(Ordering::SeqCst) {
            println!("✅ Transaction event received!");
        } else {
            println!("⚠️ No transaction events received");
        }

        if test_data.balance_updated.load(Ordering::SeqCst) {
            let confirmed = test_data.confirmed_balance.load(Ordering::SeqCst);
            let unconfirmed = test_data.unconfirmed_balance.load(Ordering::SeqCst);
            println!(
                "✅ Balance event received! Confirmed: {}, Unconfirmed: {}",
                confirmed, unconfirmed
            );
        } else {
            println!("⚠️ No balance events received");
        }

        // Stop and cleanup
        let stop_result = dash_spv_ffi_client_stop(client);
        assert_eq!(stop_result, 0, "Failed to stop client");

        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }

    // The test passes if we set up callbacks successfully
    // Events may or may not fire depending on network conditions
    println!("Test completed - callbacks were set up successfully");
}

#[test]
#[serial]
fn test_enhanced_event_callbacks() {
    unsafe {
        dash_spv_ffi_init_logging(c"info".as_ptr(), true, std::ptr::null(), 0);

        // Create test data
        let event_data = TestEventData::new();

        // Create config
        let builder = dash_spv_ffi_config_builder_regtest();
        assert!(!builder.is_null());

        // Set data directory
        let temp_dir = TempDir::new().unwrap();
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        dash_spv_ffi_config_builder_set_storage_path(builder, path.as_ptr());
        dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::None);

        let config = dash_spv_ffi_config_builder_build(builder);

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Set up enhanced event callbacks
        let event_callbacks = FFIEventCallbacks {
            on_block: Some(test_block_callback),
            on_transaction: Some(test_transaction_callback),
            on_balance_update: Some(test_balance_callback),
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_compact_filter_matched: Some(test_compact_filter_matched_callback),
            on_wallet_transaction: Some(test_wallet_transaction_callback),
            user_data: Arc::as_ptr(&event_data) as *mut c_void,
        };

        let set_result = dash_spv_ffi_client_set_event_callbacks(client, event_callbacks);
        assert_eq!(
            set_result,
            FFIErrorCode::Success as i32,
            "Failed to set enhanced event callbacks"
        );

        // Note: Wallet-specific tests have been moved to key-wallet-ffi
        // The wallet functionality is no longer part of dash-spv-ffi
        // dash-spv-ffi now focuses purely on SPV network operations
        println!("⚠️ Wallet tests have been moved to key-wallet-ffi");

        // Clean up
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);

        println!("✅ Enhanced event callbacks test completed successfully");
    }
}

#[test]
#[serial]
fn test_drain_events_integration() {
    unsafe {
        println!("Testing drain_events integration with event callbacks...");

        let event_data = TestEventData::new();

        // Create config
        let builder = dash_spv_ffi_config_builder_regtest();
        assert!(!builder.is_null());

        // Set data directory
        let temp_dir = TempDir::new().unwrap();
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        dash_spv_ffi_config_builder_set_storage_path(builder, path.as_ptr());
        dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::None);

        let config = dash_spv_ffi_config_builder_build(builder);

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Set up all event callbacks using the unified API
        let user_data = Arc::as_ptr(&event_data) as *mut c_void;
        let callbacks = FFIEventCallbacks {
            on_balance_update: Some(test_balance_callback),
            on_transaction: Some(test_transaction_callback),
            on_block: Some(test_block_callback),
            on_compact_filter_matched: Some(test_compact_filter_matched_callback),
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_wallet_transaction: None,
            user_data,
        };
        dash_spv_ffi_client_set_event_callbacks(client, callbacks);

        // Test drain_events with no pending events
        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Verify no events were processed (callbacks not called)
        assert!(!event_data.block_received.load(Ordering::SeqCst));
        assert!(!event_data.transaction_received.load(Ordering::SeqCst));
        assert!(!event_data.balance_updated.load(Ordering::SeqCst));
        assert!(!event_data.compact_filter_matched.load(Ordering::SeqCst));

        // Test multiple drain calls
        for _ in 0..10 {
            let result = dash_spv_ffi_client_drain_events(client);
            assert_eq!(result, FFIErrorCode::Success as i32);
        }

        // State should remain unchanged
        assert!(!event_data.block_received.load(Ordering::SeqCst));
        assert!(!event_data.transaction_received.load(Ordering::SeqCst));
        assert!(!event_data.balance_updated.load(Ordering::SeqCst));

        // Clean up
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);

        println!("✅ drain_events integration test completed successfully");
    }
}

#[test]
#[serial]
fn test_drain_events_concurrent_with_callbacks() {
    unsafe {
        println!("Testing drain_events concurrent access with callback setup...");

        let event_data = TestEventData::new();

        // Create config and client
        let builder = dash_spv_ffi_config_builder_regtest();
        assert!(!builder.is_null());

        let temp_dir = TempDir::new().unwrap();
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        dash_spv_ffi_config_builder_set_storage_path(builder, path.as_ptr());
        dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::None);

        let config = dash_spv_ffi_config_builder_build(builder);

        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Set up callbacks while draining events concurrently
        let user_data = Arc::as_ptr(&event_data) as *mut c_void;

        // Set up callbacks and drain events
        let callbacks = FFIEventCallbacks {
            on_balance_update: Some(test_balance_callback),
            on_transaction: Some(test_transaction_callback),
            on_block: Some(test_block_callback),
            on_compact_filter_matched: None,
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_wallet_transaction: None,
            user_data,
        };
        dash_spv_ffi_client_set_event_callbacks(client, callbacks);

        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Test concurrent draining from multiple threads
        let client_ptr = client as usize;
        let handles: Vec<_> = (0..3)
            .map(|thread_id| {
                thread::spawn(move || {
                    let client = client_ptr as *mut FFIDashSpvClient;
                    for i in 0..20 {
                        let result = dash_spv_ffi_client_drain_events(client);
                        assert_eq!(result, FFIErrorCode::Success as i32);

                        // Small delay to allow interleaving
                        if i % 5 == 0 {
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                    println!("Thread {} completed drain operations", thread_id);
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Final drain to ensure everything is cleaned up
        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Clean up
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);

        println!("✅ Concurrent drain_events test completed successfully");
    }
}

#[test]
#[serial]
fn test_drain_events_callback_lifecycle() {
    unsafe {
        println!("Testing drain_events through callback lifecycle...");

        let event_data = TestEventData::new();

        let builder = dash_spv_ffi_config_builder_regtest();
        assert!(!builder.is_null());

        let temp_dir = TempDir::new().unwrap();
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        dash_spv_ffi_config_builder_set_storage_path(builder, path.as_ptr());
        dash_spv_ffi_config_builder_set_validation_mode(builder, FFIValidationMode::None);

        let config = dash_spv_ffi_config_builder_build(builder);

        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        let user_data = Arc::as_ptr(&event_data) as *mut c_void;

        // Phase 1: No callbacks set - should work fine
        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Phase 2: Set some callbacks
        let callbacks = FFIEventCallbacks {
            on_balance_update: Some(test_balance_callback),
            on_transaction: Some(test_transaction_callback),
            on_block: None,
            on_compact_filter_matched: None,
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_wallet_transaction: None,
            user_data,
        };
        dash_spv_ffi_client_set_event_callbacks(client, callbacks);

        // Drain with callbacks set
        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Phase 3: Clear callbacks by setting to None
        let callbacks = FFIEventCallbacks {
            on_balance_update: None,
            on_transaction: None,
            on_block: None,
            on_compact_filter_matched: None,
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_wallet_transaction: None,
            user_data: std::ptr::null_mut(),
        };
        dash_spv_ffi_client_set_event_callbacks(client, callbacks);

        // Drain with cleared callbacks
        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Phase 4: Re-set callbacks with different functions
        let callbacks = FFIEventCallbacks {
            on_balance_update: None,
            on_transaction: None,
            on_block: Some(test_block_callback),
            on_compact_filter_matched: None,
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_wallet_transaction: None,
            user_data,
        };
        dash_spv_ffi_client_set_event_callbacks(client, callbacks);

        // Final drain
        let result = dash_spv_ffi_client_drain_events(client);
        assert_eq!(result, FFIErrorCode::Success as i32);

        // Verify no unexpected events were triggered
        assert!(!event_data.balance_updated.load(Ordering::SeqCst));
        assert!(!event_data.transaction_received.load(Ordering::SeqCst));
        assert!(!event_data.block_received.load(Ordering::SeqCst));

        // Clean up
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);

        println!("✅ Callback lifecycle drain_events test completed successfully");
    }
}
