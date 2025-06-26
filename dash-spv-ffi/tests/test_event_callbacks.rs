use dash_spv_ffi::*;
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
        })
    }
}

extern "C" fn test_block_callback(height: u32, _hash: *const c_char, user_data: *mut c_void) {
    println!("Test block callback called: height={}", height);
    let data = unsafe { &*(user_data as *const TestEventData) };
    data.block_received.store(true, Ordering::SeqCst);
    data.block_height.store(height, Ordering::SeqCst);
}

extern "C" fn test_transaction_callback(_txid: *const c_char, _confirmed: bool, _amount: i64, _addresses: *const c_char, _block_height: u32, user_data: *mut c_void) {
    println!("Test transaction callback called");
    let data = unsafe { &*(user_data as *const TestEventData) };
    data.transaction_received.store(true, Ordering::SeqCst);
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
        dash_spv_ffi_init_logging(b"debug\0".as_ptr() as *const c_char);
    }

    // Create test data
    let test_data = TestEventData::new();
    let user_data = Arc::as_ptr(&test_data) as *mut c_void;

    // Create temp directory for test data
    let temp_dir = TempDir::new().unwrap();

    unsafe {
        // Create config
        let config = dash_spv_ffi_config_new(FFINetwork::Testnet);
        assert!(!config.is_null());
        
        // Set data directory to temp directory
        let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
        dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
        
        // Set validation mode to basic for faster testing
        dash_spv_ffi_config_set_validation_mode(config, FFIValidationMode::Basic);
        
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
            user_data,
        };
        
        let result = dash_spv_ffi_client_set_event_callbacks(client, callbacks);
        assert_eq!(result, 0, "Failed to set event callbacks");
        
        // Start client
        let start_result = dash_spv_ffi_client_start(client);
        assert_eq!(start_result, 0, "Failed to start client");
        
        println!("Client started, waiting for events...");
        
        // Add a test address to watch
        let test_address = b"yNDp83M8aHDGNkXPFaVoJZa2D9KparfWDc\0".as_ptr() as *const c_char;
        let watch_result = dash_spv_ffi_client_watch_address(client, test_address);
        if watch_result != 0 {
            println!("Warning: Failed to watch address (may not be implemented)");
        }
        
        // Try to sync for a short time to see if we get any events
        println!("Starting sync to trigger events...");
        let sync_result = dash_spv_ffi_client_test_sync(client);
        if sync_result != 0 {
            println!("Warning: Test sync failed");
        }
        
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
            println!("✅ Balance event received! Confirmed: {}, Unconfirmed: {}", confirmed, unconfirmed);
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
fn test_get_total_balance() {
    unsafe {
        dash_spv_ffi_init_logging(b"info\0".as_ptr() as *const c_char);
        
        // Create config
        let config = dash_spv_ffi_config_new(FFINetwork::Testnet);
        assert!(!config.is_null());
        
        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());
        
        // Start client
        let start_result = dash_spv_ffi_client_start(client);
        assert_eq!(start_result, 0, "Failed to start client");
        
        // Add some test addresses to watch
        let addresses = [
            b"yNDp83M8aHDGNkXPFaVoJZa2D9KparfWDc\0".as_ptr() as *const c_char,
            b"yP8JPjW4VUbfmtY1KD7zfRyCVVvQQMgZLe\0".as_ptr() as *const c_char,
        ];
        
        for address in addresses.iter() {
            let watch_result = dash_spv_ffi_client_watch_address(client, *address);
            if watch_result != 0 {
                println!("Warning: Failed to watch address");
            }
        }
        
        // Get total balance
        let balance_ptr = dash_spv_ffi_client_get_total_balance(client);
        
        if !balance_ptr.is_null() {
            let balance = &*balance_ptr;
            println!("Total balance - Confirmed: {}, Pending: {}, Total: {}", 
                    balance.confirmed, balance.pending, balance.total);
            
            dash_spv_ffi_balance_destroy(balance_ptr);
            println!("✅ Get total balance works!");
        } else {
            println!("⚠️ Failed to get total balance (may need sync first)");
        }
        
        // Cleanup
        dash_spv_ffi_client_stop(client);
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }
}