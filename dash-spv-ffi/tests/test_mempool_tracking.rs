use dash_spv_ffi::callbacks::{
    MempoolConfirmedCallback, MempoolRemovedCallback, MempoolTransactionCallback,
};
use dash_spv_ffi::*;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Default)]
struct TestCallbacks {
    mempool_added_count: Arc<Mutex<u32>>,
    mempool_confirmed_count: Arc<Mutex<u32>>,
    mempool_removed_count: Arc<Mutex<u32>>,
}

extern "C" fn test_mempool_added(
    _txid: *const [u8; 32],
    _amount: i64,
    _addresses: *const c_char,
    _is_instant_send: bool,
    user_data: *mut c_void,
) {
    let callbacks = unsafe { &*(user_data as *const TestCallbacks) };
    let mut count = callbacks.mempool_added_count.lock().unwrap();
    *count += 1;
}

extern "C" fn test_mempool_confirmed(
    _txid: *const [u8; 32],
    _block_height: u32,
    _block_hash: *const [u8; 32],
    user_data: *mut c_void,
) {
    let callbacks = unsafe { &*(user_data as *const TestCallbacks) };
    let mut count = callbacks.mempool_confirmed_count.lock().unwrap();
    *count += 1;
}

extern "C" fn test_mempool_removed(_txid: *const [u8; 32], _reason: u8, user_data: *mut c_void) {
    let callbacks = unsafe { &*(user_data as *const TestCallbacks) };
    let mut count = callbacks.mempool_removed_count.lock().unwrap();
    *count += 1;
}

#[test]
fn test_mempool_configuration() {
    unsafe {
        // Initialize logging
        let _ = dash_spv_ffi_init_logging(CString::new("info").unwrap().as_ptr());

        // Create configuration for testnet
        let config = dash_spv_ffi_config_testnet();
        assert!(!config.is_null());

        // Set data directory
        let data_dir = CString::new("/tmp/dash-spv-test-mempool").unwrap();
        let result = dash_spv_ffi_config_set_data_dir(config, data_dir.as_ptr());
        assert_eq!(result, 0);

        // Enable mempool tracking
        let result = dash_spv_ffi_config_set_mempool_tracking(config, true);
        assert_eq!(result, 0);

        // Set mempool strategy to FetchAll
        let result = dash_spv_ffi_config_set_mempool_strategy(config, FFIMempoolStrategy::FetchAll);
        assert_eq!(result, 0);

        // Set max mempool transactions
        let result = dash_spv_ffi_config_set_max_mempool_transactions(config, 1000);
        assert_eq!(result, 0);

        // Set mempool timeout
        let result = dash_spv_ffi_config_set_mempool_timeout(config, 3600);
        assert_eq!(result, 0);

        // Verify configuration
        assert!(dash_spv_ffi_config_get_mempool_tracking(config));
        assert_eq!(dash_spv_ffi_config_get_mempool_strategy(config), FFIMempoolStrategy::FetchAll);

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Clean up
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }
}

#[test]
fn test_mempool_event_callbacks() {
    unsafe {
        // Initialize logging
        let _ = dash_spv_ffi_init_logging(CString::new("info").unwrap().as_ptr());

        // Create configuration
        let config = dash_spv_ffi_config_testnet();
        assert!(!config.is_null());

        // Set data directory
        let data_dir = CString::new("/tmp/dash-spv-test-mempool-events").unwrap();
        dash_spv_ffi_config_set_data_dir(config, data_dir.as_ptr());

        // Enable mempool tracking
        dash_spv_ffi_config_set_mempool_tracking(config, true);
        dash_spv_ffi_config_set_mempool_strategy(config, FFIMempoolStrategy::FetchAll);

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Set up test callbacks
        let test_callbacks = Box::new(TestCallbacks::default());
        let test_callbacks_ptr = Box::into_raw(test_callbacks);

        let callbacks = FFIEventCallbacks {
            on_block: None,
            on_transaction: None,
            on_balance_update: None,
            on_mempool_transaction_added: Some(test_mempool_added),
            on_mempool_transaction_confirmed: Some(test_mempool_confirmed),
            on_mempool_transaction_removed: Some(test_mempool_removed),
            user_data: test_callbacks_ptr as *mut c_void,
        };

        let result = dash_spv_ffi_client_set_event_callbacks(client, callbacks);
        assert_eq!(result, 0);

        // Clean up
        let _ = Box::from_raw(test_callbacks_ptr);
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }
}

#[test]
fn test_mempool_balance_query() {
    unsafe {
        // Initialize logging
        let _ = dash_spv_ffi_init_logging(CString::new("info").unwrap().as_ptr());

        // Create configuration
        let config = dash_spv_ffi_config_testnet();
        assert!(!config.is_null());

        // Set data directory
        let data_dir = CString::new("/tmp/dash-spv-test-mempool-balance").unwrap();
        dash_spv_ffi_config_set_data_dir(config, data_dir.as_ptr());

        // Enable mempool tracking
        dash_spv_ffi_config_set_mempool_tracking(config, true);

        // Create client
        let client = dash_spv_ffi_client_new(config);
        assert!(!client.is_null());

        // Start client (would fail without network but tests structure)
        let result = dash_spv_ffi_client_start(client);
        // Allow failure since we're not connected to network
        if result == 0 {
            // Test mempool transaction count
            let count = dash_spv_ffi_client_get_mempool_transaction_count(client);
            assert!(count >= 0);

            // Test mempool balance for address
            let address = CString::new("yXdxAYfAkQnrFZNxdVfqwJMRpDcCuC6YLi").unwrap();
            let balance = dash_spv_ffi_client_get_mempool_balance(client, address.as_ptr());
            if !balance.is_null() {
                let balance_data = (*balance);
                assert_eq!(balance_data.confirmed, 0); // No confirmed balance in mempool
                                                       // mempool and mempool_instant fields contain the actual mempool balance
                dash_spv_ffi_balance_destroy(balance);
            }

            // Stop client
            let _ = dash_spv_ffi_client_stop(client);
        }

        // Clean up
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);
    }
}
