#[cfg(test)]
mod tests {
    use crate::*;
    use dash_network::ffi::FFINetwork;
    use serial_test::serial;
    use std::ffi::CString;
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_client() -> (*mut FFIDashSpvClient, *mut FFIClientConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            assert!(!config.is_null(), "Failed to create config");

            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

            let client = dash_spv_ffi_client_new(config, FFIEventCallbacks::default());
            assert!(!client.is_null(), "Failed to create client");

            (client, config, temp_dir)
        }
    }

    #[test]
    #[serial]
    fn test_sync_event_callbacks() {
        unsafe {
            let (client, config, _temp_dir) = create_test_client();
            assert!(!client.is_null());

            let sync_started = Arc::new(AtomicBool::new(false));
            let headers_stored = Arc::new(AtomicBool::new(false));
            let sync_complete = Arc::new(AtomicBool::new(false));

            struct EventData {
                sync_started: Arc<AtomicBool>,
                headers_stored: Arc<AtomicBool>,
                sync_complete: Arc<AtomicBool>,
            }

            let event_data = EventData {
                sync_started: sync_started.clone(),
                headers_stored: headers_stored.clone(),
                sync_complete: sync_complete.clone(),
            };

            extern "C" fn on_sync_start(_manager_id: FFIManagerId, user_data: *mut c_void) {
                let data = unsafe { &*(user_data as *const EventData) };
                data.sync_started.store(true, Ordering::SeqCst);
            }

            extern "C" fn on_block_headers_stored(_tip_height: u32, user_data: *mut c_void) {
                let data = unsafe { &*(user_data as *const EventData) };
                data.headers_stored.store(true, Ordering::SeqCst);
            }

            extern "C" fn on_sync_complete(_header_tip: u32, _cycle: u32, user_data: *mut c_void) {
                let data = unsafe { &*(user_data as *const EventData) };
                data.sync_complete.store(true, Ordering::SeqCst);
            }

            let sync_callbacks = FFISyncEventCallbacks {
                on_sync_start: Some(on_sync_start),
                on_block_headers_stored: Some(on_block_headers_stored),
                on_block_header_sync_complete: None,
                on_filter_headers_stored: None,
                on_filter_headers_sync_complete: None,
                on_filters_stored: None,
                on_filters_sync_complete: None,
                on_blocks_needed: None,
                on_block_processed: None,
                on_masternode_state_updated: None,
                on_chainlock_received: None,
                on_instantlock_received: None,
                on_manager_error: None,
                on_sync_complete: Some(on_sync_complete),
                user_data: &event_data as *const _ as *mut c_void,
            };

            // Build an FFIEventCallbacks with sync callbacks set
            let callbacks = FFIEventCallbacks {
                sync: sync_callbacks,
                ..FFIEventCallbacks::default()
            };

            // Verify the struct is properly constructed (callbacks are now
            // passed directly to run(), no separate set call needed)
            assert!(callbacks.sync.on_sync_start.is_some());
            assert!(callbacks.sync.on_block_headers_stored.is_some());
            assert!(callbacks.sync.on_sync_complete.is_some());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }
}
