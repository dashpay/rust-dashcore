//! FFI callback implementations and tracker for integration tests.

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::*;

// ============================================================================
// Callback Tracker
// ============================================================================

/// Tracks callback invocations for verification.
#[derive(Default)]
pub struct CallbackTracker {
    // Sync event tracking
    pub sync_start_count: AtomicU32,
    pub block_headers_stored_count: AtomicU32,
    pub block_header_sync_complete_count: AtomicU32,
    pub filter_headers_stored_count: AtomicU32,
    pub filter_headers_sync_complete_count: AtomicU32,
    pub filters_stored_count: AtomicU32,
    pub filters_sync_complete_count: AtomicU32,
    pub blocks_needed_count: AtomicU32,
    pub block_processed_count: AtomicU32,
    pub masternode_state_updated_count: AtomicU32,
    pub chainlock_received_count: AtomicU32,
    pub instantlock_received_count: AtomicU32,
    pub manager_error_count: AtomicU32,
    pub sync_complete_count: AtomicU32,

    // Network event tracking
    pub peer_connected_count: AtomicU32,
    pub peer_disconnected_count: AtomicU32,
    pub peers_updated_count: AtomicU32,

    // Wallet event tracking
    pub transaction_received_count: AtomicU32,

    // Data from callbacks
    pub last_header_tip: AtomicU32,
    pub last_filter_tip: AtomicU32,
    pub last_connected_peer_count: AtomicU32,
    pub last_best_height: AtomicU32,
    pub errors: Mutex<Vec<String>>,
    pub connected_peers: Mutex<Vec<String>>,

    // Completion tracking
    pub sync_completed: AtomicBool,
}

// ============================================================================
// Sync Callbacks
// ============================================================================

extern "C" fn on_sync_start(manager_id: FFIManagerId, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.sync_start_count.fetch_add(1, Ordering::SeqCst);
        tracing::debug!("on_sync_start: manager={:?}", manager_id);
    }
}

extern "C" fn on_block_headers_stored(tip_height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.block_headers_stored_count.fetch_add(1, Ordering::SeqCst);
        tracker.last_header_tip.store(tip_height, Ordering::SeqCst);
        tracing::debug!("on_block_headers_stored: tip={}", tip_height);
    }
}

extern "C" fn on_block_header_sync_complete(tip_height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.block_header_sync_complete_count.fetch_add(1, Ordering::SeqCst);
        tracing::info!("on_block_header_sync_complete: tip={}", tip_height);
    }
}

extern "C" fn on_filter_headers_stored(
    _start_height: u32,
    _end_height: u32,
    tip_height: u32,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.filter_headers_stored_count.fetch_add(1, Ordering::SeqCst);
        tracker.last_filter_tip.store(tip_height, Ordering::SeqCst);
        tracing::debug!("on_filter_headers_stored: tip={}", tip_height);
    }
}

extern "C" fn on_filter_headers_sync_complete(tip_height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.filter_headers_sync_complete_count.fetch_add(1, Ordering::SeqCst);
        tracing::info!("on_filter_headers_sync_complete: tip={}", tip_height);
    }
}

extern "C" fn on_filters_stored(start_height: u32, end_height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.filters_stored_count.fetch_add(1, Ordering::SeqCst);
        tracing::debug!("on_filters_stored: {}-{}", start_height, end_height);
    }
}

extern "C" fn on_filters_sync_complete(tip_height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.filters_sync_complete_count.fetch_add(1, Ordering::SeqCst);
        tracing::info!("on_filters_sync_complete: tip={}", tip_height);
    }
}

extern "C" fn on_blocks_needed(
    _blocks: *const crate::FFIBlockNeeded,
    count: u32,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.blocks_needed_count.fetch_add(1, Ordering::SeqCst);
        tracing::debug!("on_blocks_needed: count={}", count);
    }
}

extern "C" fn on_block_processed(
    height: u32,
    _hash: *const [u8; 32],
    new_address_count: u32,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.block_processed_count.fetch_add(1, Ordering::SeqCst);
        tracing::debug!(
            "on_block_processed: height={}, new_addresses={}",
            height,
            new_address_count
        );
    }
}

extern "C" fn on_masternode_state_updated(height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.masternode_state_updated_count.fetch_add(1, Ordering::SeqCst);
        tracing::debug!("on_masternode_state_updated: height={}", height);
    }
}

extern "C" fn on_chainlock_received(
    height: u32,
    _hash: *const [u8; 32],
    _signature: *const [u8; 96],
    validated: bool,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.chainlock_received_count.fetch_add(1, Ordering::SeqCst);
        tracing::info!("on_chainlock_received: height={}, validated={}", height, validated);
    }
}

extern "C" fn on_instantlock_received(
    _txid: *const [u8; 32],
    _instantlock_data: *const u8,
    _instantlock_len: usize,
    validated: bool,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.instantlock_received_count.fetch_add(1, Ordering::SeqCst);
        tracing::debug!("on_instantlock_received: validated={}", validated);
    }
}

extern "C" fn on_manager_error(
    manager_id: FFIManagerId,
    error: *const c_char,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.manager_error_count.fetch_add(1, Ordering::SeqCst);
        let error_str = if !error.is_null() {
            CStr::from_ptr(error).to_string_lossy().to_string()
        } else {
            "Unknown error".to_string()
        };
        tracing::error!("on_manager_error: manager={:?}, error={}", manager_id, error_str);
        tracker.errors.lock().unwrap().push(error_str);
    }
}

extern "C" fn on_sync_complete(header_tip: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.sync_complete_count.fetch_add(1, Ordering::SeqCst);
        tracker.sync_completed.store(true, Ordering::SeqCst);
        // Update header tip from the sync complete event so the tracker reflects the
        // final state even when no BlockHeadersStored events fired (e.g. after restart
        // when headers are already persisted on disk).
        tracker.last_header_tip.store(header_tip, Ordering::SeqCst);
        tracing::info!("on_sync_complete: header_tip={}", header_tip);
    }
}

// ============================================================================
// Network Callbacks
// ============================================================================

extern "C" fn on_peer_connected(address: *const c_char, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.peer_connected_count.fetch_add(1, Ordering::SeqCst);
        let addr_str = if !address.is_null() {
            CStr::from_ptr(address).to_string_lossy().to_string()
        } else {
            "Unknown".to_string()
        };
        tracing::info!("on_peer_connected: {}", addr_str);
        tracker.connected_peers.lock().unwrap().push(addr_str);
    }
}

extern "C" fn on_peer_disconnected(address: *const c_char, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.peer_disconnected_count.fetch_add(1, Ordering::SeqCst);
        let addr_str = if !address.is_null() {
            CStr::from_ptr(address).to_string_lossy().to_string()
        } else {
            "Unknown".to_string()
        };
        tracing::info!("on_peer_disconnected: {}", addr_str);
    }
}

extern "C" fn on_peers_updated(connected_count: u32, best_height: u32, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.peers_updated_count.fetch_add(1, Ordering::SeqCst);
        tracker.last_connected_peer_count.store(connected_count, Ordering::SeqCst);
        tracker.last_best_height.store(best_height, Ordering::SeqCst);
        tracing::debug!(
            "on_peers_updated: connected={}, best_height={}",
            connected_count,
            best_height
        );
    }
}

// ============================================================================
// Wallet Callbacks
// ============================================================================

extern "C" fn on_transaction_received(
    wallet_id: *const c_char,
    account_index: u32,
    _txid: *const [u8; 32],
    amount: i64,
    _addresses: *const c_char,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let tracker = &*(user_data as *const CallbackTracker);
        tracker.transaction_received_count.fetch_add(1, Ordering::SeqCst);
        let wallet_str = if !wallet_id.is_null() {
            CStr::from_ptr(wallet_id).to_string_lossy().to_string()
        } else {
            "Unknown".to_string()
        };
        tracing::info!(
            "on_transaction_received: wallet={}, account={}, amount={}",
            wallet_str,
            account_index,
            amount
        );
    }
}

extern "C" fn on_balance_updated(
    wallet_id: *const c_char,
    spendable: u64,
    unconfirmed: u64,
    immature: u64,
    locked: u64,
    user_data: *mut c_void,
) {
    if user_data.is_null() {
        return;
    }
    unsafe {
        let _tracker = &*(user_data as *const CallbackTracker);
        let wallet_str = if !wallet_id.is_null() {
            CStr::from_ptr(wallet_id).to_string_lossy().to_string()
        } else {
            "Unknown".to_string()
        };
        tracing::info!(
            "on_balance_updated: wallet={}, spendable={}, unconfirmed={}, immature={}, locked={}",
            wallet_str,
            spendable,
            unconfirmed,
            immature,
            locked,
        );
    }
}

// ============================================================================
// Callback Factory Functions
// ============================================================================

/// Create sync callbacks with the minimal set needed for sync tracking.
pub fn create_minimal_sync_callbacks(tracker: &Arc<CallbackTracker>) -> FFISyncEventCallbacks {
    FFISyncEventCallbacks {
        on_sync_start: None,
        on_block_headers_stored: Some(on_block_headers_stored),
        on_block_header_sync_complete: None,
        on_filter_headers_stored: Some(on_filter_headers_stored),
        on_filter_headers_sync_complete: None,
        on_filters_stored: None,
        on_filters_sync_complete: None,
        on_blocks_needed: None,
        on_block_processed: None,
        on_masternode_state_updated: None,
        on_chainlock_received: None,
        on_instantlock_received: None,
        on_manager_error: Some(on_manager_error),
        on_sync_complete: Some(on_sync_complete),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}

/// Create full sync callbacks with all event handlers wired.
pub fn create_full_sync_callbacks(tracker: &Arc<CallbackTracker>) -> FFISyncEventCallbacks {
    FFISyncEventCallbacks {
        on_sync_start: Some(on_sync_start),
        on_block_headers_stored: Some(on_block_headers_stored),
        on_block_header_sync_complete: Some(on_block_header_sync_complete),
        on_filter_headers_stored: Some(on_filter_headers_stored),
        on_filter_headers_sync_complete: Some(on_filter_headers_sync_complete),
        on_filters_stored: Some(on_filters_stored),
        on_filters_sync_complete: Some(on_filters_sync_complete),
        on_blocks_needed: Some(on_blocks_needed),
        on_block_processed: Some(on_block_processed),
        on_masternode_state_updated: Some(on_masternode_state_updated),
        on_chainlock_received: Some(on_chainlock_received),
        on_instantlock_received: Some(on_instantlock_received),
        on_manager_error: Some(on_manager_error),
        on_sync_complete: Some(on_sync_complete),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}

pub fn create_network_callbacks(tracker: &Arc<CallbackTracker>) -> FFINetworkEventCallbacks {
    FFINetworkEventCallbacks {
        on_peer_connected: Some(on_peer_connected),
        on_peer_disconnected: Some(on_peer_disconnected),
        on_peers_updated: Some(on_peers_updated),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}

pub fn create_wallet_callbacks(tracker: &Arc<CallbackTracker>) -> FFIWalletEventCallbacks {
    FFIWalletEventCallbacks {
        on_transaction_received: Some(on_transaction_received),
        on_balance_updated: Some(on_balance_updated),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}
